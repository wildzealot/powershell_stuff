<#
.SYNOPSIS
    UAL Parser v2.6 - M365 Unified Audit Log parser for BEC investigations

.DESCRIPTION
    Parses M365 UAL exports (CSV or XLSX), extracts the nested AuditData JSON,
    and writes an investigation-ready Excel workbook.

    Changes from v2.5:
      - Fixed silent column loss: every sheet now has a fixed, uniform schema
        (Export-Excel only writes the columns of the FIRST object it receives).
      - JSON parsed with JavaScriptSerializer (PS 5.1): no 2 MB limit, keeps keys
        that differ only by case, no ConvertFrom-Json duplicate-key failures.
      - UserAgent resolved from top-level UserAgent OR ExtendedProperties
        (Entra sign-ins); Exchange ClientInfoString kept as its own column.
      - Session handling split into SessionId, AADSessionId, RequestId,
        UniqueTokenId, CorrelationId (RequestId is never reported as a session).
      - Email_Activity sheet: one row per message per event across Send, SendAs,
        SendOnBehalf, Create, Update, Move, deletes, and MailItemsAccessed
        (Bind items exploded to one row each; Sync shown per folder).
      - MailItemsAccessed AccessType and IsThrottled read from OperationProperties.
      - Inbox_Rules sheet covers New/Set/Enable/Disable/Remove-InboxRule and
        UpdateInboxRules (Outlook desktop, OperationProperties), with risk flags.
      - Exchange_Admin sheet for cmdlet activity (forwarding, permissions,
        transport rules, audit bypass) with risk flags.
      - SignIns sheet for UserLoggedIn / UserLoginFailed with device properties.
      - Sessions and IP_Summary pivot sheets.
      - Geolocation + ASN from the free DB-IP Lite databases (no account, no API
        key). Downloaded automatically once a month into a per-user cache; all
        lookups are local. If the download is blocked, the script notifies the
        user and continues without geolocation. Suspicious hosting/VPS ISP flag.
      - IPs normalized (ports stripped, IPv4-mapped IPv6 unwrapped).
      - AuditData_Flat sheet (RecordId | Path | Value): every JSON value, never dropped.
      - Excel 32,767-char cell limit handled (truncation flagged, never an error).
      - Values starting with '=' are prefixed with a space so attacker-controlled
        text (subjects, rule names) cannot become Excel formulas.
      - Sheets over the Excel row limit spill to CSV automatically.

    All timestamps are UTC.

.PARAMETER InputFile
    Path to the UAL export (CSV or XLSX).

.PARAMETER OutputFile
    Output Excel path (optional; defaults to <InputFile>_PARSED.xlsx).

.PARAMETER NoGeo
    Skip geolocation entirely (no download attempt).

.PARAMETER GeoCacheDir
    Folder for the DB-IP Lite files. Defaults to %LOCALAPPDATA%\UALParser\geo.
    For offline machines, copy dbip-country-lite-YYYY-MM.csv.gz and
    dbip-asn-lite-YYYY-MM.csv.gz into this folder and the script will use them.

.PARAMETER SuspiciousIspKeywords
    Case-insensitive substrings matched against the AS organization name.

.PARAMETER NoFlatSheet
    Skip the AuditData_Flat sheet (faster, smaller workbook).

.EXAMPLE
    .\UAL_Parserv2_6.ps1 -InputFile "C:\Exports\UAL_Export.csv"

.NOTES
    IP geolocation by DB-IP (https://db-ip.com), licensed CC BY 4.0.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$InputFile,

    [Parameter(Mandatory = $false)]
    [string]$OutputFile,

    [Parameter(Mandatory = $false)]
    [switch]$NoGeo,

    [Parameter(Mandatory = $false)]
    [string]$GeoCacheDir,

    [Parameter(Mandatory = $false)]
    [string[]]$SuspiciousIspKeywords = @(
        'Datacamp', 'Clouvider', 'DigitalOcean', 'OVH', 'M247', 'Psychz', 'QuadraNet',
        'Sharktech', 'LeaseWeb', 'Hostinger', 'Fastly', 'MTN Nigeria',
        'Vultr', 'Choopa', 'Constant Company', 'Hetzner', 'Contabo', 'Linode',
        'ColoCrossing', 'HostRoyale', 'Tzulo', 'FranTech'
    ),

    [Parameter(Mandatory = $false)]
    [switch]$NoFlatSheet,

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludedOperationSheets = @('ArchiveCreated', 'AttachmentAccess', 'ClientViewSignaled')
)

$ErrorActionPreference = 'Continue'
$startTime = Get-Date
$script:Version = '2.6'

#region Initialization
Write-Host ('=' * 70) -ForegroundColor Cyan
Write-Host "UAL PARSER v$($script:Version)" -ForegroundColor Cyan
Write-Host ('=' * 70) -ForegroundColor Cyan

if (-not (Test-Path -LiteralPath $InputFile)) {
    Write-Error "File not found: $InputFile"
    exit 1
}
$InputFile = (Resolve-Path -LiteralPath $InputFile).Path

$baseName = [System.IO.Path]::GetFileNameWithoutExtension($InputFile)
$baseDir  = [System.IO.Path]::GetDirectoryName($InputFile)
if ([string]::IsNullOrEmpty($baseDir)) { $baseDir = (Get-Location).Path }

if (-not $OutputFile) {
    $OutputFile = Join-Path $baseDir "$($baseName)_PARSED.xlsx"
}
$debugLog = Join-Path $baseDir "$($baseName)_DEBUG.txt"

@"
========================================
UAL PARSER v$($script:Version) DEBUG LOG
========================================
Started: $startTime
PowerShell: $($PSVersionTable.PSVersion)
Input: $InputFile
Output: $OutputFile
========================================

"@ | Out-File -FilePath $debugLog -Force

function Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts   = Get-Date -Format 'HH:mm:ss.fff'
    $line = "[$ts] [$Level] $Message"
    Add-Content -Path $debugLog -Value $line
    $color = switch ($Level) {
        'ERROR' { 'Red' }
        'WARN'  { 'Yellow' }
        'DEBUG' { 'DarkGray' }
        default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
}

Log 'Script initialized'

if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Log 'Installing ImportExcel module...' 'WARN'
    try {
        Install-Module -Name ImportExcel -Force -Scope CurrentUser -ErrorAction Stop
        Log 'ImportExcel installed successfully'
    } catch {
        Log "Failed to install ImportExcel: $($_.Exception.Message)" 'ERROR'
        exit 1
    }
}
Import-Module ImportExcel -ErrorAction Stop
Log 'ImportExcel module loaded'

# JSON engine: JavaScriptSerializer on Windows PowerShell 5.1, ConvertFrom-Json -AsHashtable on PS 6+
$script:JsonMode = $null
try {
    Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
    $script:Jss = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $script:Jss.MaxJsonLength  = [int]::MaxValue
    $script:Jss.RecursionLimit = 512
    $script:JsonMode = 'JavaScriptSerializer'
} catch {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $script:JsonMode = 'ConvertFromJsonHashtable'
    } else {
        Log "Could not load System.Web.Extensions: $($_.Exception.Message)" 'ERROR'
        exit 1
    }
}
Log "JSON engine: $($script:JsonMode)"

# Limits
$script:MaxCell         = 32000     # Excel hard limit is 32,767 characters per cell
$script:MaxExcelRows    = 1048575   # Excel limit minus header row
$script:AutoSizeMaxRows = 50000     # AutoSize is very slow on huge sheets
$script:NavHeader       = '[<< Summary]'
$script:TruncatedCells  = 0
#endregion

#region Compiled helpers (C# 5 compatible for PS 5.1): JSON hot paths + geo lookup
$helperCs = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Text;

public static class UalJson
{
    public static int Truncated = 0;

    // Values that passed through the PowerShell pipeline can arrive wrapped in PSObject.
    public static object Unwrap(object v)
    {
        System.Management.Automation.PSObject pso = v as System.Management.Automation.PSObject;
        return (pso != null) ? pso.BaseObject : v;
    }

    public static string Text(object v)
    {
        v = Unwrap(v);
        if (v == null) return null;
        string s = v as string;
        if (s != null) return s;
        if (v is bool) return ((bool)v) ? "True" : "False";
        if (v is DateTime) return ((DateTime)v).ToString("o", CultureInfo.InvariantCulture);
        IFormattable f = v as IFormattable;
        if (f != null) return f.ToString(null, CultureInfo.InvariantCulture);
        IList l = v as IList;
        if (l != null)
        {
            List<string> parts = new List<string>();
            foreach (object o in l) parts.Add(Text(o));
            return string.Join("; ", parts.ToArray());
        }
        return v.ToString();
    }

    // Excel cell safety: length cap, and a leading space before '=' so text cannot become a formula.
    public static string Limit(string s, int max)
    {
        if (s == null) return null;
        if (s.Length > 0 && s[0] == '=') s = " " + s;
        return LimitLength(s, max);
    }

    public static string LimitLength(string s, int max)
    {
        if (s == null || s.Length <= max) return s;
        Truncated++;
        return s.Substring(0, max) + " ...[TRUNCATED: original length " + s.Length.ToString(CultureInfo.InvariantCulture) + " chars]";
    }

    // Case-insensitive key lookup with trimmed-key fallback (some UAL keys carry trailing spaces).
    public static object Get(object d, string key)
    {
        IDictionary dict = Unwrap(d) as IDictionary;
        if (dict == null) return null;
        if (dict.Contains(key)) return Unwrap(dict[key]);
        foreach (DictionaryEntry e in dict)
        {
            string k = Unwrap(e.Key) as string;
            if (k != null && string.Equals(k.Trim(), key, StringComparison.OrdinalIgnoreCase)) return Unwrap(e.Value);
        }
        return null;
    }

    private static string[] Msg(object it, string fallbackFolder, int max)
    {
        string folder = Text(Get(Get(it, "ParentFolder"), "Path"));
        if (string.IsNullOrEmpty(folder)) folder = Text(Get(it, "Path"));
        if (string.IsNullOrEmpty(folder)) folder = fallbackFolder;
        return new string[] {
            Limit(Text(Get(it, "Subject")), max),
            Limit(Text(Get(it, "InternetMessageId")), max),
            Limit(folder, max),
            Text(Get(it, "SizeInBytes")),
            Limit(Text(Get(it, "Attachments")), max),
            "0"
        };
    }

    // Every message referenced by an Exchange record: Item, AffectedItems[], Folders[].FolderItems[].
    // Row layout: [Subject, InternetMessageId, Folder, SizeInBytes, Attachments, FolderOnly("1"/"0")]
    public static List<string[]> Messages(object root, int max)
    {
        List<string[]> list = new List<string[]>();
        root = Unwrap(root);
        if (!(root is IDictionary)) return list;
        string src = Text(Get(Get(root, "Folder"), "Path"));

        object item = Get(root, "Item");
        if (item is IDictionary) list.Add(Msg(item, src, max));

        IList affected = Get(root, "AffectedItems") as IList;
        if (affected != null)
        {
            foreach (object o0 in affected) { object o = Unwrap(o0); if (o is IDictionary) list.Add(Msg(o, src, max)); }
        }

        IList folders = Get(root, "Folders") as IList;
        if (folders != null)
        {
            foreach (object fd0 in folders)
            {
                object fd = Unwrap(fd0);
                if (!(fd is IDictionary)) continue;
                string path = Text(Get(fd, "Path"));
                IList items = Get(fd, "FolderItems") as IList;
                if (items != null && items.Count > 0)
                {
                    foreach (object fi0 in items) { object fi = Unwrap(fi0); if (fi is IDictionary) list.Add(Msg(fi, path, max)); }
                }
                else
                {
                    // Sync event: folder-level only
                    list.Add(new string[] { null, null, Limit(path, max), null, null, "1" });
                }
            }
        }
        return list;
    }

    // Appends one row per JSON leaf: [nav(null), RecordId, CreationDate, Operation, UserId, Path, Value]
    public static void FlattenRows(object root, List<object[]> rows, string recId, string ts, string op, string user, int max)
    {
        List<string[]> pairs = new List<string[]>();
        Flatten(root, "", pairs, 0, max);
        foreach (string[] p in pairs)
        {
            rows.Add(new object[] { null, recId, ts, op, user, p[0], p[1] });
        }
    }

    private static void Flatten(object node, string path, List<string[]> outList, int depth, int max)
    {
        node = Unwrap(node);
        if (depth > 64) { outList.Add(new string[] { path, "[MAX DEPTH REACHED]" }); return; }
        if (node == null) { outList.Add(new string[] { path, "" }); return; }
        IDictionary d = node as IDictionary;
        if (d != null)
        {
            if (d.Count == 0) { outList.Add(new string[] { path, "{}" }); return; }
            foreach (DictionaryEntry e in d)
            {
                string k = Convert.ToString(e.Key, CultureInfo.InvariantCulture);
                Flatten(e.Value, string.IsNullOrEmpty(path) ? k : path + "." + k, outList, depth + 1, max);
            }
            return;
        }
        if (!(node is string))
        {
            IList l = node as IList;
            if (l != null)
            {
                if (l.Count == 0) { outList.Add(new string[] { path, "[]" }); return; }
                for (int i = 0; i < l.Count; i++)
                {
                    Flatten(l[i], path + "[" + i.ToString(CultureInfo.InvariantCulture) + "]", outList, depth + 1, max);
                }
                return;
            }
        }
        outList.Add(new string[] { path, LimitLength(Text(node), max) });
    }
}

public class UalGeoResult
{
    public string Network;
    public string Country;
    public string CountryCode;
    public string Asn;
    public string AsName;
}

public static class UalGeo
{
    private sealed class Target
    {
        public int Fam;
        public ulong Hi;
        public ulong Lo;
        public string Ip;
    }

    private static int Cmp(int fa, ulong ha, ulong la, int fb, ulong hb, ulong lb)
    {
        if (fa != fb) return fa < fb ? -1 : 1;
        if (ha != hb) return ha < hb ? -1 : 1;
        if (la != lb) return la < lb ? -1 : 1;
        return 0;
    }

    private static ulong LowMask(int bits)
    {
        if (bits <= 0) return 0UL;
        if (bits >= 64) return ulong.MaxValue;
        return (1UL << bits) - 1UL;
    }

    public static bool TryKey(string s, out int fam, out ulong hi, out ulong lo)
    {
        fam = 0; hi = 0UL; lo = 0UL;
        if (string.IsNullOrEmpty(s)) return false;
        IPAddress a;
        if (!IPAddress.TryParse(s.Trim(), out a)) return false;
        byte[] b = a.GetAddressBytes();
        if (b.Length == 4)
        {
            fam = 4;
            lo = ((ulong)b[0] << 24) | ((ulong)b[1] << 16) | ((ulong)b[2] << 8) | (ulong)b[3];
            return true;
        }
        if (b.Length == 16)
        {
            fam = 6;
            for (int i = 0; i < 8; i++) hi = (hi << 8) | (ulong)b[i];
            for (int i = 8; i < 16; i++) lo = (lo << 8) | (ulong)b[i];
            return true;
        }
        return false;
    }

    public static bool IsPrivate(string s)
    {
        IPAddress a;
        if (string.IsNullOrEmpty(s) || !IPAddress.TryParse(s, out a)) return false;
        byte[] b = a.GetAddressBytes();
        if (b.Length == 4)
        {
            if (b[0] == 10 || b[0] == 127 || b[0] == 0) return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 169 && b[1] == 254) return true;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;
            if (b[0] >= 224) return true;
            return false;
        }
        bool allZero = true;
        for (int i = 0; i < 15; i++) { if (b[i] != 0) { allZero = false; break; } }
        if (allZero && (b[15] == 0 || b[15] == 1)) return true;
        if ((b[0] & 0xFE) == 0xFC) return true;
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true;
        if (b[0] == 0xFF) return true;
        return false;
    }

    private static List<string> SplitCsv(string line)
    {
        List<string> f = new List<string>();
        StringBuilder sb = new StringBuilder();
        bool q = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (q)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                    else q = false;
                }
                else sb.Append(c);
            }
            else
            {
                if (c == '"') q = true;
                else if (c == ',') { f.Add(sb.ToString()); sb.Length = 0; }
                else sb.Append(c);
            }
        }
        f.Add(sb.ToString());
        return f;
    }

    private static string Field(List<string> f, int idx)
    {
        if (idx < 0 || idx >= f.Count) return null;
        return f[idx];
    }

    private static bool TryRange(string net, out int fam, out ulong sHi, out ulong sLo, out ulong eHi, out ulong eLo)
    {
        fam = 0; sHi = 0UL; sLo = 0UL; eHi = 0UL; eLo = 0UL;
        if (string.IsNullOrEmpty(net)) return false;
        net = net.Trim();
        int dash = net.IndexOf('-');
        if (dash > 0)
        {
            int fam2;
            if (!TryKey(net.Substring(0, dash), out fam, out sHi, out sLo)) return false;
            if (!TryKey(net.Substring(dash + 1), out fam2, out eHi, out eLo)) return false;
            return fam2 == fam;
        }
        int slash = net.IndexOf('/');
        string ipPart = slash > 0 ? net.Substring(0, slash) : net;
        ulong hi;
        ulong lo;
        if (!TryKey(ipPart, out fam, out hi, out lo)) return false;
        int width = (fam == 4) ? 32 : 128;
        int prefix = width;
        if (slash > 0)
        {
            if (!int.TryParse(net.Substring(slash + 1), out prefix)) return false;
            if (prefix < 0 || prefix > width) return false;
        }
        int host = width - prefix;
        if (fam == 4)
        {
            ulong m4 = LowMask(host);
            sLo = lo & ~m4 & 0xFFFFFFFFUL;
            eLo = (lo | m4) & 0xFFFFFFFFUL;
            return true;
        }
        if (host >= 64)
        {
            ulong mh = LowMask(host - 64);
            sHi = hi & ~mh;
            eHi = hi | mh;
            sLo = 0UL;
            eLo = ulong.MaxValue;
        }
        else
        {
            ulong ml = LowMask(host);
            sHi = hi;
            eHi = hi;
            sLo = lo & ~ml;
            eLo = lo | ml;
        }
        return true;
    }

    private static string CountryName(string cc)
    {
        if (string.IsNullOrEmpty(cc) || cc == "ZZ") return null;
        try { return new RegionInfo(cc).EnglishName; } catch { return null; }
    }

    // Streams one DB-IP Lite CSV (no header: start_ip,end_ip,...) and returns the
    // matching row's fields for each target IP. Stops early once every IP is matched.
    private static Dictionary<string, string[]> Scan(string path, List<Target> targets)
    {
        Dictionary<string, string[]> hits = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(path) || !File.Exists(path) || targets.Count == 0) return hits;
        FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20);
        try
        {
            Stream input = fs;
            if (path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
            {
                input = new GZipStream(fs, CompressionMode.Decompress);
            }
            using (StreamReader r = new StreamReader(input, Encoding.UTF8))
            {
                int remaining = targets.Count;
                string line;
                while (remaining > 0 && (line = r.ReadLine()) != null)
                {
                    if (line.Length == 0) continue;
                    List<string> f = SplitCsv(line);
                    if (f.Count < 3) continue;
                    int fam;
                    ulong sHi, sLo, eHi, eLo;
                    if (!TryRange(f[0] + "-" + f[1], out fam, out sHi, out sLo, out eHi, out eLo)) continue;

                    int a = 0;
                    int bnd = targets.Count;
                    while (a < bnd)
                    {
                        int mid = (a + bnd) / 2;
                        Target tm = targets[mid];
                        if (Cmp(tm.Fam, tm.Hi, tm.Lo, fam, sHi, sLo) < 0) a = mid + 1; else bnd = mid;
                    }
                    for (int k = a; k < targets.Count; k++)
                    {
                        Target tk = targets[k];
                        if (Cmp(tk.Fam, tk.Hi, tk.Lo, fam, eHi, eLo) > 0) break;
                        if (hits.ContainsKey(tk.Ip)) continue;
                        hits[tk.Ip] = f.ToArray();
                        remaining--;
                    }
                }
            }
        }
        finally
        {
            fs.Dispose();
        }
        return hits;
    }

    // countryPath: start,end,CC   asnPath: start,end,asn,"org". Either may be null.
    public static Dictionary<string, UalGeoResult> Lookup(string countryPath, string asnPath, string[] ips)
    {
        Dictionary<string, UalGeoResult> result = new Dictionary<string, UalGeoResult>(StringComparer.OrdinalIgnoreCase);
        List<Target> targets = new List<Target>();
        foreach (string ip in ips)
        {
            int tf;
            ulong th;
            ulong tl;
            if (TryKey(ip, out tf, out th, out tl))
            {
                Target t = new Target();
                t.Fam = tf; t.Hi = th; t.Lo = tl; t.Ip = ip;
                targets.Add(t);
            }
        }
        if (targets.Count == 0) return result;
        targets.Sort(delegate(Target x, Target y) { return Cmp(x.Fam, x.Hi, x.Lo, y.Fam, y.Hi, y.Lo); });

        Dictionary<string, string[]> cHits = Scan(countryPath, targets);
        Dictionary<string, string[]> aHits = Scan(asnPath, targets);

        foreach (Target t in targets)
        {
            string[] c;
            string[] n;
            bool hasC = cHits.TryGetValue(t.Ip, out c);
            bool hasA = aHits.TryGetValue(t.Ip, out n);
            if (!hasC && !hasA) continue;
            UalGeoResult g = new UalGeoResult();
            if (hasC)
            {
                g.CountryCode = c[2];
                g.Country = CountryName(c[2]);
                if (g.Country == null) g.Country = c[2];
            }
            if (hasA)
            {
                g.Asn = "AS" + n[2];
                g.AsName = (n.Length > 3) ? n[3] : null;
                g.Network = n[0] + " - " + n[1];
            }
            else if (hasC)
            {
                g.Network = c[0] + " - " + c[1];
            }
            result[t.Ip] = g;
        }
        return result;
    }
}
'@

if (-not ('UalJson' -as [type]) -or -not ('UalGeo' -as [type])) {
    try {
        Add-Type -TypeDefinition $helperCs -Language CSharp -ErrorAction Stop
    } catch {
        Log "Failed to compile helper code: $($_.Exception.Message)" 'ERROR'
        Log "If you edited this script in this PowerShell window before, open a NEW window and re-run (compiled types cannot be reloaded)." 'ERROR'
        exit 1
    }
}
[UalJson]::Truncated = 0
#endregion

#region Helper functions
function Get-DictValue {
    # Case-insensitive key lookup with a trimmed-key fallback (some UAL keys carry trailing spaces).
    param($Dict, [string]$Key)
    if ($null -eq $Dict -or -not ($Dict -is [System.Collections.IDictionary])) { return $null }
    # JavaScriptSerializer returns Dictionary[string,object]; Hashtable on PS 6+. Both expose ContainsKey.
    $has = if ($Dict -is [System.Collections.Specialized.OrderedDictionary]) { $Dict.Contains($Key) } else { $Dict.ContainsKey($Key) }
    if ($has) { return ,$Dict[$Key] }
    foreach ($k in $Dict.Keys) {
        if ([string]::Equals(([string]$k).Trim(), $Key, [System.StringComparison]::OrdinalIgnoreCase)) {
            return ,$Dict[$k]
        }
    }
    return $null
}

function Get-JV {
    # Walk a dotted path through parsed JSON dictionaries.
    param($Root, [string]$Path)
    $cur = $Root
    foreach ($seg in $Path.Split('.')) {
        if ($null -eq $cur) { return $null }
        $cur = Get-DictValue $cur $seg
    }
    return ,$cur
}

function ConvertTo-JsonText {
    param($Value)
    try {
        if ($script:JsonMode -eq 'JavaScriptSerializer') { return $script:Jss.Serialize($Value) }
        return (ConvertTo-Json -InputObject $Value -Depth 20 -Compress)
    } catch {
        return [string]$Value
    }
}

function ConvertTo-Text {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool]) { if ($Value) { return 'True' } else { return 'False' } }
    if ($Value -is [datetime]) { return $Value.ToString('o') }
    if ($Value -is [System.Collections.IDictionary]) { return (ConvertTo-JsonText $Value) }
    if ($Value -is [System.Collections.IList]) {
        $parts = foreach ($x in $Value) { ConvertTo-Text $x }
        return (@($parts) -join '; ')
    }
    if ($Value -is [System.IFormattable]) {
        return $Value.ToString($null, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    return [string]$Value
}

function Get-JT {
    # Text value at a dotted path, or $null.
    param($Root, [string]$Path)
    $v = Get-JV $Root $Path
    if ($null -eq $v) { return $null }
    return (ConvertTo-Text $v)
}

function To-List {
    param($Value)
    if ($null -eq $Value) { return ,@() }
    if (($Value -is [System.Collections.IList]) -and -not ($Value -is [string])) { return ,$Value }
    return ,@($Value)
}

function Coalesce {
    foreach ($a in $args) {
        if ($null -ne $a -and -not [string]::IsNullOrWhiteSpace([string]$a)) { return $a }
    }
    return $null
}

function Get-Col {
    # Read the first non-empty CSV/XLSX column from a list of candidate header names.
    param($Rec, [string[]]$Names)
    foreach ($n in $Names) {
        $p = $Rec.PSObject.Properties[$n]
        if ($p -and $null -ne $p.Value -and ([string]$p.Value).Trim() -ne '') { return $p.Value }
    }
    return $null
}

function Get-NVMap {
    # Convert a Name/Value array (ExtendedProperties, DeviceProperties, Parameters,
    # OperationProperties) into an ordered, case-insensitive map.
    param($Root, [string]$ArrayName)
    $map = [ordered]@{}
    foreach ($e in (To-List (Get-DictValue $Root $ArrayName))) {
        if ($e -is [System.Collections.IDictionary]) {
            $n = Get-DictValue $e 'Name'
            if ($null -ne $n) {
                $key = ([string]$n).Trim()
                if ($key -ne '' -and -not $map.Contains($key)) {
                    $v = Get-DictValue $e 'Value'
                    if ($null -eq $v) { $v = Get-DictValue $e 'NewValue' }
                    $map[$key] = ConvertTo-Text $v
                }
            }
        }
    }
    return $map
}

function Format-NV {
    param([System.Collections.IDictionary]$Map)
    if ($null -eq $Map -or $Map.Count -eq 0) { return $null }
    $parts = foreach ($k in $Map.Keys) { "$k=$($Map[$k])" }
    return (@($parts) -join ' | ')
}

function Format-Modified {
    param($Root)
    $parts = foreach ($m in (To-List (Get-JV $Root 'ModifiedProperties'))) {
        if ($m -is [System.Collections.IDictionary]) {
            '{0}: {1} -> {2}' -f (Get-JT $m 'Name'), (Get-JT $m 'OldValue'), (Get-JT $m 'NewValue')
        }
    }
    if (@($parts).Count -eq 0) { return $null }
    return (@($parts) -join ' | ')
}

function Convert-Ts {
    # Normalize to 'yyyy-MM-dd HH:mm:ss' UTC.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        $d = $Value
        if ($d.Kind -eq [System.DateTimeKind]::Local) { $d = $d.ToUniversalTime() }
        return $d.ToString('yyyy-MM-dd HH:mm:ss')
    }
    if ($Value -is [double]) {
        try { return ([datetime]::FromOADate($Value)).ToString('yyyy-MM-dd HH:mm:ss') } catch { }
    }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return $null }
    $out = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$out)) {
        return $out.ToString('yyyy-MM-dd HH:mm:ss')
    }
    return $s
}

function Normalize-IP {
    # Strip ports/brackets/scope IDs, unwrap IPv4-mapped IPv6, canonicalize. Returns $null if not an IP.
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $s = $Value.Trim()
    if ($s -match '^\[([^\]]+)\](:\d+)?$') { $s = $Matches[1] }
    elseif ($s -match '^(\d{1,3}(\.\d{1,3}){3}):\d+$') { $s = $Matches[1] }
    $pct = $s.IndexOf('%')
    if ($pct -gt 0) { $s = $s.Substring(0, $pct) }
    if (-not (($s -match '^\d{1,3}(\.\d{1,3}){3}$') -or $s.Contains(':'))) { return $null }
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($s, [ref]$addr)) { return $null }
    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and $addr.IsIPv4MappedToIPv6) {
        $addr = $addr.MapToIPv4()
    }
    return $addr.ToString()
}

function Limit-Cell {
    param([string]$Value)
    if ($null -eq $Value) { return $null }
    $s = $Value
    if ($s.Length -gt 0 -and $s[0] -eq '=') { $s = ' ' + $s }
    if ($s.Length -gt $script:MaxCell) {
        $orig = $s.Length
        $s = $s.Substring(0, $script:MaxCell) + " ...[TRUNCATED: original length $orig chars]"
        $script:TruncatedCells++
    }
    return $s
}

function New-Row {
    # Build a row with EVERY column present, so Export-Excel never drops a column.
    param([string[]]$Columns, [hashtable]$Values)
    $o = [ordered]@{}
    foreach ($c in $Columns) {
        $v = $Values[$c]
        if ($v -is [string]) { $v = Limit-Cell $v }
        $o[$c] = $v
    }
    return [PSCustomObject]$o
}

function New-Agg {
    $cmp = [System.StringComparer]::OrdinalIgnoreCase
    return @{
        First    = $null
        Last     = $null
        Count    = 0
        Users    = New-Object 'System.Collections.Generic.HashSet[string]' ($cmp)
        IPs      = New-Object 'System.Collections.Generic.HashSet[string]' ($cmp)
        UAs      = New-Object 'System.Collections.Generic.HashSet[string]' ($cmp)
        Sessions = New-Object 'System.Collections.Generic.HashSet[string]' ($cmp)
        Ops      = @{}
    }
}

function Update-Agg {
    param($Agg, [string]$Ts, [string]$User, [string[]]$IPs, [string]$UA, [string]$Op, [string]$Session)
    $Agg.Count++
    if ($Ts) {
        if ($null -eq $Agg.First -or [string]::CompareOrdinal($Ts, $Agg.First) -lt 0) { $Agg.First = $Ts }
        if ($null -eq $Agg.Last  -or [string]::CompareOrdinal($Ts, $Agg.Last)  -gt 0) { $Agg.Last  = $Ts }
    }
    if ($User)    { [void]$Agg.Users.Add($User) }
    if ($UA)      { [void]$Agg.UAs.Add($UA) }
    if ($Session) { [void]$Agg.Sessions.Add($Session) }
    foreach ($ip in $IPs) { if ($ip) { [void]$Agg.IPs.Add($ip) } }
    if ($Op) {
        if ($Agg.Ops.ContainsKey($Op)) { $Agg.Ops[$Op]++ } else { $Agg.Ops[$Op] = 1 }
    }
}

function Join-Set {
    param($Set, [int]$Max = 50)
    if ($null -eq $Set -or $Set.Count -eq 0) { return $null }
    $arr = @($Set | Sort-Object)
    if ($arr.Count -gt $Max) { return (($arr[0..($Max - 1)] -join '; ') + "; ...(+$($arr.Count - $Max) more)") }
    return ($arr -join '; ')
}

function Format-Ops {
    param([hashtable]$Ops)
    if ($null -eq $Ops -or $Ops.Count -eq 0) { return $null }
    $parts = $Ops.GetEnumerator() | Sort-Object -Property Value -Descending | ForEach-Object { "$($_.Key)($($_.Value))" }
    return (@($parts) -join '; ')
}

function Test-SuspiciousIsp {
    param([string]$AsName)
    $hay = "$AsName"
    if ([string]::IsNullOrWhiteSpace($hay)) { return $null }
    foreach ($k in $SuspiciousIspKeywords) {
        if ($hay.IndexOf($k, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $k }
    }
    return $null
}

function Get-SafeSheetName {
    param([string]$Name, $Used)
    $n = ($Name -replace '[\\\/\*\?\[\]:]+', '_').Trim("'")
    if ($n.Length -gt 31) { $n = $n.Substring(0, 31) }
    $candidate = $n
    $i = 2
    while ($Used.Contains($candidate)) {
        $suffix = "~$i"
        $candidate = $n.Substring(0, [Math]::Min($n.Length, 31 - $suffix.Length)) + $suffix
        $i++
    }
    [void]$Used.Add($candidate)
    return $candidate
}
#endregion

#region Load Data
Log 'Loading data from file...'
$records = $null
$fileExt = [System.IO.Path]::GetExtension($InputFile).ToLower()

try {
    if ($fileExt -eq '.xlsx' -or $fileExt -eq '.xls') {
        Log 'Detected Excel format, using Import-Excel...'
        $records = @(Import-Excel -Path $InputFile -ErrorAction Stop)
    } else {
        Log 'Detected CSV format, using Import-Csv...'
        try {
            $records = @(Import-Csv -Path $InputFile -Encoding UTF8 -ErrorAction Stop)
        } catch {
            $records = @(Import-Csv -Path $InputFile -ErrorAction Stop)
        }
    }
} catch {
    Log "Failed to load file: $($_.Exception.Message)" 'ERROR'
    exit 1
}

if ($null -eq $records -or $records.Count -eq 0) {
    Log 'No records loaded from file!' 'ERROR'
    exit 1
}

$totalRecords = $records.Count
Log "Total records: $totalRecords"

$firstRecord = $records[0]
$columns     = @($firstRecord.PSObject.Properties.Name)
Log "Columns found ($($columns.Count)): $($columns -join ', ')"

$auditDataColumn = $columns | Where-Object { $_ -eq 'AuditData' } | Select-Object -First 1
if ($auditDataColumn) {
    Log "AuditData column found: '$auditDataColumn'"
} else {
    Log "AuditData column not found. Searching for a JSON-like column..." 'WARN'
    foreach ($col in $columns) {
        $val = $firstRecord.$col
        if ($val -and [string]$val -match '^\s*\{') {
            Log "Using JSON-like column '$col'" 'WARN'
            $auditDataColumn = $col
            break
        }
    }
}
if (-not $auditDataColumn) {
    Log 'No AuditData/JSON column found; output will contain CSV columns only.' 'WARN'
}
#endregion

#region DB-IP Lite acquisition (auto-download with per-user monthly cache)
$script:DbipBaseUrl = 'https://download.db-ip.com/free'
$script:GeoNotices  = New-Object System.Collections.ArrayList
$script:GeoBlocked  = $false   # set after a network-level failure so we don't wait on more attempts

function Write-GeoNotice {
    param([string]$Message, [string]$Level = 'INFO')
    $color = if ($Level -eq 'WARN') { 'Yellow' } else { 'Cyan' }
    Write-Host "[GEO] $Message" -ForegroundColor $color
    Add-Content -Path $debugLog -Value ("[{0}] [{1}] [GEO] {2}" -f (Get-Date -Format 'HH:mm:ss.fff'), $Level, $Message)
    if ($Level -eq 'WARN') { [void]$script:GeoNotices.Add($Message) }
}

function Get-GeoCacheDir {
    if ($GeoCacheDir) { return $GeoCacheDir }
    $root = $env:LOCALAPPDATA
    if (-not $root) { $root = Join-Path $HOME '.ualparser' } else { $root = Join-Path $root 'UALParser' }
    return (Join-Path $root 'geo')
}

function Test-GzipFile {
    param([string]$Path)
    try {
        $fi = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($fi.Length -lt 500000) { return $false }
        $fs = [System.IO.File]::OpenRead($Path)
        try { $b1 = $fs.ReadByte(); $b2 = $fs.ReadByte() } finally { $fs.Dispose() }
        return ($b1 -eq 0x1F -and $b2 -eq 0x8B)
    } catch { return $false }
}

function Get-DbipFile {
    # Returns the path to a usable dbip-<Kind>-lite-YYYY-MM.csv.gz, downloading the
    # current month if needed. Returns $null (with a user notice) if nothing is available.
    param([string]$Kind, [string]$Dir)

    $nowUtc = (Get-Date).ToUniversalTime()
    $months = @($nowUtc.ToString('yyyy-MM'), $nowUtc.AddMonths(-1).ToString('yyyy-MM'))

    # 1. Current month already cached
    $cur = Join-Path $Dir ("dbip-{0}-lite-{1}.csv.gz" -f $Kind, $months[0])
    if (Test-GzipFile $cur) { return $cur }

    # 2. Try to download current month, then previous month (new files appear early in the month)
    $downloadBlocked = $false
    foreach ($m in $months) {
        $name = "dbip-{0}-lite-{1}.csv.gz" -f $Kind, $m
        $dest = Join-Path $Dir $name
        if (Test-GzipFile $dest) { return $dest }
        if ($script:GeoBlocked) { break }
        $url  = "$($script:DbipBaseUrl)/$name"
        $part = "$dest.partial"
        Write-GeoNotice "Downloading DB-IP Lite $Kind database ($m) from download.db-ip.com ..."
        $oldPP = $ProgressPreference
        try {
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $url -OutFile $part -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            if (Test-GzipFile $part) {
                Move-Item -LiteralPath $part -Destination $dest -Force
                Write-GeoNotice "Saved $name to $Dir"
                # Remove older months of this kind
                Get-ChildItem -LiteralPath $Dir -Filter ("dbip-{0}-lite-*.csv.gz" -f $Kind) -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -ne $name } | Remove-Item -Force -ErrorAction SilentlyContinue
                return $dest
            }
            Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
            Write-GeoNotice "Downloaded $name but it is not a valid gzip file (proxy or block page?)." 'WARN'
            $downloadBlocked = $true
        } catch {
            Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
            $status = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }
            if ($status -eq 404) {
                Write-GeoNotice "$name is not published yet (HTTP 404); trying the previous month."
                continue
            }
            $why = if ($status) { "HTTP $status" } else { $_.Exception.Message }
            Write-GeoNotice "Download of $name failed: $why" 'WARN'
            $downloadBlocked = $true
        } finally {
            $ProgressPreference = $oldPP
        }
        if ($downloadBlocked) { $script:GeoBlocked = $true; break }   # network-level failure: stop trying
    }

    # 3. Fall back to the newest cached file of any month
    $old = Get-ChildItem -LiteralPath $Dir -Filter ("dbip-{0}-lite-*.csv.gz" -f $Kind) -ErrorAction SilentlyContinue |
        Where-Object { Test-GzipFile $_.FullName } | Sort-Object Name -Descending | Select-Object -First 1
    if ($old) {
        Write-GeoNotice "Using older cached file $($old.Name) (could not get the current month)." 'WARN'
        return $old.FullName
    }
    return $null
}

function Initialize-GeoDb {
    # Returns @{ Country = path|$null; Asn = path|$null; Status = text }
    if ($NoGeo) { return @{ Country = $null; Asn = $null; Status = 'Skipped (-NoGeo)' } }
    $dir = Get-GeoCacheDir
    try {
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
    } catch {
        Write-GeoNotice "Cannot create geo cache folder '$dir': $($_.Exception.Message)" 'WARN'
        return @{ Country = $null; Asn = $null; Status = "Unavailable: cannot create cache folder $dir" }
    }
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    try { [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials } catch { }

    $c = Get-DbipFile 'country' $dir
    $a = Get-DbipFile 'asn' $dir
    if (-not $c -and -not $a) {
        return @{ Country = $null; Asn = $null; Status = 'Unavailable: DB-IP download blocked or failed and no cached copy exists' }
    }
    $parts = @()
    if ($c) { $parts += [System.IO.Path]::GetFileName($c) } else { $parts += 'country: unavailable' }
    if ($a) { $parts += [System.IO.Path]::GetFileName($a) } else { $parts += 'ASN: unavailable' }
    return @{ Country = $c; Asn = $a; Status = ($parts -join ', ') }
}
#endregion

#region Column definitions
$colsAll = @(
    'CreationDate', 'Operation', 'Workload', 'RecordType', 'UserId', 'ResultStatus',
    'ClientIP', 'ALL_IPs', 'Geo_Country', 'Geo_ASN', 'Geo_ASName', 'SuspiciousISP',
    'UserAgent', 'ClientInfoString', 'SessionId', 'AADSessionId', 'RequestId',
    'UniqueTokenId', 'CorrelationId', 'ClientAppId', 'ClientAppName',
    'MailboxOwnerUPN', 'LogonType', 'ExternalAccess', 'ObjectId',
    'Subject', 'InternetMessageIds', 'MessageCount', 'Folder', 'DestFolder',
    'Details', 'ParseStatus', 'RecordId', 'ClientIP_Raw', 'AuditData'
)
$colsEmail = @(
    'CreationDate', 'Operation', 'UserId', 'MailboxOwnerUPN', 'ActingAs',
    'Subject', 'InternetMessageId', 'Folder', 'DestFolder', 'SizeInBytes', 'Attachments',
    'AccessType', 'IsThrottled', 'OperationCount',
    'ClientIP', 'Geo_Country', 'Geo_ASN', 'Geo_ASName', 'SuspiciousISP',
    'ClientInfoString', 'UserAgent', 'SessionId', 'AADSessionId', 'UniqueTokenId', 'ClientAppId',
    'LogonType', 'ExternalAccess', 'ResultStatus', 'RecordId'
)
$colsRules = @(
    'CreationDate', 'Operation', 'UserId', 'ObjectId', 'RuleName', 'RiskFlags', 'RuleLogicSummary',
    'ForwardTo', 'ForwardAsAttachmentTo', 'RedirectTo', 'MoveToFolder', 'DeleteMessage',
    'MarkAsRead', 'StopProcessingRules', 'AllParameters',
    'ClientIP', 'Geo_Country', 'Geo_ASN', 'Geo_ASName', 'SuspiciousISP',
    'UserAgent', 'ClientInfoString', 'SessionId', 'AADSessionId', 'ResultStatus', 'RecordId'
)
$colsAdmin = @(
    'CreationDate', 'Operation', 'Workload', 'UserId', 'ObjectId', 'RiskFlags', 'KeyParameters', 'AllParameters',
    'ClientIP', 'Geo_Country', 'Geo_ASN', 'Geo_ASName', 'SuspiciousISP',
    'UserAgent', 'ClientInfoString', 'ClientAppId', 'SessionId', 'AADSessionId', 'ResultStatus', 'RecordId'
)
$colsSignIn = @(
    'CreationDate', 'Operation', 'UserId', 'ResultStatus', 'ResultStatusDetail', 'LogonError', 'ErrorNumber',
    'ClientIP', 'Geo_Country', 'Geo_ASN', 'Geo_ASName', 'SuspiciousISP',
    'UserAgent', 'OS', 'BrowserType', 'DeviceName', 'IsCompliant', 'IsCompliantAndManaged', 'TrustType',
    'SessionId', 'RequestId', 'UserAuthenticationMethod', 'RequestType', 'KeepMeSignedIn',
    'ApplicationId', 'ObjectId', 'ExtendedProperties', 'DeviceProperties', 'RecordId'
)
$colsSessions = @(
    'SessionKey', 'KeyType', 'FirstSeen', 'LastSeen', 'EventCount', 'Users', 'IPs',
    'Countries', 'ASNames', 'SuspiciousISP', 'UserAgents', 'Operations'
)
$colsIP = @(
    'IP', 'IsPrivate', 'Geo_Country', 'Geo_CountryCode', 'Geo_ASN', 'Geo_ASName',
    'Geo_Network', 'SuspiciousISP', 'FirstSeen', 'LastSeen', 'EventCount', 'Users', 'Operations', 'SessionCount'
)
$colsErrors = @('RecordNum', 'RecordId', 'Operation', 'AuditDataLength', 'LikelyExcelTruncation', 'Error')

$riskParamNames = @(
    'ForwardingSmtpAddress', 'ForwardingAddress', 'DeliverToMailboxAndForward', 'RedirectMessageTo',
    'BlindCopyTo', 'CopyTo', 'AddToRecipients', 'AccessRights', 'User', 'Trustee', 'GrantSendOnBehalfTo',
    'AuditEnabled', 'AuditBypassEnabled', 'AutoForwardEnabled', 'SetSCL', 'TrustedSendersAndDomains',
    'ExternalEmailAddress', 'Identity'
)
#endregion

#region Main Processing
Log 'Starting record processing...'

$allRows     = New-Object System.Collections.ArrayList
$emailRows   = New-Object System.Collections.ArrayList
$ruleRows    = New-Object System.Collections.ArrayList
$adminRows   = New-Object System.Collections.ArrayList
$signInRows  = New-Object System.Collections.ArrayList
$parseErrors = New-Object System.Collections.ArrayList
$opGroups    = @{}
$ipAgg       = @{}
$sessionAgg  = @{}
$flatRows    = New-Object 'System.Collections.Generic.List[object[]]'
$throttledCount = 0

$processedCount = 0
foreach ($record in $records) {
    $processedCount++
    if ($processedCount % 500 -eq 0) {
        $pct = [math]::Round(($processedCount / $totalRecords) * 100, 1)
        Write-Progress -Activity 'Parsing UAL Records' -Status "$processedCount / $totalRecords ($pct%)" -PercentComplete $pct
    }

    try {
        # ---------- Parse AuditData ----------
        $auditDataRaw = if ($auditDataColumn) { [string]$record.$auditDataColumn } else { $null }
        $parsed = $null
        $parseStatus = 'OK'
        if ([string]::IsNullOrWhiteSpace($auditDataRaw)) {
            $parseStatus = 'NoAuditData'
        } else {
            try {
                if ($script:JsonMode -eq 'JavaScriptSerializer') {
                    $parsed = $script:Jss.DeserializeObject($auditDataRaw)
                } else {
                    $parsed = ConvertFrom-Json -InputObject $auditDataRaw -AsHashtable -Depth 1024 -ErrorAction Stop
                }
                if (-not ($parsed -is [System.Collections.IDictionary])) {
                    $parseStatus = 'NotAJsonObject'
                    $parsed = $null
                }
            } catch {
                $parseStatus = 'ParseError'
                $len = $auditDataRaw.Length
                [void]$parseErrors.Add((New-Row $colsErrors @{
                    RecordNum             = $processedCount
                    RecordId              = Get-Col $record @('RecordId', 'Identity')
                    Operation             = Get-Col $record @('Operation', 'Operations')
                    AuditDataLength       = $len
                    LikelyExcelTruncation = if ($len -ge 32700) { 'YES - AuditData hit the Excel 32,767 char cell limit. Re-export as CSV and do not open/save it in Excel.' } else { '' }
                    Error                 = $_.Exception.Message
                }))
            }
        }

        # ---------- Core fields ----------
        $recId      = Coalesce (Get-Col $record @('RecordId', 'Identity')) (Get-JT $parsed 'Id')
        $operation  = Coalesce (Get-Col $record @('Operation', 'Operations')) (Get-JT $parsed 'Operation') 'Unknown'
        $operation  = ([string]$operation).Trim()
        $ts         = Convert-Ts (Coalesce (Get-JV $parsed 'CreationTime') (Get-Col $record @('CreationDate', 'CreationTime')))
        $userId     = Coalesce (Get-Col $record @('UserId', 'UserIds')) (Get-JT $parsed 'UserId')
        $recordType = Coalesce (Get-Col $record @('RecordType')) (Get-JT $parsed 'RecordType')
        $workload   = Get-JT $parsed 'Workload'
        $result     = Get-JT $parsed 'ResultStatus'
        $objectId   = Get-JT $parsed 'ObjectId'

        $ep  = Get-NVMap $parsed 'ExtendedProperties'
        $dp  = Get-NVMap $parsed 'DeviceProperties'
        $opp = Get-NVMap $parsed 'OperationProperties'
        $pp  = Get-NVMap $parsed 'Parameters'

        # ---------- IOC resolution ----------
        $userAgent  = Coalesce (Get-JT $parsed 'UserAgent') $ep['UserAgent']
        $clientInfo = Get-JT $parsed 'ClientInfoString'
        $sessionId  = Coalesce (Get-JT $parsed 'SessionId') $dp['SessionId'] $ep['SessionId']
        $aadSession = Get-JT $parsed 'AppAccessContext.AADSessionId'
        if (-not $aadSession -and $workload -eq 'AzureActiveDirectory') { $aadSession = $dp['SessionId'] }
        $requestId  = Coalesce $ep['RequestId'] (Get-JT $parsed 'RequestId')
        $tokenId    = Get-JT $parsed 'AppAccessContext.UniqueTokenId'
        $corrId     = Get-JT $parsed 'AppAccessContext.CorrelationId'
        $clientApp  = Coalesce (Get-JT $parsed 'AppAccessContext.ClientAppId') (Get-JT $parsed 'ClientAppId') (Get-JT $parsed 'AppId') (Get-JT $parsed 'ApplicationId')
        $clientAppN = Coalesce (Get-JT $parsed 'AppAccessContext.ClientAppName') (Get-JT $parsed 'ClientAppName')

        # IPs: collect raw candidates, normalize, dedupe
        $rawIps = New-Object System.Collections.ArrayList
        foreach ($f in @('ClientIP', 'ClientIPAddress', 'ActorIpAddress', 'IPAddress')) {
            $v = Get-JT $parsed $f
            if ($v) { [void]$rawIps.Add($v) }
        }
        foreach ($k in @($ep.Keys)) {
            if ($k -match '^(clientIP|clientIpAddress|ipaddr|IpAddress)$' -and $ep[$k]) { [void]$rawIps.Add($ep[$k]) }
        }
        $ips = New-Object System.Collections.Generic.List[string]
        foreach ($r in $rawIps) {
            $n = Normalize-IP $r
            if ($n -and -not $ips.Contains($n)) { $ips.Add($n) }
        }
        $clientIpRaw = if ($rawIps.Count -gt 0) { [string]$rawIps[0] } else { $null }
        $primaryIp   = if ($ips.Count -gt 0) { $ips[0] } else { $null }
        $allIps      = if ($ips.Count -gt 0) { $ips -join '; ' } else { $null }

        $mailboxOwner = Get-JT $parsed 'MailboxOwnerUPN'
        $logonType    = Get-JT $parsed 'LogonType'
        $externalAcc  = Get-JT $parsed 'ExternalAccess'
        $destFolder   = Get-JT $parsed 'DestFolder.Path'
        $srcFolder    = Get-JT $parsed 'Folder.Path'

        # ---------- Messages (Exchange) ----------
        $msgs = [UalJson]::Messages($parsed, $script:MaxCell)
        $realMsgCount = 0
        $firstSubject = $null
        $firstFolder  = $null
        $msgIds  = New-Object System.Collections.Generic.List[string]
        $msgIdSet = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($m in $msgs) {
            # $m = [Subject, InternetMessageId, Folder, SizeInBytes, Attachments, FolderOnly]
            if (-not $firstFolder -and $m[2]) { $firstFolder = $m[2] }
            if ($m[5] -eq '1') { continue }
            $realMsgCount++
            if (-not $firstSubject -and $m[0]) { $firstSubject = $m[0] }
            if ($m[1] -and $msgIdSet.Add($m[1])) { $msgIds.Add($m[1]) }
        }

        $accessType = $null
        $isThrottled = $null
        if ($operation -eq 'MailItemsAccessed') {
            $accessType = $opp['MailAccessType']
            if (-not $accessType) {
                $accessType = if ($realMsgCount -gt 0) { 'Bind (inferred)' } elseif ($msgs.Count -gt 0) { 'Sync (inferred)' } else { 'Unknown' }
            }
            $isThrottled = $opp['IsThrottled']
            if ($isThrottled -eq 'True') { $throttledCount++ }
        }

        # ---------- Details ----------
        $details = Coalesce (Format-Modified $parsed) (Format-NV $pp) (Format-NV $opp)

        # ---------- All_Records row ----------
        $row = New-Row $colsAll @{
            CreationDate       = $ts
            Operation          = $operation
            Workload           = $workload
            RecordType         = [string]$recordType
            UserId             = [string]$userId
            ResultStatus       = $result
            ClientIP           = $primaryIp
            ALL_IPs            = $allIps
            UserAgent          = $userAgent
            ClientInfoString   = $clientInfo
            SessionId          = $sessionId
            AADSessionId       = $aadSession
            RequestId          = $requestId
            UniqueTokenId      = $tokenId
            CorrelationId      = $corrId
            ClientAppId        = $clientApp
            ClientAppName      = $clientAppN
            MailboxOwnerUPN    = $mailboxOwner
            LogonType          = $logonType
            ExternalAccess     = $externalAcc
            ObjectId           = $objectId
            Subject            = $firstSubject
            InternetMessageIds = if ($msgIds.Count -gt 0) { $msgIds -join '; ' } else { $null }
            MessageCount       = if ($realMsgCount -gt 0) { $realMsgCount } else { $null }
            Folder             = Coalesce $srcFolder $firstFolder
            DestFolder         = $destFolder
            Details            = $details
            ParseStatus        = $parseStatus
            RecordId           = [string]$recId
            ClientIP_Raw       = $clientIpRaw
            AuditData          = $auditDataRaw
        }
        [void]$allRows.Add($row)
        if (-not $opGroups.ContainsKey($operation)) { $opGroups[$operation] = New-Object System.Collections.ArrayList }
        [void]$opGroups[$operation].Add($row)

        # ---------- Email_Activity rows ----------
        if ($msgs.Count -gt 0) {
            $actingAs = Coalesce (Get-JT $parsed 'SendAsUserSmtp') (Get-JT $parsed 'SendOnBehalfOfUserSmtp')
            $opCount  = Get-JT $parsed 'OperationCount'
            # Record-level values are limited once; per-message text is limited per row.
            $eUser = Limit-Cell ([string]$userId); $eOwner = Limit-Cell $mailboxOwner; $eActing = Limit-Cell $actingAs
            $eDest = Limit-Cell $destFolder; $eCInfo = Limit-Cell $clientInfo; $eUA = Limit-Cell $userAgent
            foreach ($m in $msgs) {
                # Direct literal (same order as $colsEmail): much faster than New-Row on large Bind events.
                [void]$emailRows.Add([PSCustomObject]@{
                    CreationDate      = $ts
                    Operation         = $operation
                    UserId            = $eUser
                    MailboxOwnerUPN   = $eOwner
                    ActingAs          = $eActing
                    Subject           = $m[0]
                    InternetMessageId = $m[1]
                    Folder            = $m[2]
                    DestFolder        = $eDest
                    SizeInBytes       = $m[3]
                    Attachments       = $m[4]
                    AccessType        = $accessType
                    IsThrottled       = $isThrottled
                    OperationCount    = $opCount
                    ClientIP          = $primaryIp
                    Geo_Country       = $null
                    Geo_ASN           = $null
                    Geo_ASName        = $null
                    SuspiciousISP     = $null
                    ClientInfoString  = $eCInfo
                    UserAgent         = $eUA
                    SessionId         = $sessionId
                    AADSessionId      = $aadSession
                    UniqueTokenId     = $tokenId
                    ClientAppId       = $clientApp
                    LogonType         = $logonType
                    ExternalAccess    = $externalAcc
                    ResultStatus      = $result
                    RecordId          = [string]$recId
                })
            }
        }

        # ---------- Inbox rules ----------
        if ($operation -match 'InboxRule') {
            $rp = [ordered]@{}
            foreach ($k in $pp.Keys)  { $rp[$k] = $pp[$k] }
            foreach ($k in $opp.Keys) { if (-not $rp.Contains($k)) { $rp[$k] = $opp[$k] } }
            $allParams = Format-NV $rp
            $ruleName  = Coalesce $rp['Name'] $rp['RuleName'] $rp['Identity']

            $conditions = @()
            foreach ($c in @(
                @('FromAddressContainsWords', 'From contains'), @('From', 'From'),
                @('SubjectContainsWords', 'Subject contains'), @('SubjectOrBodyContainsWords', 'Subject/Body contains'),
                @('BodyContainsWords', 'Body contains'), @('SentTo', 'Sent to'),
                @('HeaderContainsWords', 'Header contains'), @('RecipientAddressContainsWords', 'Recipient contains'),
                @('RuleCondition', 'Condition'))) {
                if ($rp[$c[0]]) { $conditions += "$($c[1]) '$($rp[$c[0]])'" }
            }
            $actions = @()
            if ($rp['MoveToFolder'])                   { $actions += "Move to '$($rp['MoveToFolder'])'" }
            if ($rp['CopyToFolder'])                   { $actions += "Copy to '$($rp['CopyToFolder'])'" }
            if ($rp['DeleteMessage'] -eq 'True')       { $actions += 'DELETE MESSAGE' }
            if ($rp['SoftDeleteMessage'] -eq 'True')   { $actions += 'SOFT DELETE MESSAGE' }
            if ($rp['ForwardTo'])                      { $actions += "Forward to '$($rp['ForwardTo'])'" }
            if ($rp['ForwardAsAttachmentTo'])          { $actions += "Forward as attachment to '$($rp['ForwardAsAttachmentTo'])'" }
            if ($rp['RedirectTo'])                     { $actions += "Redirect to '$($rp['RedirectTo'])'" }
            if ($rp['MarkAsRead'] -eq 'True')          { $actions += 'Mark as read' }
            if ($rp['MarkImportance'])                 { $actions += "Set importance: $($rp['MarkImportance'])" }
            if ($rp['StopProcessingRules'] -eq 'True') { $actions += 'Stop processing more rules' }
            if ($rp['RuleActions'])                    { $actions += "Actions: $($rp['RuleActions'])" }

            $logic = @()
            if ($ruleName)              { $logic += "RULE: '$ruleName'" }
            if ($rp['RuleOperation'])   { $logic += "OPERATION: $($rp['RuleOperation'])" }
            if ($conditions.Count -gt 0) { $logic += 'IF: ' + ($conditions -join ' AND ') }
            if ($actions.Count -gt 0)    { $logic += 'THEN: ' + ($actions -join '; ') }
            if ($logic.Count -le 1 -and $allParams) { $logic += $allParams }

            $flags = @()
            if ($rp['ForwardTo'] -or $rp['ForwardAsAttachmentTo'] -or $rp['RedirectTo']) { $flags += 'FORWARD/REDIRECT' }
            if ($rp['DeleteMessage'] -eq 'True' -or $rp['SoftDeleteMessage'] -eq 'True') { $flags += 'DELETE' }
            if ($rp['MarkAsRead'] -eq 'True') { $flags += 'MARK-READ' }
            if ($rp['MoveToFolder'] -match '(?i)RSS|Archive|Conversation History|Junk|Deleted Items|Notes|Sync Issues|Outbox') { $flags += 'HIDE-FOLDER' }
            if ($rp['StopProcessingRules'] -eq 'True') { $flags += 'STOP-PROCESSING' }
            if ($ruleName -and ($ruleName.Trim().Length -le 2 -or $ruleName -match '^[\W_]+$')) { $flags += 'SUSPICIOUS-NAME' }
            if ($operation -eq 'UpdateInboxRules' -and $allParams) {
                if ($allParams -match '(?i)forward|redirect') { $flags += 'FORWARD/REDIRECT?' }
                if ($allParams -match '(?i)delete')           { $flags += 'DELETE?' }
                if ($allParams -match '(?i)RSS|Archive|Conversation History') { $flags += 'HIDE-FOLDER?' }
            }

            [void]$ruleRows.Add((New-Row $colsRules @{
                CreationDate          = $ts
                Operation             = $operation
                UserId                = [string]$userId
                ObjectId              = $objectId
                RuleName              = $ruleName
                RiskFlags             = (@($flags | Select-Object -Unique) -join '; ')
                RuleLogicSummary      = ($logic -join ' | ')
                ForwardTo             = $rp['ForwardTo']
                ForwardAsAttachmentTo = $rp['ForwardAsAttachmentTo']
                RedirectTo            = $rp['RedirectTo']
                MoveToFolder          = $rp['MoveToFolder']
                DeleteMessage         = $rp['DeleteMessage']
                MarkAsRead            = $rp['MarkAsRead']
                StopProcessingRules   = $rp['StopProcessingRules']
                AllParameters         = $allParams
                ClientIP              = $primaryIp
                UserAgent             = $userAgent
                ClientInfoString      = $clientInfo
                SessionId             = $sessionId
                AADSessionId          = $aadSession
                ResultStatus          = $result
                RecordId              = [string]$recId
            }))
        }
        elseif ($pp.Count -gt 0) {
            # ---------- Exchange admin / cmdlet activity ----------
            $key = [ordered]@{}
            foreach ($n in $riskParamNames) { if ($pp.Contains($n) -and $pp[$n]) { $key[$n] = $pp[$n] } }
            $flags = @()
            if ($pp['ForwardingSmtpAddress'] -or $pp['ForwardingAddress'] -or $pp['RedirectMessageTo'] -or
                $pp['BlindCopyTo'] -or $pp['AddToRecipients'] -or $pp['CopyTo']) { $flags += 'FORWARDING/REDIRECT' }
            if ($pp['AuditEnabled'] -eq 'False')       { $flags += 'AUDIT-DISABLED' }
            if ($pp['AuditBypassEnabled'] -eq 'True')  { $flags += 'AUDIT-BYPASS' }
            if ($pp['AccessRights'] -match '(?i)FullAccess|SendAs|ChangePermission|ChangeOwner') { $flags += "PERMISSION-GRANT:$($pp['AccessRights'])" }
            if ($pp['GrantSendOnBehalfTo'])            { $flags += 'SEND-ON-BEHALF-GRANT' }
            if ($pp['SetSCL'] -eq '-1')                { $flags += 'SPAM-BYPASS' }
            if ($operation -match 'TransportRule')     { $flags += 'TRANSPORT-RULE' }
            if ($operation -match 'Connector')         { $flags += 'CONNECTOR-CHANGE' }
            if ($operation -match 'JunkEmailConfiguration') { $flags += 'JUNK-CONFIG' }

            [void]$adminRows.Add((New-Row $colsAdmin @{
                CreationDate     = $ts
                Operation        = $operation
                Workload         = $workload
                UserId           = [string]$userId
                ObjectId         = $objectId
                RiskFlags        = ($flags -join '; ')
                KeyParameters    = Format-NV $key
                AllParameters    = Format-NV $pp
                ClientIP         = $primaryIp
                UserAgent        = $userAgent
                ClientInfoString = $clientInfo
                ClientAppId      = $clientApp
                SessionId        = $sessionId
                AADSessionId     = $aadSession
                ResultStatus     = $result
                RecordId         = [string]$recId
            }))
        }

        # ---------- Sign-ins ----------
        if ($operation -match '^UserLog') {
            [void]$signInRows.Add((New-Row $colsSignIn @{
                CreationDate             = $ts
                Operation                = $operation
                UserId                   = [string]$userId
                ResultStatus             = $result
                ResultStatusDetail       = $ep['ResultStatusDetail']
                LogonError               = Get-JT $parsed 'LogonError'
                ErrorNumber              = Get-JT $parsed 'ErrorNumber'
                ClientIP                 = $primaryIp
                UserAgent                = $userAgent
                OS                       = $dp['OS']
                BrowserType              = $dp['BrowserType']
                DeviceName               = $dp['DisplayName']
                IsCompliant              = $dp['IsCompliant']
                IsCompliantAndManaged    = $dp['IsCompliantAndManaged']
                TrustType                = $dp['TrustType']
                SessionId                = Coalesce $dp['SessionId'] $sessionId
                RequestId                = $requestId
                UserAuthenticationMethod = $ep['UserAuthenticationMethod']
                RequestType              = $ep['RequestType']
                KeepMeSignedIn           = $ep['KeepMeSignedIn']
                ApplicationId            = Get-JT $parsed 'ApplicationId'
                ObjectId                 = $objectId
                ExtendedProperties       = Format-NV $ep
                DeviceProperties         = Format-NV $dp
                RecordId                 = [string]$recId
            }))
        }

        # ---------- Aggregates ----------
        $uaForAgg = Coalesce $userAgent $clientInfo
        $sessKey  = Coalesce $aadSession $sessionId
        foreach ($ip in $ips) {
            if (-not $ipAgg.ContainsKey($ip)) { $ipAgg[$ip] = New-Agg }
            Update-Agg $ipAgg[$ip] $ts ([string]$userId) @() $uaForAgg $operation $sessKey
        }
        if ($sessKey) {
            if (-not $sessionAgg.ContainsKey($sessKey)) {
                $sessionAgg[$sessKey] = New-Agg
                $sessionAgg[$sessKey]['KeyType'] = if ($aadSession) { 'AADSessionId' } else { 'SessionId' }
            }
            Update-Agg $sessionAgg[$sessKey] $ts ([string]$userId) ([string[]]$ips.ToArray()) $uaForAgg $operation $null
        }

        # ---------- Flat sheet ----------
        if (-not $NoFlatSheet -and $parsed) {
            [UalJson]::FlattenRows($parsed, $flatRows, [string]$recId, $ts, $operation, [string]$userId, $script:MaxCell)
        }
    } catch {
        Log "Error processing record $processedCount : $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))" 'ERROR'
        [void]$parseErrors.Add((New-Row $colsErrors @{
            RecordNum = $processedCount
            RecordId  = 'N/A'
            Operation = 'PROCESSING_ERROR'
            Error     = "$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
        }))
    }
}
Write-Progress -Activity 'Parsing UAL Records' -Completed

Log 'Processing complete!'
Log "  Records parsed:     $($allRows.Count)"
Log "  Unique operations:  $($opGroups.Count)"
Log "  Email rows:         $($emailRows.Count)"
Log "  Inbox rule events:  $($ruleRows.Count)"
Log "  Admin events:       $($adminRows.Count)"
Log "  Sign-in events:     $($signInRows.Count)"
Log "  Unique IPs:         $($ipAgg.Count)"
Log "  Unique sessions:    $($sessionAgg.Count)"
Log "  Flat JSON values:   $($flatRows.Count)"
Log "  Parse errors:       $($parseErrors.Count)"
#endregion

#region Geolocation
$script:GeoInfo = @{}
$geoStatus = 'Not run'
$allIpList = @($ipAgg.Keys)
$publicIps = New-Object System.Collections.Generic.List[string]
foreach ($ip in $allIpList) {
    if ([UalGeo]::IsPrivate($ip)) {
        $script:GeoInfo[$ip] = [PSCustomObject]@{ Country = 'Private/Reserved'; CountryCode = $null; ASN = $null; ASName = $null; Network = $null; Suspicious = $null; IsPrivate = 'True' }
    } else {
        $publicIps.Add($ip)
    }
}

if ($publicIps.Count -eq 0) {
    $geoStatus = 'Not needed (no public IPs)'
} else {
    $geo = Initialize-GeoDb
    if (-not $geo.Country -and -not $geo.Asn) {
        $geoStatus = $geo.Status
        if (-not $NoGeo) {
            Write-Host ''
            Write-Host ('!' * 70) -ForegroundColor Yellow
            Write-Host '[GEO] Geolocation is UNAVAILABLE for this run. Parsing continues normally;' -ForegroundColor Yellow
            Write-Host '      Geo_* and SuspiciousISP columns will be blank.' -ForegroundColor Yellow
            Write-Host "      Offline fix: copy dbip-country-lite-YYYY-MM.csv.gz and dbip-asn-lite-YYYY-MM.csv.gz" -ForegroundColor Yellow
            Write-Host "      from https://db-ip.com/db/lite.php into: $(Get-GeoCacheDir)" -ForegroundColor Yellow
            Write-Host ('!' * 70) -ForegroundColor Yellow
            Write-Host ''
        }
    } else {
        Log "Geolocating $($publicIps.Count) public IPs with DB-IP Lite ($($geo.Status))..."
        $geoStart = Get-Date
        try {
            $geoMap = [UalGeo]::Lookup($geo.Country, $geo.Asn, [string[]]$publicIps.ToArray())
            $found = 0
            foreach ($ip in $publicIps) {
                if ($geoMap.ContainsKey($ip)) {
                    $g = $geoMap[$ip]
                    $found++
                    $script:GeoInfo[$ip] = [PSCustomObject]@{
                        Country     = $g.Country
                        CountryCode = $g.CountryCode
                        ASN         = $g.Asn
                        ASName      = $g.AsName
                        Network     = $g.Network
                        Suspicious  = Test-SuspiciousIsp $g.AsName
                        IsPrivate   = 'False'
                    }
                } else {
                    $script:GeoInfo[$ip] = [PSCustomObject]@{ Country = 'Not in DB'; CountryCode = $null; ASN = $null; ASName = $null; Network = $null; Suspicious = $null; IsPrivate = 'False' }
                }
            }
            $secs = [math]::Round(((Get-Date) - $geoStart).TotalSeconds, 1)
            $geoStatus = "OK: $found of $($publicIps.Count) public IPs matched in $secs s ($($geo.Status))"
            Log "  $geoStatus"
        } catch {
            $geoStatus = "FAILED: $($_.Exception.Message)"
            Log "Geo lookup failed: $($_.Exception.Message)" 'ERROR'
        }
    }
}

function Set-RowGeo {
    param($Rows)
    foreach ($r in $Rows) {
        $ip = $r.ClientIP
        if ($ip -and $script:GeoInfo.ContainsKey($ip)) {
            $g = $script:GeoInfo[$ip]
            $r.Geo_Country   = $g.Country
            $r.Geo_ASN       = $g.ASN
            $r.Geo_ASName    = $g.ASName
            $r.SuspiciousISP = $g.Suspicious
        }
    }
}
Set-RowGeo $allRows
Set-RowGeo $emailRows
Set-RowGeo $ruleRows
Set-RowGeo $adminRows
Set-RowGeo $signInRows
#endregion

#region Pivot sheets
$ipRows = New-Object System.Collections.ArrayList
foreach ($ip in $allIpList) {
    $a = $ipAgg[$ip]
    $g = $script:GeoInfo[$ip]
    [void]$ipRows.Add((New-Row $colsIP @{
        IP              = $ip
        IsPrivate       = if ($g) { $g.IsPrivate } else { $null }
        Geo_Country     = if ($g) { $g.Country } else { $null }
        Geo_CountryCode = if ($g) { $g.CountryCode } else { $null }
        Geo_ASN         = if ($g) { $g.ASN } else { $null }
        Geo_ASName      = if ($g) { $g.ASName } else { $null }
        Geo_Network     = if ($g) { $g.Network } else { $null }
        SuspiciousISP   = if ($g) { $g.Suspicious } else { $null }
        FirstSeen       = $a.First
        LastSeen        = $a.Last
        EventCount      = $a.Count
        Users           = Join-Set $a.Users
        Operations      = Format-Ops $a.Ops
        SessionCount    = $a.Sessions.Count
    }))
}
$ipRows = @($ipRows | Sort-Object -Property @{ Expression = { if ($_.SuspiciousISP) { 0 } else { 1 } } }, @{ Expression = 'EventCount'; Descending = $true })
$suspiciousIpCount = @($ipRows | Where-Object { $_.SuspiciousISP }).Count

$sessRows = New-Object System.Collections.ArrayList
foreach ($sk in $sessionAgg.Keys) {
    $a = $sessionAgg[$sk]
    $countries = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $asNames   = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $susp      = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($ip in $a.IPs) {
        $g = $script:GeoInfo[$ip]
        if ($g) {
            if ($g.Country)    { [void]$countries.Add($g.Country) }
            if ($g.ASName)     { [void]$asNames.Add($g.ASName) }
            if ($g.Suspicious) { [void]$susp.Add("$ip ($($g.Suspicious))") }
        }
    }
    [void]$sessRows.Add((New-Row $colsSessions @{
        SessionKey    = $sk
        KeyType       = $a['KeyType']
        FirstSeen     = $a.First
        LastSeen      = $a.Last
        EventCount    = $a.Count
        Users         = Join-Set $a.Users
        IPs           = Join-Set $a.IPs
        Countries     = Join-Set $countries
        ASNames       = Join-Set $asNames
        SuspiciousISP = Join-Set $susp
        UserAgents    = Join-Set $a.UAs 20
        Operations    = Format-Ops $a.Ops
    }))
}
$sessRows = @($sessRows | Sort-Object -Property FirstSeen)

# Chronological order for timeline sheets
$allRows    = @($allRows    | Sort-Object -Property CreationDate)
$emailRows  = @($emailRows  | Sort-Object -Property CreationDate)
$ruleRows   = @($ruleRows   | Sort-Object -Property CreationDate)
$adminRows  = @($adminRows  | Sort-Object -Property CreationDate)
$signInRows = @($signInRows | Sort-Object -Property CreationDate)
$flaggedRules = @($ruleRows  | Where-Object { $_.RiskFlags }).Count
$flaggedAdmin = @($adminRows | Where-Object { $_.RiskFlags }).Count
#endregion

#region Export to Excel
Log "Exporting to Excel: $OutputFile"
$tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "UAL_Parse_$([guid]::NewGuid().ToString('N')).xlsx"
Log "Using temp file: $tempFile"
if (Test-Path -LiteralPath $OutputFile) { Remove-Item -LiteralPath $OutputFile -Force -ErrorAction SilentlyContinue }

$script:CreatedSheets = New-Object System.Collections.ArrayList
$script:CsvSpills     = [ordered]@{}
$usedNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($reserved in @('Summary', 'Email_Activity', 'Inbox_Rules', 'Exchange_Admin', 'SignIns', 'Sessions', 'IP_Summary', 'All_Records', 'AuditData_Flat', 'Parse_Errors')) {
    [void]$usedNames.Add($reserved)
}

function Write-SpillCsv {
    param($Rows, [string]$Name, [string[]]$Columns)
    $csv = Join-Path $baseDir ('{0}_{1}.csv' -f $baseName, $Name)
    $Rows | Select-Object -Property $Columns | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    $script:CsvSpills[$Name] = $csv
    Log "  $Name exceeds the Excel row limit; written to CSV: $csv" 'WARN'
}

function Add-NavLink {
    param($Ws)
    $c = $Ws.Cells[1, 1]
    $c.Value = $script:NavHeader
    $c.Hyperlink = New-Object -TypeName OfficeOpenXml.ExcelHyperLink -ArgumentList ("#'Summary'!A1", 'Back to Summary')
    $c.Style.Font.UnderLine = $true
    $c.Style.Font.Bold = $true
    $c.Style.Font.Color.SetColor([System.Drawing.Color]::Blue)
    $Ws.Column(1).Width = 14
}

function Export-Sheet {
    param($Rows, [string]$Name, [string[]]$Columns)
    $count = if ($null -eq $Rows) { 0 } else { @($Rows).Count }
    if ($count -eq 0) { return }
    if ($count -gt $script:MaxExcelRows) { Write-SpillCsv $Rows $Name $Columns; return }

    $props = @(@{ Name = $script:NavHeader; Expression = { $null } }) + $Columns
    $p = @{
        ExcelPackage       = $script:Excel
        WorksheetName      = $Name
        BoldTopRow         = $true
        FreezeTopRow       = $true
        AutoFilter         = $true
        NoNumberConversion = '*'
        PassThru           = $true
    }
    if ($count -le $script:AutoSizeMaxRows) { $p['AutoSize'] = $true }
    Write-Host "[*] Adding $Name ($count rows)..." -ForegroundColor Yellow
    $null = $Rows | Select-Object -Property $props | Export-Excel @p
    $ws = $script:Excel.Workbook.Worksheets[$Name]
    if ($ws) {
        Add-NavLink $ws
        if ($count -gt $script:AutoSizeMaxRows) {
            for ($i = 2; $i -le $Columns.Count + 1; $i++) { $ws.Column($i).Width = 22 }
        }
        [void]$script:CreatedSheets.Add($Name)
        Log "  Created: $Name ($count rows)"
    }
}

try {
    $script:Excel = Open-ExcelPackage -Path $tempFile -Create

    Export-Sheet $emailRows  'Email_Activity' $colsEmail
    Export-Sheet $ruleRows   'Inbox_Rules'    $colsRules
    Export-Sheet $adminRows  'Exchange_Admin' $colsAdmin
    Export-Sheet $signInRows 'SignIns'        $colsSignIn
    Export-Sheet $sessRows   'Sessions'       $colsSessions
    Export-Sheet $ipRows     'IP_Summary'     $colsIP
    Export-Sheet $allRows    'All_Records'    $colsAll

    $opSheetMap = @{}
    foreach ($op in ($opGroups.Keys | Sort-Object)) {
        if ($ExcludedOperationSheets -contains $op) { Log "  Skipped: $op (excluded)"; continue }
        $sheetName = Get-SafeSheetName ("Op_" + $op) $usedNames
        $opRows = @($opGroups[$op] | Sort-Object -Property CreationDate)
        Export-Sheet $opRows $sheetName $colsAll
        $opSheetMap[$op] = $sheetName
    }

    if ($flatRows.Count -gt 0) {
        $flatHdr = @($script:NavHeader, 'RecordId', 'CreationDate', 'Operation', 'UserId', 'Path', 'Value')
        if ($flatRows.Count -gt $script:MaxExcelRows) {
            $csv = Join-Path $baseDir ('{0}_AuditData_Flat.csv' -f $baseName)
            $sw = New-Object System.IO.StreamWriter($csv, $false, (New-Object System.Text.UTF8Encoding($true)))
            try {
                $sw.WriteLine('"RecordId","CreationDate","Operation","UserId","Path","Value"')
                foreach ($fr in $flatRows) {
                    $cells = for ($i = 1; $i -lt $fr.Length; $i++) { '"' + ([string]$fr[$i]).Replace('"', '""') + '"' }
                    $sw.WriteLine(($cells -join ','))
                }
            } finally { $sw.Dispose() }
            $script:CsvSpills['AuditData_Flat'] = $csv
            Log "  AuditData_Flat exceeds the Excel row limit; written to CSV: $csv" 'WARN'
        } else {
            Write-Host "[*] Adding AuditData_Flat ($($flatRows.Count) rows)..." -ForegroundColor Yellow
            $ws = $script:Excel.Workbook.Worksheets.Add('AuditData_Flat')
            for ($i = 0; $i -lt $flatHdr.Count; $i++) { $ws.Cells[1, ($i + 1)].Value = $flatHdr[$i] }
            $null = $ws.Cells[2, 1].LoadFromArrays($flatRows)
            $ws.Cells[1, 1, 1, $flatHdr.Count].Style.Font.Bold = $true
            $ws.View.FreezePanes(2, 1)
            $ws.Cells[1, 1, ($flatRows.Count + 1), $flatHdr.Count].AutoFilter = $true
            $widths = @(14, 38, 20, 22, 30, 55, 80)
            for ($i = 0; $i -lt $widths.Count; $i++) { $ws.Column($i + 1).Width = $widths[$i] }
            Add-NavLink $ws
            [void]$script:CreatedSheets.Add('AuditData_Flat')
            Log "  Created: AuditData_Flat ($($flatRows.Count) rows)"
        }
    }

    Export-Sheet $parseErrors 'Parse_Errors' $colsErrors

    # ---------- Summary ----------
    $summaryRows = New-Object System.Collections.ArrayList
    function Add-Sum { param($Metric, $Value, $Link) [void]$summaryRows.Add(@{ Metric = $Metric; Value = $Value; SheetLink = $Link }) }

    Add-Sum 'Total Records'                 $totalRecords $null
    Add-Sum 'Time Range (UTC)'              ("{0}  to  {1}" -f ($allRows | Select-Object -First 1).CreationDate, ($allRows | Select-Object -Last 1).CreationDate) $null
    Add-Sum 'Email Activity Rows'           $emailRows.Count 'Email_Activity'
    Add-Sum 'Inbox Rule Events'             $ruleRows.Count 'Inbox_Rules'
    Add-Sum '  ...with Risk Flags'          $flaggedRules 'Inbox_Rules'
    Add-Sum 'Exchange Admin Events'         $adminRows.Count 'Exchange_Admin'
    Add-Sum '  ...with Risk Flags'          $flaggedAdmin 'Exchange_Admin'
    Add-Sum 'Sign-in Events'                $signInRows.Count 'SignIns'
    Add-Sum 'Unique Sessions'               $sessRows.Count 'Sessions'
    Add-Sum 'Unique IPs'                    $ipRows.Count 'IP_Summary'
    Add-Sum 'IPs on Suspicious ISPs'        $suspiciousIpCount 'IP_Summary'
    Add-Sum 'Throttled MailItemsAccessed'   $throttledCount 'Email_Activity'
    Add-Sum 'All Records'                   $allRows.Count 'All_Records'
    Add-Sum 'Flat JSON Values'              $flatRows.Count 'AuditData_Flat'
    Add-Sum 'Parse Errors'                  $parseErrors.Count 'Parse_Errors'
    Add-Sum 'Cells Truncated (32K limit)'   ($script:TruncatedCells + [UalJson]::Truncated) $null
    Add-Sum 'Geolocation'                   $geoStatus $null
    foreach ($gn in $script:GeoNotices) { Add-Sum '  Geo notice' $gn $null }
    Add-Sum 'Geo Data Source'               'IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0' $null
    Add-Sum 'JSON Engine'                   $script:JsonMode $null
    Add-Sum 'Source File'                   $InputFile $null
    Add-Sum 'Debug Log'                     $debugLog $null
    foreach ($k in $script:CsvSpills.Keys) { Add-Sum "Spilled to CSV: $k" $script:CsvSpills[$k] $null }
    Add-Sum 'Note' 'All timestamps are UTC. Values beginning with "=" are prefixed with a space to block formula injection.' $null
    Add-Sum '---' '---' $null
    foreach ($op in ($opGroups.Keys | Sort-Object)) {
        Add-Sum "Op: $op" $opGroups[$op].Count $opSheetMap[$op]
    }

    $summaryData = foreach ($s in $summaryRows) { [PSCustomObject]@{ Metric = $s.Metric; Value = $s.Value } }
    Write-Host '[*] Adding Summary...' -ForegroundColor Yellow
    $null = $summaryData | Export-Excel -ExcelPackage $script:Excel -WorksheetName 'Summary' -AutoSize -BoldTopRow -FreezeTopRow -NoNumberConversion '*' -PassThru
    $summaryWs = $script:Excel.Workbook.Worksheets['Summary']
    $script:Excel.Workbook.Worksheets.MoveToStart('Summary')

    $rowNum = 2
    foreach ($s in $summaryRows) {
        if ($s.SheetLink -and $script:CreatedSheets -contains $s.SheetLink) {
            $cell = $summaryWs.Cells[$rowNum, 1]
            $cell.Hyperlink = New-Object -TypeName OfficeOpenXml.ExcelHyperLink -ArgumentList ("#'$($s.SheetLink)'!A1", $s.Metric)
            $cell.Style.Font.UnderLine = $true
            $cell.Style.Font.Color.SetColor([System.Drawing.Color]::Blue)
        }
        $rowNum++
    }
    $summaryWs.Column(2).Width = [Math]::Min([Math]::Max($summaryWs.Column(2).Width, 20), 120)
    $script:Excel.Workbook.View.ActiveTab = 0
    Log '  Created: Summary (with hyperlinks)'

    Write-Host '[*] Saving workbook...' -ForegroundColor Yellow
    Close-ExcelPackage $script:Excel
    Copy-Item -LiteralPath $tempFile -Destination $OutputFile -Force
    Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    Log "Excel export complete: $OutputFile"
} catch {
    Log "Excel export failed: $($_.Exception.Message)" 'ERROR'
    Log "Stack trace: $($_.ScriptStackTrace)" 'ERROR'
    if ($script:Excel) { try { Close-ExcelPackage $script:Excel -NoSave } catch { } }
    if (Test-Path -LiteralPath $tempFile) { Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue }
    throw
}
#endregion

#region Final Summary
$runtime = ((Get-Date) - $startTime).TotalSeconds
Write-Host ''
Write-Host ('=' * 70) -ForegroundColor Green
Write-Host 'UAL PARSING COMPLETE' -ForegroundColor Green
Write-Host ('=' * 70) -ForegroundColor Green
Write-Host "[+] Output File:        $OutputFile" -ForegroundColor Green
Write-Host "[+] Debug Log:          $debugLog" -ForegroundColor Green
Write-Host "[+] Total Records:      $totalRecords" -ForegroundColor Green
Write-Host "[+] Email Rows:         $($emailRows.Count)" -ForegroundColor Green
Write-Host "[+] Inbox Rule Events:  $($ruleRows.Count) ($flaggedRules flagged)" -ForegroundColor Green
Write-Host "[+] Admin Events:       $($adminRows.Count) ($flaggedAdmin flagged)" -ForegroundColor Green
Write-Host "[+] Unique IPs:         $($ipRows.Count) ($suspiciousIpCount on suspicious ISPs)" -ForegroundColor Green
$geoColor = if ($geoStatus -like 'OK*' -or $geoStatus -like 'Not needed*' -or $geoStatus -like 'Skipped*') { 'Green' } else { 'Yellow' }
Write-Host "[+] Geolocation:        $geoStatus" -ForegroundColor $geoColor
Write-Host "[+] Runtime:            $([math]::Round($runtime, 2)) seconds" -ForegroundColor Green
if ($parseErrors.Count -gt 0) { Write-Host "[!] Parse Errors:       $($parseErrors.Count) (see Parse_Errors sheet)" -ForegroundColor Yellow }
if ($throttledCount -gt 0)    { Write-Host "[!] Throttled MailItemsAccessed records: $throttledCount (audit logging gap for that mailbox)" -ForegroundColor Yellow }
foreach ($k in $script:CsvSpills.Keys) { Write-Host "[!] $k written to CSV (row limit): $($script:CsvSpills[$k])" -ForegroundColor Yellow }

Write-Host ''
Write-Host 'Top 10 Operations:' -ForegroundColor Cyan
$opGroups.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 10 | ForEach-Object {
    Write-Host "  $($_.Key): $($_.Value.Count)" -ForegroundColor White
}
Log '=== SCRIPT COMPLETE ==='
Log "Total runtime: $([math]::Round($runtime, 2)) seconds"
#endregion
