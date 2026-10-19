<#
.SYNOPSIS
  One-shot hunt of Citrix NetScaler (ADC / Gateway) disk images on Windows: VMware VMDK, raw dd (.dd, .raw, .img),
  split raw (.001, .002, ...) and EnCase E01 (.E01, .E02, ...).

.DESCRIPTION
  Point it at a folder of NetScaler disk images, or at one image file. It:
    1. finds or installs Python 3.13 (per user, no admin rights needed) and builds a private environment with
       pinned packages: dissect 3.22, XlsxWriter, python-docx and tabulate;
    2. finds the disk images and opens each one READ-ONLY: VMDK snapshot chains (latest state, snapshots applied),
       raw dd images, split raw images and E01 sets (every part or segment is checked first);
    3. exports /var/log and the known implant's text logs, with SHA-256 and original UTC times (export_manifest.csv);
    4. converts EVERY exported log to .xlsx (.gz rotations included; utx.log login records parsed into rows);
    5. runs the hunts: known IOC files with hashes, boot and cron hooks, a hidden / new file sweep, log hunts A to I,
       injected NSPPE; commands, tunnel log, logins, NUL-byte runs in logs, network indicators and Fox-IT iocitrix;
    6. writes <label>_Hunt_Results.xlsx per appliance and NetScaler_Findings_Summary.docx.
  The generic hunts (log poisoning, crash loops, hidden and new files, boot and cron hooks, shell history, log
  truncation) run on every image, and the known implant paths and attacker IPs are always checked as well.
  Nothing is written inside the evidence folder. Implant scripts and webshells are recorded by hash only and are
  never exported.

.PARAMETER Path
  A folder to search, or one disk image file.
  Folder: every supported image in it and up to three folder levels below is analyzed, so a case folder with
  several VMs works. Found: VMware .vmdk descriptors (snapshot chains are followed; a .vmx is not needed), raw
  .dd/.raw/.img files, split raw sets (.000 or .001 first part, then .002, ...) and E01 sets (.E01, .E02, ...).
  Archives (.zip, .7z, .ova) are not opened; extract them first.
  File: that one image is analyzed. A .vmdk opens that disk with its parent disks (give the newest snapshot disk
  for the current state, or the base disk for the original); a .001 or .E01 opens the whole set from the same
  folder; any other file is read as a raw disk image.
.PARAMETER OutDir
  Output folder. Default: %USERPROFILE%\NSHunt\<folder or file name>_<yyyyMMdd_HHmmss>. It must not be inside the
  evidence folder (-Path, or the folder that holds the -Path file).
.PARAMETER Since
  Start of the review window (yyyy-MM-dd) for the new-file sweep and the summary timeline.
  Default: 30 days before the newest log on each image.
.PARAMETER IocIp
  Extra attacker IPs (IPv4 or IPv6) to search every log for, such as IPs from the new client's own alerts. They
  are added to the built-in list (the attacker IPs from the intrusion this tool was built on), which is always
  searched. Give a list (-IocIp 203.0.113.10, 198.51.100.7) or read a text file with one IP per line
  (-IocIp (Get-Content .\client_ips.txt)); blank lines and text after # are ignored.
.PARAMETER PythonExe
  Use this python.exe (3.10 to 3.13) as the base interpreter instead of searching for or installing one.
.PARAMETER VenvDir
  Where the private Python environment lives. Default: %LOCALAPPDATA%\NSHunt\venv. It is reused on later runs.
.PARAMETER WheelDir
  Offline install: a folder of wheel files (pip download ... -d <folder> on a connected machine).
.PARAMETER FoxItPath
  Path to Fox-IT iocitrix.py. Default: a copy next to this script (any subfolder), else it is downloaded from
  GitHub at the reviewed commit and checked against its SHA-256.
.PARAMETER SkipFoxIt
  Skip the Fox-IT checks (their SUID walk takes about 3 minutes per image).
.PARAMETER SkipLogXlsx
  Do not convert every log to .xlsx (the hunts still run; useful for a quick look).
.PARAMETER IncludeBase
  Also run the full hunt on the base (pre-snapshot) disk of each chain.
.PARAMETER NoInstall
  Never download or install Python; stop if no suitable Python is found.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-NetScalerHunt.ps1 -Path D:\Evidence\Case01

  Case folder: analyzes every supported image in D:\Evidence\Case01 and up to three folder levels below (VMDK,
  .dd/.raw/.img, split .001 and E01 can be mixed). Output goes to %USERPROFILE%\NSHunt\Case01_<date_time>.
.EXAMPLE
  .\Invoke-NetScalerHunt.ps1 -Path D:\Evidence\Case01\ns-vpx01 -OutDir C:\NSHunt\ns-vpx01

  VMware VM folder: the .vmdk snapshot chain is followed and the latest state is opened.
.EXAMPLE
  .\Invoke-NetScalerHunt.ps1 -Path D:\Evidence\Case01\ns-vpx01\ns-vpx01-000002.vmdk -OutDir C:\NSHunt\ns-vpx01

  One VMDK: opens that disk with its parent disks. Give the base disk (ns-vpx01.vmdk) to see the original state.
.EXAMPLE
  .\Invoke-NetScalerHunt.ps1 -Path D:\Evidence\Case01\ns01.dd -OutDir C:\NSHunt\ns01

  Raw dd image. .raw and .img files work the same way.
.EXAMPLE
  .\Invoke-NetScalerHunt.ps1 -Path D:\Evidence\Case01\ns02.001 -OutDir C:\NSHunt\ns02

  Split raw image (ns02.001, ns02.002, ...): give the first part; the other parts must be in the same folder.
.EXAMPLE
  .\Invoke-NetScalerHunt.ps1 -Path D:\Evidence\Case01\ns03.E01 -OutDir C:\NSHunt\ns03

  EnCase E01 image (ns03.E01, ns03.E02, ...): give the .E01; the other segments must be in the same folder.
.EXAMPLE
  .\Invoke-NetScalerHunt.ps1 -Path D:\Evidence\Case01 -OutDir C:\NSHunt\Case01 -Since 2026-09-15 -IocIp 203.0.113.10, 198.51.100.7

  Case folder with a fixed review window and two extra attacker IPs from the client (the built-in IPs are
  searched too).
.EXAMPLE
  .\Invoke-NetScalerHunt.ps1 -Path D:\Evidence\Case01\ns01.dd -IocIp (Get-Content .\client_ips.txt) -SkipFoxIt

  Raw image, extra attacker IPs read from a text file (one per line), Fox-IT checks skipped for a quicker run.
.NOTES
  Version 1.1.0. Works in Windows PowerShell 5.1 and PowerShell 7. Engine SHA-256 (LF line endings):
  __ENGINE_SHA256__
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)] [string]$Path,
  [string]$OutDir,
  [string]$Since,
  [string[]]$IocIp = @(),
  [string]$PythonExe,
  [string]$VenvDir,
  [string]$WheelDir,
  [string]$FoxItPath,
  [switch]$SkipFoxIt,
  [switch]$SkipLogXlsx,
  [switch]$IncludeBase,
  [switch]$NoInstall
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ToolVersion = '1.1.0'
$EngineSha256 = '__ENGINE_SHA256__'
$PythonVersion = '3.13.16'
$Packages = @('dissect==3.22', 'tabulate==0.10.0', 'XlsxWriter==3.2.9', 'python-docx==1.2.0')
$PackageCheck = 'dissect=3.22;tabulate=0.10.0;XlsxWriter=3.2.9;python-docx=1.2.0'
$FoxItUrl = 'https://raw.githubusercontent.com/fox-it/citrix-netscaler-triage/d12affac98a233a3a1598cd95125bd12ec656b04/iocitrix.py'
$FoxItSha256 = 'dc41fac9651b5dabe3a281fedb61584307bd6e65a9c9bbba115c236de3a2d3b9'
$OnWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ($IsWindows -eq $true)

function Write-Step([string]$Text) { Write-Host ''; Write-Host "== $Text" -ForegroundColor Cyan }
function Write-Note([string]$Text) { Write-Host "   $Text" }
function Write-Warn([string]$Text) { Write-Host "   WARNING: $Text" -ForegroundColor Yellow }

function Get-Sha256([string]$File) {
  return (Get-FileHash -Algorithm SHA256 -LiteralPath $File).Hash.ToLower()
}

function Invoke-Quiet([string]$Exe, [string[]]$Arguments) {
  # Runs a native command and returns its stdout lines; stderr is discarded. In Windows PowerShell 5.1 a redirected
  # stderr line becomes an error record, so this function never runs with ErrorActionPreference = Stop.
  $ErrorActionPreference = 'Continue'
  $out = & $Exe @Arguments 2>$null
  return , @($out)
}

function Test-PythonCandidate([string]$Exe, [string[]]$PreArgs) {
  # Returns @{ Exe; Version } when the interpreter runs and is 3.10 to 3.13, else $null.
  try {
    $code = "import sys; print('%d.%d|%s' % (sys.version_info[0], sys.version_info[1], sys.executable))"
    $out = Invoke-Quiet $Exe (@($PreArgs) + @('-c', $code))
    if ($LASTEXITCODE -ne 0 -or $out.Count -eq 0) { return $null }
    $line = @($out)[-1].ToString().Trim()
    if ($line -notmatch '^(\d+)\.(\d+)\|(.+)$') { return $null }
    $major = [int]$Matches[1]; $minor = [int]$Matches[2]; $real = $Matches[3]
    if ($major -ne 3 -or $minor -lt 10 -or $minor -gt 13) {
      Write-Note "skipping Python $major.$minor at $real (dissect 3.22 needs 3.10 to 3.13)"
      return $null
    }
    return @{ Exe = $real; Version = "$major.$minor" }
  } catch {
    return $null
  }
}

function Find-BasePython {
  if ($PythonExe) {
    $c = Test-PythonCandidate $PythonExe @()
    if (-not $c) { throw "-PythonExe '$PythonExe' did not run as Python 3.10 to 3.13." }
    return $c
  }
  if (Get-Command py -ErrorAction SilentlyContinue) {
    foreach ($v in @('3.13', '3.12', '3.11', '3.10')) {
      $c = Test-PythonCandidate 'py' @("-$v")
      if ($c) { return $c }
    }
  }
  foreach ($name in @('python', 'python3')) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Path -and $cmd.Path -notmatch '\\WindowsApps\\') {
      $c = Test-PythonCandidate $cmd.Path @()
      if ($c) { return $c }
    }
  }
  $roots = @()
  if ($env:LOCALAPPDATA) { $roots += (Join-Path $env:LOCALAPPDATA 'Programs\Python') }
  if ($env:ProgramFiles) { $roots += $env:ProgramFiles }
  foreach ($root in $roots) {
    foreach ($v in @('313', '312', '311', '310')) {
      $exe = Join-Path $root "Python$v\python.exe"
      if (Test-Path -LiteralPath $exe) {
        $c = Test-PythonCandidate $exe @()
        if ($c) { return $c }
      }
    }
  }
  return $null
}

function Install-Python {
  if (-not $OnWindows) { throw 'No Python 3.10 to 3.13 found. Install one, or pass -PythonExe.' }
  $arch = 'amd64'
  if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $arch = 'arm64' }
  $url = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-$arch.exe"
  $installer = Join-Path $env:TEMP "python-$PythonVersion-$arch.exe"
  $target = Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313'
  Write-Note "downloading $url"
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  try { [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials } catch { }
  Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing
  $sig = Get-AuthenticodeSignature -FilePath $installer
  if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Python Software Foundation') {
    Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
    throw "The Python installer's signature is not a valid Python Software Foundation signature ($($sig.Status)). Not installed."
  }
  Write-Note "signature OK ($($sig.SignerCertificate.Subject)); installing for this user only into $target"
  $argList = "/quiet InstallAllUsers=0 PrependPath=0 Include_launcher=0 Include_test=0 Include_doc=0 Include_tcltk=0 " +
             "Shortcuts=0 AssociateFiles=0 Include_pip=1 TargetDir=`"$target`""
  $p = Start-Process -FilePath $installer -ArgumentList $argList -Wait -PassThru
  Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
  if ($p.ExitCode -ne 0) { throw "The Python installer exited with code $($p.ExitCode)." }
  $c = Test-PythonCandidate (Join-Path $target 'python.exe') @()
  if (-not $c) { throw "Python was installed but $target\python.exe does not run." }
  return $c
}

function Get-EngineText {
  # The engine (Python) is embedded below between the @' and '@ lines. Do not edit it here; it is hashed.
  return @'
__ENGINE_TEXT__
'@
}

# ------------------------------------------------------------------ start
Write-Host "Invoke-NetScalerHunt $ToolVersion" -ForegroundColor Green
$started = Get-Date

if (-not (Test-Path -LiteralPath $Path)) { throw "-Path '$Path' does not exist." }
$item = Get-Item -LiteralPath $Path -Force
$Source = $item.FullName.TrimEnd('\', '/')                # what the engine opens: a folder or one image file
if ($item.PSIsContainer) {
  $Evidence = $Source
  $runName = $item.Name
} else {
  $Evidence = $item.DirectoryName.TrimEnd('\', '/')      # nothing may be written in the image file's folder
  $runName = $item.BaseName
}
if (-not $OutDir) {
  $home_ = $env:USERPROFILE
  if (-not $home_) { $home_ = $HOME }
  $OutDir = Join-Path (Join-Path $home_ 'NSHunt') ("{0}_{1}" -f $runName, (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
$OutDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir).TrimEnd('\', '/')
$sep = [System.IO.Path]::DirectorySeparatorChar
if ($OutDir -eq $Evidence -or $OutDir.StartsWith($Evidence + $sep, [System.StringComparison]::OrdinalIgnoreCase)) {
  throw "-OutDir must not be inside the evidence folder ($Evidence)."
}
if ($Since -and $Since -notmatch '^\d{4}-\d{2}-\d{2}$') { throw '-Since must look like yyyy-MM-dd.' }
# -IocIp: accept lists, comma or space separated text, and lines of a file (text after # is a comment).
$ExtraIps = New-Object System.Collections.Generic.List[string]
foreach ($entry in @($IocIp)) {
  if ($null -eq $entry) { continue }
  foreach ($tok in (($entry -replace '#.*$', '') -split '[,;\s]+')) {
    $tok = $tok.Trim().Trim('[', ']')
    if (-not $tok) { continue }
    if ($tok -match ':') {
      $ipObj = $null
      $okIp = [System.Net.IPAddress]::TryParse($tok, [ref]$ipObj) -and $tok -notmatch '%'
    } else {
      $octet = '(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'      # no leading zeros, so no octal surprises
      $okIp = $tok -match "^$octet(\.$octet){3}$"
    }
    if (-not $okIp) { throw "-IocIp: '$tok' is not an IPv4 or IPv6 address." }
    if (-not $ExtraIps.Contains($tok)) { $ExtraIps.Add($tok) }
  }
}
if (-not $VenvDir) {
  if ($env:LOCALAPPDATA) { $VenvDir = Join-Path $env:LOCALAPPDATA 'NSHunt\venv' } else { $VenvDir = Join-Path $HOME '.nshunt/venv' }
}
$ToolDir = Join-Path $OutDir '_tool'
New-Item -ItemType Directory -Force -Path $ToolDir | Out-Null
try { Start-Transcript -Path (Join-Path $ToolDir 'powershell_transcript.txt') -Append | Out-Null } catch { }

if ($item.PSIsContainer) { Write-Note "evidence : $Source (folder, read only)" }
else { Write-Note "evidence : $Source (image file, read only)" }
Write-Note "output   : $OutDir"
if ($ExtraIps.Count) { Write-Note ("extra IPs: " + ($ExtraIps -join ', ') + ' (the built-in attacker IPs are searched too)') }
try {
  $drive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($OutDir))
  $freeGb = [math]::Round($drive.AvailableFreeSpace / 1GB, 1)
  Write-Note "free space on the output drive: $freeGb GB (expect about 0.5 GB per appliance)"
  if ($freeGb -lt 3) { Write-Warn 'less than 3 GB free on the output drive.' }
} catch { }

# ------------------------------------------------------------------ Python and packages
Write-Step 'Python environment'
if ($OnWindows) { $venvPy = Join-Path $VenvDir 'Scripts\python.exe' } else { $venvPy = Join-Path $VenvDir 'bin/python' }
$haveVenv = $false
if ((Test-Path -LiteralPath $venvPy) -and -not $PythonExe) {
  $c = Test-PythonCandidate $venvPy @()
  if ($c) { $haveVenv = $true; Write-Note "reusing $VenvDir (Python $($c.Version))" }
}
if (-not $haveVenv) {
  $base = Find-BasePython
  if (-not $base) {
    if ($NoInstall) { throw 'No Python 3.10 to 3.13 found and -NoInstall was given. Install one or pass -PythonExe.' }
    Write-Note "no Python 3.10 to 3.13 found; installing Python $PythonVersion for this user"
    $base = Install-Python
  }
  Write-Note "base Python $($base.Version): $($base.Exe)"
  Write-Note "creating the environment $VenvDir"
  & $base.Exe -m venv $VenvDir
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $venvPy)) { throw "Could not create the Python environment in $VenvDir." }
}
$check = "import importlib.metadata as m; print(';'.join(p + '=' + m.version(p) for p in ('dissect','tabulate','XlsxWriter','python-docx')))"
$have = Invoke-Quiet $venvPy @('-c', $check)
if ($LASTEXITCODE -ne 0 -or $have.Count -eq 0 -or ($have[-1] -ne $PackageCheck)) {
  Write-Note ('installing ' + ($Packages -join ', '))
  $pipArgs = @('-m', 'pip', 'install', '--disable-pip-version-check')
  if ($WheelDir) { $pipArgs += @('--no-index', '--find-links', $WheelDir) }
  & $venvPy @pipArgs @Packages
  if ($LASTEXITCODE -ne 0) { throw 'pip could not install the packages (see the messages above; set HTTPS_PROXY if you are behind a proxy, or use -WheelDir).' }
} else {
  Write-Note "packages already installed: $PackageCheck"
}
$freeze = Invoke-Quiet $venvPy @('-m', 'pip', 'freeze', '--disable-pip-version-check')
Set-Content -LiteralPath (Join-Path $ToolDir 'pip_freeze.txt') -Value $freeze -Encoding ASCII

# ------------------------------------------------------------------ engine and Fox-IT
Write-Step 'Hunt engine'
$enginePath = Join-Path $ToolDir 'nshunt_engine.py'
$engineText = (Get-EngineText) -replace "`r`n", "`n"
if (-not $engineText.EndsWith("`n")) { $engineText += "`n" }
[System.IO.File]::WriteAllText($enginePath, $engineText, (New-Object System.Text.UTF8Encoding($false)))
$engineHash = Get-Sha256 $enginePath
if ($engineHash -ne $EngineSha256) {
  Write-Warn "engine SHA-256 is $engineHash, expected $EngineSha256 (the script was edited)."
} else {
  Write-Note "engine written and verified: $enginePath"
}

$foxit = $null
if (-not $SkipFoxIt) {
  Write-Step 'Fox-IT iocitrix'
  $foxDir = Join-Path $ToolDir 'foxit'
  New-Item -ItemType Directory -Force -Path $foxDir | Out-Null
  $foxDest = Join-Path $foxDir 'iocitrix.py'
  $candidate = $null
  if ($FoxItPath) {
    if (-not (Test-Path -LiteralPath $FoxItPath)) { throw "-FoxItPath '$FoxItPath' does not exist." }
    $candidate = (Get-Item -LiteralPath $FoxItPath).FullName
  } elseif ($PSScriptRoot) {
    foreach ($root in @($PSScriptRoot, (Split-Path -Parent $PSScriptRoot))) {
      if (-not $root -or $candidate) { continue }
      $found = Get-ChildItem -LiteralPath $root -Filter 'iocitrix.py' -Recurse -Depth 2 -File -ErrorAction SilentlyContinue |
        Where-Object { (Get-Sha256 $_.FullName) -eq $FoxItSha256 } | Select-Object -First 1
      if ($found) { $candidate = $found.FullName }
    }
  }
  if ($candidate) {
    Copy-Item -LiteralPath $candidate -Destination $foxDest -Force
    Write-Note "using $candidate"
  } else {
    try {
      [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
      try { [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials } catch { }
      Invoke-WebRequest -Uri $FoxItUrl -OutFile $foxDest -UseBasicParsing
      Write-Note "downloaded $FoxItUrl"
    } catch {
      Write-Warn "could not download iocitrix.py ($($_.Exception.Message)); Fox-IT checks skipped. Use -FoxItPath."
    }
  }
  if (Test-Path -LiteralPath $foxDest) {
    $h = Get-Sha256 $foxDest
    if ($h -eq $FoxItSha256) {
      $foxit = $foxDest
      Write-Note 'SHA-256 matches the reviewed commit d12affa'
    } elseif ($FoxItPath) {
      $foxit = $foxDest
      Write-Warn "iocitrix.py SHA-256 is $h, not the reviewed $FoxItSha256; running it because you chose it."
    } else {
      Remove-Item -LiteralPath $foxDest -Force
      Write-Warn "iocitrix.py SHA-256 is $h, expected $FoxItSha256; not used. Fox-IT checks skipped."
    }
  }
}

# ------------------------------------------------------------------ run
Write-Step 'Hunting (progress below; about 2 to 6 minutes per appliance)'
$engineArgs = @('-B', $enginePath, '--path', $Source, '--out', $OutDir)
if ($Since) { $engineArgs += @('--since', $Since) }
if ($ExtraIps.Count) { $engineArgs += '--ioc-ip'; $engineArgs += $ExtraIps.ToArray() }
if ($foxit) { $engineArgs += @('--foxit', $foxit) }
if ($SkipLogXlsx) { $engineArgs += '--skip-log-xlsx' }
if ($IncludeBase) { $engineArgs += '--include-base' }
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:NO_COLOR = '1'
& $venvPy @engineArgs
$code = $LASTEXITCODE

Write-Step 'Result'
$info = Join-Path $ToolDir 'run_info.json'
if (Test-Path -LiteralPath $info) {
  try {
    $run = Get-Content -LiteralPath $info -Raw | ConvertFrom-Json
    foreach ($r in @($run.results | Where-Object { $_ })) {
      Write-Note ("{0}: {1}" -f $r.label, $r.status)
      if ($r.workbook) { Write-Note ("   workbook: {0}" -f $r.workbook) }
      if ($r.sections) {
        $parts = @()
        foreach ($p in $r.sections.PSObject.Properties) { $parts += ('{0}={1}' -f $p.Name, $p.Value) }
        Write-Note ('   hunt hits: ' + ($parts -join ' '))
      }
    }
    if ($run.docx) { Write-Note "Word summary: $($run.docx)" }
  } catch { }
}
switch ($code) {
  0 { Write-Host ("Done in {0:N1} minutes. Output: {1}" -f ((Get-Date) - $started).TotalMinutes, $OutDir) -ForegroundColor Green }
  1 { Write-Warn "no image could be analyzed as a NetScaler disk; see the status lines above and $ToolDir\engine.log" }
  2 { Write-Warn ("no disk image could be opened from $Source (supported: VMDK, .dd/.raw/.img, split .001, E01; " +
                  'archives are not opened). The note lines above say why a file was skipped.') }
  3 { Write-Warn 'the output folder is inside the evidence folder.' }
  default { Write-Warn "the engine exited with code $code; see $ToolDir\engine.log" }
}
try { Stop-Transcript | Out-Null } catch { }
exit $code
