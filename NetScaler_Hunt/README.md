# NetScaler Hunt (Invoke-NetScalerHunt.ps1)

Version 1.2.0

One PowerShell script for Windows that hunts Citrix NetScaler (ADC / Gateway) disk images for signs of compromise.
Point it at a folder of images, or at one image file. It installs what it needs, opens every image read-only,
exports the logs, saves every log as an .xlsx file, runs the hunts, and writes a results workbook per appliance plus
a Word summary of the findings.

The Python hunt engine is embedded in `Invoke-NetScalerHunt.ps1`, so that one file is all you need to copy. The
`src` folder holds the same engine as a plain Python file, the script template, and the build script.

## Supported disk images

| Format | Files | Give `-Path` as | Notes |
|---|---|---|---|
| VMware VMDK | `.vmdk` (descriptor with `-flat.vmdk`, or a monolithic sparse disk), snapshot disks `-000001.vmdk` ... | the VM folder, or one `.vmdk` | A folder opens the latest state of each disk chain (snapshots applied). One `.vmdk` opens that disk with its parent disks. A `.vmx` is not needed. Missing or short extent files are reported. |
| Raw dd | `.dd`, `.raw`, `.img` | the image file, or its folder | Given as `-Path`, a file with any other extension is read as a raw image too. |
| Split raw | `.001`, `.002`, ... (or `.000`, `.001`, ...) | the first part, or the folder | All parts in one folder with the same name and zero-padded numbers. A set with a missing part is not opened. |
| EnCase E01 | `.E01`, `.E02`, ... | the `.E01`, or the folder | All segments in one folder. A set with a missing segment is not opened. EWF2 (`.Ex01`) is not supported: convert it to E01 or raw first. |

Not opened: archives (`.zip`, `.7z`, `.rar`, `.ova`, `.tar`, `.tgz`) and compressed images (`.dd.gz` and similar).
Extract them first; the run lists every file it skipped and why.

A folder is searched three levels deep, and different formats can be mixed. A disk that is not a NetScaler system
disk (for example a separate crash-dump disk) gets a file listing (`<label>_Disk_Inventory.xlsx`) instead of the hunt.

## Quick start

```powershell
# Once, if the script was downloaded from GitHub or copied from another machine:
Unblock-File .\Invoke-NetScalerHunt.ps1

# Every image in a case folder. Output goes to %USERPROFILE%\NSHunt\Case01_<date_time>:
powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-NetScalerHunt.ps1 -Path "D:\Evidence\Case01"
```

The first run downloads and installs what is missing (a few minutes). Later runs reuse the Python environment.

## Syntax examples by image type

The examples use `.\Invoke-NetScalerHunt.ps1` from a PowerShell window. From cmd.exe or a shortcut, put
`powershell -NoProfile -ExecutionPolicy Bypass -File` in front, as in the quick start.

```powershell
# Case folder: every supported image in it and three levels below (VMDK, .dd/.raw/.img, split, E01 can be mixed)
.\Invoke-NetScalerHunt.ps1 -Path "D:\Evidence\Case01" -OutDir "C:\NSHunt\Case01"

# VMware: the VM folder (the snapshot chain is followed and the latest state is opened)
.\Invoke-NetScalerHunt.ps1 -Path "D:\Evidence\Case01\ns-vpx01" -OutDir "C:\NSHunt\ns-vpx01"

# VMware: one disk. A snapshot disk opens with its parents; give the base disk (ns-vpx01.vmdk) for the original state
.\Invoke-NetScalerHunt.ps1 -Path "D:\Evidence\Case01\ns-vpx01\ns-vpx01-000002.vmdk" -OutDir "C:\NSHunt\ns-vpx01"

# Raw dd image (.raw and .img work the same way)
.\Invoke-NetScalerHunt.ps1 -Path "D:\Evidence\Case01\ns01.dd" -OutDir "C:\NSHunt\ns01"

# Split raw image: give the first part; .002, .003 ... must be in the same folder
.\Invoke-NetScalerHunt.ps1 -Path "D:\Evidence\Case01\ns02.001" -OutDir "C:\NSHunt\ns02"

# EnCase image: give the .E01; .E02, .E03 ... must be in the same folder
.\Invoke-NetScalerHunt.ps1 -Path "D:\Evidence\Case01\ns03.E01" -OutDir "C:\NSHunt\ns03"

# Add the client's own attacker IPs (the built-in IPs are searched too) and fix the review window
.\Invoke-NetScalerHunt.ps1 -Path "D:\Evidence\Case01" -OutDir "C:\NSHunt\Case01" -Since 2026-09-15 -IocIp 203.0.113.10, 198.51.100.7

# Attacker IPs from a text file (one per line; blank lines and text after # are ignored), Fox-IT skipped
.\Invoke-NetScalerHunt.ps1 -Path "D:\Evidence\Case01\ns01.dd" -IocIp (Get-Content .\client_ips.txt) -SkipFoxIt
```

With `-File` (cmd.exe), give a list of IPs as one comma-separated value: `-IocIp "203.0.113.10,198.51.100.7"`.

Each image gets a label: the folder name, or `<folder>_<file>` when `-Path` is a file or one folder holds several
images. Labels are made unique, and name the output folders.

## What it looks for

Every run checks every image for all of the following. Nothing has to be configured for a new client.

**Generic signs of NetScaler compromise**

- A, B: commands injected through log poisoning (user names containing `NSPPE;`, the CVE-2026-88771 pattern) and
  their execution by the call-home crash checker, with the URLs, domains and IPs inside each injected command.
- C, D: nsaaad crash loops, pitboss reboots and packet engine (NSPPE) crashes.
- Boot script (`rc.netscaler*`, `nsbefore.sh`, `nsafter.sh`) and crontab lines, flagged when they run something from
  a hidden folder or /tmp, start a background process, use network or encoding tools, or contain an IP address.
- A sweep of `/flash` and `/var` for hidden items, implant-like names and files created in the review window
  (Discovery sheet).
- I: suspicious shell history (curl, fetch, ssh, scp, tar, crontab, truncation, deletes, and more), with a view of
  each distinct command, rarest first; rare commands in the shell audit log.
- Logins from `utx.log*`, log files containing runs of NUL bytes (often a sign of truncation), and Fox-IT
  iocitrix (webshells, timestomping, cron jobs, SUID binaries).

**Known indicators** from the intrusion this tool was built on (October 2026: CVE-2026-88771 log poisoning, then a
webshell, tunnels and configuration theft) and from public reporting up to 2026-10-19

- 21 known implant and persistence paths, with SHA-256 and times, and whether each is also on the base
  (pre-snapshot) disk: the hidden folders `/flash/nsconfig/.slap`, `/flash/nsconfig/.relay` and `/var/tmp/.ux`
  (which held `slapshot.py` and `whipd.py`), the logs `/var/tmp/.s2loot.log`, `.relay-ssh.log`, `.relay-socks.log`
  and `.slap-*`, the webshell copies `.ctxs.receiver`, `.slap.receiver` and `receiver.deb` under
  `/var/netscaler/logon/LogonPoint/custom/`, the `nobody` crontab and `rc.netscaler.ptbak`. From Rapid7's
  2026-10-19 report on the same implant: the nsvmd Go proxy folder `/flash/.nsvm/` (its `.agent.log` and `.wd.log`
  are exported) and the loot folder `/var/tmp/.s2loot/`; Rapid7 also lists `reverse-agent.sh`, `vcscan-agent.sh` and
  `vc` inside `.slap`, and `run.sh` and `target_agent.py` inside `.relay` (everything inside those folders is listed
  and hashed).
- E, E2: requests to those webshell paths and to other probe paths; F: `.relay` installer lines; G: cron runs of
  the implant; the implant's tunnel log (`agent.log`) and the destinations it reached.
- H: every log line that mentions one of 189 built-in attacker IPs, and `-IocIp` adds more. The 10 IPs from the
  intrusion this tool was built on:

| IP | Level | Seen doing (2026-10) |
|---|---|---|
| 213.209.159.55 | confirmed | sent the poisoned logins, hosted the payload script that Call Home ran, used the webshell |
| 124.198.132.44 | confirmed | used the webshell as a tunnel into the internal network; SSH server of the reverse SSH tunnels |
| 162.33.177.119 | confirmed | tried 118 times to download a config archive that an injected command was meant to create |
| 152.233.50.151 | likely | requested the webshell minutes before a config theft |
| 146.70.211.157 | suspected | probed this implant's webshell paths |
| 23.162.8.173 | suspected | probed this implant's webshell paths |
| 37.19.221.148 | suspected | probed this implant's webshell paths |
| 104.36.50.29 | suspected | probed this implant's webshell paths |
| 23.234.94.126 | suspected | probed this implant's webshell paths |
| 68.235.46.82 | suspected | probed this implant's webshell paths |

"Suspected" IPs only probed for the webshell files and could be scanners that know those paths (the webshell names
were in public community reporting by 2026-10-02). 146.70.211.157 and 23.162.8.173 were also seen sending
CVE-2026-88771 injection checks to Huntback.io decoys.

The other 179 come from public reporting up to 2026-10-19: Rapid7, Zscaler, watchTowr, Unit 42, LevelBlue, eSentire,
Mandiant, GreyNoise, Arctic Wolf, Sygnia, Truesec, Beazley, TENEX, SOCRadar, Lupovis, Corelight, IFIN, and the
Poppelgaard NetScaler checker (which relays Gotham Technology Group incident-response data and Huntback.io decoy
data). They have two levels:

| Level | Count | What it means |
|---|---|---|
| `reported-infra` | 38 | C2, payload, staging or exfiltration servers. A NetScaler or internal host talking to one of these is a strong lead. Includes Rapid7's infrastructure for this same implant: 192.159.99.139 (.slap C2, relay and loot upload), 45.92.1.17 (stage and loot server), 209.74.64.192 (nsvmd C2) and 179.60.146.241 (served 1.sh). |
| `reported-exploit` | 141 | Exploit sources and webshell users named by vendor or incident-response reports, such as watchTowr's and Zscaler's source IPs and Unit 42's webshell users. Many are VPN, cloud or home addresses, so a hit shows targeting, not compromise. |

Mass-scan feeds, Tor exit relays and Cloudflare WARP addresses are left out because ordinary users share them. Every
hit is a lead: read the log line before you call it attacker activity. The H sheet shows each IP's level and what it
was seen doing, with its sources (`supplied` for IPs given with `-IocIp`). To change the lists, edit
`CASE_IOC_IPS` or the `_REPORTED_IOC_IPS` block in `src/nshunt_engine.py` and rebuild (see "Building from source").

## What it does

1. **Python.** Uses an installed Python 3.10 to 3.13 (the `py` launcher, `python` on PATH, or the standard folders).
   If none is found it downloads Python 3.13.16 from python.org, checks that the installer is signed by the Python
   Software Foundation, and installs it for the current user only (no admin rights, nothing added to PATH).
   Python 3.14 is skipped because dissect.target 3.25.1 does not import on it.
2. **Packages.** Creates `%LOCALAPPDATA%\NSHunt\venv` and installs pinned versions: dissect 3.22 (dissect.target
   3.25.1), XlsxWriter 3.2.9, python-docx 1.2.0 and tabulate 0.10.0.
3. **Fox-IT iocitrix.** Uses a copy of `iocitrix.py` found next to the script (or one folder up), otherwise downloads
   it from GitHub at the reviewed commit d12affa. In both cases its SHA-256 must be
   `dc41fac9651b5dabe3a281fedb61584307bd6e65a9c9bbba115c236de3a2d3b9`; otherwise those checks are skipped.
4. **Disks.** Finds the images (see "Supported disk images") and opens each one read-only with dissect. Split and
   E01 sets are checked before they are opened.
5. **Export.** Copies all of `/var/log` (with subfolders) and the known implant's text logs out of the image.
   `export_manifest.csv` holds each file's path in the image, SHA-256 and original UTC times. Implant scripts and
   webshells are never exported; they are recorded by SHA-256 and metadata only, so antivirus does not react to the
   output.
6. **Every log to .xlsx.** Each exported log becomes its own workbook under `logs_xlsx` (same folder layout as the
   image). `.gz` rotations are decompressed. httpaccess logs get parsed columns (client IP, method, path, status,
   bytes, user agent). Binary `utx.log*` login records are decoded into rows. Runs of NUL bytes are shown as
   `[NUL xN]`. Text is never turned into formulas or links.
7. **Hunts.** Everything under "What it looks for".
8. **Reports.** `<label>_Hunt_Results.xlsx` per appliance (about 30 sheets, including a UTC timeline) and
   `NetScaler_Findings_Summary.docx` for the whole run.

Nothing is written inside the evidence folder (`-Path`, or the folder that holds the `-Path` file); the script
refuses an output folder inside it.

## Output layout

```
<OutDir>\
  NetScaler_Findings_Summary.docx
  SHA256SUMS.txt                          SHA-256 of every file this run wrote (except engine.log and the transcript)
  <label>\                                one folder per image
    <label>_Hunt_Results.xlsx             (<label>_Disk_Inventory.xlsx for a disk that is not a NetScaler disk)
    foxit_iocitrix_output.txt
    logs\var_log\...                      raw exported logs (Windows-safe names)
    logs\implant_logs\var\tmp\...         implant text logs, for example var\tmp\.ux\agent.log and var\tmp\.s2loot.log
    logs\export_manifest.csv
    logs_xlsx\var_log\...\<log>.xlsx      every log as .xlsx
    logs_xlsx\implant_logs\...
  _tool\                                  engine copy, foxit\iocitrix.py, engine.log, dissect_messages.log,
                                          run_info.json, pip_freeze.txt, powershell_transcript.txt
```

Expect about 0.5 GB of output per appliance. Other files already in `-OutDir` are left alone.

## Parameters

| Parameter | Meaning |
|---|---|
| `-Path` | A folder to search, or one image file (required). See "Supported disk images". |
| `-OutDir` | Output folder. Default `%USERPROFILE%\NSHunt\<folder or file name>_<yyyyMMdd_HHmmss>`. |
| `-Since yyyy-MM-dd` | Start of the review window for the new-file sweep and the timeline. Default: 30 days before the newest log of each image. |
| `-IocIp` | Extra attacker IPs (IPv4 or IPv6) to search every log for, added to the built-in list. A list, a comma-separated value, or `(Get-Content file.txt)`. |
| `-PythonExe` | Use this python.exe (3.10 to 3.13) as the base interpreter. |
| `-VenvDir` | Location of the Python environment. Default `%LOCALAPPDATA%\NSHunt\venv`. |
| `-WheelDir` | Install the packages offline from a folder of wheel files. |
| `-FoxItPath` | Use this iocitrix.py instead of searching for or downloading it. |
| `-SkipFoxIt` | Skip the Fox-IT checks (they take about 3 minutes per image). |
| `-SkipLogXlsx` | Do not convert every log to .xlsx (the hunts still run). |
| `-IncludeBase` | Also run the full hunt on each base (pre-snapshot) VMDK. |
| `-NoInstall` | Never download or install Python. |

Exit codes: 0 at least one NetScaler image analyzed, 1 no image could be analyzed as a NetScaler disk (or the
parameters were rejected), 2 no disk image could be opened from `-Path`, 3 output folder inside the evidence folder.

## Running the engine without PowerShell

The engine runs on Linux, macOS or Windows with Python 3.10 to 3.13:

```bash
python3 -m venv ~/nshunt-venv
~/nshunt-venv/bin/pip install dissect==3.22 tabulate==0.10.0 XlsxWriter==3.2.9 python-docx==1.2.0
~/nshunt-venv/bin/python -B src/nshunt_engine.py --path /cases/case01 --out ~/nshunt/case01
~/nshunt-venv/bin/python -B src/nshunt_engine.py --path /cases/case01/ns02.001 --out ~/nshunt/ns02 --ioc-ip 203.0.113.10 2001:db8::5
```

Options: `--since YYYY-MM-DD`, `--ioc-ip IP [IP ...]`, `--foxit /path/to/iocitrix.py` (the reviewed commit d12affa),
`--skip-log-xlsx`, `--include-base`. `python -B src/nshunt_engine.py --help` lists them.

## Troubleshooting

- **"running scripts is disabled"**: use the `powershell -NoProfile -ExecutionPolicy Bypass -File ...` form. It
  applies to that one process only. If your organization enforces signed scripts, it may still be blocked.
- **Proxy**: the Python download uses the Windows proxy settings. For pip, set `$env:HTTPS_PROXY = 'http://proxy:port'`
  before running.
- **No internet**: on a connected Windows machine with the same Python version, run
  `py -3.13 -m pip download dissect==3.22 tabulate==0.10.0 XlsxWriter==3.2.9 python-docx==1.2.0 -d C:\wheels`, copy
  the folder over, and run with `-WheelDir C:\wheels -NoInstall`, plus `-FoxItPath` (or `-SkipFoxIt`).
- **"no disk image could be opened"**: read the `note:` lines in the output. They name each file that was skipped
  and why (archive, missing split part or E01 segment, data file of a VMDK descriptor, smaller than 1 MiB).
- **A split or E01 set is "not opened"**: put every part or segment in one folder with the same base name. Split
  parts must be numbered with leading zeros (`.001`, not `.1`).
- **Antivirus**: the output contains no implant code, but the logs quote attacker commands as text. If something is
  quarantined, add an exclusion for the output folder.
- **Removing it**: delete `%LOCALAPPDATA%\NSHunt`. If the script installed Python, uninstall "Python 3.13.16" from
  Apps and features (it sits in `%LOCALAPPDATA%\Programs\Python\Python313`).

## Verifying the files

From the folder that holds `Invoke-NetScalerHunt.ps1`:

```powershell
Get-Content .\SHA256SUMS.txt | ForEach-Object {
  $h, $f = $_ -split '\s+', 2
  '{0}  {1}' -f $(if ((Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash -eq $h) { 'OK  ' } else { 'FAIL' }), $f
}
```

The script also checks its embedded engine at run time against the SHA-256 in its help (`Get-Help
.\Invoke-NetScalerHunt.ps1 -Full`, under NOTES).

## Building from source

Edit `src/nshunt_engine.py` or `src/Invoke-NetScalerHunt.template.ps1`, then run `python src/build.py`. It embeds
the engine in `Invoke-NetScalerHunt.ps1` (Windows line endings) and rewrites `SHA256SUMS.txt`. Keep both source
files plain ASCII: Windows PowerShell 5.1 reads a file without a byte order mark in the local code page.

## How it was tested

- 1.0.0 ran on Windows and in Linux against two VMware NetScaler VPX images (snapshot chains) from the intrusion it
  was built for, with the same hunt counts on both.
- 1.1.0 ran in Linux (PowerShell 7.4.6, Python 3.13.16, dissect 3.22) against a synthetic NetScaler-like disk saved
  as raw `.dd`, split raw, E01 and a VMDK, plus a disk that is not a NetScaler disk and an empty folder. All four
  formats gave identical results and the same disk contents; single-file runs were also given a later part (`.002`,
  `.E02`). Exit codes, `-IocIp` checks (including IPv6 and a file with comments), output folder checks, the default
  output name and the run-only SHA256SUMS were checked. PSScriptAnalyzer found no Windows PowerShell 5.1
  compatibility problems.
- 1.2.0 repeated those tests with a publicly reported IP of each level, a `/flash/.nsvm/` folder and a
  `/var/tmp/.s2loot/` folder added to the test disk. All four formats gave identical results, the H sheet showed the
  `reported-infra` and `reported-exploit` levels, both new paths were flagged and the nsvmd logs were exported.
  With 189 IPs, matching 300,000 log lines took 1.7 seconds (the 1.1.0 matching method took 161 seconds with the
  same list).
- Not yet done for 1.1.0 and 1.2.0: a run on Windows, a run against a real raw or E01 NetScaler image, and a run on
  one snapshot `.vmdk` given directly as `-Path`.

## Changes

**1.2.0** (2026-10-19)

- 179 attacker IPs from public reporting are now built in (levels `reported-infra` and `reported-exploit`), next to
  the 10 from the tool's own case, so every run checks 189 IPs plus any given with `-IocIp`. Each H hit shows what
  the IP was seen doing and who reported it.
- New known paths from Rapid7's report on the same implant: `/flash/.nsvm/` (nsvmd) and `/var/tmp/.s2loot/`. The
  nsvmd logs are exported, and nsvmd, v5v.in and the new script names are added to the implant-string search.
- IP matching now looks each IPv4 address up in a set, so the larger list does not slow the log pass.

**1.1.0** (2026-10-19)

- Raw dd (`.dd`, `.raw`, `.img`), split raw (`.001` ...) and EnCase E01 (`.E01` ...) images, found in folders or
  given directly. `-Path` can now be one image file; a `.vmdk` opens that disk with its parent disks.
- Split and E01 sets are checked before they are opened; a missing part, a gap in the numbering or a foreign file
  with the set's name stops that image with a note instead of reading corrupt data.
- The built-in attacker IPs now cover all ten seen in the source intrusion, each with a level. `-IocIp` adds to the
  built-in list instead of replacing it, accepts IPv6, and can read a text file. The H sheet gains Level and
  Known for columns.
- Fixed: on Windows, implant logs landed in `implant_logs\_var_tmp` and `_var_tmp_.ux`; they now keep the image
  layout (`implant_logs\var\tmp\...`). Two images with the same folder name no longer share an output folder.
  `SHA256SUMS.txt` lists only the files of this run (1.0.0 hashed everything under `-OutDir`). Tunnel log
  (`agent.log`) lines whose time of day is more than an hour after the file's modified time are dated to the day
  before (1.0.0 put them a day late). `.ovf` files are no longer reported as archives.

**1.0.0** (2026-10-13): first version (VMware VMDK only).
