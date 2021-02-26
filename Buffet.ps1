

<#
Buffet v1.0
Windows Live Forensic Flight Plan for CyberDefenses
Written by Ethan Waters
Automated (poorly) by I.A. Wilds
1/21/21
#>

<# 
This script will run many windows forensics commands and then write them to a file that you are prompted to name.
The file can then be stored offline and searched by multiple analysts at once.
NOTE: COMMENT OUT ANY COMMNADS THAT YOU DO NOT NEED FOR YOUR INVESTIGATION#>


<#The second version of this script needs to include more in-depth forensic commands that search for hidden processes
It also needs to write specific results to specific folders and then compress the folders

UPDATE V2.0 complete
I.A.Wilds
2/18/2021
#>

<# 
UPDATE 3.0 IDEAS:
The third update needs to create functions for steps that reoccur
complete 2/25/2021
it should also remove unecessary or redundant commnands
it should also have error handling
Any folders that don't have any input should not be created and a file should be written to listing their name
#>


<#
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@                                                                                                              @@@
@@@                      :::::::::INSTRUCTIONS for using this script::::::::::                                   @@@
@@@                                                                                                              @@@
@@@              To run this script, save it to the host in a directory of your choosing.                        @@@
@@@                           Open an administrator powershell terminal                                          @@@
@@@                 navigate to the directory where you saved the Buffet.ps1 script                              @@@
@@@                     run the script from the command line using "./Buffet.ps1"                                @@@
@@@                        When prompted, input a folder name of your choosing                                   @@@
@@@                             I recommend CDI or CyberDefenses                                                 @@@
@@@       This script takes approximately 40 minutes to run on a single laptop so plan accordingly               @@@
@@@            If you choose to uncomment FORENSICTIMELINE, this script takes up to 4 hours                      @@@
@@@                                                                                                              @@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@


$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
                                                                                                                                    $
NOTE: THE FORENSIC TIMELINE COMMAND FOUND BELOW '*****POWER FORENSICS SID AND TIMELINE*****' CAN TAKE  A FEW HOURS TO COMPLETE      $
IF YOU A RE PRESSED FOR TIME CONSIDER LEAVING IT COMMENTED OUT                                                                      $
                                                                                                                                    $
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
#>

$gray= @"




                                .do-^^***'-o..
                             .o^*            **^^..
                           ,,''                    *
                          d'                      ^*b
                         d^d:                       ^b.
                        ,,dP                         `Y.
                       d`88                           `8.
 ooooooooooooooooood888Y88'                            88888888888bo,
d****          ^^***^Y:d8P                              8,           b
8                    Y888b                               8           8
8                   :8d888,                           ,8:8.          8
:                   dY88888                           8' 8:          8
:                   8:8888                               2b          8
:                   Pd88P',...                     ,d888o.8          8
:                   :88'dd888888o.                d8888888:          8
:                  ,:Y:d8888888888b             ,d888888888          8
*                  ^88b88d888888888b.          ,d888888bY8b          8
*                   b8P8;888888888888.        ,88888888888P          8
*                   8:b88888888888888:        888888888888'          8
*                   8:8.8888888888888:        Y8888888888P           8
*                   YP88d8888888888P'          **888888"Y            8
:                   :bY8888P^**Y8*^                     :            8
:                    8'8888'                            d            8
:                    :bY888,                           ,P            8
:                     Y,8888           d.  ,-         ,8'            8
:                     ^8)888:           '            ,P'             8
:                      ^88888.          ,...        ,P               8
:                       ^Y8888,       ,888888o     ,P                8
:                         Y888b      ,88888888    ,P'                8
:                          ^888b    ,888888888   ,,'                 8
:                           ^Y88b  dPY888888OP   :'                  8
:                             :88.,'.   *^  8P-"b.                   8
:.                             )8P,   ,b '  -   ^*b                  8
::                            :':   d,'d^b, .  - ,db                 8
::                            *b. dP' d8':      d88'                 8
::                             '8P" d8P' 8 -  d88P'                  8
::                            d,' ,d8'  ''  dd88'                    8
|*                           d'   8P'  d' dd88'8                     8
**                          ,:   ^*'   d:ddO8P' 8b.                  8
**                  ,dooood88: ,    ,d8888"     ^**b.                8
**               .o8"'   **^Y8.b    8 *^''    .o'  `*^^ob.           8
**              dP'         `8:     K       dP''        "`Yo.        8
**             dP            88     8b.   ,d'              ^*b       8
**             8.            8P     8^*'  `*                 :.      8
**            :8:           :8'    ,:                        ::      8
**            :8:           d:    d'                         ::      8
**            :8:          dP   ,,'                          ::      8
**            `8:     :b  dP   ,,                            ::      8
**            ,8b     :8 dP   ,,                             d       8
*             :8P     :8dP    d'                       d     8       8
*             :8:     d8P    d'                      d88    :P       8
*             d8'    ,88'   ,P                     ,d888    d'       8
*             88     dP'   ,P                      d8888b   8        8
*            ,8:   ,dP'    8.                     d8''88'  :8        8
*            :8   d8P'    d88b                   d"'  88   :8        8
*              d: ,d8P'    ,8P".                      88   :P        8
*            8 ,88P'     d'                           88   ::        8
*           ,8 d8P       8                            88   ::        8
*           d: 8P       ,:  -hrr-                    :88   ::        8
*           8',8:,d     d'                           :8:   ::        8
*          ,8,8P'8'    ,8                            :8'   ::        8
*          :8*' d'     d'                            :8    ::        8
*          *8  ,P     :8                             :8:   ::        8
*           8,        d8.                            :8:   8:        8
*           :8       d88:                            d8:   8         8
*,          *8,     d8888                            88b   8         8
**           88   ,d::888                            888   Y:        8
**           YK,oo8P :888                            888.  8b        8
**           %8888P  :888:                          ,888:   Y,       8
**            **'     888b                          :888:   8b       8
**                    8888                           888:    ::      8
**                    8888:                          888b     Y.     8,
**                    8888b                          :888     8b     8:
**                    88888.                         ^888,     Y     8:
*..ob...............--****** ---------------------- --------------^^***
"@
 
Write-Host $gray


# Detect the current woring directory and prompt the user for a file name to store all results
$holdPath = Get-Location
$folderName = read-host "what would you like to name your folder? `n"
New-Item -Path $holdPath -Name $folderName -ItemType "directory"
#$folderName = ($holdPath.Path + "\" + $folderName) 
#($folderName + "`n") | tee-object -Append -FilePath $folderName
Set-Location $folderName
$holdPath = Get-Location
Get-Location


# Install PowerForensics 
# By default, the module will be installed in the %ProgramFiles%\WindowsPowerShell\Modules directory, which makes it available for all users
#WARNING POWERSHELL GALLERY IS ONLY AVAILABLE IN WINDOW MANAGEMENT FRAMEWORK 5
Install-Module -Force -Name PowerForensics
Import-Module PowerForensics
#To view all commands available with PowerForensics run the below command
# Get-Command -Module PowerForensics


$filename = New-Item -Path $holdPath -Name ($folderName + "_System Info") -ItemType "file" 
Write-Output "************System Hardware and Operating System Information************ `n" | tee-object -Append -FilePath $filename
wmic CPU get Caption,Name | tee-object -Append -FilePath $filename
wmic COMPUTERSYSTEM get UserName,Domain,WorkGroup,Manufacturer,Model,SystemType | tee-object -Append -FilePath $filename
wmic OS get BuildNumber,Caption,CSName,CurrentTimeZone,MUILanguages,Name,OSArchitecture /FORMAT:list | tee-object -Append -FilePath $filename
wmic BOOTCONFIG list brief | tee-object -Append -FilePath $filename


#compress all files and remove the previous files

function Get-ZippedCleaner {
 $zippy = ($filename.Name + ".zip")
$holdPath = ($holdPath.Path + "\" + $filename.Name)
Compress-Archive -Path $holdPath -DestinationPath .\$zippy
Remove-Item $filename.Name
$holdPath = Get-Location
}

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Interfaces") -ItemType "file"
Write-Output "************Interfaces************ `n" | tee-object -Append -FilePath $filename
wmic NICCONFIG get Description,MACAddress,IPAddress | tee-object -Append -FilePath $filename
ipconfig /all | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_System Patches") -ItemType "file"
Write-Output "************System Patches************ `n" | tee-object -Append -FilePath $filename
wmic QFE list brief | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Installed Products") -ItemType "file"
Write-Output "************Installed Products************ `n" | tee-object -Append -FilePath $filename

wmic PRODUCT get LocalPackage,Description | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Network Connections") -ItemType "file"
Write-Output "************Network Connections************ `n" | tee-object -Append -FilePath $filename

netstat -anob | findstr LIST | tee-object -Append -FilePath $filename
netstat -anob | findstr ESTA | tee-object -Append -FilePath $filename
netstat -ay | findstr ESTA | tee-object -Append -FilePath $filename
powershell "Get-NetTCPConnection -State Established" | tee-object -Append -FilePath $filename
powershell "Get-NetTCPConnection -AppliedSetting Internet" | tee-object -Append -FilePath $filename
netsh winhttp show proxy
Write-Output "************NETWORK CONNECTIONS WITH HASH AND DNS CACHE INFO************ `n" | tee-object -Append -FilePath $filename
#Obtain hash and establIshed network connections for running executables with DNS CACHE
Get-NetTCPConnection -State Established | Select-Object RemoteAddress, RemotePort, OwningProcess, @{n="Path";e={(Get-Process -Id $_.OwningProcess).Path}},@{n="Hash";e={(Get-Process -Id $_.OwningProcess|Get-Item|Get-filehash).hash}}, @{n="User";e={(Get-Process -Id $_.OwningProcess -IncludeUserName).UserName}},@{n="DNSCache";e={(Get-DnsClientCache -Data $_.RemoteAddress -ea 0).Entry}}|Sort-Object|Get-Unique -AS|Format-Table | tee-object -Append -FilePath $filename
Get-NetTCPConnection -State LISTEN | Select-Object LocalAddress, LocalPort, OwningProcess, @{n="Path";e={(Get-Process -Id $_.OwningProcess).Path}},@{n="Hash";e={(Get-Process -Id $_.OwningProcess|Get-Item|Get-filehash).hash}}, @{n="User";e={(Get-Process -Id $_.OwningProcess -IncludeUserName).UserName}}|Sort-Object|Get-Unique -AS|Format-Table | tee-object -Append -FilePath $filename
#Possible tunneled network connections
Write-Output "************POSSIBLE TUNNELED NETWORK CONNECTIONS************ `n" | tee-object -Append -FilePath $filename
Get-NetTCPConnection -State ESTABLISHED |Where-Object LocalAddress -Like "::1" | Select-Object RemoteAddress, RemotePort, OwningProcess, @{n="Path";e={(Get-Process -Id $_.OwningProcess).Path}},@{n="Hash";e={(Get-Process -Id $_.OwningProcess|Get-Item|Get-filehash).hash}}, @{n="User";e={(Get-Process -Id $_.OwningProcess -IncludeUserName).UserName}},@{n="DNSCache";e={(Get-DnsClientCache -Data $_.RemoteAddress).Entry}}|Sort-Object|Get-Unique -AS|Format-Table | tee-object -Append -FilePath $filename
Get-NetTCPConnection -State Established |Where-Object LocalAddress -Like "127.0.0.1"| Select-Object RemoteAddress, RemotePort, OwningProcess, @{n="Path";e={(Get-Process -Id $_.OwningProcess).Path}},@{n="Hash";e={(Get-Process -Id $_.OwningProcess|Get-Item|Get-filehash).hash}}, @{n="User";e={(Get-Process -Id $_.OwningProcess -IncludeUserName).UserName}},@{n="DNSCache";e={(Get-DnsClientCache -Data $_.RemoteAddress).Entry}}|Sort-Object|Get-Unique -AS|Format-Table | tee-object -Append -FilePath $filename
Get-NetTCPConnection -State LISTEN |Where-Object LocalAddress -Like "127.0.0.1" | Select-Object LocalAddress, LocalPort, OwningProcess, @{n="Path";e={(Get-Process -Id $_.OwningProcess).Path}},@{n="Hash";e={(Get-Process -Id $_.OwningProcess|Get-Item|Get-filehash).hash}}, @{n="User";e={(Get-Process -Id $_.OwningProcess -IncludeUserName).UserName}}|Sort-Object|Get-Unique -AS|Format-Table | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Processes") -ItemType "file"
Write-Output "************Processes************ `n" | tee-object -Append -FilePath $filename

tasklist | tee-object -Append -FilePath $filename
wmic PROCESS get Name,ProcessId,ParentProcessId | tee-object -Append -FilePath $filename
wmic PROCESS list brief | tee-object -Append -FilePath $filename
powershell Get-Process | tee-object -Append -FilePath $filename
powershell "Get-Process | Select-Object -Property Id,Name,Company,Path" | tee-object -Append -FilePath $filename
powershell "Get-Process | Where Id -eq <pid> | Select *" | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Network Capable") -ItemType "file"
Write-Output "************Network Capable Modules************ `n" | tee-object -Append -FilePath $filename

tasklist /m wininet.dll | tee-object -Append -FilePath $filename
tasklist /m ws2_32.dll | tee-object -Append -FilePath $filename
# The tree command works better through Powershell
# tree C:\Users | tee-object -Append -FilePath $filename
Get-ChildItem | tree | tee-object -Append -FilePath $filename
# This command is meant to show the time of creation of a file or directory
cmd.exe /c dir /T:C C:\Users | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Active Shares") -ItemType "file"
Write-Output "************Active Shares************ `n" | tee-object -Append -FilePath $filename

wmic SHARE list brief | tee-object -Append -FilePath $filename
powershell Get-SmbShare | tee-object -Append -FilePath $filename
powershell "Get-WmiObject -class Win32_Share" | tee-object -Append -FilePath $filename
net share | tee-object -Append -FilePath $filename
net use | tee-object -Append -FilePath $filename
Write-Output "Running Services `n" | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Running Processes") -ItemType "file"
Write-Output "************RUNNING PROCESSES************ `n" | tee-object -Append -FilePath $filename
tasklist /SVC | tee-object -Append -FilePath $filename
#get cannot be ran in a powershell terminal and must be passed via cmd.exe
cmd.exe /c 'wmic PROCESS where Name="svchost.exe" get CommandLine,ExecutablePath,ProcessId,ParentProcessId' | tee-object -Append -FilePath $filename
wmic SERVICE list brief | tee-object -Append -FilePath $filename
cmd.exe /c 'wmic SERVICE where State="Running" get Caption,Description,DisplayName,Name,PathName,ProcessId,StartMode,StartName /FORMAT:list' | tee-object -Append -FilePath $filename
cmd.exe /c 'wmic SERVICE where (State="Running" AND StartName="NT AUTHORITY\\NetworkService") get Caption,Description,DisplayName,Name,PathName,ProcessId,StartMode,StartName /FORMAT:list' | tee-object -Append -FilePath $filename
sc.exe query type= service | tee-object -Append -FilePath $filename
sc.exe query type=service state=inactive | tee-object -Append -FilePath $filename
# sc query <service name>
# sc qc <service name>

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Start Ups") -ItemType "file"
Write-Output "************Startups************ `n" | tee-object -Append -FilePath $filename

cmd.exe /c 'wmic STARTUP get Command,User' | tee-object -Append -FilePath $filename
wmic STARTUP list full /FORMAT:list | tee-object -Append -FilePath $filename
Get-ChildItem /a "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" | tee-object -Append -FilePath $filename
Get-ChildItem /a "c:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" | tee-object -Append -FilePath $filename
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run | tee-object -Append -FilePath $filename
reg query HCU\Software\Microsoft\Windows\CurrentVersion\Run | tee-object -Append -FilePath $filename
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce | tee-object -Append -FilePath $filename
reg query HCU\Software\Microsoft\Windows\CurrentVersion\RunOnce | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Scheduled Tasks") -ItemType "file"
Write-Output "************Scheduled Tasks************ `n" | tee-object -Append -FilePath $filename

powershell Get-ScheduledTask | tee-object -Append -FilePath $filename
schtasks /query /FO list | tee-object -Append -FilePath $filename
powershell "Get-ScheduledTask | Select-Object -Property TaskPath" | Sort-Object /unique | tee-object -Append -FilePath $filename
Get-ForensicScheduledJob -VolumeName C: | tee-object -Append -FilePath $filename
Get-ScheduledTask | Select-Object TaskName,TaskPath,Date,Author,Actions,Triggers,Description,State | Where-Object Author -NotLike 'Microsoft' | Where-Object Author -NotLike 'Microsoft Corporation' | Where-Object Author -ne $null | tee-object -Append -FilePath $filename
Get-ScheduledJob | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Jobs") -ItemType "file"
Write-Output "************Jobs************ `n" | tee-object -Append -FilePath $filename

wmic JOB list brief | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Drivers") -ItemType "file"
Write-Output "************Drivers************ `n" | tee-object -Append -FilePath $filename

powershell "Get-WindowsDriver -Online" | tee-object -Append -FilePath $filename
sc.exe query type= driver | tee-object -Append -FilePath $filename
#Driver enumeration
Get-ChildItem C:\Windows\*\DriverStore\FileRepository\ -recurse -include *.inf | Format-List FullName,LastWriteTime,LastWriteTimeUtc | tee-object -Append -FilePath $filename
Get-ChildItem -path C:\Windows\System32\drivers -include *.sys -recurse -ea SilentlyContinue | tee-object -Append -FilePath $filename
sc.exe query type=driver state=all | tee-object -Append -FilePath $filename
Get-ChildItem -path C:\Windows\System32\drivers -include *.sys -recurse -ea SilentlyContinue | Get-AuthenticodeSignature | Where-Object {$_.status -ne 'Valid'} | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_User Accounts") -ItemType "file"
Write-Output "************User Accounts************ `n" | tee-object -Append -FilePath $filename

wmic USERACCOUNT get Domain,Name,SID | tee-object -Append -FilePath $filename
powershell Get-LocalUser | tee-object -Append -FilePath $filename
powershell Get-LocalUser | Select-Object -Property Name, SID | tee-object -Append -FilePath $filename

net user | tee-object -Append -FilePath $filename
# net user <user>

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Groups") -ItemType "file"
Write-Output "************Groups************ `n" | tee-object -Append -FilePath $filename

wmic GROUP get Domain,Name,SID | tee-object -Append -FilePath $filename
net localgroup | tee-object -Append -FilePath $filename
# net localgroup <group>
net localgroup Administrators | tee-object -Append -FilePath $filename
net localgroup "Backup Operators" | tee-object -Append -FilePath $filename
net localgroup "Power Users" | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Event Logs") -ItemType "file"
Write-Output "************List of Event Logs************ `n" | tee-object -Append -FilePath $filename

wmic NTEVENTLOG get Name | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Logon Events") -ItemType "file"
Write-Output "************Logon Events************ `n" | tee-object -Append -FilePath $filename

powershell "Get-EventLog -logname Security -InstanceId 4611,4624,4625,4643,4648,4776,4778,4779 | Select-Object -Property TimeGenerated,InstanceId,Message" | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Alternate Data Streams") -ItemType "file"
Write-Output "************Alternate Data Streams************ `n" | tee-object -Append -FilePath $filename
Get-ChildItem | ForEach-Object { Get-Item $_.FullName -stream * } | Where-Object Stream -ne ':$Data' | tee-object -Append -FilePath $filename

<#
The Get-ForensicAlternateDataStream cmdlet parses the Master File Table and returns AlternateDataStream objects for files that contain more than one $DATA attribute.
NTFS stores file contents in $DATA attributes. The file system allows a single file to maintain multiple $DATA attributes. When a file has more than one $DATA attribute the additional 
attributes are referred to as "Alternate Data Streams".
#>
#I do not see the value in this command
#Get-ForensicAlternateDataStream -VolumeName C: | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 


#Write-Output "************Directory File and Listing************ `n" | tee-object -Append -FilePath $filename

$filename = New-Item -Path $holdPath -Name ($folderName + "_Search By File Type") -ItemType "file"
Write-Output "************Search by File Type************ `n" | tee-object -Append -FilePath $filename
powershell "Get-ChildItem C:\ -include *.bat -recurse -ErrorAction silentlycontinue" | tee-object -Append -FilePath $filename
powershell "Get-ChildItem C:\ -include *.bat -recurse" | tee-object -Append -FilePath $filename
Write-Output "************LIST COMPRESSED FILES************ `n" | tee-object -Append -FilePath $filename
Get-ChildItem -r C:\* | Where-Object {$_.attributes -match "compressed"} | ForEach-Object { $_.fullname }



#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

#F---O---R----E---N---S---I---C---S
#begin PowerForensics commands
$filename = New-Item -Path $holdPath -Name ($folderName + "_Master File Table Attributes") -ItemType "file"
Write-Output "************MASTER FILE TABLE ATTRIBUTES************ `n" | tee-object -Append -FilePath $filename
Get-ForensicAttrDef -VolumeName C: | tee-object -Append -FilePath $filename
#NOTE: IF YOU HAVE MORE THAN JUST PHYSICAL DRIVE 0, YOU NEED TO UNCOMMENT THE COMMANDS FOR MORE DRIVES
Get-ForensicBootSector -Path \\.\PHYSICALDRIVE0 | tee-object -Append -FilePath $filename
#Get-ForensicBootSector -Path \\.\PHYSICALDRIVE1 | tee-object -Append -FilePath $filename
#Get-ForensicBootSector -Path \\.\PHYSICALDRIVE2 | tee-object -Append -FilePath $filename
#Get-ForensicBootSector -Path \\.\PHYSICALDRIVE3 | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_FORENSICS_Explorer Type Path") -ItemType "file"
Write-Output "************POWER FORENSICS EXPLORER TYPED PATH************ `n" | tee-object -Append -FilePath $filename
Get-ForensicExplorerTypedPath -VolumeName C:   | Tee-Object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_FORENSICS_Office File and Outlook") -ItemType "file"
Write-Output "************POWER FORENSICS OFFICE FILE MRU AND OFFICE OUTLOOK CATALOG************ `n" | tee-object -Append -FilePath $filename
Get-ForensicOfficeFileMru -VolumeName C:  | tee-object -Append -FilePath $filename
Get-ForensicOfficeOutlookCatalog -VolumeName c: | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 


$filename = New-Item -Path $holdPath -Name ($folderName + "_FORENSICS_Registry Key Info") -ItemType "file"
Write-Output "************POWER FORENSICS REGISTRY KEY INFO************ `n" | tee-object -Append -FilePath $filenameGet-ForensicPrefetch -VolumeName C: | tee-object -Append -FilePath $filename
Get-ForensicRegistryKey -HivePath C:\Windows\System32\config\SAM -Recurse | tee-object -Append -FilePath $filename
Get-ForensicRunKey -VolumeName C: | tee-object -Append -FilePath $filename
Get-ForensicRunMru -HivePath C:\Users\Public\NTUSER.DAT | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_FORENSICS_Shell Link") -ItemType "file"
Write-Output "************POWER FORENSICS SHELL LINK************ `n" | tee-object -Append -FilePath $filename
Get-ForensicShellLink -VolumeName C: | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Sid and Timeline") -ItemType "file"
Write-Output "************POWER FORENSICS SID AND TIMELINE************ `n" | tee-object -Append -FilePath $filename
Get-ForensicSid -HivePath C:\Windows\System32\config\SAM | Format-List | tee-object -Append -FilePath $filename
#UNCOMMENT THIS LINE TO RUN A FORENSIC TIMELINE
#IT WILL TAKE A COUPLE OF HOURS TO COMPLETE
#Get-ForensicTimeline | Sort-Object -Property Date tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_FORENSICS_Typed Url and User Assist") -ItemType "file"
Write-Output "************POWER FORENSICS TYPE URL AND USER ASSIST************ `n" | tee-object -Append -FilePath $filename
Get-ForensicTypedUrl -VolumeName C: | tee-object -Append -FilePath $filename

$userAssistExplanation = @"

INFO:
UserAssist
On a Windows System, every GUI-based programs launched from the desktop are tracked in this registry key:

HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
This key contains two GUID subkeys (CEBFF5CD Executable File Execution, F4E57C4B Shortcut File Execution): each subkey maintains a list of system objects such as program, 
shortcut, and control panel applets that a user has accessed.

"@

Write-Host $userAssistExplanation | tee-object -Append -FilePath $filename

Get-ForensicUserAssist -HivePath C:\Users\Public\NTUSER.DAT | tee-object -Append -FilePath $filename
Get-ForensicUsnJrnl | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_FORENSICS_Windows Search History") -ItemType "file"
Write-Output "************POWER FORENSICS OUTPUT WINDOWS SEARCH HISTORY************ `n" | tee-object -Append -FilePath $filename
Get-ForensicWindowsSearchHistory | tee-object -Append -FilePath $filename

#POWERFORENSIC CAN BE USED TO COLLECT A BIT FOR BIT COPY i.e. DD
#Invoke-ForensicDD instructions can be found at the link below
# https://powerforensics.readthedocs.io/en/latest/modulehelp/Invoke-ForensicDD/

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_FORENSICS_Installed Software") -ItemType "file"
Write-Output "************POWER FORENSICS INSTALLED SOFTWARE************ `n" | tee-object -Append -FilePath $filename
#list installed software
#Win32_product
Get-CimInstance -ClassName Win32_Product | Select-Object Name,Version,Vendor,InstallDate,InstallLocation,InstallSource,PackageCache,PackageName,LocalPackage | tee-object -Append -FilePath $filename
#64 bit applications will NOT be listed
#logged on user
Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Name,UserName,PrimaryOwnerName,Domain,TotalPhysicalMemory,Model,Manufacturer | tee-object -Append -FilePath $filename
#get running processes
#Get-Process | Select-Object StartTime,ProcessName,Id,Path | format-list | tee-object -Append -FilePath $filename
#get scheduled tasks


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Persistence Mechanisms") -ItemType "file"
Write-Output "************PERSISTENCE MECHANISMS************ `n" | tee-object -Append -FilePath $filename
# check for persistence
Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\ | tee-object -Append -FilePath $filename
Get-ItemProperty -Path HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce | tee-object -Append -FilePath $filename
Get-ItemProperty -Path HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx | tee-object -Append -FilePath $filename
Get-ItemProperty -Path HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run | tee-object -Append -FilePath $filename
Get-ItemProperty -Path HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32 | tee-object -Append -FilePath $filename
Get-ItemProperty -Path HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder | tee-object -Append -FilePath $filename
Get-ItemProperty -Path HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run | tee-object -Append -FilePath $filename
Get-ItemProperty -Path HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Chrome History") -ItemType "file"
Write-Output "************Chrome History************ `n" | tee-object -Append -FilePath $filename
#chrome history for malicious sites
Get-ChildItem -path "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions" -recurse -erroraction SilentlyContinue | tee-object -Append -FilePath $filename
Get-ChildItem -path 'C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions' -recurse -erroraction SilentlyContinue -include manifest.json | Get-Content | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Firefox History") -ItemType "file"
Write-Output "************FIREFOX HISTORY************ `n" | tee-object -Append -FilePath $filename
#firefox history
Get-ChildItem -path "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\extensions" -recurse -erroraction SilentlyContinue | tee-object -Append -FilePath $filename
Get-ChildItem -path "C:\Program Files\Mozilla Firefox\plugins\" -recurse -erroraction SilentlyContinue | tee-object -Append -FilePath $filename
Get-ChildItem -path registry::HKLM\SOFTWARE\Mozilla\*\extensions | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Edge History") -ItemType "file"
Write-Output "************EDGE HISTORY************ `n" | tee-object -Append -FilePath $filename
#edge history 
Get-ChildItem -Path C:\Users\*\AppData\Local\Packages\ -recurse -erroraction SilentlyContinue | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_internet Explorer History") -ItemType "file"
Write-Output "************Internet Explorer History************ `n" | tee-object -Append -FilePath $filename
#Internet Explorer
Get-ChildItem -path "C:\Program Files\Internet Explorer\Plugins\" -recurse -erroraction SilentlyContinue | tee-object -Append -FilePath $filename
reg query 'HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects' | tee-object -Append -FilePath $filename
reg query 'HKLM\Software\Microsoft\Internet Explorer\Toolbar' | tee-object -Append -FilePath $filename
reg query 'HKLM\Software\Microsoft\Internet Explorer\URLSearchHooks' | tee-object -Append -FilePath $filename
reg query 'HKLM\Software\Microsoft\Internet Explorer\Explorer Bars' | tee-object -Append -FilePath $filename
reg query 'HKU\{SID}\Software\Microsoft\Internet Explorer\Explorer Bars' | tee-object -Append -FilePath $filename
reg query 'HKLM\SOFTWARE\Microsoft\Internet Explorer\Extensions' | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_DLL Search Order Hijacking") -ItemType "file"
Write-Output "************DLL SEARCH ORDER HIJACKING************ `n" | tee-object -Append -FilePath $filename
#DLL Search order Hijacking
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" | tee-object -Append -FilePath $filename
Get-ChildItem -path C:\Windows\* -include *.dll | Get-AuthenticodeSignature | Where-Object Status -NE "Valid" | tee-object -Append -FilePath $filename
Get-ChildItem -path C:\Windows\System32\* -include *.dll | Get-AuthenticodeSignature | Where-Object Status -NE "Valid" | tee-object -Append -FilePath $filename
Get-Process | Format-List ProcessName, @{l="Modules";e={$_.Modules|Out-String}} | tee-object -Append -FilePath $filename
Get-Process | Where-Object {$_.Modules -like '*{DLLNAME}*'} | Format-List ProcessName, @{l="Modules";e={$_.Modules|Out-String}} | tee-object -Append -FilePath $filename
$dll = Get-Process | Where-Object {$_.Modules -like '*{DLLNAME}*' } | Select-Object Modules;$dll.Modules | tee-object -Append -FilePath $filename
(Get-Process).Modules.FileName | tee-object -Append -FilePath $filename
(Get-Process).Modules | Format-List FileName,FileVersionInfo | tee-object -Append -FilePath $filename
(Get-Process).Modules.FileName | get-authenticodesignature | Where-Object Status -NE "Valid" | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Unsigned Executables") -ItemType "file"
Write-Output "************UNSIGNED EXECUTABLES************ `n" | tee-object -Append -FilePath $filename
#Check for unsigned executables
Get-ChildItem C:\windows\*\*.exe -File -force |get-authenticodesignature|Where-Object{$_.IsOSBinary -notmatch 'True'} (Get-Process).Modules | Format-List FileName,FileVersionInfo

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_User Opened Files") -ItemType "file"
Write-Output "************USER OPENED FILES************ `n" | tee-object -Append -FilePath $filename
# which files did the user open?
Get-ChildItem "REGISTRY::HKU\*\Software\Microsoft\Office\*\Word\Reading Locations\*" (Get-Process).Modules | Format-List FileName,FileVersionInfo

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Files Without Extensions") -ItemType "file"
Write-Output "************FILES WITHOUT EXTENSIONS************ `n" | tee-object -Append -FilePath $filename
#files WITHOUT extensions
Get-ChildItem -Path C:\Users\[user]\AppData -Recurse -Exclude *.* -File -Force -ea SilentlyContinue  | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Persitent WMI Subscriptions") -ItemType "file"
Write-Output "************PERSISTENT WMI SUBSCRIPTIONS************ `n" | tee-object -Append -FilePath $filename
# show persistenT WMI subscriptions
Get-WmiObject -Class __FilterToConsumerBinding -Namespace root\subscription | tee-object -Append -FilePath $filename
Get-WmiObject -Class __EventFilter -Namespace root\subscription | tee-object -Append -FilePath $filename
Get-WmiObject -Class __EventConsumer -Namespace root\subscription | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Check For Mimikatz") -ItemType "file"
Write-Output "************CHECK FOR MIMIKATZ************ `n" | tee-object -Append -FilePath $filename
#check for Mimikatz
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest | tee-object -Append -FilePath $filename
Write-Output "UseLogonCredential should be 0 to prevent the password in LSASS/WDigest `n"  | Tee-Object -Append -FilePath $filename
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa | tee-object -Append -FilePath $filename
Write-Output "RunAsPPL should be set to dword:00000001 to enable LSA Protection which prevents non-protected processes from interacting with LSASS `n" | tee-object -Append -FilePath $filename
#Mimikatz can remove these flags using a custom driver called mimidriver.
#This uses the command **!+** and then **!processprotect /remove /process:lsass.exe** by default so tampering of this registry key can be indicative of Mimikatz activity.
tasklist /m wdigest.dll | tee-object -Append -FilePath $filename
tasklist /m lsasrv.dll | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_WLAN Info") -ItemType "file"
Write-Output "************PREVIOUS CONNECTED AND LOCAL WIFI WLANS************ `n" | tee-object -Append -FilePath $filename
#show previous connected and local wifi wlans
netsh wlan show profile | tee-object -Append -FilePath $filename
netsh wlan show network mode=bssid | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Named Pipes") -ItemType "file"
Write-Output "************NAMED PIPES************ `n" | tee-object -Append -FilePath $filename
#show named pipes
[System.IO.Directory]::GetFiles("\\.\\pipe\\") | tee-object -Append -FilePath $filename
get-childitem \\.\pipe\ | tee-object -Append -FilePath $filename
Get-ChildItem \\.\pipe\\ | tee-object -Append -FilePath $filename

#MOVE TO NETWORK
#list of RDP connections if any
Get-WinEvent -Log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' | Select-Object -exp Properties | Where-Object {$_.Value -like '*.*.*.*' } | Sort-Object Value -u | tee-object -Append -FilePath $filename

#MOVE TO LOGS
#powershell logs
Get-WinEvent -LogName "Windows Powershell" | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_PSEXEC Lateral Movement") -ItemType "file"
Write-Output "************PSEXEC LATERAL MOVEMENT************ `n" | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='2'} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5140'; Data='\\*\ADMIN$'} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045'; Data='PSEXESVC'} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
reg query HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC | tee-object -Append -FilePath $filename
reg query HKLM\SYSTEM\CurrentControlSet\Services\ | tee-object -Append -FilePath $filename
Get-ChildItem C:\Windows\Prefetch\psexesvc.exe*.pf | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Binary file version OS comparison") -ItemType "file"
Write-Output "************BINARY FILE VERSION AND OS RELEASE COMPARISON************ `n" | tee-object -Append -FilePath $filename
#binary file version and OS release comparison
Get-Process -FileVersionInfo -ea 0|Where-Object {$_.ProductVersion -notmatch $([System.Environment]::OSVersion.Version|Select-Object -exp Build)} | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 


$filename = New-Item -Path $holdPath -Name ($folderName + "_Windows Defender Exclusions") -ItemType "file"
Write-Output "************WINDOWS DEFENDER EXCLUSIONS************ `n" | tee-object -Append -FilePath $filename
#CHECK Windows Defender for excluded files
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions" /s | tee-object -Append -FilePath $filename
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions' | tee-object -Append -FilePath $filename
Get-MpPreference | Select-Object Exclusion* | tee-object -Append -FilePath $filename
Get-MpPreference | Select-Object *DefaultAction | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Hash All Executables") -ItemType "file"
Write-Output "************HASH ALL EXECUTABLES************ `n" | tee-object -Append -FilePath $filename
#GRAB ALL THE HASHES 
cmd.exe /c FOR /F %i IN ('wmic process where "ExecutablePath is not null" get ExecutablePath') DO certutil -hashfile %i SHA256 | findstr -v : | tee-object -Append -FilePath $filename

#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_EasyHook Injection Check") -ItemType "file"
Write-Output "************EASYHOOK INJECTION CHECK************ `n" | tee-object -Append -FilePath $filename
#Finding easyhook injection
tasklist /m EasyHook32.dll;tasklist /m EasyHook64.dll;tasklist /m EasyLoad32.dll;tasklist /m EasyLoad64.dll | tee-object -Append -FilePath $filename
#Check common directories for unsual files
cmd.exe /c dir /s /b %localappdata%\*.exe | findstr /e .exe | tee-object -Append -FilePath $filename
cmd.exe /c dir /s /b %appdata%\*.exe | findstr /e .exe | tee-object -Append -FilePath $filename
cmd.exe /c dir /s /b %localappdata%\*.dll | findstr /e .dll | tee-object -Append -FilePath $filename
cmd.exe /c dir /s /b %appdata%\*.dll | findstr /e .dll | tee-object -Append -FilePath $filename
cmd.exe /c dir /s /b %localappdata%\*.bat | findstr /e .bat | tee-object -Append -FilePath $filename
cmd.exe /c dir /s /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\" | findstr /e .lnk | tee-object -Append -FilePath $filename
cmd.exe /c dir /s /b "C:\Users\Public\" | findstr /e .exe | tee-object -Append -FilePath $filename
cmd.exe /c dir /s /b "C:\Users\Public\" | findstr /e .lnk | tee-object -Append -FilePath $filename
cmd.exe /c dir /s /b "C:\Users\Public\" | findstr /e .dll | tee-object -Append -FilePath $filename
cmd.exe /c dir /s /b "C:\Users\Public\" | findstr /e .bat | tee-object -Append -FilePath $filename
cmd.exe /c ls "C:\Users\[User]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" | findstr /e .lnk | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Webshell Check") -ItemType "file"
Write-Output "************WEBSHELL CHECK************ `n" | tee-object -Append -FilePath $filename
#Webshell check
Get-ChildItem -path "C:\inetpub\wwwroot" -recurse -File -ea SilentlyContinue | Select-String -Pattern "runat" | Format-List | tee-object -Append -FilePath $filename
Get-ChildItem -path "C:\inetpub\wwwroot" -recurse -File -ea SilentlyContinue | Select-String -Pattern "eval" | Format-List | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Services Lateral Movement") -ItemType "file"
Write-Output "************SERVICES LATERAL MOVEMENT************ `n" | tee-object -Append -FilePath $filename
#services lateral movement detection
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4697';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7034';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7035';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7036';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7040';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
reg query 'HKLM\SYSTEM\CurrentControlSet\Services\' | tee-object -Append -FilePath $filename



#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_WMI/WMIC Lateral Movement") -ItemType "file"
Write-Output "************WMI/WMIC LATERAL MOVEMENT************ `n" | tee-object -Append -FilePath $filename
#WMI/WMIC lateral movement
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | Format-Listrmat-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Id='5857';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Id='5860';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Id='5861';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
C:\Windows\System32\wbem\Repository | tee-object -Append -FilePath $filename
Get-ChildItem C:\Windows\Prefetch\wmiprvse.exe*.pf | tee-object -Append -FilePath $filename
Get-ChildItem C:\Windows\Prefetch\mofcomp.exe*.pf | tee-object -Append -FilePath $filename



#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 
$filename = New-Item -Path $holdPath -Name ($folderName + "_Powershell Lateral Movement") -ItemType "file"
Write-Output "************POWERSHELL LATERAL MOVEMENT************ `n" | tee-object -Append -FilePath $filename
#PowerShell Lateral Movement Detection
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id='4103';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id='4104';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id='53504';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Windows PowerShell'; Id='400';} | Format-Listrmat-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Windows PowerShell'; Id='403';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WinRM/Operational'; Id='91';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WinRM/Operational'; Id='168';} | Format-List TimeCreated,Message | tee-object -Append -FilePath $filename
Get-ChildItem C:\Windows\Prefetch\wsmprovhost.exe*.pf | tee-object -Append -FilePath $filename



#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_Webcam and Microphone usage") -ItemType "file"
Write-Output "************PROGRAMS USING WEBCAM AND MICROPHONE************ `n" | tee-object -Append -FilePath $filename

#programs using webcam and microphone
$a=$(Get-ChildItem-ChildItem REGISTRY::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam -Select-ObjSelect-Object Select PSChildName | Out-String);$a.replace("#","\") | tee-object -Append -FilePath $filename
$a=$(Get-ChildItem REGISTRY::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone -recurse | Select-Object PSChildName | Out-String);$a.replace("#","\") | tee-object -Append -FilePath $filename


#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 

$filename = New-Item -Path $holdPath -Name ($folderName + "_User Registry keys") -ItemType "file"
Write-Output "************LOCATE USER REGISTRY KEYS************ `n" | tee-object -Append -FilePath $filename
#locate USER registry keys
$UserProfiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where-Object {$_.PSChildName -match "S-1-5-21-(\d+-?){4}$" } | Select-Object @{Name="SID"; Expression={$_.PSChildName}}, @{Name="UserHive";Expression={"$($_.ProfileImagePath)\ntuser.dat"}} | tee-object -Append -FilePath $filename
$UserProfiles



#Call the zipcleaner function to compress and rename the file output
Get-ZippedCleaner 


#CLEAN UP THE MESS!

#compress the resulting folder with all files inside
Set-Location ..
$holdPath2 = Get-Location
$holdPath2 = ($holdPath2.Path + "\" + $folderName)
$zippy = ($folderName + ".zip")
Compress-Archive -Path $holdPath2 -DestinationPath .\$zippy

remove-item $folderName -Recurse

#uninstall PowerForensics
Uninstall-Module -Name PowerForensics