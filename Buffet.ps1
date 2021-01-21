

<#
Windows Live Forensic Flight Plan for CyberDefenses
Written by Ethan Waters
Automated (poorly) by I.A. Wilds
1/21/21
#>

<# 
This script will run many windows forensics commands and then write them to a file that you are prompted to name.
The file can then be stored offline and searched by multiple analysts at once.
NOTE: COMMENT OUT ANY COMMNADS THAT YOU DO NOT NEED FOR YOUR INVESTIGATION#>




# Write-Output "Search by File Hash `n"
# you would need to get the hash as an input from the user
# Get-FileHash -Algorithm MD5 -ErrorAction silentlycontinue | Where-Object hash -eq <hash> | Select Path

$holdPath = Get-Location
$filename = read-host "what would you like to name your file? `n"



$rhino = @"
              _                 __                 
      __.--**"""**--...__..--**""""*-.            
    .'                                `-.         
  .'                         _           \        
 /                         .'        .    \   _._ 
:                         :          :`*.  :-'.' ;
;    `                    ;          `.) \   /.-' 
:     `                             ; ' -*   ;    
       :.    \           :       :  :        :    
 ;     ; `.   `.         ;     ` |  '             
 |         `.            `. -*"*\; /        :     
 |    :     /`-.           `.    \/`.'  _    `.   
 :    ;    :    `*-.__.-*""":`.   \ ;  'o` `. /   
       ;   ;                ;  \   ;:       ;:   ,/
  |  | |            [bug]      /`  | ,      `*-*'/ 
  `  : :  :                /  /    | : .    ._.-'  
   \  \ ,  \              :   `.   :  \ \   .'     
    :  *:   ;             :    |`*-'   `*+-*       
    `**-*`""               *---*

"@

Write-Host $rhino

$filename = ($holdPath.Path + "\" + $filename) 
($filename + "`n") | tee-object -Append -FilePath $filename

Write-Output "************System Hardware and Operating System Information************ `n" | tee-object -Append -FilePath $filename

wmic CPU get Caption,Name | tee-object -Append -FilePath $filename
wmic COMPUTERSYSTEM get UserName,Domain,WorkGroup,Manufacturer,Model,SystemType | tee-object -Append -FilePath $filename
wmic OS get BuildNumber,Caption,CSName,CurrentTimeZone,MUILanguages,Name,OSArchitecture /FORMAT:list | tee-object -Append -FilePath $filename
wmic BOOTCONFIG list brief | tee-object -Append -FilePath $filename

Write-Output "************Interfaces************ `n" | tee-object -Append -FilePath $filename

wmic NICCONFIG get Description,MACAddress,IPAddress | tee-object -Append -FilePath $filename
ipconfig /all | tee-object -Append -FilePath $filename

Write-Output "************System Patches************ `n" | tee-object -Append -FilePath $filename

wmic QFE list brief | tee-object -Append -FilePath $filename

Write-Output "************Installed Products************ `n" | tee-object -Append -FilePath $filename

wmic PRODUCT get LocalPackage,Description | tee-object -Append -FilePath $filename


Write-Output "************Network Connections************ `n" | tee-object -Append -FilePath $filename

netstat -anob | findstr LIST | tee-object -Append -FilePath $filename
netstat -anob | findstr ESTA | tee-object -Append -FilePath $filename
netstat -ay | findstr ESTA | tee-object -Append -FilePath $filename
powershell "Get-NetTCPConnection -State Established" | tee-object -Append -FilePath $filename
powershell "Get-NetTCPConnection -AppliedSetting Internet" | tee-object -Append -FilePath $filename

Write-Output "************Processes************ `n" | tee-object -Append -FilePath $filename

tasklist | tee-object -Append -FilePath $filename
wmic PROCESS get Name,ProcessId,ParentProcessId | tee-object -Append -FilePath $filename
wmic PROCESS list brief | tee-object -Append -FilePath $filename
powershell Get-Process | tee-object -Append -FilePath $filename
powershell "Get-Process | Select-Object -Property Id,Name,Company,Path" | tee-object -Append -FilePath $filename
powershell "Get-Process | Where Id -eq <pid> | Select *" | tee-object -Append -FilePath $filename

Write-Output "************Network Capable Modules************ `n" | tee-object -Append -FilePath $filename

tasklist /m wininet.dll | tee-object -Append -FilePath $filename
tasklist /m ws2_32.dll | tee-object -Append -FilePath $filename

Write-Output "************Active Shares************ `n" | tee-object -Append -FilePath $filename

wmic SHARE list brief | tee-object -Append -FilePath $filename
powershell Get-SmbShare | tee-object -Append -FilePath $filename
powershell "Get-WmiObject -class Win32_Share" | tee-object -Append -FilePath $filename
net share | tee-object -Append -FilePath $filename
net use | tee-object -Append -FilePath $filename
Write-Output "Running Services `n" | tee-object -Append -FilePath $filename

tasklist /SVC | tee-object -Append -FilePath $filename
wmic PROCESS where Name="svchost.exe" get CommandLine,ExecutablePath,ProcessId,ParentProcessId | tee-object -Append -FilePath $filename
wmic SERVICE list brief | tee-object -Append -FilePath $filename
wmic SERVICE where State="Running" get Caption,Description,DisplayName,Name,PathName, ProcessId,StartMode,StartName /FORMAT:list | tee-object -Append -FilePath $filename
wmic SERVICE where (State="Running" AND StartName="NT AUTHORITY\\NetworkService") get Caption,Description,DisplayName,Name,PathName,ProcessId,StartMode,StartName /FORMAT:list | tee-object -Append -FilePath $filename
sc query type= service | tee-object -Append -FilePath $filename
# sc query <service name>
# sc qc <service name>

Write-Output "************Startups************ `n" | tee-object -Append -FilePath $filename

wmic STARTUP get Command, User | tee-object -Append -FilePath $filename
wmic STARTUP list full /FORMAT:list | tee-object -Append -FilePath $filename
dir /a "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" | tee-object -Append -FilePath $filename
dir /a "c:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" | tee-object -Append -FilePath $filename
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run | tee-object -Append -FilePath $filename
reg query HCU\Software\Microsoft\Windows\CurrentVersion\Run | tee-object -Append -FilePath $filename
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce | tee-object -Append -FilePath $filename
reg query HCU\Software\Microsoft\Windows\CurrentVersion\RunOnce | tee-object -Append -FilePath $filename

Write-Output "************Scheduled Tasks************ `n" | tee-object -Append -FilePath $filename

powershell Get-ScheduledTask | tee-object -Append -FilePath $filename
schtasks /query /FO list | tee-object -Append -FilePath $filename
powershell "Get-ScheduledTask | Select-Object -Property TaskPath" | sort /unique | tee-object -Append -FilePath $filename

Write-Output "************Jobs************ `n" | tee-object -Append -FilePath $filename

wmic JOB list brief | tee-object -Append -FilePath $filename

Write-Output "************Drivers************ `n" | tee-object -Append -FilePath $filename
powershell "Get-WindowsDriver -Online" | tee-object -Append -FilePath $filename
sc query type= driver | tee-object -Append -FilePath $filename


Write-Output "************User Accounts************ `n" | tee-object -Append -FilePath $filename

wmic USERACCOUNT get Domain,Name,SID | tee-object -Append -FilePath $filename
powershell Get-LocalUser | tee-object -Append -FilePath $filename
powershell "Get-LocalUser | Select-Object -Property Name, SID" | tee-object -Append -FilePath $filename

net user | tee-object -Append -FilePath $filename
# net user <user>

Write-Output "************Groups************ `n" | tee-object -Append -FilePath $filename

wmic GROUP get Domain,Name,SID | tee-object -Append -FilePath $filename
net localgroup | tee-object -Append -FilePath $filename
# net localgroup <group>
net localgroup Administrators | tee-object -Append -FilePath $filename
net localgroup "Backup Operators" | tee-object -Append -FilePath $filename
net localgroup "Power Users" | tee-object -Append -FilePath $filename

Write-Output "************List of Event Logs************ `n" | tee-object -Append -FilePath $filename

wmic NTEVENTLOG get Name | tee-object -Append -FilePath $filename

Write-Output "************Logon Events************ `n" | tee-object -Append -FilePath $filename

powershell "Get-EventLog -logname Security -InstanceId
4611,4624,4625,4643,4648,4776,4778,4779 | Select-Object -Property TimeGenerated,InstanceId,Message" | tee-object -Append -FilePath $filename

Write-Output "************Alternate Data Streams************ `n" | tee-object -Append -FilePath $filename

powershell "Get-ChildItem | % { Get-Item $_.FullName -stream * } | where Stream -ne ':$Data'" | tee-object -Append -FilePath $filename

Write-Output "************Directory File and Listing************ `n" | tee-object -Append -FilePath $filename

Write-Output "************Search by File Type************ `n" | tee-object -Append -FilePath $filename
powershell "Get-ChildItem C:\ -include *.bat -recurse -ErrorAction silentlycontinue" | tee-object -Append -FilePath $filename
powershell "Get-ChildItem C:\ -include *.bat -recurse" | tee-object -Append -FilePath $filename


# The tree command works better through Powershell
# tree C:\Users | tee-object -Append -FilePath $filename
Get-ChildItem | tree | tee-object -Append -FilePath $filename

# This command is meant to show the time of creation of a file or directory
# it is a CMD command and not a powershell command
# dir /T:C C:\Users | tee-object -Append -FilePath $filename








