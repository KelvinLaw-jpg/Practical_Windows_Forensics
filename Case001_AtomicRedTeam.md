# Atomic Red Team Attack Script

Project Brief: This project is to set up a win 10 virtual machine as a target, attack it using the attomic red team attack script. Simulate that we are a Forensic Analyst just arriving to the site 
and proceed with a full Windows Forensics project as we would on field. Finishing with a deacted forensic report at the end.

Below are the attacks that this script has executed:
![ART](images/PWF_Analysis-MITRE.png)

Tools used:
- EZTools
- Volitility
- KAPE
- Autopsy
- RegRipper
- Arsenal Image Mounter

### Collection

**Order of collection should always follow the order of volitility**
**Step 1**: In real life we will either take a live Data from the machine or put the machine into hibernation so we can collect the data from the memory through hiber.sys file on windows. All this should be done
with a write blocker. In the VM now, we will suspend the VM first. Since I am using VMware, I will preserve the .vmem and the .vmsn and hash it. Next we will collect the disk by using qemu-img by running 
`qemu-img.exe convert -O vpc <full path that contains vmdk> output_image.vhd`. Hashes will be generated after all this. In real life, all this should be done with FTK Imager instead. 

List of artifacts to collect and examine

Disk Analysis Process: 
- System & Usesr Info
   - Registry
- File Analysis
   - NTFS
- Evidence of Execution
   - Background Activity Moderator
   - ShimCache
   - Amcache
   - Prefetch
- Persistence Mechanisms
   - Run Keys
   - Startup Folder
   - Scheduled Tasks
   - Services
- Event Log Analysis

## System Information

Computername: 
Registry: HKLM\System\CurrentControlSet\Control\Computername\

`DESKTOP-BBERDPP`

Windows Version: 
Registry: HKLM\Software\Microsoft\Windows NT\Currentversion\

```
ProductName               Windows 10 Enterprise Evaluation
ReleaseID                 2009
BuildLab                  19041.vb_release.191206-1406
BuildLabEx                19041.1.amd64fre.vb_release.191206-1406
CompositionEditionID      EnterpriseEval
RegisteredOrganization
RegisteredOwner           PWF_Victim
UBR                       2006
InstallDate               2025-05-28 19:20:00Z
InstallTime               2025-05-28 19:20:00Z
UBR                       2006
```

Timezone:
Registry: HKLM\System\CurrentControlSet\Control\TimeZoneInformation\

```
TimeZoneInformation key
ControlSet001\Control\TimeZoneInformation
LastWrite Time 2025-05-29 04:17:17Z
  DaylightName   -> @tzres.dll,-211
  StandardName   -> @tzres.dll,-212
  Bias           -> 480 (8 hours)
  ActiveTimeBias -> 420 (7 hours)
  TimeZoneKeyName-> Pacific Standard Time

Network Information: 
Registry: HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{interface-name}
```

```
Adapter: {3b4cb90d-57a4-4414-8c13-e6ca6904c4d8}
LastWrite Time: 2025-05-28 19:27:50Z
  EnableDHCP                   1
  Domain
  NameServer
  DhcpIPAddress                192.168.65.150
  DhcpSubnetMask               255.255.255.0
  DhcpServer                   192.168.65.254
  Lease                        1800
  LeaseObtainedTime            2025-05-28 19:27:50Z
  T1                           2025-05-28 19:42:50Z
  T2                           2025-05-28 19:54:05Z
  LeaseTerminatesTime          2025-05-28 19:57:50Z
  AddressType                  0
  IsServerNapAware             0
  DhcpConnForceBroadcastFlag   0
  DhcpDomain                   localdomain
  DhcpNameServer               192.168.65.2
  DhcpDefaultGateway           192.168.65.2
  DhcpSubnetMaskOpt            255.255.255.0
```

```
Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles
Network
  Key LastWrite    : 2025-05-28 19:33:52Z
  DateLastConnected: 2025-05-28 12:33:52
  DateCreated      : 2025-05-28 20:19:54
  DefaultGatewayMac: 00-50-56-FB-B6-EB
  Type             : wired
```

Shutdown time: 
Registry: HKLM\System\ControlSet001\Control\Windows\ShutdownTime
```
ControlSet001\Control\Windows key, ShutdownTime value
LastWrite time: 2025-05-28 19:42:04Z
ShutdownTime  : 2025-05-28 19:42:04Z
```

Defender settings:
Registry: HKLM\Software\Microsoft\Windows Defender\

```
defender v.20200427
(Software) Get Windows Defender settings
Key path: Microsoft\Windows Defender
LastWrite Time 2025-05-28 19:27:26Z
Key path: Microsoft\Windows Defender\Exclusions\Paths
Key path: Microsoft\Windows Defender\Exclusions\Extensions
Key path: Microsoft\Windows Defender\Exclusions\Processes
Key path: Microsoft\Windows Defender\Exclusions\TemporaryPaths
Key path: Microsoft\Windows Defender\Exclusions\IpAddresses
Key path: Microsoft\Windows Defender\Features
TamperProtection value = 1
If TamperProtection value = 1, it's disabled
Key path: Microsoft\Windows Defender\Spynet
LastWrite Time: 2025-05-28 19:41:34Z
Spynet\SpynetReporting value = 2
Spynet\SubmitSamplesConsent value = 1
Key path: Microsoft\Windows Defender\Real-Time Protection
LastWrite Time: 2025-05-29 03:17:40Z
Key path: Policies\Microsoft\Windows Defender
LastWrite Time 2025-05-28 19:41:33Z
Key path: Policies\Microsoft\Windows Defender\Exclusions\Paths
Key path: Policies\Microsoft\Windows Defender\Exclusions\Extensions
Key path: Policies\Microsoft\Windows Defender\Exclusions\Processes
Key path: Policies\Microsoft\Windows Defender\Exclusions\TemporaryPaths
Key path: Policies\Microsoft\Windows Defender\Exclusions\IpAddresses
DisableAntiSpyware value = 1
Key path: Policies\Microsoft\Windows Defender\Real-Time Protection
LastWrite Time: 2025-05-28 19:41:33Z
DisableRealtimeMonitoring value = 1
```

## Users, Groups, User Profiles

| User ID | User Name         | Created On           | Last Login Time       | Last Password Change  | Total Login Count | Groups                   | Comment                                                              | Account Disabled | Password Not Required | Normal User Account | Password Does Not Expire |
|---------|-------------------|----------------------|------------------------|------------------------|-------------------|--------------------------|----------------------------------------------------------------------|------------------|------------------------|----------------------|---------------------------|
| 500     | Administrator     | 2025-05-28 19:19:59  |                        |                        | 0                 | Administrators           | Built-in account for administering the computer/domain              | TRUE             | FALSE                  | TRUE                 | TRUE                      |
| 501     | Guest             | 2025-05-28 19:19:59  |                        |                        | 0                 | Guests                   | Built-in account for guest access to the computer/domain            | TRUE             | TRUE                   | TRUE                 | TRUE                      |
| 503     | DefaultAccount    | 2025-05-28 19:19:59  |                        |                        | 0                 | System Managed Accounts Group | A user account managed by the system                          | TRUE             | TRUE                   | TRUE                 | TRUE                      |
| 504     | WDAGUtilityAccount| 2025-05-28 19:19:59  |                        | 2025-05-29 03:17:24    | 0                 |                          | Managed by the system for Windows Defender App Guard               | TRUE             | FALSE                  | TRUE                 | FALSE                     |
| 1001    | PWF_Victim        | 2025-05-28 19:22:51  | 2025-05-28 19:42:31    | 2025-05-28 19:22:51    | 5                 | Administrators           |                                                                      | FALSE            | TRUE                   | TRUE                 | TRUE                      |
| 1002    | art-test          | 2025-05-28 19:47:16  |                        | 2025-05-28 19:47:16    | 0                 | Administrators, Users    |                                                                      | FALSE            | FALSE                  | TRUE                 | FALSE                     |

**Active accounts during the attack timeframe?**
In reg explorer, we see that the account has a last login time at Wed May 28 19:42:31, which shows that it is highly likely that this is the account being compromised.

```
Username        : PWF_Victim [1001]
SID             : S-1-5-21-247958990-3900953996-3769339170-1001
Full Name       : 
User Comment    : 
Account Type    : 
Account Created : Wed May 28 19:22:50 2025 Z
Security Questions:
    Question 1  : What was your first pet’s name?
    Answer 1    : dsf
    Question 2  : What was your childhood nickname?
    Answer 2    : dsaf
    Question 3  : What’s the name of the first school you attended?
    Answer 3    : dsaf
Name            :  
Last Login Date : Wed May 28 19:42:31 2025 Z
Pwd Reset Date  : Wed May 28 19:22:51 2025 Z
Pwd Fail Date   : Never
Login Count     : 5
  --> Password does not expire
  --> Password not required
  --> Normal user account
```

**Which account(s) were created?**

art-test, created during the time frame and has 0 login. Administrator account is usually a target, however, it has a 0 login here and is also disabled. 
Which demonstates good security practice.

**Which accounts are Administrator group members?**

PWF_Victim [1001], art-test [1002]

**Which users have profiles?**

```
Path      : C:\Users\PWF_Victim
SID       : S-1-5-21-247958990-3900953996-3769339170-1001
LastWrite : 2025-05-28 19:42:01Z
```

## User Behavior

**Active accounts during the attack timeframe?**
UserAssist:
NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist

```
{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA} – a list of app, files, links, and other objects that have been accessed.
2025-05-28 19:44:35Z
  Microsoft.Windows.Explorer (11)
2025-05-28 19:42:38Z
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\notepad.exe (2)
2025-05-28 19:42:35Z
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe (2)
2025-05-28 19:38:54Z
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\mmc.exe (1)
2025-05-28 19:33:07Z
  MSEdge (1)
2025-05-28 19:26:24Z
  D:\setup64.exe (1)
2025-05-28 19:25:46Z
  D:\setup.exe (1)
2025-05-28 19:21:34Z
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\SnippingTool.exe (9)
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\mspaint.exe (7)

Value names with no time stamps:
  C:\$WINDOWS.~BT\Sources\SetupHost.exe
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe

{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F} – Lists the shortcut links used to start programs. The crono order if earlist at bottom and latest to the top.
2025-05-28 19:44:35Z
  {9E3995AB-1F9C-4F13-B827-48B24B6C7174}\TaskBar\File Explorer.lnk (6)
2025-05-28 19:42:35Z
  {A77F5D77-2E2B-44C3-A6A2-ABA601054A51}\System Tools\Command Prompt.lnk (2)
2025-05-28 19:21:34Z
  {0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Accessories\Snipping Tool.lnk (9)
  {0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Accessories\Paint.lnk (7)
```

From the above, we see that within the time frame of 2025-05-28 19:20, the following programs have been accessed: powershell, cmd, paint, mmc, notepad, snipping tool.

RecentDocs (store something interacted recently with user):
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Exploere\RecenDocs\

```
recentdocs v.20200427
(NTUSER.DAT) Gets contents of user's RecentDocs key

RecentDocs
**All values printed in MRUList\MRUListEx order.
Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
LastWrite Time: 2025-05-28 19:42:38Z
  5 = New Text Document.txt
  0 = The Internet
  4 = threat/
  3 = Network and Internet
  2 = ::{8E908FC9-BECC-40F6-915B-F4CA0E70D03D}
  1 = network

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.com/search?q=network+discovery&form=WNSGPH&qs=OS&cvid=1065b9c5d2b6474f9945e48741f295fe&pq=nnetwork+discovery&cc=US&setlang=en-US&nclid=A30A34DCE1B5359F031D07AC889D52AA&ts=1748460786948&nc
LastWrite Time 2025-05-28 19:33:07Z
MRUListEx = 

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt
LastWrite Time 2025-05-28 19:42:38Z
MRUListEx = 0
  0 = New Text Document.txt

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\Folder
LastWrite Time 2025-05-28 19:37:25Z
MRUListEx = 0,1
  0 = The Internet
  1 = Network and Internet
```

ShellBags:
To do with windows explorers and windows, they can be under: 
NTUSER.DAT:
HKCU\Software\Microsoft\Windows\Shell\BagMRU
HKCU\Software\Microsoft\Windows\Shell\Bags

USRCLASS.DAT:
Local Settings\Software\Microsoft\Windows\Shell\BagMRU
Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags

```
shellbags v.20200428
(USRCLASS.DAT) Shell/BagMRU traversal in Win7+ USRCLASS.DAT hives

MRU Time             |Modified             | Accessed             | Created              | Zip_Subfolder        | MFT File Ref |Resource
------------         |------------         | ------------         | ------------         | ------------         | ------------ |------------
                     |                     |                      |                      |                      |              |My Games [Desktop\0\]
                     |                     |                      |                      |                      |              |My Computer [Desktop\1\]
2025-05-28 19:26:18  |                     |                      |                      |                      |              |My Computer\D:\ [Desktop\1\0\]
                     |                     |                      |                      |                      |              |My Network Places [Desktop\2\]
2025-05-28 19:34:18  |                     |                      |                      |                      |              |Control Panel [Desktop\3\]
2025-05-28 19:34:08  |                     |                      |                      |                      |              |Control Panel\Network and Internet [Desktop\3\0\]
                     |                     |                      |                      |                      |              |Control Panel\Network and Internet\CLSID_Network Connections [Desktop\3\0\0\]
2025-05-28 19:34:07  |                     |                      |                      |                      |              |Control Panel\Network and Internet\CLSID_Network and Sharing Center [Desktop\3\0\1\]
2025-05-28 19:34:18  |                     |                      |                      |                      |              |Control Panel\Network and Internet\CLSID_Network and Sharing Center\Advanced sharing settings [Desktop\3\0\1\0\]
```
## NTFS - File System Analysis

We will parse the file with the following command `MFTECmd.exe -f <the mft we want to parse> --csv <Full path that we wanna store the CSV> --csvf <name of csv eg: MFT.csv>`

**Which files are related to AtomicRedTeam?**
- Invoke-AtomicRedTeam.psd1
- Invoke-AtomicRedTeam.psm1
- AtomicClassSchema.ps1
- Get-AtomicTechnique.ps1
- ART-attack.ps1

**What is the MFT Entry Number for the file "ART-attack.ps1"?**



To see the full file,we can `MFTECmd.exe -f <MFT> --de <Entry Number>` and we will see the metadata of that file entry
```
**** STANDARD INFO ****
  Attribute #: 0x0, Size: 0x60, Content size: 0x48, Name size: 0x0, ContentOffset 0x18. Resident: True
  Flags: Archive, Max Version: 0x0, Flags 2: None, Class Id: 0x0, Owner Id: 0x0, Security Id: 0x6B8, Quota charged: 0x0, Update sequence #: 0xB2C5A8

  Created On:         2025-05-28 19:42:44.7804853
  Modified On:        2025-05-28 19:42:44.7804853
  Record Modified On: 2025-05-28 19:43:14.4523418
  Last Accessed On:   2025-05-28 19:42:44.7804853

**** FILE NAME ****
  Attribute #: 0x6, Size: 0x78, Content size: 0x5A, Name size: 0x0, ContentOffset 0x18. Resident: True

  File name: ART-AT~1.PS1
  Flags: Archive, Name Type: Dos, Reparse Value: 0x0, Physical Size: 0x1000, Logical Size: 0xD20
  Parent Entry-seq #: 0x191D1-0x1

  Created On:         2025-05-28 19:42:44.7804853
  Modified On:        2025-05-28 19:42:44.7804853
  Record Modified On: 2025-05-28 19:42:44.7804853
  Last Accessed On:   2025-05-28 19:42:44.7804853
```

**What are the MACB timestamps for "ART-attack.ps1"?**
| Event             | Flag | Timestamp                     |
|-------------------|------|-------------------------------|
| Modified | m... | 2025-05-28 19:43:14.4523418 |
| Accessed | .a.. | 2025-05-28 19:42:44.7804853 |
| Changed ($MFT) | ..c. | 2025-05-28 19:43:14.4523418 |
| Birth (Creation) | ...b | 2025-05-28 19:42:44.7804853 |

**Was "ART-attack.ps1" timestomped?**

Since all the time in MAC(b) is very similar, it is unlikely that the MFT had been modified. (Even if the time isn't exactly the same, if they are close to each other, it might still be genuine. Since a file inherits the FN time from the zip file.)

**When was the file "deleteme_T1551.004" created and deleted?**

![image](https://github.com/user-attachments/assets/b4072d72-d5c3-44b5-ab86-2d2487dba6c9)

![image](https://github.com/user-attachments/assets/d4800b79-7dbe-46d2-bd65-e6526c8f93f3)

 ```
  Attribute #: 0x2, Size: 0x80, Content size: 0x66, Name size: 0x0, ContentOffset 0x18. Resident: True

  File name: deleteme_T1551.004
  Flags: Archive, Name Type: Windows, Reparse Value: 0x0, Physical Size: 0x0, Logical Size: 0x0
  Parent Entry-seq #: 0x191E6-0x1

  Created On:         2025-05-28 19:48:30.7159520
  Modified On:        2025-05-28 19:48:30.7159520
  Record Modified On: 2025-05-28 19:48:30.7159520
  Last Accessed On:   2025-05-28 19:48:30.7159520
```

We can check the $J for file creation, close and deletion. As shown in image, it was deleted in 2025-05-28 19:48:37

**What was the Entry number for "deleteme_T1551.004" and does it still exist in the MFT?**

102492 and since it is FLAGed `IsFree`, it has been deleted. But not overwrited by new files, so might still exist in memory.

## Execution Artifacts

Background Activity Moderator (BAM)
Registry: HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings

**Which executables (.exe files) did the BAM record for the IEUser (RID 1000) incl. their last execution date and time?**
```
S-1-5-21-247958990-3900953996-3769339170-1001
  2025-05-28 19:42:01Z - Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy
  2025-05-28 19:42:01Z - \Device\HarddiskVolume3\Windows\explorer.exe
  2025-05-28 19:42:01Z - Microsoft.Windows.Search_cw5n1h2txyewy
  2025-05-28 19:42:01Z - Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy
  2025-05-28 19:42:00Z - \Device\HarddiskVolume3\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
  2025-05-28 19:42:01Z - MicrosoftWindows.Client.CBS_cw5n1h2txyewy
  2025-05-28 19:26:31Z - \Device\HarddiskVolume3\Windows\Temp\{A08E84A9-A757-4778-AD42-13439F2A43EF}\.cr\vcredist_x86.exe
  2025-05-28 19:26:34Z - \Device\HarddiskVolume3\Windows\Temp\{B9033729-81BF-4656-B974-E3D5315CBE85}\.cr\vcredist_x64.exe
  2025-05-28 19:42:00Z - \Device\HarddiskVolume3\Program Files\VMware\VMware Tools\vmtoolsd.exe
  2025-05-28 19:41:56Z - \Device\HarddiskVolume3\Windows\System32\cmd.exe
  2025-05-28 19:42:01Z - \Device\HarddiskVolume3\Windows\System32\ApplicationFrameHost.exe
  2025-05-28 19:42:01Z - Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe
  2025-05-28 19:35:09Z - windows.immersivecontrolpanel_cw5n1h2txyewy
  2025-05-28 19:37:30Z - Microsoft.Windows.SecHealthUI_cw5n1h2txyewy
  2025-05-28 19:41:36Z - \Device\HarddiskVolume3\Windows\System32\mmc.exe
  2025-05-28 19:41:55Z - \Device\HarddiskVolume3\Windows\System32\notepad.exe
```

**Determine the cache entry position for:** 
- AtomicService.exe: 24
- mavinject.exe: 23

**What SHA-1 hash did Amcache record for AtomicService.exe?**
Very interesting thing for trouble shooting, if we check the Amcache we got. There would be no Atomic services. After a bit of digging, I found that the Amcache
 is updated by the Microsoft Compatibility Appraiser Schedule Task Detail Blog post: https://dfir.ru/2018/12/02/the-cit-database-and-the-syscache-hive/

 So to get what we want, we have to revert the VM to freshly compromised and execute this schtask. Then we will see the atomic service and it's hash:
 `c51217ce3d1959e99886a567d21d0b97022bd6e3`

**Prefetch: Use the Prefetch-Timeline output to produce a timeline of suspicious execution events in the Eric Zimmerman Timeline Explorer:**
POWERSHELL.exe
cmd.exe
NET.exe
REG.exe
SCHTASKS.exe
SC.exe
ATOMICSERVICE.EXE
MAVINJECT.exe
NOTEPAD.exe

Shortcut (LNK) Files
Path: C:\users\<username>\AppData\Roaming\Microsoft\Windows\Recent
Path: C:\users\<username>\AppData\Roaming\Microsoft\Office\Recent

## Persistence Mechanisms

**What is the full path of the AtomicService.exe that was added to the run keys?**
```
Software\Microsoft\Windows\CurrentVersion\Run
LastWrite Time 2025-05-28 19:47:24Z
  MicrosoftEdgeAutoLaunch_146C45B6908C4329765758A943921973 - "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window --win-session-start
  OneDrive - "C:\Users\PWF_Victim\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
  Atomic Red Team - C:\Path\AtomicRedTeam.exe
```

Path file was deleted. 

**What is the name of the suspicious script in the StartUp folder?**
In the KAPE TRIAGE package, we also found nothing. However, we can have a look in the MFT.csv

batstartup.bat

**When was the suspicious atomic service installed?**

2025-05-28 19:47:34

**Which tasks were created by the IEUser and what's the creation time?**
```
Path: \T1053_005_OnLogon
URI : \T1053_005_OnLogon
Task Reg Time : 2025-05-28 19:47:32Z
Task Last Run : 2025-06-02 08:27:49Z
Task Completed: 2025-06-02 08:27:58Z
```

```
Path: \T1053_005_OnStartup
URI : \T1053_005_OnStartup
Task Reg Time : 2025-05-28 19:47:32Z
Task Last Run : 2025-06-02 08:27:48Z
Task Completed: 2025-06-02 08:27:57Z
```
**How many times did they execute?**
Never

## Windows Event Log Analysis

**Was Defender on?**

**What logins do we have during the time frame?**

below is base64 decoded string of event 400 from PS
Set-Content -path "$env:SystemRoot/Temp/art-marker.txt" -value "Hello from the Atomic Red Team"


## Memory Analysis

**PID of suspicious processes?**
powershell.exe		<PID>
notepad.exe		<PID>
AtomicService.exe	<PID>

**Suspicious registry key in HKCU?**
