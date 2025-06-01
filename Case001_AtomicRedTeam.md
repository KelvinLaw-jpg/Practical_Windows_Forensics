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

RecentDocs (store something interacted recently with user):
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Exploere\RecenDocs\

ShellBags:
To do with windows explorers and windows, they can be under: 
NTUSER.DAT:
HKCU\Software\Microsoft\Windows\Shell\BagMRU
HKCU\Software\Microsoft\Windows\Shell\Bags

USRCLASS.DAT:
Local Settings\Software\Microsoft\Windows\Shell\BagMRU
Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags

## NTFS - File System Analysis

**Which files are located in My Computer\CLSID_Desktop\PWF-main\PWF-main\AtomicRedTeam?**
`MFTECmd.exe -f <the mft we want to parse> --csv <Full path that we wanna store the CSV> --cdvf <name of csv eg: MFT.csv>`

**What is the MFT Entry Number for the file "ART-attack.ps1"?**
To see the full file,we can `MFTECmd.exe -f <MFT> --de <Entry Number>` and we will see the metadata of that file entry

**What are the MACB timestamps for "ART-attack.ps1"?**

**Was "ART-attack.ps1" timestomped?**

**When was the file "deleteme_T1551.004" created and deleted?**

**What was the Entry number for "deleteme_T1551.004" and does it still exist in the MFT?**

## Execution Artifacts

Background Activity Moderator (BAM)
Registry: HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings

**Which executables (.exe files) did the BAM record for the IEUser (RID 1000) incl. their last execution date and time?**

Determine the cache entry position for: 
•	AtomicService.exe: 
•	mavinject.exe: 

**What SHA-1 hash did Amcache record for AtomicService.exe?**

Prefetch: Use the Prefetch-Timeline output to produce a timeline of suspicious execution events in the Eric Zimmerman Timeline Explorer:
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

**What is the name of the suspicious script in the StartUp folder?**

**When was the suspicious atomic service installed?**

**Which tasks were created by the IEUser and what's the creation time?**

**How many times did they execute?**

## Windows Event Log Analysis

**Was Defender on?**

**What logins do we have during the time frame?**

## Memory Analysis

**PID of suspicious processes?**
powershell.exe		<PID>
notepad.exe		<PID>
AtomicService.exe	<PID>

**Suspicious registry key in HKCU?**
