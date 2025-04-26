# Practical Windows Forensics project and write up

Project Brief: This project is to set up a win 10 virtual machine as a target, attack it using the attomic red team attack script. Simulate that we are a Forensic Analyst just arriving to the site 
and proceed with a full Windows Forensics project as we would on field. Finishing with a Forensic report at the end.

Tools used:
- EZTools
- Volitility
- KAPE


### NTFS Disk Analysis 

### Event log Analysis

Tools required: 
- [Event Log Explorer](https://eventlogxp.com/) (To view event logs)
- EvtxECmd-EZTools (Parse Event logs to csv files) and view with Timeline Explorer or Excel

**Notes**
- log location: c:\Windows\System32\winevt\logs
- Event log cheat sheet: [ultimatewindowssecurity](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j), [https://github.com/stuhli/awesome-event-ids?tab=readme-ov-file#event-id-documentation](https://github.com/stuhli/awesome-event-ids?tab=readme-ov-file#event-id-documentation)
- Important logs: security, system, sysmon
- New services event 7045 (malicious activities usually need to start new services)
- logon that is around the malicious activity time
- Tip: After finding the user associated with the malicious activity, search by the Logon ID of the user and creat a local timeline

---
**Key Event IDs to look at**
5000 Defender enabled
5001 Defender disabled
7045 A new service was installed
4624 An account was successfully logged on
400 A new PowerShell was initiated @ windows powershell log
4104 & 4103 Execute a remote command & executing pipeline @ Windows PowerShell Operational log

**Sysmon logs**
1 Process creation
3 Network connection
11 File create
12, 13 Registry Events
22 DNS query

---




### Memory Analysis with Volitility


### Super Timeline 

1. Creating the timeline


## Acknowledgements
 All materials used here go to:
 - [https://bluecapesecurity.com/getting-started/](https://bluecapesecurity.com/getting-started/)
