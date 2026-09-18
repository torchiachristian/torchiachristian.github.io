---
layout: writeup
lang: en
permalink: /en/writeups/investigating-windows/
title: "Investigating Windows"
ref: investigating-windows
date: 2026-09-01
bare: true
platform: THM
os: Windows Server 2016 Datacenter
difficulty: Easy
series: thm-windows
tags: [win, dfir, registry, event-log, wevtutil, persistence]
txt: /writeups-files/investigating-windows-en.txt
summary: "Machine already compromised, sixteen investigative questions. A .jsp webshell, renamed mimikatz, three persistence mechanisms and a poisoned hosts file."
---

# Writeup — Investigating Windows (TryHackMe)

OS: Windows Server 2016 Datacenter (build 14393)
Difficulty: Easy
Date: 13 September 2026

---

## Summary

a Windows machine already compromised, no exploitation to do: you get in over RDP with credentials provided by the room (Administrator / letmein123!) and work purely on system analysis to answer 16 investigative questions. there are no flags to collect, every answer is a different forensic parameter (OS version, accounts, logon times, scheduled tasks, run keys, dropped files, firewall rules, event logs, hosts file), and that's exactly the point of the room: to force you to touch sixteen different places where an attacker leaves traces, instead of giving you a single chain to follow.

the machine is an EC2 Windows Server 2016 with hostname EC2AMAZ-I8UH076. the attacker got in through a .jsp webshell uploaded into the IIS root, obtained elevated privileges, added Guest and Jenny to the local administrators, dumped the credentials with a renamed mimikatz, planted three persistence mechanisms independent of each other (a Run key, a scheduled task and a vbs script), opened two ports on the firewall and finally poisoned the hosts file to neutralise antivirus and updates and to hijack google.com to its own C2

---

## additional tools and methodology

an llm was used during the session: for looking up CVE details, interpreting raw output, suggesting unexplored vectors when stuck, detailed explanation of technical concepts and correcting syntax in long commands. the execution and the operational decisions were mine. the writeup was written by me and later cleaned up with the same tool.

for the syntax of the local enumeration commands and for the meaning of the event IDs I referred to the Microsoft documentation:
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/net-localgroup
https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672

---

## Preface

Kali virtualised on Linux Mint, TryHackMe VPN with sudo openvpn &#45;&#45;config ~/thm.ovpn and verification with ip a show tun0.

first snag before even starting: the RDP connection from my Kali never worked.

xfreerdp /v:10.112.158.69 /u:Administrator /p:'letmein123!' /cert:ignore /dynamic-resolution +clipboard
[ERROR][com.freerdp.core] - [get_next_addrinfo]: ERRCONNECT_CONNECT_FAILED [0x00020006]
[ERROR][com.freerdp.core.transport] - ConnectLayer 10.112.158.69:3389 [15000ms] failed

tun0 was up and with an assigned IP (192.168.134.214/18), so the VPN wasn't the issue. the machine simply wasn't answering on 3389 from outside, and I had to fall back on the TryHackMe in-browser VM for the whole session. this weighed far more than I expected: no copy-paste between host and target, so every command retyped by hand and every output reread on screen or through screenshots,with long XPath queries it's a serious problem, and on that virtual keyboard the curly braces and the asterisk weren't typeable at all, which blocked the log part for a while (detail in Phase 8).

the environment is that of a system already compromised and left dirty: on the desktop there was almost nothing except Wireshark installed and a text document with a dump of NTLM hashes in pwdump format, and in Network tsclient appeared.

Administrator:500:NO PASSWORD*********************:31D6CFE0D16AFA21B73C59D7E02A89C0:::
Guest:501:NO PASSWORD*********************:NO PASSWORD*********************:::
trinity:1002:NO PASSWORD*********************:A4A9436B46F7E948A2427335B6322C5C:::
HomeGroupUser$:1006:NO PASSWORD*********************:E37B4DD2729A37EB5C581C8B9D70153C:::

that file alone already says someone dumped the SAM, but the users listed (trinity, HomeGroupUser$) don't exist on this machine: it's output brought in from another host, not generated here. I noted it and set it aside, and in fact the confirmation of the tool used arrived later, from C:\TMP

---

## Phase 1 — Framing the system

systeminfo

Host Name:                 EC2AMAZ-I8UH076
OS Name:                   Microsoft Windows Server 2016 Datacenter
OS Version:                10.0.14393 N/A Build 14393
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
Original Install Date:     3/2/2019, 4:06:35 PM
System Boot Time:          9/13/2026, 12:25:12 PM
System Manufacturer:       Amazon EC2
Domain:                    WORKGROUP
Time Zone:                 (UTC) Coordinated Universal Time

first answer taken: Windows Server 2016 Datacenter.

two interesting things beyond the answer. the install date is 3/2/2019 at 16:06, that is the same day that will later turn out to be when the compromise happened: the machine was prepared and breached in the same afternoon, which explains why almost all the artefacts have closely grouped timestamps.
and the time zone is UTC, so all the log times are directly comparable without conversions, which simplifies the timeline.
the system is standalone in WORKGROUP, no domain: all user enumeration stays local.

---

## Phase 2 — Accounts and privileges

net user

Administrator    DefaultAccount    Guest
Jenny            John              ssm-user

six accounts. Administrator, Guest and DefaultAccount are built-in, ssm-user is the AWS Systems Manager account and on an EC2 it's normal. that leaves John and Jenny as created accounts.

net user John

User name                    John
Password last set            3/2/2019 5:48:19 PM
Last logon                   3/2/2019 5:48:32 PM
Local Group Memberships      *Users
Global Group memberships     *None

net user Jenny

User name                    Jenny
Password last set            3/2/2019 4:52:25 PM
Last logon                   Never
Local Group Memberships      *Administrators       *Users
Global Group memberships     *None

three answers come out together here, plus a big clue.
John made his last logon on 3/2/2019 at 5:48:32 PM, and he's also the last user to have logged into the system at all.
Jenny on the other hand never logged in, but she's in Administrators. an account that has never logged in and sits in the administrators group isn't an account used by a person: it's an account created or promoted by somebody else. the password was set at 16:52, so inside the compromise window.

to list the group the first attempt failed:

net localgroup Administrators
The specified local group does not exist.

it seemed absurd given that net localgroup with no arguments listed Administrators among the aliases just fine. the reason is trivial but I note it because I lost a few minutes on it: I was in a PowerShell console, not in cmd, and the argument parsing behaved differently. the native cmdlet resolves it without argument:

Get-LocalGroupMember -Group Administrators

Administrator
Guest
Jenny
ssm-user

Comment: admin have complete and unrestricted access to the computer/domain

Guest inside Administrators is the heaviest anomaly of the whole phase. the Guest account is disabled and privilege-free by design, promoting it to administrator has no legitimate reason and is a classic persistence technique precisely because nobody thinks to check it.
excluding Administrator (explicitly excluded by the question) and ssm-user (a legitimate AWS service account, present since the instance was created), the accounts with added administrative privileges are Guest and Jenny.

---

## Phase 3 — Scheduled tasks

scheduled tasks are one of the most common places to plant persistence. schtasks is the native command to query them, and with /fo table /nh you get a compact list. the problem is that a Windows Server has hundreds of legitimate ones, all under \Microsoft\Windows\, so I filtered those out:

schtasks /query /fo table /nh &#124; findstr /v Microsoft

Folder: \
Amazon Ec2 Launch - Instance Initializat  N/A                    Disabled
Amazon Ec2 Launch - Userdata Execution    N/A                    Ready
BADR                                      N/A                    Ready
BadrClient                                N/A                    Ready
check logged in                           9/13/2026 4:59:43 PM   Ready
Clean file system                         9/13/2026 4:55:17 PM   Ready
falshupdate22                             9/13/2026 12:45:04 PM  Ready
npcapwatchdog                             N/A                    Ready
update windows                            N/A                    Ready

in the root folder there are nine tasks and at least five have suspicious names. the two Amazon Ec2 Launch ones are legitimate parts of the AMI, npcapwatchdog belongs to Npcap and is consistent with the installed Wireshark.
that leaves BADR, BadrClient, check logged in, Clean file system, falshupdate22, update windows. falshupdate22 is an obvious typo of flash update, a classic camouflage, and update windows is inverted compared to the real Microsoft name.

the question asks for only one, so I checked the one with the most innocuous name and an active next run time:

schtasks /query /tn "Clean file system" /fo list /v

HostName:                             EC2AMAZ-I8UH076
TaskName:                             \Clean file system
Next Run Time:                        9/13/2026 4:55:17 PM
Status:                               Ready
Logon Mode:                           Interactive only
Last Run Time:                        9/13/2026 12:28:29 PM
Author:                               EC2AMAZ-I8UH076\Administrator
Task To Run:                          C:\TMP\nc.ps1 -l 1348
Comment:                              A task to clean old files of the system
Scheduled Task State:                 Enabled
Run As User:                          Administrator
Schedule Type:                        Daily
Start Time:                           4:55:17 PM
Start Date:                           3/2/2019
Days:                                 Every 1 day(s)

three answers in one go.
the name is what looks like system cleanup, the description too ("A task to clean old files of the system"), but the command executed is C:\TMP\nc.ps1 -l 1348, that is netcat in PowerShell form put into listening on port 1348. it runs every day, as Administrator, starting from 3/2/2019.
a bind shell scheduled daily: if the attacker loses access, all they need is to reconnect on 1348 the next day.
the path C:\TMP is what interested me most, because it isn't a standard Windows folder and from here on it became the centre of the investigation.

I didn't open the other suspicious tasks one by one for time reasons, but the names stay noted as multiple persistence: BADR and BadrClient tie back to the start-badr.vbs found later in the run keys, so they are the same implant seen from two different points.

---

## Phase 4 — Run keys

the question about the IP contacted at startup points directly to the autoruns. the machine key is the one:

reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

UpdateSvc    REG_SZ    C:\TMP\p.exe -s \\10.34.2.3 'net user' > C:\TMP\o2.txt
BadrClient   REG_SZ    wscript.exe "C:\badr\start-badr.vbs" //B //Nologo

the IP contacted at startup is 10.34.2.3

the entry is called UpdateSvc to look like an update service but it runs p.exe with the syntax typical of PsExec (-s to run as SYSTEM, \\host as the target), launches net user on the remote machine and redirects the output into C:\TMP\o2.txt. it is therefore not a connection towards an external C2, it's lateral movement towards an internal host with user harvesting: 10.34.2.3 is on the private network.
this is a point worth not flattening, because further on there's a question about the external C2 and the answer is a completely different IP. the two addresses have two distinct functions and confusing them is the easy mistake of this room.

the second entry is the counterpart of the BadrClient task seen earlier: a vbs script executed with wscript in silent mode (//B //Nologo, no window, no banner). persistence number two.

---

## Phase 5 — The toolkit in C:\TMP

dir C:\TMP

Mode     LastWriteTime        Length   Name
-a&#45;&#45;&#45;&#45;   3/2/2019 4:37 PM       9673   d.txt
-a&#45;&#45;&#45;&#45;   3/2/2019 4:37 PM       3389   mim-out.txt
-a&#45;&#45;&#45;&#45;   3/2/2019 4:37 PM     663552   mim.exe
-a&#45;&#45;&#45;&#45;   3/2/2019 4:45 PM     176148   moutput.tmp
-a&#45;&#45;&#45;&#45;   3/2/2019 4:37 PM      36864   nbtscan.exe
-a&#45;&#45;&#45;&#45;   3/2/2019 4:37 PM      37640   nc.ps1
-a&#45;&#45;&#45;&#45;   3/2/2019 4:37 PM     381816   p.exe
-a&#45;&#45;&#45;&#45;   3/2/2019 4:46 PM          0   scan1.tmp
-a&#45;&#45;&#45;&#45;   3/2/2019 4:46 PM          0   scan2.tmp
-a&#45;&#45;&#45;&#45;   3/2/2019 4:46 PM          0   scan3.tmp
-a&#45;&#45;&#45;&#45;   3/2/2019 4:45 PM       7022   schtasks-backdoor.ps1
-a&#45;&#45;&#45;&#45;   3/2/2019 4:45 PM   40464394   somethingwindows.dmp
-a&#45;&#45;&#45;&#45;   3/2/2019 4:46 PM      11950   sys.dmp
-a&#45;&#45;&#45;&#45;   3/2/2019 4:37 PM      19998   wMIBackdoor.ps1
-a&#45;&#45;&#45;&#45;   3/2/2019 4:37 PM     843776   xCmd.exe

this is the attacker's working folder and on its own it reconstructs half the attack.

mim.exe with mim-out.txt alongside it is a renamed mimikatz: the answer to the question about the tool used to take the passwords is mimikatz. the shortened name serves to avoid being caught by trivial filename checks, but the output sitting next to it leaves no doubt and is consistent with the hash dump found on the desktop in the preface.
p.exe is PsExec, the one called by the Run key.
nc.ps1 is the PowerShell netcat of the scheduled task.
nbtscan.exe and the three empty scan*.tmp files are NetBIOS network reconnaissance, the zero-byte files say the scans were launched but produced no results.
xCmd.exe is another remote execution tool, an alternative to PsExec.
wMIBackdoor.ps1 and schtasks-backdoor.ps1 are the other two persistence routes, WMI event subscription and scheduled tasks.
somethingwindows.dmp at 40 MB and sys.dmp are memory dumps, material to extract credentials from offline.
d.txt I opened thinking it contained configuration or addresses, and instead it's a recursive filesystem listing (it started from C:\MSOCache with all the Office packages and went on for pages). it's disk reconnaissance, it contains nothing useful to the questions, and I note it precisely as an exclusion: it cost me time because the short name made it look like a config file.

all the timestamps fall between 16:37 and 16:46 of 3/2/2019, so the compromise date is 03/02/2019 and the operational window is barely ten minutes. this is the time reference I then used to search the event logs.

---

## Phase 6 — Webshell and entry vector

the question talks about a shell uploaded through the site, so the default IIS root:

dir C:\inetpub\wwwroot

b.jsp
shell.gif
tests.jsp

extension: .jsp

two jsp files in an IIS wwwroot are already anomalous in themselves, and shell.gif alongside is the classic file uploaded with an image extension to get past an upload filter and then renamed or interpreted otherwise.
the webserver actually wasn't running on the machine at the time of the analysis, the room simulates it leaving only the artefacts on disk. I verified it because I tried looking for URL references inside tests.jsp with findstr /i "http" and nothing came out: the files are present but emptied of useful content.
this is nevertheless the entry point: unfiltered upload on an exposed Java application, then command execution from the shell.

---

## Phase 7 — Firewall and hosts file

netsh advfirewall firewall show rule name=all &#124; findstr /i "Rule Name LocalPort"

the output is extremely long because it lists all of Windows' predefined rules, but among Network Discovery and the Microsoft app rules two pop out that don't belong to any standard set:

Rule Name:  Allow outside connections for development
LocalPort:  1337
Rule Name:  Service Firewall
LocalPort:  8888

both added by hand. the name of the first is almost a signature, "allow outside connections for development" is the excuse you write to justify a hole. the second disguises itself as a generic service rule.
the answer to the last port opened is 1337. initially I had bet on 8888 reasoning from the order in which they appeared in the list, but netsh's output order doesn't reflect the creation order, and the room considers the last in the chain of added inbound rules to be the one on 1337. I keep it as a methodological note: to really determine the chronological creation order of the rules you'd need the registry or the firewall event logs, netsh on its own doesn't say.

then the hosts file, which is where you check for local DNS poisoning:

type C:\Windows\System32\drivers\etc\hosts

127.0.0.1        localhost
::1              localhost
0.2.2.2          update.microsoft.com
127.0.0.1        www.virustotal.com
27.0.0.1         www.www.com
27.0.0.1         dci.sophosupd.com
0.2.2.2          update.microsoft.com
127.0.0.1        www.virustotal.com
27.0.0.1         www.www.com
27.0.0.1         dci.sophosupd.com
76.32.97.132     google.com
76.32.97.132     www.google.com

two answers here, and they need separating properly because the temptation is to give the same one for both.

the entries pointing to 127.0.0.1, 0.2.2.2 and 27.0.0.1 are defensive sabotage, not redirection: they point to local or non-existent addresses to stop the machine reaching Windows Update, VirusTotal and the Sophos update servers. they serve to keep the system blind and un-updated, and I exclude them from the question about the targeted site precisely because they don't redirect anywhere, they just block.
the only entry pointing to a real public IP is google.com (and www.google.com) towards 76.32.97.132. that is the only real hijack, so the site targeted by DNS poisoning is google.com and the IP of the external command and control server is 76.32.97.132.

before getting there I had looked for the C2 in the wrong place: inside d.txt, inside the jsp files and even looking for a possible pcap on the disk (with Wireshark installed it seemed sensible). ls C:\Users -r -fi *.pcap* returned nothing. the C2 was in the most banal file on the system

---

## Phase 8 — Event logs and the hunt for 4672

the last question asks for the time at which Windows first assigned special privileges to a new logon during the compromise. the reference event ID is 4672 (Special privileges assigned to new logon), which is generated when an account receives a token with sensitive privileges like SeDebugPrivilege or SeTakeOwnershipPrivilege.

this single question took me more time than all the other fifteen put together, so I write it out in full because the value is in the route, not in the answer.

first attempt, the standard way:

Get-WinEvent -FilterHashtable @{LogName='Security';Id=4672} -MaxEvents 5

No events found that match criteria.

the problem here wasn't the query but the keyboard: on the in-browser VM the curly braces weren't typeable, so the hashtable never arrived at its destination intact. I realised that late.

second attempt with Get-EventLog:

Get-EventLog Security -InstanceId 4672 -Newest 5
Get-EventLog : No matches found

third with XPath inside Get-WinEvent:

Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4672]]" -Oldest -MaxEvents 1
No events found

fourth with a pipeline and client-side filtering:

Get-WinEvent -LogName Security -Oldest &#124; ? Id -eq 4672 &#124; select -First 1 TimeCreated

this hung forever: the Security log had 99,196 events and filtering client-side means going through them all. I interrupted it.

what worked is wevtutil, which filters at the log level and enumerates nothing:

wevtutil qe Security /q:"*[System[(EventID=4672)]]" /c:1 /rd:false /f:text

Event[0]:
  Log Name: Security
  Source: Microsoft-Windows-Security-Auditing
  Date: 2026-09-13T13:16:01.601
  Event ID: 4672
  Task: Special Logon
Special privileges assigned to new logon.
Subject:
  Security ID:    S-1-5-21-3685962493-259677494-3116396707-500
  Account Name:   Administrator
Privileges:       SeSecurityPrivilege
                  SeBackupPrivilege
                  SeRestorePrivilege
                  SeTakeOwnershipPrivilege
                  SeDebugPrivilege
                  &#46;&#46;&#46;

it works, but the date is 2026: these are my own RDP logins from today. on that instance the log had rotated and the 4672 events from 2019 had been overwritten by the events generated during the three hours of the session, in Event Viewer there were five left in total and all of them from today.

I restarted the lab machine to start from a fresh snapshot, and there the historical events were present:

Date: 2019-02-13T08:14:30.347
Event ID: 4672
Account Name: SYSTEM

but the very first one is from February and belongs to SYSTEM, so it isn't the one from the compromise. I narrowed it to the day:

wevtutil qe Security /q:"*[System[(EventID=4672) and TimeCreated[@SystemTime>='2019-03-02T00:00:00' and @SystemTime<='2019-03-03T00:00:00']]]" /c:1 /f:text

Date: 2019-03-02T16:02:58.125
Account Name: SYSTEM

still SYSTEM. I tried excluding the SID S-1-5-18 and got NETWORK SERVICE, then filtering on SubjectUserName='Administrator' I got to 16:09:34, which is already inside the right window but isn't the first.

the correct answer popped out by relaunching the base query on a just-started instance, without having yet confirmed the initial dialog box that appears at first login: under those conditions wevtutil returns many more historical 4672 events than the ones visible from the GUI afterwards (which showed only five, all recent). presumably that initial step triggers activity that fills the log and pushes the old records out.

Date: 2019-03-02T16:04:49

answer: 03/02/2019 4:04:49 PM.

two concrete lessons from here. the first is that on a log with a hundred thousand events the difference between filtering server-side (wevtutil, XPath inside the query) and client-side (a pipeline with Where-Object) isn't a matter of style, it's the difference between one second and never. the second is that on a forensic machine uptime is itself a destructive factor: the longer you keep it on, the more the historical logs you need to analyse get overwritten by your own analysis activity. in a real case the first thing would be to export Security.evtx, not to query it live.

---

## Full chain

reconstructed timeline of the attack, all times in UTC of 2 March 2019.

16:04:49  first assignment of special privileges to a new logon (4672), the attacker obtains a token with elevated privileges after getting in through the .jsp webshell uploaded to C:\inetpub\wwwroot
16:37     toolkit dropped in C:\TMP: mim.exe (mimikatz), p.exe (PsExec), xCmd.exe, nc.ps1, nbtscan.exe, wMIBackdoor.ps1
16:37     mimikatz executed, output into mim-out.txt, system credentials dumped
16:45     memory dumps somethingwindows.dmp and sys.dmp created, along with schtasks-backdoor.ps1
16:46     network reconnaissance with nbtscan, scan1/2/3.tmp return empty
16:47     first malicious scheduled tasks registered
16:52     password set for the account Jenny, which is added to Administrators together with Guest without ever having logged in
16:55     task "Clean file system" scheduled daily, runs C:\TMP\nc.ps1 -l 1348, a permanent bind shell
&#45;&#45;        HKLM Run key UpdateSvc: p.exe towards 10.34.2.3 for internal lateral movement, output into o2.txt
&#45;&#45;        HKLM Run key BadrClient: wscript on C:\badr\start-badr.vbs in silent mode
&#45;&#45;        inbound firewall rules added by hand, 8888 and finally 1337
&#45;&#45;        hosts file poisoned: update.microsoft.com, virustotal and sophosupd neutralised towards local addresses, google.com hijacked to the external C2 76.32.97.132
17:48:32  John's last logon, the last user access recorded on the system

in summary: entry through a webshell upload on IIS, escalation to administrative privileges, credential theft with mimikatz, redundant persistence on three fronts (run key, scheduled task, WMI/vbs), opening of inbound ports and finally blinding of the defences plus local DNS hijacking towards its own command server.

---

## Room answers

1.  Windows Server 2016 Datacenter
2.  Administrator
3.  03/02/2019 5:48:32 PM
4.  10.34.2.3
5.  Guest, Jenny
6.  Clean file system
7.  C:\TMP\nc.ps1
8.  1348
9.  Never
10. 03/02/2019
11. 03/02/2019 4:04:49 PM
12. mimikatz
13. 76.32.97.132
14. .jsp
15. 1337
16. google.com

---

## Lessons learned

the technical part of this room is all native enumeration and no step is difficult in itself. what makes sixteen questions tiring is the context: with no copy-paste, with a keyboard that doesn't type half the special characters and with a log of a hundred thousand events, the difference is made by picking the right tool on the first go instead of insisting on the familiar one. I lost forty minutes on Get-WinEvent when wevtutil answered in one second.

the other thing I take away is methodological and holds beyond the room. on a compromised system the two IPs found (10.34.2.3 and 76.32.97.132) have opposite roles, and the mere presence of an address says nothing: one is internal lateral movement via PsExec, the other is the external C2 in the hosts file. the same goes for the hosts file entries, where sabotaging updates and hijacking a domain look like the same action but answer two different questions. distinguishing matters more than finding

---

## Tools used

RDP (TryHackMe in-browser VM), systeminfo, net user, net localgroup, Get-LocalGroupMember, schtasks, reg query, dir, findstr, type, netsh advfirewall, Get-WinEvent, Get-EventLog, wevtutil, Event Viewer
