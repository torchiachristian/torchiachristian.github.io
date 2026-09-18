---
layout: writeup
lang: en
permalink: /en/writeups/anthem/
title: "Anthem"
ref: anthem
date: 2026-09-01
bare: true
platform: THM
os: Windows Server 2019 (Umbraco 7.15.4 + Articulate)
difficulty: Easy
series: thm-windows
tags: [win, umbraco, osint, rdp, acl, privesc]
txt: /writeups-files/anthem.txt
summary: "No exploit, only observation required. Password in robots.txt, username derived from a document, privilege escalation by rewriting the ACLs of a folder."
---

# Writeup — Anthem (TryHackMe)

OS: Windows Server 2019 (build 17763, Umbraco 7.15.4 + Articulate)
Difficulty: Easy
Date: 9 September 2026

---

## Summary

Windows Server 2019 machine, not domain-joined, with only two ports exposed, a webserver on 80 and RDP on 3389. No exploit, no vulnerable service: the room is entirely about observation. The site is an Umbraco blog with the Articulate plugin, and it hides four flags in places you don't see by opening the page in a browser, all inside the HTML source or in secondary profile fields. The robots.txt contains a password left at the top of the file outside any valid syntax. the corresponding username isn't the one signed at the bottom of the posts, which is the real author of the poem quoted, but the subject of the poem itself, reduced to initials following the scheme of the email found in the other post. From RDP as a standard user the filesystem is almost empty, except for an unreadable backup file: changing its ACLs from the Windows interface reveals the Administrator's password, and from there the root flag

Chain: nmap → 80 and 3389 → HTML source → Umbraco/Articulate + first flag in the search placeholder → robots.txt → password → RSS for the real post links → meta og:description → two flags → author page → fourth flag → poem Solomon Grundy → username SG → RDP → user.txt → C:\backup\restore.txt unreadable → ACLs modified → Administrator password → RDP as Administrator → root.txt.

---

## additional tools and methodology

an llm was used during the session: for looking up CVE details, interpreting raw output, suggesting unexplored vectors when stuck and detailed explanation of technical concepts. the execution and the operational decisions were mine. the writeup was written by me and later cleaned up with the same tool.

the connection between the poem and the username was suggested by the chatbot after I had exhausted about ten formats based on the wrong author. one flag, the last one, I recovered from a public writeup after the machine expired: I write it here because it's the only step of this room I didn't execute personally.

---

## Preface

room done from my virtualised Kali, with the VPN already up from the previous session on Blueprint. technically there's nothing difficult, but it's the room where I lost the most time on a single detail: the RDP username. the password is found in the first two minutes, the username took about fifteen attempts on three different people before realising I was looking at the wrong name

the second thing that slowed me down is that the flags turn up in places disconnected from each other, meta tags, the placeholder of a search field, profile fields, and when you find them you have no way of knowing which room question they correspond to. I collected them all first and matched them afterwards,by trial and error.

the machine expired right after reading the root flag and without a subscription it can't be redeployed, so the final part verifying Administrator privileges was left unexecuted.

---

## Phase 1 — Reconnaissance

same scanning scheme as the previous room:

IP=10.112.170.81; sudo nmap -sS -Pn -p- --min-rate 5000 -oN anthem_full.txt IP && sudo nmap -sV -sC -p (grep -oP '^\d+(?=/tcp\s+open)' anthem_full.txt | paste -sd,) -oN anthem_svc.txt $IP

Not shown: 65533 filtered tcp ports (no-response)
80/tcp open http
3389/tcp open ms-wbt-server

the second scan died immediately with "Host seems down": in the chained command I had left the -Pn only in the first one, and on a host that filters everything the preliminary ping fails. relaunched by hand:

sudo nmap -sV -sC -Pn -p80,3389 -oN anthem_svc.txt 10.112.170.81

80/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
3389/tcp open ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
| Target_Name: WIN-LU09299160F
| NetBIOS_Domain_Name: WIN-LU09299160F
| DNS_Computer_Name: WIN-LU09299160F
| Product_Version: 10.0.17763

Windows Server 2019, hostname WIN-LU09299160F, and the fact that the NetBIOS domain and the machine name coincide confirms it isn't domain-joined: the accounts are local. all the other 65533 ports are filtered, not closed, so there's a firewall that drops rather than refuses .

with only two ports and no vulnerable version in sight, the webserver is the only surface to work.

---

## Phase 2 — Homepage source

instead of opening the site in a browser I read the raw HTML directly, which is faster and also shows what the browser doesn't render:

curl -s http://10.112.170.81/ | head -60

from the head of the page comes everything needed to frame the application:

<link href="/DependencyHandler.axd?s=L0FwcF9QbHVnaW5zL0FydGljdWxhdGUvVGhlbWVzL1ZBUE9SL... <div class="bloglogo" style="background: url(/media/articulate/default/capture3.png...

the path /App_Plugins/Articulate/Themes/VAPOR/ (also readable in base64 inside the DependencyHandler) identifies Umbraco as the CMS, with the Articulate blog plugin and the VAPOR theme on top. the plugin's standard endpoints are also exposed: /rss, /archive/, /categories, /tags, /opensearch, /rsd/1073, /wlwmanifest/1073.

and in the search bar, inside the placeholder attribute, there is the first flag:

<input type="text" name="term" placeholder="Search... THM{G!T_G00D}" />

invisible when looking at the page, because the text is preceded by about fifty spaces and gets truncated by the field. it's only visible in the source.

---

## Phase 3 — robots.txt

curl -s http://10.112.170.81/robots.txt

UmbracoIsTheBest!

Use for all search robots

User-agent: *

Define the directories not to crawl

Disallow: /bin/
Disallow: /config/
Disallow: /umbraco/
Disallow: /umbraco_client/

robots.txt is a text file that sits in the root of any site and serves to tell search engine crawlers which folders not to index. it isn't an application endpoint and it isn't a protection: anyone can read it, and precisely because it lists the folders the owner would like to hide it often reveals the administrative paths. it should always be read, right after the homepage, together with sitemap.xml

here it confirms /umbraco/ as the administration panel, but above all it has at the top a line that has nothing to do with the file's syntax: UmbracoIsTheBest!. it's a password, left there by someone and never removed.

---

## Phase 4 — The posts and the hunt for the author

I have the password, the username is missing. the blog posts are two, "We are hiring" and "A cheers to our IT department".

first mistake: I tried to guess the post URLs with the date scheme typical of WordPress (/2021/04/we-are-hiring/), and Articulate always answered me with the archive page instead of the single post, making me believe for a couple of attempts that I was reading the right content. the real links are in the RSS feed, which the blog exposes and which nobody was stopping me from reading:

curl -s http://10.112.170.81/rss | grep -oP '(?<=<link>)[^<]+'

http://10.112.170.81/
http://10.112.170.81/archive/we-are-hiring/
http://10.112.170.81/archive/a-cheers-to-our-it-department/

the second post contains the poem:

curl -s http://10.112.170.81/archive/a-cheers-to-our-it-department/ | sed -e 's/<[^>]>//g' | grep -v '^\s$' | head -40

During our hard times our beloved admin managed to save our business by redesigning the entire website.
As we all around here knows how much I love writing poems I decided to write one about him:
Born on a Monday,Christened on Tuesday,Married on Wednesday,Took ill on Thursday,
Grew worse on Friday,Died on Saturday,Buried on Sunday.That was the end...
Author
James Orchard Halliwell

the first post gives the other piece:

If you have an interest in being a part of the movement send me your CV at JD@anthem.com
Author
Jane Doe

so two names and an email format. from here a long series of failed attempts begins,first with xfreerdp:

xfreerdp3 /v:10.112.170.81 /u:jhalliwell /p:'UmbracoIsTheBest!' /cert:ignore +clipboard /dynamic-resolution

[ERROR][com.freerdp.core.rdp] - CONNECTION_STATE_NLA - nla_recv_pdu() fail

xfreerdp3 is the command-line RDP client for Linux, the equivalent of Windows' Remote Desktop Connection. /u: is the local user, /p: the password found in robots.txt, /cert:ignore accepts the machine's self-signed certificate. every attempt however requires waiting for the complete handshake, and it's slow.

to speed things up I switch to NetExec, which tests credentials against the protocol without opening the graphical session:

nxc rdp 10.112.170.81 -u jane.doe -p 'UmbracoIsTheBest!'

RDP 10.112.170.81 3389 WIN-LU09299160F [*] Windows 10 or Windows Server 2016 Build 17763 (name:WIN-LU09299160F) (domain:WIN-LU09299160F) (nla:False)
RDP 10.112.170.81 3389 WIN-LU09299160F [-] WIN-LU09299160F\jane.doe:UmbracoIsTheBest! (STATUS_LOGON_FAILURE)

nla:False is useful information in itself: network level authentication is disabled, so authentication happens after establishing the session and not before. STATUS_LOGON_FAILURE however doesn't distinguish between a non-existent user and a wrong password, so it neither confirms nor rules out the name.

with a loop you test nine formats in a few seconds:

for u in JD jd jane janedoe j.doe doe UmbracoAdmin admin administrator; do nxc rdp 10.112.170.81 -u $u -p 'UmbracoIsTheBest!'; done

all STATUS_LOGON_FAILURE. including administrator, which with that password doesn't get in.

the reasoning that unblocks the situation: the post says the poem is dedicated to the admin, and the signature at the bottom of the page is of whoever wrote the text, not of whoever is its subject. the poem is Solomon Grundy, an English nursery rhyme collected and published by James Orchard Halliwell himself. the admin is therefore called Solomon Grundy, and the email format of the other post (JD@anthem.com for Jane Doe) says that on this machine the accounts are just the initials.

for u in SG sg solomon grundy s.grundy sgrundy solomon.grundy; do nxc rdp 10.112.170.81 -u $u -p 'UmbracoIsTheBest!'; done

RDP 10.112.170.81 3389 WIN-LU09299160F [+] WIN-LU09299160F\SG:UmbracoIsTheBest! (Pwn3d!)
RDP 10.112.170.81 3389 WIN-LU09299160F [+] WIN-LU09299160F\sg:UmbracoIsTheBest! (Pwn3d!)

it works both uppercase and lowercase because Windows doesn't distinguish case in usernames. the extended variants all fail, so the account is exactly SG.

---

## Phase 5 — The flags hidden in the meta

the first flag was in an HTML attribute, so it's worth grepping the source of every page instead of reading them by eye:

curl -s 'http://10.112.170.81/archive/we-are-hiring/' | grep -iE 'user|admin|THM|<!--'

<meta content="THM{L0L_WH0_US3S_M3T4}" property="og:description" />

same treatment on the other post:

curl -s 'http://10.112.170.81/archive/a-cheers-to-our-it-department/' | grep -iE 'THM|<!--|user'

<meta content="THM{AN0TH3R_M3TA}" property="og:description" />

the og:description field is the text that would appear in the preview when the link is shared on a social network. nobody reads it in the browser, and that's why they put the flags in there.

(note on braces: grep -iE "THM{...}" with double quotes in zsh gives "event not found" because of the exclamation mark and history expansion. with single quotes it works.)

the fourth flag I didn't find during the session, and with the machine expired I recovered it from a public writeup. it's in the Website field of the author's profile page, /authors/jane-doe/, which Articulate generates automatically for every author and which is linked from the signature at the bottom of the posts:

curl -s http://10.112.170.81/authors/jane-doe/ | grep -o 'THM{[^}]*}'

THM{L0L_WH0_D15}

it's the same scheme as the other two, a value placed in a profile field nobody reads, and I would have got it with the same grep if I had followed the author link instead of stopping at the two posts.

Flags collected: THM{G!T_G00D} in the search placeholder, THM{L0L_WH0_US3S_M3T4} and THM{AN0TH3R_M3TA} in the og:description meta of the two posts, THM{L0L_WH0_D15} in the Website field of the author page.

---

## Phase 6 — RDP access and the user flag

xfreerdp3 /v:10.112.170.81 /u:'SG' /p:'UmbracoIsTheBest!' /cert:ignore +clipboard /dynamic-resolution

full desktop session as SG. on the desktop is the user flag:

THM{N00T_NO0T}

the rest of the filesystem is almost all empty or inaccessible, but it's worth noting what is there and what isn't, because the shape of the disk is itself a clue:

C:\Users\SG contains the five standard folders (Music, Videos, Pictures, Documents, Downloads) all empty. C:\Users\Public likewise.

C:\inetpub has the five IIS folders: custerr, history, logs, temp, wwwroot. logs, history and temp\IIS Temporary Compressed Files can't be opened with SG's privileges. custerr\en-US contains only the predefined HTML error pages (500-17, 500-18, 500-19, 404-9, 404-10).

under wwwroot there is the Web folder with the application: robots.txt (the same one already read over HTTP, password included), default.aspx which is three lines of Umbraco directive, global.asax which is a single one, and web.config, which is the only substantial file. reading it with Notepad confirms umbracoConfigurationStatus 7.15.4, the database on SQL Server Compact (Umbraco.sdf) instead of an external server, umbracoUseSSL false, and at the bottom a machineKey block with validationKey and decryptionKey in cleartext. it isn't needed for this room but it's sensitive material left readable to a standard user

C:\ProgramData is instead full and accessible, with the folders of the installed services: ssh, VMware, USOShared, USOPrivate, Amazon, Microsoft, regid.1991-06.

in C:\Users\SG\AppData\Local\Temp there is wmsetup.log, which dates the machine's installation:

[*WMC Logging begun at 2020/04/05 - 23:40:06. Logging at level: '4'. OS is NT. OSVer is 10.0.17763.0.475. System Lang is 2057.]
Current command line: '/FirstLogon'.

System Lang 2057 is British English, consistent with the time zone seen in the initial scan.

C:\Temp doesn't exist, C:\Windows\Temp requires privileges, C:\Program Files\Umbraco doesn't exist (the application sits under inetpub), C:\Users\Administrator isn't accessible.

the only thing out of place is C:\backup, which contains a single file, restore.txt, not openable with SG's privileges. a backup folder at root level on a machine with all the user profiles empty but with consistent creation dates is exactly the kind of anomaly to look at.

---

## Phase 7 — ACLs and privilege escalation

the file isn't readable but the folder is mine to modify as effective owner, and Windows allows the ACLs to be rewritten from the graphical interface without touching the command line. right click on C:\backup, Properties, Security tab, Advanced, Add.

the permission entry inserted:

Principal: SG (WIN-LU09299160F\SG)
Type: Allow
Applies to: This folder, subfolders and files

Basic permissions:
[x] Full control
[x] Modify
[x] Read & execute
[x] List folder contents
[x] Read
[x] Write
[ ] Special permissions (not selectable)

[ ] Only apply these permissions to objects and/or containers within this container

"Applies to: This folder, subfolders and files" is the field that counts, because without it the permission would stay on the folder and wouldn't propagate to the file inside. confirmed with OK and reapplied, restore.txt opens with Notepad:

ChangeMeBaby1MoreTime

password of the local Administrator account. second RDP session:

xfreerdp3 /v:10.112.170.81 /u:'Administrator' /p:'ChangeMeBaby1MoreTime' /cert:ignore +clipboard /dynamic-resolution

Administrator's desktop with Server Manager opening by itself at login, the filesystem entirely navigable, and the root flag:

THM{Y0U_4R3_1337}

the synthetic sequence of this phase: from SG the file C:\backup\restore.txt is unreadable, you add SG with full control in the folder's advanced ACLs propagating to the files contained, inside there is the local Administrator's password, you reopen RDP with that account and the flag is on its desktop.

the machine expired a few minutes later, so the concrete proof of Administrator privileges (writing to System32, creating a local account in the Administrators group, a Run key in the registry) remained planned but not executed. I flag it instead of presenting it as done.

---

## Full chain

nmap → only 80 and 3389, Windows Server 2019 not domain-joined
→ HTML source of the homepage → Umbraco 7.15.4 + Articulate
→ first flag in the placeholder of the search field
→ robots.txt → password UmbracoIsTheBest! outside the syntax at the top of the file
→ post URLs guessed wrong → RSS for the real links
→ post 1: email JD@anthem.com, author Jane Doe
→ post 2: poem Solomon Grundy, signed James Orchard Halliwell
→ og:description meta of the two posts → second and third flag
→ author page /authors/jane-doe/, Website field → fourth flag
→ about fifteen failed usernames on nxc rdp
→ subject of the poem + initials scheme from the email → SG
→ RDP as SG → user.txt
→ filesystem empty except C:\backup\restore.txt unreadable
→ advanced ACLs: SG with Full control propagated to files → Administrator password
→ RDP as Administrator → root.txt

---

## Lessons learned

the signature at the bottom of a piece of content says who wrote it, not who it is about. all the difficulty of this room was there, and I burned about fifteen login attempts on two wrong people before rereading the sentence that introduced the poem, where it was written in plain text that the piece was dedicated to the admin and not signed by him.

when one flag is found in an HTML attribute, all the others will be in the same kind of place. after the first one in the placeholder I should have immediately grepped every page generated by the CMS, including the secondary ones like the author profiles, instead of limiting myself to the main content. the command for p in / /categories /tags /archive/ /authors/; do curl -s "$IP$p" | grep -o 'THM{[^}]*}'; done would have closed the phase in one go.

testing credentials with a tool that speaks the protocol (nxc) instead of with the full client (xfreerdp) changes the timings by an order of magnitude when the attempts are many. the same applies every time you need to try a list of usernames.

on Windows, not having permission to read a file doesn't mean you can't read it: if you control the folder, the ACLs are rewritten from the interface in three clicks, and the permission must be propagated explicitly to the files contained or it stays on the folder and nothing else

---

## Tools used

nmap, curl, sed, grep, NetExec (nxc rdp), xfreerdp3, Windows File Explorer and ACL editor, Notepad
