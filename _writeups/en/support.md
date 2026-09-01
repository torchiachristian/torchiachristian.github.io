---
layout: writeup
lang: en
permalink: /en/writeups/support/
title: "Support"
ref: support
date: 2026-06-18
platform: HTB
os: Windows
difficulty: Easy
tags: [win, AD, ldap, rbcd, kerberos, privesc]
txt: /writeups-files/support.txt
---

Active Directory machine. Starts from an anonymous SMB share with an internal .NET tool.
Chain: anonymous SMB → credential extraction from .NET binary → ldap → password in LDAP info field → WinRM support → WRITE on DC$ → RBCD → S4U → Administrator.

## Phase 1 — Reconnaissance
nmap on SMB. Non-standard share "support-tools" accessible anonymously.
Domain: support.htb / DC: dc.support.htb

## Phase 2 — Anonymous share and binary analysis
UserInfo.exe.zip in the share. A .NET tool that queries LDAP with encrypted credentials.
monodis extracts enc_password and key = "armando".

## Phase 3 — Decryption
Several failed attempts with standard ciphers (AES-ECB/CBC, RC4).
Actual scheme: base64 decode + XOR with key and a constant → ldap account password.

## Phase 4 — LDAP enumeration
ldapsearch enumerates 21 users. The support account password is hidden in the "info" field.
→ Ironside47pleasure40Watchful

## Phase 5 — WinRM as support
support is in Remote Management Users. evil-winrm → shell. User flag.

## Phase 6 — Privesc hunt (with failures)
support is in no privileged group. Failed: Administrator password reset, direct DCSync,
Kerberoasting (no SPN), AS-REP Roasting (no users), GPO/SYSVOL write.

## Phase 7 — RBCD and final access
bloodyAD reveals DACL: WRITE on DC$. Combined with SeMachineAccountPrivilege → RBCD.
Create a computer account, set RBCD on DC$, S4U to impersonate Administrator.
getST.py → ticket → wmiexec → Administrator → root.
Final NTDS.DIT DCSync confirming full-domain impact.
      

<div class="writeup-image">
  <img src="/assets/writeups/support.png" alt="Proof of pwn">
  <div class="img-caption">Proof of pwn</div>
</div>

