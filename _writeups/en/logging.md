---
layout: writeup
lang: en
permalink: /en/writeups/logging/
title: "Logging"
ref: logging
date: 2026-05-26
platform: HTB
os: Windows
difficulty: Medium
tags: [win, AD, kerberos, nmap, privesc]
txt: /writeups-files/logging.txt
---

Active Directory machine. Initial credentials for wallace.everette are provided by the platform.
Chain: SMB log analysis → password recovery → Shadow Credentials → WinRM gMSA → DLL hijacking → Credential Vault dump → Administrator.

## Phase 1 — Reconnaissance
Full nmap scan. Relevant ports: 53 (DNS), 88 (Kerberos), 139/445 (SMB), 389/636 (LDAP), 5985 (WinRM).
Domain: logging.htb / DC: DC01.logging.htb

## Phase 2 — SMB and credential discovery
Non-standard share "Logs" containing system logs. IdentitySync_Trace_20260219.log
reveals a cleartext password for svc_recovery (expired). Year pattern → Em3rg3ncyPa$$2026.
getTGT.py confirms: ticket obtained.

## Phase 3 — BloodHound
svc_recovery has GenericWrite on MSA_HEALTH$ (gMSA).
MSA_HEALTH$ is member of Remote Management Users.
IT group has Full Control over C:\Program Files\UpdateMonitor\bin\

## Phase 4 — Shadow Credentials
bloodyAD adds Shadow Credentials to MSA_HEALTH$.
PKINIT unstable across respawns (KDC_ERR_PADATA_TYPE_NOSUPP on some instances).
Solution: gMSA NT hash stays valid across respawns (rotates every 30 days).
evil-winrm with hash → shell as msa_health$

## Phases 5-6 — DLL Hijacking
UpdateMonitor.exe loads settings_update.dll from a ZIP in ProgramData.
Six failed attempts: wrong architecture, missing export, system() mute in session 0,
reverse shell blocked by egress firewall.
Correct vector: CredEnumerate() WinAPI to read jaylee.clifton's Credential Vault.

## Phase 7 — Final access
jaylee.clifton and Administrator credentials recovered from vault.
psexec.py → SYSTEM shell. Flags retrieved.
      

<div class="writeup-image">
  <img src="/assets/writeups/logging.png" alt="Proof of pwn">
  <div class="img-caption">Proof of pwn</div>
</div>

