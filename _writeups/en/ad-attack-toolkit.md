---
layout: writeup
lang: en
permalink: /en/writeups/ad-attack-toolkit/
title: "AD Attack Toolkit — tool testing"
ref: ad-attack-toolkit
date: 2026-06-28
kind: lab
platform: LAB
platform_color: "#1d4ed8"
os: Windows
tags: [win, AD, kerberos, ldap, python, tooling]
txt: /writeups-files/adtoolkit-lab-test.txt
repo: https://github.com/torchiachristian/ad-attack-toolkit
---

Test of my ad-attack-toolkit against an Active Directory domain built from scratch, to check
whether it held up in real use or hid bugs that only surfaced because it was tuned on the
development environment. Result: two latent bugs, both fixed. Tool bumped to v1.1.
The version below is a summary: the full writeup is in the linked .txt file above.

## Phase 1 — Test domain
Isolated host-only VirtualBox lab. Windows Server 2022 DC, psychosec.local domain, vulnerable
targets created by hand (AS-REP, Kerberoasting, Domain Admin). NetBIOS typed PSYCHOSE instead
of PSYCHOSEC: a seemingly cosmetic detail, actually the key to the first bug.

## Phase 2-3 — LDAP bind bug
Immediate crash: invalidCredentials. The orchestrator derived the NetBIOS from the DNS name
(split + upper) and prepended it to the username, building a non-existent domain. AD's SIMPLE
bind wanted a UPN. Fix: build the UPN from the real domain, no hardcoded NetBIOS assumption.

## Phase 4-6 — Kerberoasting hashes rejected by hashcat
After the fix, enumeration runs clean but TGS hashes were rejected (separator unmatched).
Character-by-character comparison with impacket's reference format: three overlapping defects
in the hash format (duplicated SPN, :1433 port in the SPN field, checksum not separated from
the ticket). All fixed in kerberoast.py.

## Phase 7 — Full chain
Hashes regenerated with the fixed tool and cracked natively, no longer going through impacket.
Four passwords recovered (2 AS-REP, 2 Kerberoasting). Working end-to-end chain: enumeration ->
hash capture -> cracking -> PDF report. Tool promoted to v1.1.
      

<div class="writeup-image">
  <img src="/assets/writeups/adtoolkit-bind-fail.png" alt="Fase 1: crash al primo run, bind rifiutato (invalidCredentials)">
  <div class="img-caption">Fase 1: crash al primo run, bind rifiutato (invalidCredentials)</div>
</div>

<div class="writeup-image">
  <img src="/assets/writeups/adtoolkit-enum.png" alt="Dopo il fix del bind: enumerazione completa, target AS-REP e Kerberoasting">
  <div class="img-caption">Dopo il fix del bind: enumerazione completa, target AS-REP e Kerberoasting</div>
</div>

<div class="writeup-image">
  <img src="/assets/writeups/adtoolkit-report.png" alt="Run completo dopo i fix: tutte le fasi e report PDF generato">
  <div class="img-caption">Run completo dopo i fix: tutte le fasi e report PDF generato</div>
</div>

