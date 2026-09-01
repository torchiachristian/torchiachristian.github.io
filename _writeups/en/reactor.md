---
layout: writeup
lang: en
permalink: /en/writeups/reactor/
title: "Reactor"
ref: reactor
date: 2026-05-30
platform: HTB
os: Linux
difficulty: Easy
tags: [lin, rce, nmap, privesc, CVE-2025-55182]
txt: /writeups-files/reactor.txt
---

Next.js 15.0.3 vulnerable to CVE-2025-55182 (React2Shell), unauthenticated RCE.
Chain: Next.js RCE → SQLite dump → MD5 crack → SSH user → Node Inspector abuse → root.

## Phase 1 — Reconnaissance
nmap: port 22 (SSH) and 3000. Headers reveal Next.js.
App: static dashboard "ReactorWatch" with three staff profiles.

## Phase 2 — Vector identification
/_next/image returns 400 (not 404) → endpoint exists.
Version 15.0.3 → CVE-2025-55182. Test with RSC headers → 200 response. Vulnerable.

## Phase 3 — RCE via React2Shell
Public PoC (jensnesten/React2Shell-PoC):
python3 main.py http://10.129.9.91:3000 'id'
→ uid=999(node)
Note: long output must be redirected to a temp file (RSC parser corrupts binary stdout).

## Phase 4 — SQLite dump and crack
strings on reactor.db → users table with two MD5 hashes.
First hash cracks on CrackStation → engineer / [password]

## Phase 5 — Privilege escalation
ps aux: root Node.js process with --inspect=127.0.0.1:9229
Node Inspector exposes a WebSocket that executes arbitrary JS in the root process context.
Manual WebSocket handshake via Python + Chrome DevTools Protocol:
Runtime.evaluate → process.mainModule.require("child_process").execSync("cat /root/root.txt")
Note: bare require() doesn't work in the raw V8 debugger context — use process.mainModule.require().
      

<div class="writeup-image">
  <img src="/assets/writeups/reactor.png" alt="Proof of pwn">
  <div class="img-caption">Proof of pwn</div>
</div>

