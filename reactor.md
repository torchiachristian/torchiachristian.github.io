---
title: "Reactor"
ref: reactor
date: 2026-05-30
bare: true
platform: HTB
os: Linux
difficulty: Easy
tags: [lin, rce, nmap, privesc, CVE-2025-55182]
txt: /writeups-files/reactor.txt
---

# Writeup — Reactor (HackTheBox)

OS: Linux (Ubuntu 24.04)
Difficoltà: Easy
Data: 29 maggio 2026

---

## Sommario

La macchina espone una webapp Next.js 15.0.3 vulnerabile a CVE-2025-55182 (React2Shell), un RCE unauthenticated nel protocollo React Server Components. Ottenuto RCE come utente node, ho dumpato un database SQLite locale, craccato un hash MD5 per la password di engineer, e fatto accesso SSH. La privilege escalation a root avviene abusando del Node.js Inspector (porta 9229) che gira come root su /opt/uptime-monitor/worker.js.

Catena: RCE Next.js → SQLite dump → MD5 crack → SSH user → Node Inspector abuse → root.

---

## Fase 1 — Ricognizione

Port scan iniziale:

nmap -p- --min-rate=5000 10.129.9.91
nmap -sV -p 22,3000 10.129.9.91

Risultato: porta 22 (SSH, OpenSSH 9.6p1) e porta 3000. Nmap non riconosce il servizio sulla 3000, ma i response headers la identificano come Next.js:

X-Powered-By: Next.js

La webapp è una dashboard di monitoraggio chiamata ReactorWatch. Completamente statica: metriche di sistema, tre profili staff, zero form o interattività.

---

## Fase 2 — Enumerazione web

Ho provato directory brute-forcing con dirb, che trova solo /api/cgi-bin/ con un 308. Seguendo il redirect non porta a nulla di concreto: il 308 è il comportamento standard di Next.js per il trailing slash, non indica una route reale.

Ho controllato il build manifest dell'app:

curl -s http://10.129.9.91:3000/_next/static/[build-id]/_buildManifest.js

Conferma solo due route statiche: home e pagina di errore. Non c'è nulla da fuzzare.

Ho anche tentato brute force SSH con username basati sui profili dello staff visibili nella dashboard, senza risultati.

---

## Fase 3 — Identificazione del vettore

Testando gli endpoint interni di Next.js, l'endpoint /_next/image risponde 400 invece di 404, confermando che esiste. Più importante: la versione 15.0.3 è vulnerabile a CVE-2025-55182 (React2Shell). Lo verifico inviando una richiesta con gli header RSC tipici del protocollo React Server Components:

curl -s -H "RSC: 1" -H "Next-Action: anything" -H "Content-Type: text/plain" \
  --data-binary '...' \
  http://10.129.9.91:3000/ -w "%{http_code}"

Risposta 200. Il server accetta richieste RSC ed è vulnerabile.

---

## Fase 4 — RCE via React2Shell

Clono il PoC pubblico e lo eseguo:

git clone https://github.com/jensnesten/React2Shell-PoC.git
cd React2Shell-PoC
python3 main.py http://10.129.9.91:3000 'id'

Output:

uid=999(node) gid=988(node) groups=988(node)

RCE confermato come utente node. Il PoC sfrutta la deserializzazione insicura del protocollo RSC "flight" di Next.js: invia un payload JSON malevolo via POST, il server lo deserializza ed esegue il comando embedded.

Nota tecnica: i comandi che producono output lungo o binario vengono corrotti dal parser RSC. Soluzione: redirigere su file temporaneo e fare cat separato.

python3 main.py http://10.129.9.91:3000 'ls /opt/reactor-app > /tmp/o && cat /tmp/o'

Trovo nella root dell'app un file reactor.db.

---

## Fase 5 — Dump del database e crack hash

python3 main.py http://10.129.9.91:3000 'strings /opt/reactor-app/reactor.db > /tmp/o && cat /tmp/o'

Il database contiene una tabella users con due record. Estraggo due hash MD5. Il primo cracca su CrackStation, il secondo no (probabilmente salted).

Credenziali ottenute: engineer / [password]

---

## Fase 6 — User flag

ssh engineer@10.129.9.91

Accesso riuscito. Il file user.txt è nella home.

---

## Fase 7 — Privilege escalation

Enumerazione iniziale: sudo -l nega tutto, nessun SUID sospetto. Guardo i processi attivi:

ps aux | grep node

Trovo due processi Node.js. Uno gira come root con il flag --inspect=127.0.0.1:9229. Questo attiva il debugger di Node.js sulla porta 9229, che accetta connessioni WebSocket e permette di eseguire codice JavaScript arbitrario nel contesto del processo — in questo caso, root.

Recupero il session ID del debugger:

node -e "const http=require('http'); /* GET /json su 127.0.0.1:9229 */ ..."

Ottengo il webSocketDebuggerUrl con l'UUID della sessione. Il modulo ws non è disponibile, quindi costruisco l'handshake WebSocket manualmente via TCP con Python, poi invio un messaggio Chrome DevTools Protocol:

Runtime.evaluate con expression: process.mainModule.require("child_process").execSync("cat /root/root.txt").toString()

Nota: require() diretto non funziona nel contesto V8 nudo del debugger — bisogna usare process.mainModule.require().

Il debugger esegue il comando come root e restituisce il contenuto del file nella risposta JSON.

---

## Catena completa

RCE unauthenticated su Next.js 15.0.3 (CVE-2025-55182)
→ accesso come node (uid 999)
→ dump SQLite + crack MD5
→ SSH come engineer
→ Node.js Inspector esposto su processo root
→ esecuzione arbitraria via Chrome DevTools Protocol
→ root

---

## Note difensive

Aggiornare Next.js a versione 15.0.5 o superiore (fix per CVE-2025-55182). Non usare --inspect su processi in produzione, e mai su processi con privilegi elevati. Sostituire MD5 con bcrypt o Argon2 per gli hash delle password. I servizi di monitoraggio non hanno bisogno di girare come root: principio di least privilege.

<div class="writeup-image">
  <img src="/assets/writeups/reactor.png" alt="Proof of pwn">
  <div class="img-caption">Proof of pwn</div>
</div>
