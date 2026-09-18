---
layout: writeup
lang: it
permalink: /writeups/anthem/
title: "Anthem"
ref: anthem
date: 2026-09-09
bare: true
platform: THM
os: Windows Server 2019 (Umbraco 7.15.4 + Articulate)
difficulty: Easy
series: thm-windows
tags: [win, umbraco, osint, rdp, acl, privesc]
txt: /writeups-files/anthem.txt
summary: "Nessun exploit, solo osservazione. Password nel robots.txt, username ricavato dal soggetto di una poesia, privilege escalation riscrivendo le ACL di una cartella."
---

# Writeup — Anthem (TryHackMe)

OS: Windows Server 2019 (build 17763, Umbraco 7.15.4 + Articulate)
Difficoltà: Easy
Data: 9 settembre 2026

---

## Sommario

Macchina Windows Server 2019 non in dominio con due sole porte esposte, un webserver sulla 80 e RDP sulla 3389. Nessun exploit, nessun servizio vulnerabile: la room è interamente di osservazione. Il sito è un blog Umbraco con il plugin Articulate, e nasconde quattro flag in punti che non si vedono aprendo la pagina nel browser, tutti dentro il sorgente HTML o in campi anagrafici secondari. Il robots.txt contiene una password lasciata in cima al file fuori da qualsiasi sintassi valida. lo username corrispondente non è quello firmato in fondo ai post, che è l'autore reale della poesia citata, ma il soggetto della poesia stessa, ridotto alle iniziali secondo lo schema dell'email trovata nell'altro post. Da RDP come utente standard il filesystem è quasi vuoto, tranne un file di backup illeggibile: cambiandone le ACL dall'interfaccia di Windows si legge la password dell'Administrator, e da lì la root flag

Catena: nmap → 80 e 3389 → sorgente HTML → Umbraco/Articulate + prima flag nel placeholder di ricerca → robots.txt → password → RSS per i link reali dei post → meta og:description → due flag → pagina autore → quarta flag → poesia Solomon Grundy → username SG → RDP → user.txt → C:\backup\restore.txt illeggibile → ACL modificate → password Administrator → RDP come Administrator → root.txt.

---

## strumenti e metodologie aggiuntive

durante la sessione è stato utilizzato un llm: per recupero dettagli su CVE, interpretazione di output grezzi, suggerimenti su vettori inesplorati in caso di blocco e spiegazione dettagliata di concetti tecnici. l'esecuzione e le scelte operative erano mie. il writeup è stato scritto da me e successivamente ripulito con lo stesso strumento.

il collegamento tra la poesia e lo username è stato suggerito dal chatbot dopo che avevo esaurito una decina di formati basati sull'autore sbagliato. una flag, l'ultima, l'ho recuperata da un writeup pubblico dopo la scadenza della macchina: lo scrivo qui perché è l'unico passaggio di questa room che non ho eseguito personalmente.

---

## Premessa

room fatta dalla mia Kali virtualizzata, con la VPN già attiva dalla sessione precedente su Blueprint. tecnicamente non c'è niente di difficile, ma è la room in cui ho perso più tempo su un dettaglio solo: lo username RDP. la password si trova nei primi due minuti, il nome utente ha richiesto una quindicina di tentativi su tre persone diverse prima di capire di stare guardando il nome sbagliato

la seconda cosa che mi ha rallentato è che le flag saltano fuori da posti scollegati tra loro, meta tag, placeholder di un campo di ricerca, campi profilo, e quando le trovi non hai nessun modo di sapere a quale domanda della room corrispondono. le ho raccolte tutte prima e associate dopo,per tentativi.

la macchina è scaduta subito dopo la lettura della root flag e senza abbonamento non è ridispiegabile, quindi la parte finale di verifica dei privilegi da Administrator è rimasta non eseguita.

---

## Fase 1 — Ricognizione

stesso schema di scansione della room precedente:

IP=10.112.170.81; sudo nmap -sS -Pn -p- --min-rate 5000 -oN anthem_full.txt IP && sudo nmap -sV -sC -p (grep -oP '^\d+(?=/tcp\s+open)' anthem_full.txt | paste -sd,) -oN anthem_svc.txt $IP

Not shown: 65533 filtered tcp ports (no-response)
80/tcp open http
3389/tcp open ms-wbt-server

il secondo scan è saltato subito con "Host seems down": nella concatenazione avevo lasciato il -Pn solo nel primo comando, e su un host che filtra tutto il resto il ping preliminare fallisce. rilanciato a mano:

sudo nmap -sV -sC -Pn -p80,3389 -oN anthem_svc.txt 10.112.170.81

80/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
3389/tcp open ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
| Target_Name: WIN-LU09299160F
| NetBIOS_Domain_Name: WIN-LU09299160F
| DNS_Computer_Name: WIN-LU09299160F
| Product_Version: 10.0.17763

Windows Server 2019, hostname WIN-LU09299160F, e il fatto che dominio NetBIOS e nome macchina coincidano conferma che non è in dominio: gli account sono locali. tutte le altre 65533 porte sono filtered, non closed, quindi c'è un firewall che scarta invece di rifiutare .

con due sole porte e nessuna versione vulnerabile in vista, il webserver è l'unica superficie da lavorare.

---

## Fase 2 — Sorgente della homepage

invece di aprire il sito nel browser leggo direttamente l'HTML grezzo, che è più veloce e mostra anche quello che il browser non renderizza:

curl -s http://10.112.170.81/ | head -60

dalla testa della pagina esce tutto quello che serve per inquadrare l'applicazione:

<link href="/DependencyHandler.axd?s=L0FwcF9QbHVnaW5zL0FydGljdWxhdGUvVGhlbWVzL1ZBUE9SL... <div class="bloglogo" style="background: url(/media/articulate/default/capture3.png...

il path /App_Plugins/Articulate/Themes/VAPOR/ (leggibile anche in base64 dentro il DependencyHandler) identifica Umbraco come CMS, con sopra il plugin blog Articulate e il tema VAPOR. sono esposti anche gli endpoint standard del plugin: /rss, /archive/, /categories, /tags, /opensearch, /rsd/1073, /wlwmanifest/1073.

e nella barra di ricerca, dentro l'attributo placeholder, c'è la prima flag:

<input type="text" name="term" placeholder="Search... THM{G!T_G00D}" />

invisibile guardando la pagina, perché il testo è preceduto da una cinquantina di spazi e viene troncato dal campo. si vede solo nel sorgente.

---

## Fase 3 — robots.txt

curl -s http://10.112.170.81/robots.txt

UmbracoIsTheBest!

Use for all search robots

User-agent: *

Define the directories not to crawl

Disallow: /bin/
Disallow: /config/
Disallow: /umbraco/
Disallow: /umbraco_client/

robots.txt è un file di testo che sta nella root di qualunque sito e serve a dire ai crawler dei motori di ricerca quali cartelle non indicizzare. non è un endpoint applicativo e non è una protezione: chiunque lo può leggere, e proprio perché elenca le cartelle che il proprietario vorrebbe nascondere spesso rivela i path amministrativi. va letto sempre, subito dopo la homepage, insieme a sitemap.xml

qui conferma /umbraco/ come pannello di amministrazione, ma soprattutto ha in cima una riga che con la sintassi del file non c'entra niente: UmbracoIsTheBest!. è una password, lasciata lì da qualcuno e mai tolta.

---

## Fase 4 — I post e la ricerca dell'autore

la password ce l'ho, manca lo username. i post del blog sono due, "We are hiring" e "A cheers to our IT department".

primo errore: ho provato a indovinare le URL dei post con lo schema a data tipico di WordPress (/2021/04/we-are-hiring/), e Articulate mi ha risposto sempre con la pagina archivio invece del singolo post, facendomi credere per un paio di tentativi di stare leggendo il contenuto giusto. i link veri stanno nel feed RSS, che il blog espone e che nessuno mi impediva di leggere:

curl -s http://10.112.170.81/rss | grep -oP '(?<=<link>)[^<]+'

http://10.112.170.81/
http://10.112.170.81/archive/we-are-hiring/
http://10.112.170.81/archive/a-cheers-to-our-it-department/

il secondo post contiene la poesia:

curl -s http://10.112.170.81/archive/a-cheers-to-our-it-department/ | sed -e 's/<[^>]>//g' | grep -v '^\s$' | head -40

During our hard times our beloved admin managed to save our business by redesigning the entire website.
As we all around here knows how much I love writing poems I decided to write one about him:
Born on a Monday,Christened on Tuesday,Married on Wednesday,Took ill on Thursday,
Grew worse on Friday,Died on Saturday,Buried on Sunday.That was the end...
Author
James Orchard Halliwell

il primo post dà l'altro pezzo:

If you have an interest in being a part of the movement send me your CV at JD@anthem.com
Author
Jane Doe

quindi due nomi e un formato email. da qui parte una lunga serie di tentativi falliti,prima con xfreerdp:

xfreerdp3 /v:10.112.170.81 /u:jhalliwell /p:'UmbracoIsTheBest!' /cert:ignore +clipboard /dynamic-resolution

[ERROR][com.freerdp.core.rdp] - CONNECTION_STATE_NLA - nla_recv_pdu() fail

xfreerdp3 è il client RDP per Linux da riga di comando, l'equivalente di Connessione Desktop Remoto di Windows. /u: è l'utente locale, /p: la password trovata nel robots.txt, /cert:ignore accetta il certificato self-signed della macchina. ogni tentativo però richiede di aspettare l'handshake completo, ed è lento.

per accorciare passo a NetExec, che testa le credenziali contro il protocollo senza aprire la sessione grafica:

nxc rdp 10.112.170.81 -u jane.doe -p 'UmbracoIsTheBest!'

RDP 10.112.170.81 3389 WIN-LU09299160F [*] Windows 10 or Windows Server 2016 Build 17763 (name:WIN-LU09299160F) (domain:WIN-LU09299160F) (nla:False)
RDP 10.112.170.81 3389 WIN-LU09299160F [-] WIN-LU09299160F\jane.doe:UmbracoIsTheBest! (STATUS_LOGON_FAILURE)

nla:False è un'informazione utile in sé: l'autenticazione a livello di rete è disattivata, quindi l'autenticazione avviene dopo aver stabilito la sessione e non prima. STATUS_LOGON_FAILURE però non distingue tra utente inesistente e password errata, quindi non conferma né esclude il nome.

con un ciclo si testano nove formati in pochi secondi:

for u in JD jd jane janedoe j.doe doe UmbracoAdmin admin administrator; do nxc rdp 10.112.170.81 -u $u -p 'UmbracoIsTheBest!'; done

tutti STATUS_LOGON_FAILURE. compreso administrator, che con quella password non entra.

il ragionamento che sblocca la situazione: il post dice che la poesia è dedicata all'admin, e la firma in fondo alla pagina è di chi ha scritto il testo, non di chi ne è il soggetto. la poesia è Solomon Grundy, filastrocca inglese raccolta e pubblicata proprio da James Orchard Halliwell. l'admin quindi si chiama Solomon Grundy, e il formato dell'email dell'altro post (JD@anthem.com per Jane Doe) dice che su questa macchina gli account sono le sole iniziali.

for u in SG sg solomon grundy s.grundy sgrundy solomon.grundy; do nxc rdp 10.112.170.81 -u $u -p 'UmbracoIsTheBest!'; done

RDP 10.112.170.81 3389 WIN-LU09299160F [+] WIN-LU09299160F\SG:UmbracoIsTheBest! (Pwn3d!)
RDP 10.112.170.81 3389 WIN-LU09299160F [+] WIN-LU09299160F\sg:UmbracoIsTheBest! (Pwn3d!)

funziona sia maiuscolo che minuscolo perché Windows non distingue il case negli username. le varianti estese falliscono tutte, quindi l'account è esattamente SG.

---

## Fase 5 — Le flag nascoste nei meta

la prima flag stava in un attributo HTML, quindi vale la pena grepparne il sorgente di ogni pagina invece di leggerle a occhio:

curl -s 'http://10.112.170.81/archive/we-are-hiring/' | grep -iE 'user|admin|THM|<!--'

<meta content="THM{L0L_WH0_US3S_M3T4}" property="og:description" />

stesso trattamento sull'altro post:

curl -s 'http://10.112.170.81/archive/a-cheers-to-our-it-department/' | grep -iE 'THM|<!--|user'

<meta content="THM{AN0TH3R_M3TA}" property="og:description" />

il campo og:description è il testo che comparirebbe nell'anteprima quando il link viene condiviso su un social. nessuno lo legge nel browser, ed è per questo che ci hanno messo le flag dentro.

(nota sulle graffe: grep -iE "THM{...}" con le doppie virgolette in zsh dà "event not found" per via del punto esclamativo e dell'espansione della history. con gli apici singoli funziona.)

la quarta flag non l'ho trovata durante la sessione, e con la macchina scaduta l'ho recuperata da un writeup pubblico. sta nel campo Website della pagina profilo dell'autore, /authors/jane-doe/, che Articulate genera automaticamente per ogni autore e che è linkata dalla firma in fondo ai post:

curl -s http://10.112.170.81/authors/jane-doe/ | grep -o 'THM{[^}]*}'

THM{L0L_WH0_D15}

è lo stesso schema delle altre due, un valore piazzato in un campo anagrafico che nessuno legge, e l'avrei presa con lo stesso grep se avessi seguito il link dell'autore invece di fermarmi ai due post.

Flag raccolte: THM{G!T_G00D} nel placeholder di ricerca, THM{L0L_WH0_US3S_M3T4} e THM{AN0TH3R_M3TA} nei meta og:description dei due post, THM{L0L_WH0_D15} nel campo Website della pagina autore.

---

## Fase 6 — Accesso RDP e user flag

xfreerdp3 /v:10.112.170.81 /u:'SG' /p:'UmbracoIsTheBest!' /cert:ignore +clipboard /dynamic-resolution

sessione desktop completa come SG. sul desktop c'è la user flag:

THM{N00T_NO0T}

il resto del filesystem è quasi tutto vuoto o inaccessibile, ma vale la pena annotare cosa c'è e cosa no, perché la forma del disco è essa stessa un indizio:

C:\Users\SG contiene le cinque cartelle standard (Music, Videos, Pictures, Documents, Downloads) tutte vuote. C:\Users\Public idem.

C:\inetpub ha le cinque cartelle di IIS: custerr, history, logs, temp, wwwroot. logs, history e temp\IIS Temporary Compressed Files non sono apribili con i privilegi di SG. custerr\en-US contiene solo le pagine di errore HTML predefinite (500-17, 500-18, 500-19, 404-9, 404-10).

sotto wwwroot c'è la cartella Web con l'applicazione: robots.txt (lo stesso già letto via HTTP, password compresa), default.aspx che è tre righe di direttiva Umbraco, global.asax che ne è una sola, e web.config, che è l'unico file corposo. leggendolo con Blocco note si conferma umbracoConfigurationStatus 7.15.4, il database su SQL Server Compact (Umbraco.sdf) invece che su un server esterno, umbracoUseSSL false, e in fondo un blocco machineKey con validationKey e decryptionKey in chiaro. non serve per questa room ma è materiale sensibile lasciato leggibile a un utente standard

C:\ProgramData è invece pieno e accessibile, con le cartelle dei servizi installati: ssh, VMware, USOShared, USOPrivate, Amazon, Microsoft, regid.1991-06.

in C:\Users\SG\AppData\Local\Temp c'è wmsetup.log, che data l'installazione della macchina:

[*WMC Logging begun at 2020/04/05 - 23:40:06. Logging at level: '4'. OS is NT. OSVer is 10.0.17763.0.475. System Lang is 2057.]
Current command line: '/FirstLogon'.

System Lang 2057 è l'inglese britannico, coerente con il fuso orario visto nello scan iniziale.

C:\Temp non esiste, C:\Windows\Temp richiede privilegi, C:\Program Files\Umbraco non esiste (l'applicazione sta sotto inetpub), C:\Users\Administrator non è accessibile.

l'unica cosa fuori posto è C:\backup, che contiene un solo file, restore.txt, non apribile con i privilegi di SG. una cartella di backup a livello di root su una macchina con tutti i profili utente vuoti ma con date di creazione coerenti è esattamente il tipo di anomalia da guardare.

---

## Fase 7 — ACL e privilege escalation

il file non è leggibile ma la cartella è mia da modificare come proprietario effettivo, e Windows permette di riscrivere le ACL dall'interfaccia grafica senza toccare la riga di comando. tasto destro su C:\backup, Proprietà, scheda Sicurezza, Avanzate, Aggiungi.

la voce di permesso inserita:

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
[ ] Special permissions (non selezionabile)

[ ] Only apply these permissions to objects and/or containers within this container

"Applies to: This folder, subfolders and files" è il campo che conta, perché senza quello il permesso resterebbe sulla cartella e non si propagherebbe al file dentro. confermato con OK e riapplicato, restore.txt si apre con Blocco note:

ChangeMeBaby1MoreTime

password dell'account Administrator locale. seconda sessione RDP:

xfreerdp3 /v:10.112.170.81 /u:'Administrator' /p:'ChangeMeBaby1MoreTime' /cert:ignore +clipboard /dynamic-resolution

desktop di Administrator con Server Manager che si apre da solo al login, filesystem interamente navigabile, e la root flag:

THM{Y0U_4R3_1337}

la sequenza sintetica di questa fase: da SG il file C:\backup\restore.txt è illeggibile, si aggiunge SG con controllo completo nelle ACL avanzate della cartella propagando ai file contenuti, dentro c'è la password dell'Administrator locale, si riapre RDP con quell'account e la flag è sul suo desktop.

la macchina è scaduta pochi minuti dopo, quindi la prova concreta dei privilegi da Administrator (scrittura in System32, creazione di un account locale nel gruppo Administrators, chiave di Run nel registro) è rimasta pianificata ma non eseguita. lo segnalo invece di presentarla come fatta.

---

## Catena completa

nmap → solo 80 e 3389, Windows Server 2019 non in dominio
→ sorgente HTML della homepage → Umbraco 7.15.4 + Articulate
→ prima flag nel placeholder del campo di ricerca
→ robots.txt → password UmbracoIsTheBest! fuori sintassi in cima al file
→ URL dei post indovinate male → RSS per i link reali
→ post 1: email JD@anthem.com, autore Jane Doe
→ post 2: poesia Solomon Grundy, firmata James Orchard Halliwell
→ meta og:description dei due post → seconda e terza flag
→ pagina autore /authors/jane-doe/, campo Website → quarta flag
→ una quindicina di username falliti su nxc rdp
→ soggetto della poesia + schema iniziali dall'email → SG
→ RDP come SG → user.txt
→ filesystem vuoto tranne C:\backup\restore.txt illeggibile
→ ACL avanzate: SG con Full control propagato ai file → password Administrator
→ RDP come Administrator → root.txt

---

## Lezioni apprese

la firma in fondo a un contenuto dice chi lo ha scritto, non di chi parla. tutta la difficoltà di questa room stava lì, e ho bruciato una quindicina di tentativi di login su due persone sbagliate prima di rileggere la frase che introduceva la poesia, dove era scritto in chiaro che il testo era dedicato all'admin e non firmato da lui.

quando una flag si trova in un attributo HTML, tutte le altre saranno nello stesso tipo di posto. dopo la prima nel placeholder avrei dovuto grepparne subito ogni pagina generata dal CMS, comprese quelle secondarie come i profili autore, invece di limitarmi ai contenuti principali. il comando for p in / /categories /tags /archive/ /authors/; do curl -s "$IP$p" | grep -o 'THM{[^}]*}'; done avrebbe chiuso la fase in un colpo solo.

testare le credenziali con uno strumento che parla il protocollo (nxc) invece che con il client completo (xfreerdp) cambia i tempi di un ordine di grandezza quando i tentativi sono molti. la stessa cosa vale ogni volta che serve provare una lista di username.

su Windows non avere il permesso di leggere un file non significa non poterlo leggere: se si controlla la cartella, le ACL si riscrivono dall'interfaccia in tre click, e il permesso va propagato esplicitamente ai file contenuti o resta sulla cartella e basta

---

## Tool utilizzati

nmap, curl, sed, grep, NetExec (nxc rdp), xfreerdp3, Esplora risorse e editor ACL di Windows, Blocco note
