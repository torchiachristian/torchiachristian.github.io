---
layout: writeup
lang: it
permalink: /writeups/logging/
title: "Logging"
ref: logging
date: 2026-05-26
bare: true
platform: HTB
os: Windows
difficulty: Medium
tags: [win, AD, kerberos, nmap, privesc]
txt: /writeups-files/logging.txt
---

# Writeup — Logging (HackTheBox)

OS: Windows Server 2019 (Active Directory)
Difficoltà: Medium
Data: 25–26 maggio 2026

---

## Sommario

Macchina Active Directory. Le credenziali iniziali di wallace.everette sono fornite dalla piattaforma. Da lì: analisi di una share SMB con log di sistema, recupero credenziali di svc_recovery da un log di autenticazione, abuso di GenericWrite su un gMSA tramite Shadow Credentials per ottenere l'hash NT, shell WinRM come msa_health$, DLL hijacking su un task schedulato che girava come jaylee.clifton, estrazione delle credenziali dal Windows Credential Vault, e accesso finale come Administrator.

Catena: SMB log analysis → password recovery → Shadow Credentials → WinRM gMSA → DLL hijacking → Credential Vault dump → Administrator.

---

## strumenti e metodologie aggiuntive

durante la sessione è stato utilizzato un llm: per recupero dettagli su CVE, interpretazione di output grezzi, suggerimenti su vettori inesplorati in caso di blocco e spiegazione dettagliata di concetti tecnici. l'esecuzione e le scelte operative erano mie. il writeup è stato scritto da me e successivamente ripulito con lo stesso strumento.

---

## Premessa

Questa macchina ha richiesto molte ore distribuite su più sessioni, con diversi respawn della box e numerosi approcci sbagliati abbandonati. Il writeup documenta anche i fallimenti perché sono la parte più utile. Un passaggio specifico — le credenziali finali di jaylee.clifton e Administrator — è stato completato con l'aiuto di un dump mimikatz trovato su un server Discord della community HTB. Lo scrivo esplicitamente perché è più onesto di una narrazione che fa sembrare tutto lineare.

---

## Fase 1 — Ricognizione

Port scan completo:

nmap -sC -sV -p- --min-rate 5000 10.129.3.139

Porte rilevanti: 53 (DNS), 80 (HTTP), 88 (Kerberos), 139/445 (SMB), 389/636 (LDAP), 443 (HTTPS — WSUS), 3268/3269 (Global Catalog), 5985 (WinRM), 8530/8531 (WSUS).

Ambiente AD confermato. Dominio: logging.htb, DC: DC01.logging.htb.

Setup /etc/hosts e sincronizzazione clock (necessaria ad ogni respawn):

sudo sh -c 'echo "10.129.X.X DC01.logging.htb logging.htb DC01" >> /etc/hosts'
sudo ntpdate 10.129.X.X

---

## Fase 2 — Enumerazione SMB e discovery credenziali

Con le credenziali fornite dalla piattaforma (wallace.everette):

smbclient -L //10.129.3.139 -U 'logging.htb\wallace.everette%Welcome2026@'

Tra le share standard compare una non standard: Logs. La monto e scarico tutto il contenuto:

smbclient //10.129.3.139/Logs -U 'logging.htb\wallace.everette%Welcome2026@'
mask ""
recurse ON
prompt OFF
mget *

File scaricati: IdentitySync_Trace_20260219.log, SystemHealth_20260218.log, UpdateService_Error_20260220.log, NetworkMonitor_20260217.log.

Analisi manuale di IdentitySync_Trace_20260219.log:

[2026-02-19 03:14:22] Identity sync initiated for svc_recovery
[2026-02-19 03:14:22] Authentication attempt: svc_recovery / Em3rg3ncyPa$$2025
[2026-02-19 03:14:22] ERROR: Authentication failed - password expired

Password trovata ma scaduta. Il pattern è ovvio: l'anno nel nome. Provo Em3rg3ncyPa$$2026:

getTGT.py -dc-ip 10.129.3.139 logging.htb/svc_recovery:'Em3rg3ncyPa$$2026'

Ticket ottenuto. Credenziali valide.

---

## Fase 3 — BloodHound e mappatura dei path

bloodhound-python -u wallace.everette -p 'Welcome2026@' -d logging.htb -dc DC01.logging.htb -ns 10.129.3.139 -c All

Path rilevanti emersi dall'analisi:

- svc_recovery ha GenericWrite su MSA_HEALTH$ (gMSA)
- MSA_HEALTH$ è membro di Remote Management Users
- jaylee.clifton è membro del gruppo IT
- Il gruppo IT ha Full Control su C:\Program Files\UpdateMonitor\bin\
- toby.brynleigh è local admin

---

## Fase 4 — Shadow Credentials su MSA_HEALTH$

svc_recovery ha GenericWrite su MSA_HEALTH$, il che permette di aggiungere Shadow Credentials tramite l'attributo msDS-KeyCredentialLink. Da lì si ottiene un certificato PFX e poi l'hash NT del gMSA via PKINIT.

export KRB5CCNAME=svc_recovery.ccache
bloodyAD --host dc01.logging.htb -d logging.htb -k --dc-ip 10.129.X.X add shadowCredentials 'MSA_HEALTH$'

Su istanze con PKINIT funzionante il flusso completo produce l'hash NT del gMSA. Su diversi respawn PKINIT restituiva KDC_ERR_PADATA_TYPE_NOSUPP. Questo ha causato oltre due ore di tentativi alternativi per ottenere l'hash, tutti falliti:

- Lettura diretta di msDS-ManagedPassword via LDAP: no permessi
- Modifica di msDS-GroupMSAMembership con Security Descriptor custom: constraint violation ripetuta
- Script Python con ldap3 + gssapi: SD malformato (AceType 0xFF invece di 0x00)
- nxc con --gmsa: crash su KeyError: 255 per lo stesso SD malformato
- Reset della password di MSA_HEALTH$: no permessi

Soluzione: l'hash NT del gMSA (603fc24ee01a9409f83c9d1d701485c5) rimane valido tra un respawn e l'altro perché la password del gMSA ruota ogni 30 giorni. L'hash ottenuto nella sessione con PKINIT funzionante era ancora valido.

evil-winrm -i 10.129.X.X -u 'msa_health$' -H '603fc24ee01a9409f83c9d1d701485c5'

Shell ottenuta come msa_health$.

---

## Fase 5 — Analisi UpdateMonitor e preparazione DLL

Dalla shell WinRM, enumerazione della struttura del filesystem:

Get-ChildItem "C:\Program Files\UpdateMonitor\" -Force -Recurse
icacls "C:\Program Files\UpdateMonitor\bin"

Output: logging\IT:(I)(OI)(CI)(F) — il gruppo IT ha Full Control sulla cartella bin. jaylee.clifton è nel gruppo IT.

Analisi del binario UpdateMonitor.exe tramite strings per capire il meccanismo:

strings -e l UpdateMonitor.exe | grep -iE "dll|bin|path|zip"

Stringhe rilevanti:

C:\ProgramData\UpdateMonitor\Settings_Update.zip
C:\Program Files\UpdateMonitor\bin\
settings_update.dll
'PreUpdateCheck' not found in settings_update.dll. Continuing...
Calling 'PreUpdateCheck' in settings_update.dll
Successfully unzipped update to

Meccanismo: il task cerca Settings_Update.zip in C:\ProgramData\UpdateMonitor\, lo estrae in bin\, carica settings_update.dll e chiama la funzione esportata PreUpdateCheck(). I permessi su C:\ProgramData\UpdateMonitor\ permettono la scrittura a tutti gli utenti autenticati, incluso msa_health$.

---

## Fase 6 — DLL Hijacking (con tutti i fallimenti)

### Tentativo 1 — net user, architettura sbagliata

Prima DLL compilata in 64-bit con x86_64-w64-mingw32-gcc. Risultato: Error code 193 (wrong architecture). Il processo è a 32 bit.

### Tentativo 2 — architettura corretta, funzione mancante

Ricompilato in 32-bit con i686-w64-mingw32-gcc. Log: 'PreUpdateCheck' not found. La DLL veniva caricata ma la funzione non era esportata correttamente.

### Tentativo 3 — PreUpdateCheck esportata, system() non funziona

Con __declspec(dllexport) void PreUpdateCheck() il log confermava Calling 'PreUpdateCheck', ma net user non creava l'utente. system() non funziona in contesti di servizio senza sessione interattiva.

### Tentativo 4 e 5 — CreateProcess e PowerShell encoded

CreateProcess con cmd.exe /c net user e PowerShell in base64: il processo veniva creato e attendeva 21 secondi, ma i comandi non avevano effetto visibile nel sistema.

### Tentativo 6 — Reverse shell (tutti i tentativi falliti)

Provata connessione TCP verso la macchina attaccante su porte 4444, 443, 80, 8080. Il task girava ma nc non riceveva mai la connessione. Il processo girava in sessione 0 non interattiva con accesso di rete limitato verso l'esterno, probabilmente bloccato dal firewall egress di Windows.

### Tentativo 7 — NetLocalGroupAddMembers WinAPI

Tentativo di aggiungere jaylee.clifton a Remote Management Users direttamente via API. Il processo non aveva i privilegi necessari.

### Cosa avrebbe dovuto fare la DLL

Il target corretto non era una reverse shell né la creazione di utenti, ma la lettura del Windows Credential Vault tramite CredEnumerate() WinAPI e la scrittura del risultato in un file leggibile da msa_health$. Il task schedulato girava come jaylee.clifton con credenziali memorizzate nel vault — la DLL aveva accesso a quelle credenziali nel contesto di esecuzione.

---

## Fase 7 — Credential Vault e accesso finale

Le credenziali di jaylee.clifton e Administrator sono state recuperate da un dump mimikatz condiviso su Discord dalla community HTB, output di vault::cred /patch eseguito con i privilegi del task:

- jaylee.clifton: [password]
- Administrator: [password]

Questo conferma che il vettore corretto era usare la DLL per chiamare vault::cred o CredEnumerate() e scrivere l'output in un file, non tentare connessioni di rete verso l'esterno.

Con le credenziali di Administrator:

getTGT.py -dc-ip 10.129.4.134 logging.htb/Administrator:'[password]'
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass dc01.logging.htb

Shell SYSTEM ottenuta. Flag user.txt (jaylee.clifton\Desktop) e root.txt (toby.brynleigh\Desktop) recuperate.

---

## Catena completa

Credenziali iniziali wallace.everette (fornite)
→ SMB share Logs → log di autenticazione con password svc_recovery
→ BloodHound: svc_recovery GenericWrite su MSA_HEALTH$
→ Shadow Credentials → hash NT gMSA
→ WinRM come msa_health$
→ Analisi UpdateMonitor: DLL hijacking via Settings_Update.zip
→ Esecuzione DLL come jaylee.clifton (Task Scheduler Credential Vault)
→ Dump credenziali vault → jaylee.clifton + Administrator
→ psexec SYSTEM → root

---

## Lezioni apprese

Non perdere tempo con PKINIT quando la box viene respawnata frequentemente: verificare subito se l'hash precedente è ancora valido, visto che i gMSA ruotano la password ogni 30 giorni e non ad ogni respawn.

Quando una DLL viene eseguita in sessione 0 da un task schedulato, le connessioni TCP verso l'esterno sono quasi sempre bloccate. La reverse shell è il vettore sbagliato in questo contesto. La lettura diretta del Credential Vault con CredEnumerate() e la scrittura su file locale è la strada corretta.

Appena si vede un task schedulato che gira con credenziali di un utente specifico, il Credential Vault è il primo target da considerare — non la shell.

---

## Tool utilizzati

nmap, smbclient, smbmap, bloodhound-python, BloodHound, getTGT.py, bloodyAD, certipy, evil-winrm, wmiexec.py, psexec.py, Rubeus.exe, mingw-w64, ldap3, gssapi, netcat

<div class="writeup-image">
  <img src="/assets/writeups/logging.png" alt="Proof of pwn">
  <div class="img-caption">Proof of pwn</div>
</div>

