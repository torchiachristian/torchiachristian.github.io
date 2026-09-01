---
layout: writeup
lang: it
permalink: /writeups/ad-attack-toolkit/
title: "AD Attack Toolkit — tool testing"
ref: ad-attack-toolkit
date: 2026-06-28
kind: lab
bare: true
platform: LAB
platform_color: "#1d4ed8"
os: Windows
tags: [win, AD, kerberos, ldap, python, tooling]
txt: /writeups-files/adtoolkit-lab-test.txt
repo: https://github.com/torchiachristian/ad-attack-toolkit
---

# Writeup — AD Attack Toolkit, test su nuovo dominio

OS: Windows Server 2022 (Active Directory)
Tipo: progetto personale/testing tool offensivo
Data: 28 giugno 2026
Repo del tool: github.com/torchiachristian/ad-attack-toolkit

---

## Sommario

ad-attack-toolkit è un mio tool Python sviluppato in precedenza che automatizza un assessment semplice su Active Directory: esegue un' enumerazione LDAP, attacchi ASREP Roasting, Kerberoasting, Pass-the-Hash, e produce un report PDF finale. Fino ad ora l'avevo runnato solo sul dominio su cui era stato sviluppato. L'obiettivo di questa sessione era costruire da zero un dominio nuovo per esercizio e verificare se reggeva un utilizzo pulito, cioè se funzionava davvero su un AD configurato indipendentemente o se nascondeva bug emersi solo perché tarato su misura sul primo AD.

Risultato: il tool funzionava in parte e riportava bug. Su un dominio nuovo è andato in crash alla prima fase per un errore nel bind LDAP, e una volta superato quello ha prodotto hash di Kerberoasting in un formato che hashcat rifiutava diverse volte. un secondo bug riportava difetti sovrapposti riguardo casi speciali,tutti corretti. Il tool è stato rinominato poi in versione 1.1, con la catena completa enumerazione -> cattura hash -> cracking finalmente funzionante su un ambiente indipendente.

Catena del test: build dominio nuovo -> run tool -> crash bind LDAP -> fix -> run -> hash Kerberoasting malformati -> diagnosi su 3 difetti -> fix -> cracking completo delle 4 password.

---

## strumenti e metodologie aggiuntive

durante la sessione è stato utilizzato un llm per: interpretazione di output verbosi e grezzi, spiegazione dettagliata di concetti tecnici, diagnosi dei bug e correzioni mirate al codice. l'esecuzione e le scelte operative erano mie. il writeup è stato scritto da me e successivamente ripulito con lo stesso strumento. 

---

## Premesse

Il senso del test era non fidarsi del fatto che "sul mio dominio funziona ". Un tool offensivo che funziona solo sull'ambiente in cui è nato è migliorabile: assume valore operando su un AD qualsiasi. Per questo ho costruito un dominio nuovo (psychosec.local) con utenti e misconfigurazioni messe a mano, partendo da zero, e ci ho puntato il tool senza adattarlo. I due bug che sono emersi sono il tipo di problema che non vedi finché non cambi ambiente.

L'ambiente è un lab isolato e ricreabile da chiunque dal README del repo.
---

## Fase 1 — Costruzione del dominio di test

Lab in VirtualBox, rete isolata (192.168.56.0/24, no uscite verso internet). Un Domain Controller Windows Server 2022 a 192.168.56.10, dominio psychosec.local.

Promozione a DC e popolamento del dominio con bersagli volutamente vulnerabili: due utenti con pre autenticazione Kerberos disabilitata (target ASREP), due service account con SPN registrato e password deboli (target Kerberoasting), alcuni Domain Admin. Personalmente creati a mano via PowerShell, così la configurazione è indipendente da qualsiasi assunzione del tool.

Nota: in fase di promozione il NetBIOS del dominio è stato scritto PSYCHOSE invece di PSYCHOSEC (una lettera persa). Il DNS però restava psychosec.local corretto. Dettaglio casuale che si è rivelato la chiave per scoprire il primo bug.

---

## Fase 2 — Primo run: crash sul bind LDAP

Tool clonato dal mio repo, ambiente virtuale attivato, dipendenze (ldap3, impacket,reportlab), e lancio contro il DC:

python3 ad_attack.py --dc-ip 192.168.56.10 --domain psychosec.local -u labadmin -p '****' --all

Crash in Fase 1:

ERROR - Errore: automatic bind not successful - invalidCredentials

[SCREENSHOT: adtoolkit-bind-fail.png]

Le credenziali erano corrette, il DC rispondeva, la rete funzionava. Per isolare il problema ho testato il bind a parte, provando le tre forme dell'username:

labadmin@psychosec.local   -> OK
PSYCHOSE\labadmin          -> OK
labadmin                   -> FAIL (invalidCredentials)

Solo l'username falliva. Active Directory, con bind SIMPLE, vuole l'utente in forma user@dominio o NetBIOS (DOMINIO\user), non il nome secco. Quindi il tool stava passando a LDAP qualcosa che AD non poteva risolvere.

---

## Fase 3 — Bug del bind (errore di programmazione)

Aggiungendo un print nel punto del bind ho fatto debugging:

username ricevuto: 'PSYCHOSEC\labadmin'

Qui si è chiuso il cerchio con il refuso del NetBIOS. L'orchestratore ad_attack.py costruiva l'username da solo, così:

  f"{args.domain.split('.')[0].upper()}\\{args.username}"

Cosa sbagliava: prende psychosec.local, taglia al primo punto -> psychosec, lo rende maiuscolo -> PSYCHOSEC (con la C), e antepone all'username. Risultato: PSYCHOSEC\labadmin. Ma il NetBIOS reale del dominio era PSYCHOSE (senza C). Il tool tentava il bind verso un dominio NetBIOS che non esiste, da cui invalidCredentials. 

Versione prima (ad_enum.py, connect_ldap):

  conn = Connection(server, user=username, password=password, auto_bind=True)

Versione dopo:

  if "@" in username or "\\" in username:
      bind_user = username
  elif domain:
      bind_user = f"{username}@{domain}"
  else:
      bind_user = username
  conn = Connection(server, user=bind_user, password=password, auto_bind=True)

E in ad_attack.py, invece di anteporre un NetBIOS derivato a mano, ora si passa l'username grezzo più il dominio, lasciando alla funzione il compito di costruire l'UPN corretto. Il bind diventa labadmin@psychosec.local, che AD accetta. Funziona su qualsiasi dominio, senza assunzioni sul NetBIOS.

Dopo il fix, Fase 1 pulita: 12 utenti enumerati, 48 gruppi, 2 target AS-REP, 2 target Kerberoasting, 3 Domain Admin individuati.

[SCREENSHOT: adtoolkit-enum.png]

---

## Fase 4 — AS-REP Roasting e primo cracking con librerie

Catturati i due hash ASREP (in etype 23, RC4):

$krb5asrep$23$user.nopreauth@PSYCHOSEC.LOCAL:e868...c36a6

Primo tentativo di cracking con libreria rockyou.txt: esito Exhausted, zero recuperati. Non un bug ma realismo. Le password del lab (struttura Parola+numeri+simbolo) pur essendo deboli per policy non comparivano come righe esatte nel dizionario. Con una wordlist mirata:

user.nopreauth -> [password]
test.nopreauth -> [password]

Su un target reale si costruiscono wordlist mirate sull'organizzazione specifica

---

## Fase 5 — Kerberoasting: hash rifiutati da hashcat

Catturati i due hash TGS, ma al cracking hashcat li rifiutava:

Token length exception / Separator unmatched (errore ripetuto parecchie volte) / No hashes loaded

Il problema era il formato dell'hash, non la password. Per avere un riferimento certo del formato corretto ho richiesto gli stessi TGS con GetUserSPNs.py di impacket, che li scrive nel formato che hashcat accetta, e ho confrontato carattere per carattere il mio output con il suo. Da li sono emersi tre difetti sovrapposti in kerberoast.py.

---

## Fase 6 — I tre difetti del formato TGS (con il confronto)

Il formato che hashcat (mode 13100) si aspetta è:

  $krb5tgs$23$*user$realm$spn*$checksum$ticket

Quello che il mio tool produceva:

  $krb5tgs$23$*SPN*$REALM$SPN*$tuttoilcipherattaccato

### Difetto 1 = SPN duplicato con asterisco di troppo

Il tool scriveva *{spn}*${realm}${spn}* chiudendo il primo blocco con un asterisco e riaprendolo. Il formato vuole un solo blocco tra asterischi con i campi separati internamente da $. Asterisco di chiusura rimosso.

### Difetto 2 = la porta nel campo SPN

Il primo campo conteneva l'SPN intero MSSQLSvc/DC01.psychosec.local:1433. I due punti di :1433 mandavano in confusione il parser dei separatori. Risolto pulendo l'SPN dalla porta e usando come primo campo un'etichetta priva di / e di : 

### Difetto 3  = checksum non separato dal ticket

Confrontando con impacket:

  mio:       ...*$869409c2...   (cipher tutto attaccato)
  impacket:  ...*$e8d4d970b4a4b02345c89d3900fa30a9$fc15...   (un $ dopo 32 hex)

hashcat vuole il checksum (primi 16 byte =32 hex) separato dal resto del ticket con un $. Il mio tool buttava tutto il cipher in un blocco unico. 
Blocco inserito: 
  checksum = cipher_data[:32]
  ticket   = cipher_data[32:]
  hash_str = f"$krb5tgs${etype}$*{spn_label}${domain_upper}${spn_clean}*${checksum}${ticket}"

Tutti e tre i difetti erano invisibili sul dominio di sviluppo e sono saltati fuori solo provando a craccare per davvero su un ambiente nuovo.

---

## Fase 7 — Verifica finale

Rigenerati gli hash TGS col tool corretto e craccati direttamente, senza più passare da impacket (potfile disabilitato per testare il formato vero e NON la cache):

svc_sql    -> [password]
svc_backup -> [password]

[SCREENSHOT: adtoolkit-report.png]

Sommando agli AS-REP, tutte e quattro le password del dominio recuperate dalla sola catena del tool:

  user.nopreauth   AS-REP Roasting
  test.nopreauth   AS-REP Roasting
  svc_sql          Kerberoasting
  svc_backup       Kerberoasting

Catena completa funzionante: enumerazione -> identificazione target -> cattura hash -> cracking offline -> credenziali in chiaro -> report PDF.

---

## Catena del test in ordine cronologico

build dominio psychosec.local da zero
-> run tool -> crash bind LDAP (NetBIOS hardcodato + bind che si fida della stringa)
-> fix: costruzione UPN dal dominio reale
-> run -> hash Kerberoasting rifiutati da hashcat
-> confronto con formato impacket di riferimento
-> fix di 3 difetti: SPN duplicato, porta nel campo SPN, checksum non separato
-> cracking nativo delle 4 password
-> tool promosso a v1.1

---

## Lezioni apprese

Un tool che "funziona" sul proprio ambiente di sviluppo non è un tool qualitativo. Entrambi i bug erano latenti e mascherati= il dominio originale aveva NetBIOS coincidente con la prima label del DNS, quindi l'username sbagliato non si notava; e nessuno aveva mai provato a craccare davvero gli hash TGS prodotti, perciò il formato malformato passava inosservato.
Quando un hash viene rifiutato da hashcat con "separator unmatched" o token length, il problema è quasi sempre il formato e non la password. 

---

## Modifiche al repo (v1.1)

ad_enum.py    = bind LDAP costruito come UPN dal dominio reale invece di fidarsi dell'username ricevuto
ad_attack.py  = il dominio viene passato fino alla funzione di bind. rimossa la derivazione hardcodata del NetBIOS
kerberoast.py = formato hash TGS conforme a hashcat 13100: rimosso SPN duplicato, tolta la porta dal campo SPN, checksum separato dal ticket

---

## Tool utilizzati

Python (ldap3,impacket, reportlab), VirtualBox, PowerShell, hashcat, GetUserSPNs.py (impacket, come riferimento per il formato hash)

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

