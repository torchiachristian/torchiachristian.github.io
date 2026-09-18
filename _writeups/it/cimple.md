---
layout: writeup
lang: it
permalink: /writeups/cimple/
title: "Cimple"
ref: cimple
date: 2026-08-30
bare: true
platform: KCTF
platform_color: "#0f7a3d"
os: Windows (.NET 8 single-file)
series: kaspersky-ctf-2026
tags: [reverse, .NET, vm-bytecode, packer, unicorn, python]
txt: /writeups-files/cimple.txt
summary: "83 punti. Bundle .NET 8 con dentro una VM bytecode custom e una DLL nativa compressa. La flag non esiste in chiaro: è la preimmagine di 16 target a 32 bit."
---

# Writeup — Cimple (Kaspersky CTF 2026)

Categoria: Reverse Engineering
Architettura: .NET 8 single-file bundle + VM bytecode custom + DLL nativa PE32+ x86-64 compressa (packer custom)
Link: https://ctf.kaspersky.com/challenges/16

Sample: CimpleManaged_ac9bc4e10212783b.exe
SHA-256: 77adcef5e3bea9066380b401b2258b102fe78231100a9da1f32ad10130bb9747

FLAG: kaspersky{1s_c1mpl3_s1mple_3n0ugh_1ab7d0159a87f}

---

## Sommario

Il binario è una challenge a più livelli. Un apphost Windows nativo racchiude un bundle .NET 8 single-file. L'entry point managed carica tre risorse embedded: una DLL nativa compressa, un assembly di estensione managed cifrato, e il bytecode di una macchina virtuale custom. L'input utente viene passato alla VM, che esegue 16 controlli indipendenti su blocchi da 3 byte dell'input e confronta ogni risultato con un target a 32 bit precalcolato. La flag non è mai presente in chiaro durante l'esecuzione: esiste solo come preimmagine corretta dei 16 target sotto una trasformazione reversibile

Catena: apphost → bundle .NET 8 → CimpleManaged.dll → stringhe managed ROL/XOR/ROR → risorsa r1KV8L4Y8H → interprete VM → estensione CimpleExtension.dll (5 opcode in più) → unpacking di CimpleNative.dll → export rinominati per hash del nome macchina → validatore a 16 blocchi da 3 byte → inversione della catena → flag.

---

## strumenti e metodologie aggiuntive

durante la sessione è stato utilizzato un llm: per recupero dettagli su CVE, interpretazione di output grezzi, suggerimenti su vettori inesplorati in caso di blocco, spiegazione dettagliata di concetti tecnici e correzione di sintassi in comandi lunghi. l'esecuzione e le scelte operative erano mie. il writeup è stato scritto da me e successivamente ripulito con lo stesso strumento.

la riproduzione del comportamento dello stub di decompressione è stata eseguita tramite emulazione statica/offline del codice unpacked con Unicorn Engine, mappando codice, memoria VM, registri e stack, senza eseguire direttamente il sample non fidato.

---

## Premessa

questo writeup è diviso in tre blocchi, ed è voluto. prima la soluzione tecnica pulita, come consegnata. poi il perché il primo tentativo, tutto giocato sull'analisi dinamica live, non ha funzionato, spiegato in linguaggio semplice. infine la cronaca completa di ogni tentativo fatto durante la notte, comando per comando, con l'esito e la causa tecnica del fallimento

la parte sui fallimenti non è riempitivo: il motivo per cui ore di debugger non hanno prodotto niente è esattamente il punto interessante di questa challenge, e sta in un errore di modello mentale, non in un errore di sintassi.

---

## Fase 1 — Livello esterno, bundle .NET 8 single-file

Il PE esterno (CLR Directory: 0/0) è un apphost nativo. Racchiude un bundle .NET 8 standard, identificato dalla firma bundle a offset 0x22720. Il manifest del bundle dichiara:

  - runtimeconfig.json a offset 0x25000
  - assembly principale (CimpleManaged.dll) a offset 0x26000, lunghezza 0xF200

Estrazione:

dd if=CimpleManaged_ac9bc4e10212783b.exe of=CimpleManaged.dll bs=1 skip=$((0x26000)) count=$((0xF200))

SHA-256(CimpleManaged.dll):
87080ab1b3ad2fa65c1d12fbf46d3b537842d1710a39ed10074b047103ca6829

---

## Fase 2 — Offuscamento delle stringhe managed

Le user string nell'heap metadata #US non sono in chiaro. Ogni stringa è codificata Base64 e ulteriormente trasformata byte per byte con una chiave statica di 32 byte:

  key = "7e8m3ZRpDE1FAV1WbkgKAawzWb1BEUjh"

Routine di decrittazione (per ogni byte i del buffer decodificato da Base64):

  x = input[i]
  x = ROL8(x, 5)
  x = x XOR key[i % 32]
  x = ROR8(x, 4)

```python
def decrypt_string(s, key):
    raw = base64.b64decode(s)
    out = bytearray()
    for i, b in enumerate(raw):
        x = rol8(b, 5)
        x ^= key[i % len(key)]
        x = ror8(x, 4)
        out.append(x)
    return out.decode()
```

Tra le stringhe decrittate: i due messaggi del prompt e il nome di una risorsa embedded, r1KV8L4Y8H.

---

## Fase 3 — Risorse managed embedded

CimpleManaged.dll incorpora tre risorse managed:

  Nome         Offset   Lunghezza  Contenuto
  BfyPYgNCok   0        9728       DLL nativa COMPRESSA
  4etw99fg5I   9732     7168       assembly managed CIFRATO
  r1KV8L4Y8H   16904    2505       bytecode della VM

Hash dei blob originali:

  BfyPYgNCok  3bd6a277d233af986799d026df6f932f25f204d5c3c6675c9ecafab7fe0a5b1f
  4etw99fg5I  e5ab2a46becf884791df09b82342d9390a1d1fd54d1abb95b393a4899e30d828
  r1KV8L4Y8H  2915ff9df140dcb575791918b85fbe8611938ca29cc02acfe9a342208f2f8f4f

Flusso all'avvio: l'entry point managed carica r1KV8L4Y8H, costruisce l'interprete VM, copia l'input UTF-8 nella memoria lineare della VM a indirizzo 0x11000, avvia il ciclo di esecuzione.

---

## Fase 4 — Architettura della VM

  - 8 registri signed a 32 bit
  - 8 slot per oggetti managed
  - 1 MiB di memoria lineare (il buffer input risiede a 0x11000)
  - dispatch table indicizzata per opcode

Opcode di base:

  0      exit
  1–2    move reg/reg, move reg/immediato
  3–8    add, sub, mul, div, xor, and
  9–10   load/store a 32 bit
  11–13  jump, jump-if-zero, jump-if-not-zero
  14     stampa intero
  15     carica un assembly managed
  16     carica un PE nativo in memoria
  17     invoca un export nativo
  18     invoca un metodo managed
  19     risolve proprietà/campi via reflection
  20–22  conversioni/copie tra oggetti e memoria VM
  23     converte intero in esadecimale formato "X4"

Un controllo anti-debug richiama System.Diagnostics.Debugger.IsAttached e termina l'esecuzione se un debugger MANAGED è collegato.

---

## Fase 5 — Estensione dinamica (risorsa 4etw99fg5I)

Decifrata a runtime per produrre CimpleExtension.dll. Chiave iniziale (8 byte): "aK3y0fAj".

Decrittazione: XOR con la chiave; dopo ogni gruppo di 8 byte, ciascuna metà a 32 bit della chiave viene incrementata di 0x13371338 (key-schedule progressivo, non XOR statico).

L'assembly caricato registra 5 opcode aggiuntivi:

  24  ROR32
  25  ROL32
  26  shift logico a destra
  27  shift a sinistra
  28  stampa stringa UTF-8 dalla memoria VM

Due messaggi di esito precaricati in memoria VM:

  0x12000  ">>> Yay, exacly! How pretty!"
  0x12100  ">>> No no no... it's something different!"

---

## Fase 6 — DLL nativa compressa (risorsa BfyPYgNCok)

BfyPYgNCok è una DLL PE32+ x64 (nome interno CimpleNative.dll) compressa con un packer custom in stile UPX/NRV:

  - sezione virtuale a RVA 0x1000, size 0x8000, senza dati raw su disco
  - dati compressi a RVA 0x9000, raw offset 0x400, size 0x1C00
  - .rsrc a RVA 0xB000
  - entry point dello stub di decompressione a RVA 0xA810

Comportamento dello stub a runtime:

  1. Decomprime il flusso da RVA 0x9000 verso RVA 0x1000, producendo 0x8384 byte a partire da 0x180C byte compressi.
  2. Applica un filtro inverso agli operandi dei branch relativi x86 nei primi 0x2200 byte del codice decompresso (89 operandi corretti), trasformazione branch-call standard usata dai packer stile UPX per migliorare il rapporto di compressione.
  3. Risolve gli import.
  4. Ripristina i permessi delle sezioni (VirtualProtect).
  5. Passa il controllo al codice originale a RVA 0x25B0.

SHA-256(CimpleNative, unpacked):
7025a5eb59a9373c9c621fadbc6425d9e3e90cd3a8369db41e513b6491ee97ef

---

## Fase 7 — Offuscamento dei nomi export

CimpleNative non espone nomi export stabili. Durante DllMain calcola un hash del nome del computer locale e lo usa per riscrivere la tabella dei nomi export a runtime:

  h = 0x812BDF8D
  for b in machine_name:
      h = ((h ^ b) * 0x00FF653F) & 0xFFFFFFFF
  name = f"{h:X4}"

Ogni valore calcolato viene rihashato per derivare il nome successivo. Il bytecode della VM riproduce lo stesso algoritmo per risolvere quale export invocare sull'host corrente.

Tabella export statica (nomi su disco, ordinal, RVA unpacked):

  Nome su disco  Ordinale  RVA unpacked
  ______1n       5         0x1A80
  ______i5       3         0x1870
  _____th3       6         0x1BE0
  ____d4rk       7         0x1C90
  ____fl4g       2         0x17C0
  ____th3_       1         0x1440
  __h1dden       4         0x1920

Questi nomi su disco concatenati formano una frase leggibile ("th3_fl4g_i5_h1dden_1n_th3_dark") ma non vengono mai usati come tali dal programma; i nomi reali, dipendenti dall'host, sono prodotti solo dalla catena di hash sopra descritta

---

## Fase 8 — Logica del validatore

Input: 48 byte totali, letti a partire dall'indirizzo VM 0x11000, elaborati in 16 blocchi da 3 byte (24 bit) ciascuno.

Per ogni blocco i (0..15), letto come DWORD little-endian da 0x11000 + 3*i, mascherato con 0x00FFFFFF:

Costanti:

  C3         = 322376503
  C6         = (-1489910311) & 0xFFFFFFFF
  C2         = 322375971
  C4         = 1103547991
  INNER_SEED = 27097905
  ADD_C      = 0x3719A531
  GOLDEN     = 0x9E3779B9

Passo 1:

  x = chunk XOR (i*C3 + C6)

Passo 2 — 8 round, j = 0..7:

  a = i*INNER_SEED + j*C2 + C4
  x += a
  x = ROL32(x, 3*i + j + 5)
  s = j+1 se j<5, altrimenti j-4
  x ^= x >> s
  x = swap_adjacent_bits(x)
  x *= 5
  x += 7*j + 0x3719A531
  x = ROR32(x, 3*j + i + 7)
  x ^= (x << 5) & 0xF0F0F0F0
  x ^= SAR32(x, 4) & 0x0F0F0F0F
  x ^= (j*0x11111111) XOR 0x9E3779B9
  x = ROL32(x, a >> 27)

swap_adjacent_bits(x) = ((x & 0x55555555) << 1) ^ ((x & 0xAAAAAAAA) >> 1)

Ogni blocco trasformato viene confrontato con un target a 32 bit precalcolato:

  targets = [
    0x264D7B93, 0x5CF34FBC, 0x49B2F699, 0x21842F55,
    0x1E90355E, 0x7E173EE8, 0x2655C670, 0x88D8CA77,
    0x36BB5BCE, 0xA3FC037D, 0x2779A2D3, 0xA9939A8A,
    0x9521F3A0, 0xB39EDBC9, 0x2FA250EE, 0xFAEA1FF2,
  ]

---

## Fase 9 — Solver

Ogni operazione della catena è invertibile:

  - addizione <-> sottrazione
  - ROL <-> ROR
  - moltiplicazione per 5 <-> moltiplicazione per l'inverso modulare 5^-1 mod 2^32 = 0xCCCCCCCD
  - lo swap dei bit adiacenti è la propria inversa (involuzione)
  - gli XOR-shift si invertono per iterazione a punto fisso (32 iterazioni, sufficienti per larghezza a 32 bit)

```python
MASK = 0xFFFFFFFF
INV5 = pow(5, -1, 1 << 32)

C3, C6 = 322376503, (-1489910311) & MASK
C2, C4 = 322375971, 1103547991
INNER_SEED, ADD_C, GOLDEN = 27097905, 0x3719A531, 0x9E3779B9

targets = [
    0x264D7B93, 0x5CF34FBC, 0x49B2F699, 0x21842F55,
    0x1E90355E, 0x7E173EE8, 0x2655C670, 0x88D8CA77,
    0x36BB5BCE, 0xA3FC037D, 0x2779A2D3, 0xA9939A8A,
    0x9521F3A0, 0xB39EDBC9, 0x2FA250EE, 0xFAEA1FF2,
]

def u32(x): return x & MASK

def rol(x, n):
    n &= 31
    return u32((x << n) | (x >> ((32-n) & 31)))

def ror(x, n):
    n &= 31
    return u32((x >> n) | (x << ((32-n) & 31)))

def sar(x, n):
    sx = x if x < 0x80000000 else x - 0x100000000
    return u32(sx >> n)

def swap_adjacent(x):
    return u32(((x & 0x55555555) << 1) ^
               ((x & 0xAAAAAAAA) >> 1))

def inv_xor_rshift(y, shift):
    x = y
    for _ in range(32):
        x = u32(y ^ (x >> shift))
    return x

def inv_xor_lshift_mask(y, shift, mask):
    x = y
    for _ in range(32):
        x = u32(y ^ ((x << shift) & mask))
    return x

def inv_native5(y):
    x = y
    for _ in range(32):
        x = u32(y ^ (sar(x, 4) & 0x0F0F0F0F))
    return x

def reverse(target, i):
    x = target
    for j in reversed(range(8)):
        a = u32(i*INNER_SEED + j*C2 + C4)
        x = ror(x, a >> 27)
        x ^= u32(j*0x11111111) ^ GOLDEN
        x = inv_native5(x)
        x = inv_xor_lshift_mask(x, 5, 0xF0F0F0F0)
        x = rol(x, 3*j + i + 7)
        x = u32(x - (7*j + ADD_C))
        x = u32(x * INV5)
        x = swap_adjacent(x)
        s = j+1 if j < 5 else j-4
        x = inv_xor_rshift(x, s)
        x = ror(x, 3*i + j + 5)
        x = u32(x - a)
    return u32(x ^ u32(i*C3 + C6))

answer = bytearray()
for i, target in enumerate(targets):
    chunk = reverse(target, i)
    assert chunk <= 0xFFFFFF
    answer += chunk.to_bytes(3, "little")

print(answer.decode("ascii"))
```

---

## Fase 10 — Risultato

  i    Target     Chunk (LE)   ASCII
  0    264D7B93   73616B       kas
  1    5CF34FBC   726570       per
  2    49B2F699   796B73       sky
  3    21842F55   73317B       {1s
  4    1E90355E   31635F       _c1
  5    7E173EE8   6C706D       mpl
  6    2655C670   735F33       3_s
  7    88D8CA77   706D31       1mp
  8    36BB5BCE   5F656C       le_
  9    A3FC037D   306E33       3n0
  10   2779A2D3   686775       ugh
  11   A9939A8A   61315F       _1a
  12   9521F3A0   643762       b7d
  13   B39EDBC9   353130       015
  14   2FA250EE   386139       9a8
  15   FAEA1FF2   7D6637       7f}

Concatenazione (48 caratteri, completa, nessun wrapping aggiuntivo richiesto):

  kaspersky{1s_c1mpl3_s1mple_3n0ugh_1ab7d0159a87f}

---

## Fase 11 — Verifica

Il bytecode VM è stato rieseguito sotto emulazione usando la stringa recuperata come input. Trace di esecuzione osservata:

  09ad: print_string ''
  09b5: print_string ' >>> Yay, exacly! How pretty!'
  09b7: exit

Un input errato raggiunge invece il ramo di fallimento:

  >>> No no no... it's something different!

Questo conferma l'intera catena: parsing del bundle, decrittazione delle risorse, estensione degli opcode, unpacking della DLL nativa, invocazione degli export nativi, inversione dei 16 blocchi del validatore.

---

## Perché il primo tentativo non ha funzionato

Il punto centrale è questo: durante l'analisi dinamica si cercava la password sbagliando completamente bersaglio.

Immagina il programma come una scatola con dentro altre scatole più piccole. La prima fase di analisi ha aperto la scatola grande (l'exe), trovato il pacchetto .NET dentro (CimpleManaged.dll), e da lì individuato correttamente il buffer dove finiva l'input digitato dall'utente (offset 0x11000). Fin lì tutto giusto, nessun errore.

Il problema è cosa si pensava accadesse DOPO. Si presumeva che il controllo della password fosse fatto da codice nativo x86 normale, tipo un pezzo di programma scritto in C++ che fa "se input == password stampa giusto". Per questo si sono passate ore a cercare di intercettare quel codice con un debugger (gdb), piazzando trappole (watchpoint) sull'indirizzo di memoria, sperando di vedere l'istruzione esatta di confronto.

Ma non era così. Dentro al programma c'è una specie di piccolo computer finto, una macchina virtuale (VM): non è codice x86 normale, è un programma scritto in un linguaggio bytecode inventato apposta per questa challenge, che gira DENTRO al programma stesso. Una scatola cinese in più, mai aperta durante la prima fase di analisi.

Perché non ci si è accorti prima? Perché quella VM viene caricata da una "risorsa", un file nascosto dentro l'assembly .NET, che si chiama r1KV8L4Y8H. Quella stringa era già stata trovata (era una delle stringhe decriptate), ma è stata interpretata come un possibile frammento di flag o un dato a caso. Invece era il nome di un file nascosto, e semplicemente non si è mai controllato "esiste un file con questo nome dentro il programma?" (cioè non si è mai enumerata la tabella delle risorse managed .NET, ManifestResource, cosa diversa dalle risorse PE native, che invece erano già state controllate).

Ecco perché il debugger non trovava mai il punto giusto: si cercava un confronto diretto in codice x86, ma il vero confronto avviene dentro questo mini-computer finto, che esegue istruzioni sue proprie, diverse da x86. un debugger normale non "vede" quella logica allo stesso modo, perché il ciclo che il debugger intercetta è solo il dispatch generico della VM, uguale per ogni istruzione bytecode, non la logica di validazione specifica.

C'era anche un secondo trabocchetto: la DLL nativa che si era provato a disassemblare era compressa, tipo uno zip. I nomi delle funzioni trovati (th3_fl4g_i5_h1dden...) sembravano un indizio leggibile, ma erano finti, un'esca messa apposta dalla challenge, perché a runtime il programma li rinomina in base all'hash del nome del computer.

---

## Cronaca dei tentativi di analisi dinamica

Questa sezione documenta ogni tentativo fatto durante la fase di analisi dinamica, in ordine cronologico, con l'esito osservato e, dove nota, la causa tecnica del fallimento alla luce della soluzione completa.

### Setup ambiente di esecuzione

Il file .exe non gira nativamente su Linux (errore "unable to find an interpreter": il loader managed chiama API Windows reali via kernel32.dll per il caricamento in memoria della DLL nativa, quindi serve emulazione Win32).

Tentativo con dotnet-runtime-8.0 installato via apt e lanciato direttamente sulla DLL managed estratta (/tmp/Cimple.dll): fallito per mancanza di runtimeconfig.json/deps.json accanto alla DLL. Ricreato runtimeconfig.json manualmente puntando a net8.0, il programma parte ma va in crash con DllNotFoundException su kernel32.dll: confermato che il loader managed richiede API Win32 reali, non eseguibili su .NET Core Linux puro.

Setup funzionante raggiunto: Wine (wine-stable) + winetricks dotnet8 (runtime .NET 8.0.12 installato nel prefix Wine). Sotto questa configurazione il binario esegue correttamente (stampa ASCII art, prompt, legge input, risponde con successo/fallimento).

### Analisi statica del PE esterno

pefile identifica: PE32+ x86-64, EntryPoint 0x11ad0, ImageBase 0x140000000, CLR Directory 0/0, overlay a offset 151552 size 66263.

Overlay identificato inizialmente come "JSON data" dal comando `file`. Ricerca di marker MZ nell'overlay tramite regex su tutto il buffer: trovati 6 offset (4096, 11572, 16740, 20959, 55787, 60821). Ognuno estratto in file separati sotto /tmp/cimple_parts/.

Il file più promettente (/tmp/cimple_parts/part_00_1000.bin) identificato da `file` come "PE32+ executable (DLL) (console) x86-64 Mono/.Net assembly, for MS Windows": corrisponde all'assembly managed CimpleManaged.dll (coincide, con offset diversi, con quanto poi trovato leggendo correttamente il manifest del bundle .NET nella Fase 1).

NOTA RETROSPETTIVA: la ricerca di marker MZ grezzi ha comunque individuato correttamente i file interessanti, ma per una via più indiretta rispetto a leggere il manifest del bundle .NET, che dichiara gli offset esatti in modo esplicito.

### Tentativi con monodis / Mono

monodis sul file .exe esterno: fallito ("Error while trying to process").
monodis sul payload managed estratto: crash (Aborted, core dumped).
Esecuzione diretta con Mono: fallita con "Could not load file or assembly 'System.Runtime, Version=8.0.0.0'", causa identificata: il payload è compilato per .NET 8, non compatibile con Mono.

### Analisi metadata con dnfile

dnfile riconosce correttamente le tabelle CLR (TypeDef, MethodDef, MemberRef, AssemblyRef). Individuato l'heap UserStringHeap (#US) a offset file 55600, dimensione stimata ~704 byte (fino all'inizio dello stream successivo a 56304).

Errore iniziale: `for s in pe.net.user_strings` solleva TypeError ("UserStringHeap object is not iterable"), limite della versione di dnfile installata. Risolto passando a lettura manuale via offset diretto nell'heap.

Estrazione manuale delle 10 user string e decrittazione tramite l'algoritmo ROL/XOR/ROR con chiave "7e8m3ZRpDE1FAV1WbkgKAawzWb1BEUjh" (identico a quanto descritto nella Fase 2, individuato correttamente leggendo l'IL dei metodi #1 RVA 0x28fc e #2 RVA 0x293c).

Tra le stringhe decrittate: "r1KV8L4Y8H", interpretata a questo punto come possibile dato di flag o seed, MAI verificata come nome di risorsa managed. è la causa radice del fallimento successivo.

### Analisi del flusso managed (IL)

Identificato correttamente Method #9 (RVA 0x2cd0): stampa l'ASCII art (campo statico 0x0400004e, 1127 byte, FieldRva RVA 0x2048), stampa i due messaggi decrittati, esegue Console.ReadLine(), chiama Method #12 con (input, 69632).

L'ASCII art è stata estratta ed esaminata byte per byte (ricerca di pattern flag{/kaspersky{/ctf{/Base64/XOR 0-255): nessun risultato, corretto, l'ASCII art non contiene la flag.

Method #12 (RVA 0x2d8c) analizzato: converte l'input in UTF-8, esegue una copia byte a byte verso un buffer nativo a offset 69632 (0x11000), aggiunge terminatore NUL. CONCLUSIONE CORRETTA in questa fase: il controllo vero non è nel codice managed diretto, avviene altrove dopo la copia nel buffer a 0x11000.

Questa conclusione era esatta (coincide con la Fase 4: il buffer a 0x11000 è davvero l'inizio della memoria lineare della VM), ma l'ipotesi successiva, che "altrove" significasse "codice nativo x86 diretto", si è rivelata sbagliata.

### Estrazione ed enumerazione dei PE embedded nell'overlay

Script Python con regex su tutto il buffer dell'exe per trovare ogni occorrenza di "MZ" con header PE valido (verifica campo e_lfanew e firma "PE\0\0"). Trovati 3 PE validi:

  /tmp/cimple_auto/p/06_29164.bin  (DLL, contiene gli export)
  /tmp/cimple_auto/p/00_0.bin      (EXE console)
  /tmp/cimple_auto/p/04_26000.bin  (falso positivo "Mono/.Net assembly" da parte di `file`)

Stringhe estratte da tutti e tre: identiche in ciascuno (CimpleNative.pdb, CimpleNative.dll, OrdinalFlag32, OrdinalFlag64, mem_is_valid, LoaderFlags, ecc.), segno che sono copie/riferimenti dello stesso modulo nativo, non file distinti con contenuto diverso.

### Disassemblata statica degli export (fallimento chiave)

pefile ha enumerato correttamente 7 export ordinal in 06_29164.bin:

  ordinal 1: ____th3_    RVA 0x1440
  ordinal 2: ____fl4g    RVA 0x17c0
  ordinal 3: ______i5    RVA 0x1870
  ordinal 4: __h1dden    RVA 0x1920
  ordinal 5: ______1n    RVA 0x1a80
  ordinal 6: _____th3    RVA 0x1be0
  ordinal 7: ____d4rk    RVA 0x1c90

Concatenati per ordinal: "th3_fl4g_i5_h1dden_1n_th3_d4rk", interpretata come possibile password diretta.

objdump -d su ciascun RVA: TUTTE le disassemblate hanno prodotto istruzioni x86 insensate/spazzatura (opcode "(bad)", sequenze senza senso logico, nessun pattern di confronto riconoscibile).

CAUSA REALE (nota solo dopo la soluzione, Fase 7): questi RVA (0x1440-0x1c90) appartengono a una sezione dichiarata come VUOTA su disco nel file packed (RVA 0x1000-0x9000, size 0x8000, nessun dato raw). il codice reale viene scritto lì SOLO a runtime dallo stub di decompressione UPX/NRV-like, che decomprime i dati reali da RVA 0x9000. La disassemblata statica su file non decompresso equivaleva a leggere byte vuoti/residui, non codice offuscato-ma-presente.

### Test della password ricostruita dagli ordinal

Test tramite `printf` con vari wrapper (flag{}, CTF{}, cimple{}, sasc{}, ecc.), nessun test contro il programma reale a questo punto, solo costruzione di candidati.

Primo tentativo di esecuzione diretta:
  echo "..." | wine ...exe
  -> "You must install .NET to run this application" (dotnet mancante nel prefix Wine)

Installato dotnet-runtime-8.0 nativo Linux via apt (inutile per Wine, serve nel prefix Wine, non sul sistema host), poi risolto correttamente con winetricks dotnet8.

Con Wine + dotnet8 funzionante: il programma gira, mostra ASCII art e prompt, ma la stringa "th3_fl4g_i5_h1dden_1n_th3_d4rk" (e tutte le varianti con wrapper) produce sempre:

  >>> No no no... it's something different!

CAUSA REALE (Fase 7): i nomi degli export sono un DEPISTAGGIO strutturale. A runtime CimpleNative calcola un hash del nome macchina e riscrive la tabella export con nomi diversi, dipendenti dall'host. i nomi statici letti dal file su disco non sono mai usati come tali dal validatore.

### Tentativi di memory dump statico (dd, gdb core-file)

Tentativo 1 — dd su /proc/pid/mem con skip= sull'intera region rw-p: fallito, file di output 0 byte (dd con skip= grande su region non completamente residenti fisicamente va spesso in errore silenzioso/EIO).

Tentativo 2 — gdb generate-core-file completo: il core file ha raggiunto oltre 17 GB (include l'intero runtime .NET Wine, tutte le DLL mappate, mapping condivisi), impraticabile in tempo utile, processo terminato manualmente.

Tentativo 3 — dump mirato via script Python (lettura diretta di /proc/pid/mem su region rw-p anonime, escludendo file >200MB): completato con successo (101MB di dump), ma nessun pattern "flag{"/"kaspersky{"/ecc. trovato via grep su strings.

CAUSA REALE (Fase 8): il validatore non costruisce mai la flag in chiaro in memoria, lavora esclusivamente su rappresentazioni numeriche a 32 bit trasformate, confrontate con 16 costanti precalcolate. Non esiste, per costruzione, un momento in cui la stringa "kaspersky{...}" sia presente in memoria salvo che l'utente non l'abbia già digitata correttamente.

### Tentativo di breakpoint su VirtualProtect

gdb con breakpoint sulla funzione VirtualProtect (API usata dal loader per rendere eseguibile la memoria scritta a runtime): un solo hit intercettato, con newprot=0 (PAGE_NOACCESS), non correlato al momento di interesse per la decompressione del codice nativo. Il vero mprotect rilevante (verso PAGE_EXECUTE) non è mai stato isolato con questo approccio.

Analisi via strace -e trace=mprotect: confermata una chiamata mprotect(0x100051000, 69632, PROT_READ|PROT_EXEC), l'offset 69632 = 0x11000 coincide esattamente con l'offset del buffer input già noto dall'analisi IL. Questo ha confermato correttamente l'indirizzo virtuale runtime del buffer (0x100000000 + 0x11000 = 0x100011000), ma si riferisce alla memoria lineare della VM, non al codice nativo decompresso dello stub, che risiede a un'altra regione (RVA 0x1000-0x9000 nell'immagine di CimpleNative) mai isolata specificamente con mprotect tracing mirato.

### Hardware watchpoint su 0x100011000

Tentativo con `awatch *(char*)0x100011000` in gdb, con vari schemi di `continue` (fissi e in loop Python).

Il watchpoint scatta ripetutamente, ma SEMPRE con PC dentro coreclr.dll (0x6ffffc2ff91b), corrisponde alla scrittura managed (Buffer.MemoryCopy di Method #12) che tocca l'indirizzo target durante la copia stessa, mai a un hit successivo con PC dentro il range 0x100000000-0x100300000 (CimpleNative).

Problema tecnico identificato durante i tentativi: CoreCLR usa SIGUSR1 per sospendere i thread durante le pause di garbage collection; gdb si ferma anche su questi segnali oltre che sul watchpoint, causando falsi "hit" interpretati erroneamente dal loop di controllo come termine del watchpoint. Anche dopo aver impostato `handle SIGUSR1 nostop noprint pass`, il processo target è terminato prematuramente ("Inferior exited normally") prima che un hit reale nella regione nativa potesse verificarsi, compatibile con una race condition tra i tempi fissi (sleep) dello script bash e l'overhead combinato di Wine + gdb + CoreCLR.

CAUSA REALE PIÙ PROFONDA: anche ottenendo un hit pulito, non sarebbe stato possibile osservare un "confronto" diretto significativo tramite un singolo watchpoint su indirizzo fisso. la lettura del buffer avviene tramite il ciclo di dispatch generico della VM bytecode, che itera sullo stesso codice per ogni istruzione interpretata, non tramite un punto di lettura nativo isolato.

### Tentativo di bruteforce scriptato con pexpect

Script Python con pexpect per testare in sequenza automatica tutti i candidati raccolti fino a quel momento, con pattern matching su "No no no" vs "flag{"/"kaspersky{".

Risultato: la maggior parte dei tentativi in TIMEOUT (pexpect non intercettava correttamente lo stdout del processo sotto Wine entro la finestra di timeout data). I due "match" positivi su flag{ e kaspersky{ erano falsi positivi: pexpect stava matchando l'ECHO dell'input inviato dallo script stesso, non l'output reale del programma.

### Enumerazione risorse PE (nativa, non managed)

pefile.DIRECTORY_ENTRY_RESOURCE su 06_29164.bin: trovata una sola risorsa, un manifest XML standard Windows (asInvoker, SegmentHeap), nessun dato utile.

CAUSA MANCATA (Fase 3): questa era l'enumerazione delle risorse del PE NATIVO (CimpleNative), struttura dati diversa dalle risorse MANAGED .NET (tabella metadata ManifestResource dell'assembly CimpleManaged.dll), mai enumerate. Sono proprio le risorse managed a contenere BfyPYgNCok, 4etw99fg5I e r1KV8L4Y8H, la chiave per sbloccare l'intera catena successiva

---

## Catena completa

apphost PE32+ nativo, CLR Directory 0/0 → firma bundle .NET 8 a offset 0x22720
→ manifest del bundle → CimpleManaged.dll estratta da 0x26000, lunghezza 0xF200
→ user string nell'heap #US cifrate Base64 + ROL8/XOR/ROR8 con chiave a 32 byte
→ fra le stringhe decrittate esce r1KV8L4Y8H, nome di una risorsa managed
→ tabella ManifestResource: BfyPYgNCok (DLL nativa compressa), 4etw99fg5I (assembly cifrato), r1KV8L4Y8H (bytecode VM)
→ input UTF-8 copiato nella memoria lineare della VM a 0x11000
→ interprete VM: 8 registri, 1 MiB lineare, dispatch per opcode, anti-debug su Debugger.IsAttached
→ 4etw99fg5I decifrata con key-schedule progressivo (+0x13371338) → CimpleExtension.dll, opcode 24-28
→ BfyPYgNCok unpacked dallo stub a RVA 0xA810 → CimpleNative.dll, codice reale scritto a RVA 0x1000 solo a runtime
→ nomi export riscritti in DllMain via hash del nome macchina, i nomi su disco sono un'esca
→ validatore: 48 byte in 16 blocchi da 3, XOR iniziale poi 8 round di add/ROL/xorshift/swap bit/mul 5/ROR/mask
→ confronto con 16 target a 32 bit precalcolati
→ ogni operazione invertibile (INV5 = 0xCCCCCCCD, swap involutivo, xorshift a punto fisso)
→ inversione dei 16 target → 48 byte ASCII → flag
→ verifica: bytecode rieseguito sotto emulazione con la stringa recuperata, ramo di successo raggiunto

---

## Lezioni apprese

il fallimento di questa challenge non è stato tecnico ma di modello mentale. avevo individuato correttamente il buffer di input a 0x11000 e concluso correttamente che il controllo avveniva dopo quella copia, e da lì ho dedotto che "dopo" significasse codice nativo x86. non era così, e tutte le ore di debugger sono andate in un punto della catena dove non c'era niente da vedere.

una stringa che non capisci va trattata come un puntatore, non come un dato. r1KV8L4Y8H era già nelle mani mie dopo mezz'ora di analisi, decrittata insieme agli altri messaggi, e l'ho archiviata come possibile frammento di flag. era il nome di una risorsa managed, e la domanda che non mi sono fatto è la più semplice possibile: esiste qualcosa nel programma che si chiama così?

risorse PE native e risorse managed .NET sono due tabelle diverse. avevo enumerato la prima e trovato solo un manifest XML, e quel risultato vuoto mi ha dato la falsa sensazione di aver chiuso la questione risorse. la tabella ManifestResource dell'assembly, quella che conteneva tutto, non l'ho mai aperta.

un disassemblato che produce spazzatura non è codice offuscato, è codice assente. gli RVA degli export stavano in una sezione con size 0x8000 e zero dati raw su disco: leggendo quel range stavo leggendo byte residui. il segnale c'era nell'header delle sezioni, prima di lanciare objdump.

quando il target implementa un interprete, il debugger vede il loop di dispatch, non la logica. un watchpoint su indirizzo fisso intercetta la lettura del buffer da parte dello stesso ciclo che esegue ogni istruzione bytecode, quindi non isola nulla di specifico. contro una VM custom la strada è ricostruire il bytecode, non seguire l'esecuzione nativa.

la flag in chiaro in memoria non esisteva, e 101 MB di dump grepati a vuoto lo dimostrano per via empirica. un validatore che confronta trasformazioni numeriche contro costanti precalcolate non ha nessun istante in cui la stringa corretta sia materializzata, a meno che non l'abbia già digitata tu

---

## Tool utilizzati

dd, pefile, dnfile, monodis/Mono, objdump, Wine (wine-stable) + winetricks dotnet8, dotnet-runtime-8.0, gdb (breakpoint, hardware watchpoint, generate-core-file), strace (trace=mprotect), pexpect, Unicorn Engine (emulazione statica del codice unpacked), Python (solver, estrazione PE embedded, decrittazione stringhe), strings, grep
