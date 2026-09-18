---
layout: writeup
lang: it
permalink: /writeups/sudokrypt/
title: "Sudokrypt"
ref: sudokrypt
date: 2026-08-01
bare: true
platform: KCTF
platform_color: "#0f7a3d"
series: kaspersky-ctf-2026
tags: [crypto, chosen-plaintext, GF(4093), linear-recurrence, vandermonde, python]
txt: /writeups-files/sudokrypt.txt
summary: "53 punti. Il servizio cifra qualunque cosa gli mandi, e la flag te la dà solo cifrata. Con 96 tentativi si ricostruisce il generatore di chiavi, che non è casuale come sembra, e si decifra."
---

# Writeup — Sudokrypt (Kaspersky CTF 2026)

Categoria: crypto
Valore: 53 points
Link: https://ctf.kaspersky.com/challenges/6
Data: 08/2026

FLAG: kaspersky{D4mn_1m_s0_c00l!!_1_c4n_d0_sud0ku_n0w_st4cy_t0t4lly_g01ng_t0_pr0m_w1th_m3}

---

## Sommario

Il servizio espone quattro operazioni, di cui una sola conta davvero: encrypt one block. È un oracolo di cifratura chosen-plaintext con 96 query disponibili, ogni query un plaintext da 16 byte con il relativo ciphertext in risposta. La flag si ottiene con peek at Stacy's homework, che però non la restituisce in chiaro ma cifrata con lo stesso schema, quindi va ricostruito abbastanza del cifrario da poterlo invertire.

Lo schema è a quattro strati: inner_word, rotazione, public_wrapper, diffuse_words. Gli ultimi due sono completamente pubblici e l'autore fornisce direttamente le funzioni inverse, quindi non proteggono niente. La parte interessante è inner_word, che dipende da uno stream pseudo-casuale generato da una struttura algebrica su GF(4093) con 56 nodi spettrali. Quello stream non è casuale: è una sequenza lineare ricorrente di ordine 56, quindi con abbastanza campioni consecutivi il comportamento futuro è deterministico e si ricostruisce con algebra lineare

Catena: 96 chosen plaintext → undiffuse_words e public_wrapper_inv per togliere gli strati pubblici → recupero delle rotazioni relative dai q-label → brute force di R0 e symbol_inv[0] su 256 combinazioni → sistema lineare sovradeterminato su GF(4093) per il polinomio caratteristico → 56 radici, cioè i nodi spettrali → Vandermonde per i coefficienti delle lane → recupero di symbol_inv e q_perm → fold_for_flag non distrugge la struttura spettrale, quindi lo stato post-fold è calcolabile → stream della flag predetti → inversione blocco per blocco → PKCS#7 rimosso → flag.

---

## strumenti e metodologie aggiuntive

durante la sessione è stato utilizzato un llm: per interpretazione di output grezzi, spiegazione dettagliata di concetti tecnici, suggerimenti su vettori inesplorati in caso di blocco e scrittura del solver. l'esecuzione, le scelte operative e il design dei plaintext erano mie. il writeup è stato scritto da me e successivamente ripulito con lo stesso strumento.

---

## Premessa

questa è classificata come challenge facile e in un certo senso lo è, ma non perché ci sia poca matematica dentro. lo è perché le tre debolezze strutturali si riconoscono tutte guardando il codice fornito, e una volta viste il resto è meccanico. il problema è vederle

la parte che ha richiesto più iterazioni non è stata la matematica ma il design dei plaintext: i primi solver fallivano perché sprecavano query, e il modo giusto di spendere le 96 disponibili è quello che decide se la challenge è risolvibile o no. i due errori operativi (glob di tar e buffering TCP) sono in fondo, e sono il tipo di cosa che ti fa perdere mezz'ora su un problema che non c'entra niente con la crypto.

---

## Fase 1 — Il servizio

Il server crea l'istanza così:

core = SudoKrypt(
    os.environ.get("CHALLENGE_SEED", '0'),
    os.environ.get("FLAG", 'kaspersky{testflag}'),
    int(os.environ.get("QUERY_LIMIT", "96")),
)

quindi il seed è presumibilmente quello di default, CHALLENGE_SEED = "0", ma c'è anche un session_nonce = os.urandom(16), e ogni sessione genera una nuova istanza.

il vincolo che conta:

def encrypt_block(self, plaintext):
    if self.flag_taken:
        raise RuntimeError("encrypt oracle is closed after encrypted flag")
    &#46;&#46;&#46;
    self.remaining -= 1
    return self.crypt_block(plaintext)

96 query, e devono essere tutte fatte PRIMA di chiedere la flag. dopo, l'oracolo è chiuso.

la flag invece viene cifrata da:

def encrypt_flag(self):
    self.flag_taken = True
    self.prng.fold_for_flag()
    &#46;&#46;&#46;

quel fold_for_flag è la distinzione che conterà alla fine.

la struttura complessiva della cifratura:

plaintext
   |
   v
inner_word()
   |
   v
rotation
   |
   v
public_wrapper()
   |
   v
diffuse_words()
   |
   v
ciphertext

---

<div class="writeup-image">
  <img src="/assets/writeups/kctf-sudokrypt.png" alt="Pagina della challenge Sudokrypt">
  <div class="img-caption">La challenge sulla piattaforma, categoria crypto</div>
</div>

## Fase 2 — Togliere gli strati pubblici

La cifratura produce 16 parole da 16 bit e poi applica diffuse_words(). Ma diffuse_words è lineare e nel codice esiste esplicitamente undiffuse_words(). Stesso discorso per public_wrapper, che è un Feistel a 4 round e ha il suo public_wrapper_inv già scritto.

quindi dal ciphertext si arriva alle inner word in due passaggi:

def decrypt_public_layer(ciphertext):
    words = [
        int.from_bytes(ciphertext[i:i + 2], "big")
        for i in range(0, 32, 2)
    ]
    words = undiffuse_words(words)
    return [
        public_wrapper_inv(word, rank)
        for rank, word in enumerate(words)
    ]

questo è il passaggio fondamentale: dopo queste due inversioni né il Feistel pubblico né la diffusione esistono più come problema. resta solo inner_word.

---

## Fase 3 — inner_word e la struttura della word

La funzione interessante è:

def inner_word(self, byte, stream_value):

prende un byte e uno stream_value e costruisce una word da 16 bit. il byte viene scomposto così:

q = byte >> 4
symbol = ((byte & 15) - q) & 15

cioè:

byte = q << 4 &#124; (symbol + q)
q = nibble alto
symbol = nibble basso - q mod 16

questo è molto utile perché possiamo scegliere q e symbol in modo indipendente.

la word interna è:

return (
    self.q_perm[q] << 12
) &#124; (
    row_field << 8
) &#124; (
    col_field << 4
) &#124; check

cioè:

 15          12 11         8 7          4 3         0
+&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;+&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;+&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;+&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;-+
&#124;   q_label    &#124; row_field  &#124; col_field  &#124;   check   &#124;
+&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;+&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;+&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;+&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;-+

dopo aver invertito public_wrapper otteniamo esattamente questi quattro campi.

---

## Fase 4 — Recuperare stream_value

inner_word usa lo stream così:

high = stream_value >> 8
mask = (stream_value >> 4) & 15
low  = stream_value & 15

quindi lo stream è un valore a 12 bit, high&#124;mask&#124;low su 8+4+4. e poi:

row_code  = SBOX[low]
base_col  = (self.symbol_inv[symbol] - row_code) & 15
row_field = (row_code + mask) & 15
col_field = (base_col + 2 * mask) & 15

sostituendo base_col dentro col_field:

col_field = sinv - row_code + 2(row_field - row_code)
          = sinv + 2*row_field - 3*row_code

quindi:

3*row_code = sinv + 2*row_field - col_field

in modulo 16 l'inverso di 3 è 11, perché 3 * 11 = 33 = 1 mod 16. quindi:

row_code = 11 * (sinv + 2*row_field - col_field) mod 16

e da lì low = SBOX_INV[row_code], mask = row_field - row_code, base_col = sinv - row_code, high = check ^ SBOX[&#46;&#46;&#46;].

conclusione: da una ciphertext word possiamo ricostruire lo stream_value, a patto di conoscere symbol_inv[symbol].

---

## Fase 5 — I due segreti: symbol_inv e la rotazione

symbol_inv non lo conosciamo. nel costruttore c'è:

self.symbol_perm = symbol_permutation_from_model(&#46;&#46;&#46;)
self.symbol_inv = inverse_permutation(&#46;&#46;&#46;)

una permutazione segreta symbol → internal symbol. ma il plaintext lo scegliamo noi: se imponiamo symbol = 0 su un byte, l'unico valore ignoto diventa symbol_inv[0], che ha 16 possibilità. brute-forzabile.

il secondo segreto è la rotazione. dopo aver creato le 16 word:

rotation = block_rotation(values, block_number)
ranked = [words[(rank + rotation) & 15] for rank in range(16)]

quindi il ciphertext non mantiene l'ordine dei 16 byte. ma q_label = q_perm[q] e q lo scegliamo noi: mandando q = 0,1,2,&#46;&#46;&#46;,15 i 16 q_label nel ciphertext sono semplicemente una permutazione di q_perm[0..15], e la stessa permutazione vale in ogni blocco.

detta R0 la rotazione del blocco 0, nel blocco b si ha rotation_b = R0 + delta_b mod 16. confrontando l'array dei q_label del blocco b con quello del blocco 0 si recupera delta_b senza conoscere né q_perm né R0. tutte le rotazioni relative, gratis. resta solo R0, altre 16 possibilità.

16 x 16 = 256 tentativi in totale. niente.

---

## Fase 6 — Lo spectral generator, il cuore della challenge

Nel costruttore:

self.nodes, self.coefficients = make_spectral_model(self.instance_key)
self.prng = SpectrumGenerator(self.nodes, self.coefficients)

make_spectral_model crea SPECTRUM_SIZE = 56 nodi. lo stream di una lane è:

result = [sum(row) % FIELD &#46;&#46;&#46;]

e dopo ogni blocco row[j] *= node[j]. quindi per una lane:

S[n] = Σ c_j * node_j^n

cioè una sequenza lineare ricorrente di ordine 56 su GF(4093), con λ_j = node_j.

una sequenza di quella forma soddisfa una ricorrenza lineare il cui polinomio caratteristico è Π(x - λ_j), di grado 56. esistono quindi coefficienti C1&#46;&#46;&#46;C56 tali che:

S_n + C1*S_(n-1) + C2*S_(n-2) + &#46;&#46;&#46; + C56*S_(n-56) = 0   (mod 4093)

e questa è la vulnerabilità vera: lo "stream crittografico" non è imprevedibile se hai abbastanza campioni consecutivi.

il numero di query è praticamente un indizio. 56 parametri, 96 query concesse, quindi 96 - 56 = 40 equazioni di verifica per ogni lane. e le lane sono 16, indipendenti ma con lo stesso insieme di nodi. la ridondanza rende il recupero molto robusto.

---

## Fase 7 — Come spendere le 96 query

Questo è il punto che ha richiesto la correzione dei primi solver, ed è la parte di design vera della soluzione.

per i primi 56 blocchi vogliamo che tutte e 16 le lane abbiano symbol = 0:

plaintext = bytes((q << 4) &#124; q for q in range(16))

perché symbol = low - q = q - q = 0. così tutti i symbol_inv[symbol] collassano su symbol_inv[0], l'unico valore da brute-forzare.

nei restanti 40 blocchi si fa una cosa più furba: le lane 1..15 restano su symbol 0, quindi continuano a produrre campioni puliti dello stream fino al blocco 95, mentre la sola lane 0 cicla sui simboli 1,2,3,&#46;&#46;&#46;,15,1,2,3,&#46;&#46;&#46; e viene usata come sonda per recuperare symbol_inv[1] &#46;&#46;&#46; symbol_inv[15].

nel codice è una riga:

sym = 0 if b < 56 else 1 + ((b - 56) % 15)

le 96 query fanno quindi due lavori insieme: 56 blocchi per imparare lo spettro, 40 blocchi per continuare a osservarlo e contemporaneamente testare i 15 simboli segreti. è esattamente quello che permette di stare dentro il limite.

---

## Fase 8 — Recuperare il polinomio e i nodi

Per ogni coppia candidata (R0, sinv0) si ricostruisce lo stream, ad esempio della lane 1. se il candidato è corretto la sequenza S[0..95] rispetta una ricorrenza di ordine 56.

nel solver finale ho evitato Berlekamp-Massey e sono andato di algebra lineare diretta. per n = 56..95 ogni campione dà un'equazione:

[C1,C2,&#46;&#46;&#46;,C56] · [S_(n-1),&#46;&#46;&#46;,S_(n-56)] = -S_n

tutto in GF(4093). sono 40 equazioni per lane, e con 15 lane pulite fanno 15 x 40 = 600 equazioni per soli 56 coefficienti. sistema fortemente sovradeterminato, molto più solido che sperare in una singola sequenza.

ottenuto il polinomio x^56 + C1*x^55 + &#46;&#46;&#46; + C56, i nodi sono le sue radici. FIELD = 4093 è primo, quindi basta provare x = 1..4092 e cercare P(x) = 0. i nodi sono esattamente 56, e lo spettro è ricostruito.

conoscendo i nodi, i coefficienti di ogni lane escono da un sistema di Vandermonde:

S_0  = c0 + c1 + &#46;&#46;&#46; + c55
S_1  = c0*λ0 + c1*λ1 + &#46;&#46;&#46;
&#46;&#46;&#46;
S_55 = &#46;&#46;&#46;

risolto modulo 4093 per ciascuna delle 16 lane. a questo punto coefficients[lane][node] è completamente ricostruito.

---

## Fase 9 — Recuperare le permutazioni

Con gli stream dei blocchi 0..95 ormai prevedibili, le due permutazioni cadono.

per symbol_inv: sulla lane 0 sappiamo quale simbolo abbiamo mandato in ogni blocco dal 56 in poi. per ogni x ∈ {0..15} calcoliamo quale stream deriverebbe da quella word e lo confrontiamo con lo stream predetto. il match è univoco, e si ottengono symbol_inv[1] &#46;&#46;&#46; symbol_inv[15]. invertendo si ha symbol_perm.

per q_perm: dal primo blocco sappiamo q = 0..15 e osserviamo i q_label, ma l'ordine è ruotato di R0. noto R0:

qperm[q] = base[(q - R0) & 15]

e da lì qinv.

a questo punto abbiamo R0, q_perm, q_inv, symbol_perm, symbol_inv, nodes, coefficients. possiamo prevedere stream[lane][block] per qualunque blocco futuro.

---

## Fase 10 — fold_for_flag

Resta un problema: la flag non viene cifrata subito dopo il blocco 95, prima viene chiamata fold_for_flag():

def fold_for_flag(self):
    for lane, row in enumerate(self.state):
        for j, node in enumerate(self.nodes):
            shift = 1 + (
                self.coefficients[lane][j] * (lane + 1)
                + (j + 3) * (j + 7)
            ) % (FIELD - 1)
            row[j] = row[j] * pow(node, shift, FIELD) % FIELD

prima del fold, dopo 96 query, row[j] = coeff[j] * node[j]^96. dopo il fold:

row[j] = coeff[j] * node[j]^96 * node[j]^shift
       = coeff[j] * node[j]^(96 + shift)

il fold non distrugge la struttura spettrale, la cambia soltanto moltiplicando ogni componente per una potenza nota del nodo. e lo shift è calcolabile, perché dipende solo dai coefficienti che abbiamo già recuperato. quindi per il blocco t della flag:

stream_lane(t) = Σ folded_coeff[lane][j] * node[j]^t

tutti gli stream della flag sono calcolabili direttamente.

---

## Fase 11 — Decifrare la flag e togliere il padding

Per ogni blocco del ciphertext della flag:

ciphertext → undiffuse → public_wrapper_inv → inner words

poi si calcola la rotazione:

rotation = (sum(stream) + 3*stream[0] + block_number) & 15

e si inverte inner_word usando q_inv, symbol_perm e lo stream. ogni byte si ricostruisce come:

byte = (q << 4) &#124; ((symbol + q) & 15)

e si rimette nella posizione originale con plaintext_index = (rank + rotation) & 15.

la flag era stata cifrata con padded = pkcs7_pad(self.flag), quindi alla fine si toglie il padding. nel nostro caso il plaintext recuperato termina con un padding PKCS#7 valido, che è la conferma finale che tutta la catena è coerente.

---

## Fase 12 — Solver

```python
import socket,sys
HOST="tcp.sasc.tf"; PORT=31415; P=4093; N=56
SBOX=(6,4,12,5,0,7,2,14,1,15,3,13,8,10,9,11)
SI=[0]*16
for i,v in enumerate(SBOX): SI[v]=i
ML=(0,1,5,9,13,3,7,11,15,2,6,10,14,4,8,12)
MR=(7,11,3,13,5,15,9,1,14,6,12,4,10,2,8,0)

def r4(v,a):
    a&=3; v&=15
    return v if not a else ((v<<a)&#124;(v>>(4-a)))&15

def r8(v,a):
    a&=7; v&=255
    return v if not a else ((v<<a)&#124;(v>>(8-a)))&255

def r16(v,a):
    a&=15; v&=65535
    return v if not a else ((v<<a)&#124;(v>>(16-a)))&65535

def ff(v,k,r):
    x=(SBOX[v>>4]<<4)&#124;SBOX[v&15]
    x=(x+k+19*r)&255
    return r8(x,r+1)^((v*0x3d)&255)

def winv(w,r):
    l,h=w>>8,w&255
    for rnd in range(3,-1,-1):
        k=(0x53+r*0x29+rnd*0x47)&255
        l,h=h^ff(l,k,rnd),l
    return (l<<8)&#124;h

def undiff(w):
    f=[0]*16
    f[15]=w[15]
    for i in range(14,-1,-1):
        f[i]=w[i]^r16(w[i+1],-MR[i])
    z=[f[0]]
    for i in range(1,16):
        z.append(f[i]^r16(f[i-1],ML[i]))
    return z

def inner(ct):
    w=[int.from_bytes(ct[i:i+2],"big") for i in range(0,32,2)]
    w=undiff(w)
    return [winv(x,i) for i,x in enumerate(w)]

def fld(w):
    return ((w>>12)&15,(w>>8)&15,(w>>4)&15,w&15)

def candidate(w,q,sinv):
    _,rf,cf,ch=fld(w)
    rc=(11*(sinv+2*rf-cf))&15
    low=SI[rc]
    mask=(rf-rc)&15
    bc=(sinv-rc)&15
    hi=ch^SBOX[(rc^r4(bc,1)^q^low)&15]
    v=(hi<<8)&#124;(mask<<4)&#124;low
    if v>=P:return None
    return v

class Client:
    def __init__(self):
        self.s=socket.create_connection((HOST,PORT),15)
        self.s.settimeout(30)
        self.b=b""
    def until(self,t):
        while t not in self.b:
            x=self.s.recv(4096)
            if not x: raise RuntimeError("server closed")
            self.b+=x
        i=self.b.index(t)+len(t)
        z=self.b[:i]
        self.b=self.b[i:]
        return z
    def query(self,pt):
        self.until(b"> ")
        self.s.sendall(b"1\n")
        self.until(b"plaintext hex> ")
        self.s.sendall(pt.hex().encode()+b"\n")
        z=self.until(b"queries left:")
        h=z.split(b"ciphertext:",1)[1].split()[0]
        return bytes.fromhex(h.decode())
    def getflag(self):
        self.until(b"> ")
        self.s.sendall(b"2\n")
        z=self.until(b"encrypted flag:")
        while b"\n" not in self.b:
            x=self.s.recv(4096)
            if not x: raise RuntimeError("server closed")
            self.b+=x
        line,self.b=self.b.split(b"\n",1)
        return bytes.fromhex(line.split()[0].decode())
    def close(self):
        self.s.close()

def gauss(A,b):
    m=len(A)
    n=len(A[0])
    a=[[(x%P) for x in A[i]]+[b[i]%P] for i in range(m)]
    row=0
    piv=[]
    for col in range(n):
        k=None
        for r in range(row,m):
            if a[r][col]:
                k=r
                break
        if k is None:
            continue
        a[row],a[k]=a[k],a[row]
        iv=pow(a[row][col],P-2,P)
        for j in range(col,n+1):
            a[row][j]=a[row][j]*iv%P
        for r in range(m):
            if r!=row and a[r][col]:
                q=a[r][col]
                for j in range(col,n+1):
                    a[r][j]=(a[r][j]-q*a[row][j])%P
        piv.append(col)
        row+=1
        if row==m:
            break
    if len(piv)<n:
        return None
    for r in range(row,m):
        if all(a[r][c]==0 for c in range(n)) and a[r][n]:
            return None
    x=[0]*n
    for r,c in enumerate(piv):
        x[c]=a[r][n]
    return x

def poly_value(C,x):
    y=0
    for c in C:
        y=(y*x+c)%P
    return y

def roots(C):
    return [x for x in range(1,P) if poly_value(C,x)==0]

def coeffs(seq,nodes):
    A=[[pow(x,k,P) for x in nodes] for k in range(N)]
    return gauss(A,seq[:N])

def sval(c,nodes,n):
    return sum(c[j]*pow(nodes[j],n,P) for j in range(N))%P

def rotation_data(blocks):
    labs=[[fld(w)[0] for w in b] for b in blocks]
    base=labs[0]
    ds=[]
    for b in range(len(blocks)):
        hit=[d for d in range(16)
             if all(labs[b][r]==base[(r+d)&15] for r in range(16))]
        if len(hit)!=1:
            raise RuntimeError(("rotation",b,hit))
        ds.append(hit[0])
    return base,ds

def aligned(blocks,ds,R0,b,lane):
    R=(R0+ds[b])&15
    return blocks[b][(lane-R)&15]

def zero_seq(blocks,ds,R0,lane,s0):
    out=[]
    for b in range(96):
        v=candidate(aligned(blocks,ds,R0,b,lane),lane,s0)
        if v is None:
            return None
        out.append(v)
    return out

def main():
    c=Client()
    blocks=[]
    print("[+] collecting 96 queries&#46;&#46;&#46;")
    for b in range(96):
        sym=0 if b<56 else 1+((b-56)%15)
        pt=[]
        for q in range(16):
            s=sym if q==0 else 0
            pt.append((q<<4)&#124;((q+s)&15))
        ct=c.query(bytes(pt))
        blocks.append(inner(ct))
        if (b+1)%16==0:
            print(f"    {b+1}/96")

    base,ds=rotation_data(blocks)
    print("[+] rotations recovered")

    model=None
    for R0 in range(16):
        for s0 in range(16):
            seqs=[]
            good=True
            for lane in range(1,16):
                seq=[]
                for b in range(96):
                    v=candidate(
                        aligned(blocks,ds,R0,b,lane),
                        lane,
                        s0
                    )
                    if v is None:
                        good=False
                        break
                    seq.append(v)
                if not good:
                    break
                seqs.append(seq)
            if not good:
                continue

            A=[]
            bb=[]
            for seq in seqs:
                for n in range(56,96):
                    A.append(
                        [seq[n-i] for i in range(1,N+1)]
                    )
                    bb.append((-seq[n])%P)
            C=gauss(A,bb)
            if C is None:
                continue

            for seq in seqs:
                for n in range(56,96):
                    if (
                        seq[n]
                        + sum(
                            C[i-1]*seq[n-i]
                            for i in range(1,N+1)
                        )
                    )%P:
                        good=False
                        break
                if not good:
                    break
            if not good:
                continue

            Cpoly=[1]+C
            nodes=roots(Cpoly)
            if len(nodes)!=56:
                continue

            coeff=[]
            for seq in seqs:
                cc=coeffs(seq,nodes)
                if cc is None:
                    good=False
                    break
                coeff.append(cc)
            if not good:
                continue

            model=(R0,s0,Cpoly,nodes,coeff)
            break
        if model:
            break

    if not model:
        raise RuntimeError("spectral model not recovered")

    R0,s0,Cpoly,nodes,clean_coeff=model
    print("[+] spectral model recovered")
    print("    R0 =",R0,"sinv[0] =",s0)
    print("    nodes =",len(nodes))

    lane0_seq=[]
    for b in range(56):
        v=candidate(
            aligned(blocks,ds,R0,b,0),
            0,
            s0
        )
        if v is None:
            raise RuntimeError("lane0 reconstruction failed")
        lane0_seq.append(v)

    lane0_coeff=coeffs(lane0_seq,nodes)
    if lane0_coeff is None:
        raise RuntimeError("lane0 coeff recovery failed")
    coeff=[lane0_coeff]+clean_coeff

    qperm=[base[(q-R0)&15] for q in range(16)]
    qinv=[0]*16
    for q,x in enumerate(qperm):
        qinv[x]=q

    pred=[
        [sval(coeff[l],nodes,b) for b in range(96)]
        for l in range(16)
    ]

    sinv=[None]*16
    sinv[0]=s0
    print("[+] recovering symbol permutation&#46;&#46;&#46;")
    for sym in range(1,16):
        vals=set()
        for b in range(56,96):
            if 1+((b-56)%15)!=sym:
                continue
            w=aligned(blocks,ds,R0,b,0)
            target=pred[0][b]
            for x in range(16):
                if candidate(w,0,x)==target:
                    vals.add(x)
        if len(vals)!=1:
            raise RuntimeError(
                f"symbol {sym} ambiguous: {sorted(vals)}"
            )
        sinv[sym]=next(iter(vals))

    if len(set(sinv))!=16:
        raise RuntimeError("invalid symbol permutation")

    sperm=[0]*16
    for sym,x in enumerate(sinv):
        sperm[x]=sym
    print("[+] symbol_inv =",sinv)

    print("[+] requesting encrypted flag&#46;&#46;&#46;")
    fc=c.getflag()
    if len(fc)==0 or len(fc)%32:
        raise RuntimeError(
            f"bad encrypted flag length {len(fc)}"
        )
    print("[+] encrypted flag =",len(fc),"bytes")

    folded=[[0]*N for _ in range(16)]
    for lane in range(16):
        for j,node in enumerate(nodes):
            cc=coeff[lane][j]
            shift=1+(
                cc*(lane+1)
                +(j+3)*(j+7)
            )%(P-1)
            folded[lane][j]=(
                cc*pow(node,96+shift,P)
            )%P

    plain=bytearray()
    for t in range(len(fc)//32):
        blockno=96+t
        stream=[
            sum(
                folded[l][j]*pow(nodes[j],t,P)
                for j in range(N)
            )%P
            for l in range(16)
        ]
        R=(
            sum(stream)
            +3*stream[0]+blockno
        )&15
        words=inner(fc[t*32:(t+1)*32])
        out=[0]*16
        for rank,w in enumerate(words):
            label,rf,cf,ch=fld(w)
            q=qinv[label]
            sv=stream[(rank+R)&15]
            low=sv&15
            mask=(sv>>4)&15
            high=sv>>8
            rc=SBOX[low]
            bc=(cf-2*mask)&15
            if rf!=((rc+mask)&15):
                raise RuntimeError(("row check",t,rank))
            check=(
                high
                ^ SBOX[
                    (rc^r4(bc,1)^q^low)&15
                ]
            )
            if check!=ch:
                raise RuntimeError(("check field",t,rank))
            sym=sperm[(rc+bc)&15]
            out[(rank+R)&15]=(
                (q<<4)
                &#124;((sym+q)&15)
            )
        plain.extend(out)

    pad=plain[-1]
    if not(1<=pad<=16):
        raise RuntimeError(("padding",pad))
    if plain[-pad:]!=bytes([pad])*pad:
        raise RuntimeError("invalid padding")
    plain=plain[:-pad]

    print()
    print("="*60)
    print("FLAG =",plain.decode(errors="replace"))
    print("="*60)

if __name__=="__main__":
    try:
        main()
    except Exception as e:
        print("[!] ERROR:",repr(e),file=sys.stderr)
        sys.exit(1)
```

---

## Fase 13 — Errori incontrati

Tre problemi durante il solve, e nessuno dei tre era di crypto.

**glob del file.** avevo scritto:

tar -xzf *sudocrypt*.tar.gz

ma nella directory c'erano due file, sudocrypt_&#46;&#46;&#46;tar.gz e sudocrypt_&#46;&#46;&#46; (1).tar.gz. il glob produceva due argomenti e tar interpretava male il secondo. la soluzione è passare esplicitamente il nome:

tar -xzf 'sudocrypt_08ec969ff2e58b97 (1).tar.gz'

**buffering TCP.** il server manda il prompt > insieme ad altri dati nella stessa recv(). un client che cerca sempre il prompt e butta via i byte successivi perde la sincronizzazione. risolto mantenendo un buffer:

self.b += chunk
&#46;&#46;&#46;
out = self.b[:i]
self.b = self.b[i:]

è un pattern che vale per qualunque exploit TCP interattivo, non solo per questa challenge.

**primo design dei plaintext.** la prima idea cercava di ricostruire la ricorrenza usando blocchi che poi venivano modificati troppo presto, e la sequenza si sporcava. il design corretto è quello della Fase 7: lane 0 come sonda per i simboli, lane 1..15 sempre su symbol 0 per avere una quantità enorme di campioni puliti.

---

## Catena completa

96 chosen plaintexts
   |
   v
+&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;+
&#124;   encryption   &#124;
&#124;     oracle     &#124;
+&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;+
   |
   v
ciphertext blocks
   |
   v
undiffuse_words()
   |
   v
public_wrapper_inv()
   |
   v
inner words
   |
   +&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;+&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;+
   |                         |
   v                         v
q-labels              row/col/check
   |                         |
   v                         v
rotation deltas       stream candidates
   |                         |
   +&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;+&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;+
                |
                v
        recover R0 / sinv0
                |
                v
   linear recurrence over GF(4093)
                |
                v
     characteristic polynomial
                |
                v
         56 spectral nodes
                |
                v
       Vandermonde inversion
                |
                v
      spectral coefficients
                |
      +&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;-+&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;-+
      |                   |
      v                   v
 q permutation    symbol permutation
      |                   |
      +&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;-+&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;-+
                |
                v
            full model
                |
                v
         fold_for_flag()
                |
                v
     predict future streams
                |
                v
         encrypted flag
                |
                v
   inverse wrapper + inner
                |
                v
             PKCS#7
                |
                v
              FLAG

---

## Lezioni apprese

chosen plaintext più uno stream con struttura lineare più abbastanza campioni significa che puoi ricostruire il generatore, anche se la challenge lo chiama crypto. il punto non è la quantità di matematica, è riconoscere che una sequenza della forma S_n = Σ c_j λ_j^n non è casuale ma deterministica.

quando l'autore ti fornisce le funzioni inverse di uno strato, quello strato non è protezione. public_wrapper_inv e undiffuse_words erano nel codice, e appena le usi restano solo 16 word da 16 bit con quattro campi leggibili. mezza challenge sparisce così.

i parametri del challenge sono un indizio. FIELD = 4093, SPECTRUM_SIZE = 56 e QUERY_LIMIT = 96 sono perfettamente allineati per rendere il recupero possibile: 56 incognite, 40 equazioni di verifica in più, campo primo abbastanza piccolo da enumerare le radici per forza bruta. quando i numeri tornano così bene non è generosità, è il design della soluzione prevista.

la parte più elegante del solve è una riga sola, sym = 0 if b < 56 else 1 + ((b-56) % 15). non è brute force, è usare le stesse 96 query per due scopi contemporaneamente: imparare lo spettro e testare i 15 simboli segreti. ed è esattamente quello che permette di stare dentro il limite

un segreto che vive in uno spazio di 16 valori non è un segreto. symbol_inv[0] e R0 avevano 16 possibilità ciascuno, 256 combinazioni in totale, verificabili in un ciclo. il fatto che due permutazioni segrete si riducano a 256 tentativi è quello che rende praticabile tutto il resto.

fold_for_flag sembra una protezione e non lo è, perché non distrugge la struttura spettrale ma moltiplica ogni componente per una potenza nota del nodo. una volta recuperata la decomposizione, lo stato post-fold è calcolabile direttamente. una trasformazione che preserva la struttura che stai cercando di nascondere non nasconde niente

---

## Tool utilizzati

Python 3 (solver interamente custom: socket raw, eliminazione di Gauss su GF(4093), ricerca radici per enumerazione, sistema di Vandermonde), tar, netcat per i test manuali sul servizio
