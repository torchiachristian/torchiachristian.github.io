# Come pubblicare un articolo

## Il flusso, cinque passi

1. Crea due file: `_writeups/it/nome-articolo.md` e `_writeups/en/nome-articolo.md`.
   Lo stesso nome file nelle due cartelle è quello che collega le traduzioni.
2. Incolla il front matter (vedi sotto) e sotto il testo.
3. Metti gli screenshot in `assets/writeups/`.
4. `git add . && git commit -m "writeup: nome" && git push`
5. GitHub Pages ricostruisce da solo in un paio di minuti.

Non serve installare niente in locale. Se vuoi l'anteprima prima di pubblicare
servono Ruby e Jekyll, ma non è obbligatorio.

## Front matter

Le uniche due righe obbligatorie sono `title` e `ref`. Tutto il resto è opzionale
e se lo ometti sparisce dalla pagina.

```
---
title: "Nome del writeup"
ref: nome-articolo
date: 2026-09-01
platform: HTB
os: Linux
difficulty: Easy
tags: [lin, rce, privesc]
summary: "Una riga che compare solo nell'elenco."
txt: /writeups-files/nome.txt
repo: https://github.com/torchiachristian/nome
---
```

`ref` deve essere identico nei due file, italiano e inglese. È così che il
pulsante di lingua sa dove mandare il lettore.

`difficulty` accetta Easy, Medium, Hard, Insane e prende il colore giusto.

`platform` disegna il badge nero. Per un colore diverso aggiungi
`platform_color: "#1d4ed8"` (le virgolette servono, altrimenti YAML legge il
cancelletto come un commento).

## Scrivere il testo

Il testo è markdown normale. Gli a capo singoli restano a capo, quindi puoi
incollare un txt così com'è senza riformattarlo.

Attenzione: siccome ogni a capo conta, un paragrafo di prosa va scritto su una
riga sola. Se lo spezzi su più righe vedrai le interruzioni anche nella pagina.

Titoli di sezione con `##`, sottosezioni con `###`.

Comandi e output di terminale dentro tre backtick:

    ```
    nmap -sV 10.10.10.10
    ```

Tabelle di confronto:

    | Colonna | Altra |
    |---|---|
    | valore  | valore |

Immagine con didascalia:

    <div class="writeup-image">
      <img src="/assets/writeups/nome.png" alt="descrizione">
      <div class="img-caption">didascalia</div>
    </div>

## Struttura del repo

```
_config.yml              configurazione, si tocca raramente
_layouts/base.html       scheletro comune a tutte le pagine
_layouts/writeup.html    intestazione degli articoli
_includes/head.html      meta tag e CSP
_includes/nav.html       barra di navigazione e pulsante lingua
_writeups/it/            articoli in italiano
_writeups/en/            articoli in inglese
writeups.html            elenco, si aggiorna da solo
style.css                unico foglio di stile
index.html               invariato, non passa da Jekyll
about.html               invariato
projects.html            invariato
assets/writeups/         immagini
writeups-files/          i txt integrali scaricabili
```

Le tre pagine fisse non hanno front matter, quindi Jekyll le copia identiche
senza toccarle. Se un giorno vuoi farle passare dal layout, basta aggiungere
`---\nlayout: base\n---` in cima e togliere l'HTML duplicato.

## Anteprima locale, se ti serve

```
gem install bundler jekyll
jekyll serve
```

Poi apri `http://localhost:4000`.
