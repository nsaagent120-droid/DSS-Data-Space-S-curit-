# ⚔️ HackerLab CTF Toolkit & Assistant IA (v2.0 Ultimate) — Guide Complet

> Boîte à outils tout-en-un multi-spécialités (**Scanner de Sécurité Intégré, Crypto, Forensics, Reverse, Pwn, Web, Réseau/PCAP, OSINT & Dictionnaires**) avec **Assistant d'Analyse et de Méthodologie IA** pour les compétitions HackerLab / CTF.

---

## 📑 Table des matières
1. [Vue d'ensemble de la Boîte à Outils](#1-vue-densemble)
2. [Mode Interactif (TUI Menu)](#2-mode-interactif-tui-menu)
3. [Modules Spécialisés](#3-modules-spécialisés)
   - [🛡️ 1. Scanner de Sécurité Intégré (D-Scan v3.0)](#️-1-scanner-de-sécurité-intégré-d-scan-v30)
   - [🔐 2. Cryptographie & Solveurs Mathématiques (`crypto`)](#-2-cryptographie--solveurs-mathématiques-crypto)
   - [🔬 3. Forensics & Stéganographie (`forensics`)](#-3-forensics--stéganographie-forensics)
   - [⚙️ 4. Reverse Engineering & Binaire (`reverse`)](#-4-reverse-engineering--binaire-reverse)
   - [💥 5. Pwn & Exploitation Math (`pwn`)](#-5-pwn--exploitation-math-pwn)
   - [🌐 6. Sécurité Web & Code Audit (`web`)](#-6-sécurité-web--code-audit-web)
   - [📡 7. Analyse Réseau & PCAP (`pcap`)](#-7-analyse-réseau--pcap-pcap)
   - [🌍 8. OSINT, Réseau & Dictionnaires (`osint` & `wordlist`)](#-8-osint-réseau--dictionnaires-osint--wordlist)
   - [🤖 9. Assistant IA & Méthodologies CTF (`ai`)](#-9-assistant-ia--méthodologies-ctf-ai)
4. [Scénarios Pratiques de Compétition](#4-scénarios-pratiques-de-compétition)

---

## 1. Vue d'ensemble

Le script `hackerlab.py` regroupe l'intégralité des outils nécessaires pour une compétition CTF moderne en une seule interface autonome sans dépendances externes :

| Domaine | Outils & Capacités Incluses |
|---|---|
| **🛡️ Scanner Intégré** | D-Scan v3.0 (Scan TCP & UDP, Versions -sV, OSINT Geo, WAF, CMS, DNS, SSL, Rapports HTML/XML). |
| **🔐 Cryptographie** | Décodeur multi-formats (Base64, Hex, Binaire, Morse, ROT13), Chiffres classiques (César, Vigenère, Rail Fence, Affine, Bacon), Bruteforce XOR 1-octet, Hashes ID, Solveurs RSA (p, q, e -> d, racine e, Fermat) et Logarithme Discret (Baby-step Giant-step). |
| **🔬 Forensics** | Magic bytes / Headers, Entropie Shannon, Réparateur de dimensions PNG corrompues (CRC32 IHDR), File carving, Chasseur de flags CTF. |
| **⚙️ Reverse** | Checksec ELF natif (NX, PIE, Canary, RELRO, Stripped), extracteur de symboles et fonctions clés, détection de packers (UPX). |
| **💥 Pwn** | Générateur cyclique de De Bruijn (`cyclic`), calculateur d'offset de crash (`find`), packing Little-Endian (`p32`/`p64`), vérificateur de badchars. |
| **🌐 Web** | Inspecteur & forgeur JWT (`alg: none`), bibliothèque de payloads SSTI (Jinja2, Twig, ERB), regex d'audit de code source. |
| **📡 PCAP / Réseau** | Parseur de captures réseau sans Wireshark (DNS, HTTP, identifiants en clair FTP/Basic Auth, flags en transit). |
| **🌍 OSINT & Wordlists** | Calculateur de sous-réseaux CIDR, générateur de Google Dorks, constructeur OUI MAC, générateur de mutations Leetspeak CTF. |
| **🤖 Assistant IA** | Classificateur d'énoncés, checklists méthodologiques pas-à-pas par catégorie, diagnostiqueur heuristique et générateur de prompts LLM. |

---

## 2. Mode Interactif (TUI Menu)

Lancez simplement la boîte à outils sans argument pour naviguer dans le menu interactif :

```bash
python3 hackerlab.py
```

---

## 3. Modules Spécialisés

### 🛡️ 1. Scanner de Sécurité Intégré (`scan`)
```bash
# Scan complet agressif d'un serveur ou lab CTF
python3 hackerlab.py scan -t 192.168.1.50 -A --html rapport.html
```

### 🔐 2. Cryptographie & Solveurs (`crypto`)
```bash
# Décodage multi-formats instantané
python3 hackerlab.py crypto decode "SGFja2VyTGFiIENURg=="

# Casser un Chiffre de César
python3 hackerlab.py crypto break-caesar "Kdfnhuode fuBSwr"

# Déchiffrer avec Vigenère
python3 hackerlab.py crypto vigenere "Lxw tglq" "SECRETKEY"

# Déchiffrer ou bruteforcer un Chiffre Rail Fence
python3 hackerlab.py crypto rail-fence "HkLbCTaeraF" -r 2

# Déchiffrer un Chiffre Affine (ax + b mod 26)
python3 hackerlab.py crypto affine "Iekkm" -a 7 -b 3

# Déchiffrer le Code Bacon
python3 hackerlab.py crypto bacon "BAABA ABABA AABAB AABAA"

# Bruteforce XOR sur 1 octet
python3 hackerlab.py crypto xor "1b37373331363f78151b7f2b783431333d"

# Identifier le type d'un hash
python3 hackerlab.py crypto hash-id "5d41402abc4b2a76b9719d911017c592"

# Solveur RSA classique (p, q, e -> d et déchiffrement de c)
python3 hackerlab.py crypto rsa-pq -p 61 -q 53 -e 17 -c 2790

# Résoudre un logarithme discret (g^x = y mod p)
python3 hackerlab.py crypto dlog -g 2 -y 8 -p 11
```

### 🔬 3. Forensics & Stéganographie (`forensics`)
```bash
# Inspection Forensics complète (Magic bytes, entropie, carving, flags)
python3 hackerlab.py forensics info image_suspecte.png

# Réparer les dimensions d'une image PNG tronquée d'après son CRC32 IHDR
python3 hackerlab.py forensics fix-png image_tronquee.png

# Extraire les chaînes de caractères imprimables (longueur >= 6)
python3 hackerlab.py forensics strings dump.raw -n 6

# Chasser automatiquement les motifs de flags CTF
python3 hackerlab.py forensics flags capture_memoire.dmp
```

### ⚙️ 4. Reverse Engineering (`reverse`)
```bash
# Checksec sur un binaire ELF (NX, PIE, Canary, RELRO)
python3 hackerlab.py reverse checksec challenge.elf

# Extraire les fonctions et symboles clés
python3 hackerlab.py reverse symbols crackme.bin
```

### 💥 5. Pwn & Buffer Overflow Math (`pwn`)
```bash
# Générer une séquence cyclique de De Bruijn (50 octets)
python3 hackerlab.py pwn cyclic 50

# Trouver l'offset exact du crash EIP/RIP
python3 hackerlab.py pwn find "Aa3"

# Convertir une adresse en octets Little-Endian (p32 / p64)
python3 hackerlab.py pwn pack 0x080484b6

# Vérifier la présence de Bad Characters (\x00, \x0a, \x0d)
python3 hackerlab.py pwn badchars "31c050682f2f736800"
```

### 🌐 6. Sécurité Web & Code Audit (`web`)
```bash
# Décoder un token JWT sans signature
python3 hackerlab.py web jwt-decode "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Forger un JWT non signé (alg: none)
python3 hackerlab.py web jwt-forge '{"typ":"JWT"}' '{"user":"admin","role":"admin"}'

# Afficher la bibliothèque de payloads SSTI
python3 hackerlab.py web ssti
```

### 📡 7. Analyse Réseau & PCAP (`pcap`)
```bash
# Analyser une capture de trafic PCAP en local
python3 hackerlab.py pcap analyze capture.pcap
```

### 🌍 8. OSINT & Dictionnaires (`osint` & `wordlist`)
```bash
# Calculateur de sous-réseau CIDR
python3 hackerlab.py osint cidr 192.168.1.0/24

# Générateur de Google Dorks pour un domaine
python3 hackerlab.py osint dorks example.com

# Résolution de constructeur OUI d'une adresse MAC
python3 hackerlab.py osint mac 00:50:56:12:34:56

# Générateur de mutations de mots de passe Leetspeak CTF
python3 hackerlab.py wordlist mutate "admin" -n 20
```

### 🤖 9. Assistant IA & Méthodologies (`ai`)
```bash
# Classifier un challenge et obtenir une checklist d'investigation
python3 hackerlab.py ai analyze -t "RSA Strange Primes" -d "On nous a donné p et q très proches avec le ciphertext c"

# Diagnostiquer un texte suspect ou un encodage inconnu
python3 hackerlab.py ai detect "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."

# Générer un prompt LLM optimisé
python3 hackerlab.py ai prompt -c "Reverse" -f "void validate(char *input) { ... }"
```

---

## 4. Scénarios Pratiques de Compétition

### 🚩 Scénario 1 : Image PNG tronquée (Flag invisible en bas de l'image)
1. `python3 hackerlab.py forensics fix-png challenge.png` → Détecte l'incohérence CRC32 et calcule la hauteur réelle (ex: 800px au lieu de 200px).
2. Ouvrez l'image dans un éditeur hexadécimal et appliquez la hauteur pour révéler le flag !

### 🚩 Scénario 2 : Exploitation d'un Buffer Overflow binaire
1. `python3 hackerlab.py reverse checksec vuln_bin` → Vérifie si NX ou Canary sont activés.
2. `python3 hackerlab.py pwn cyclic 100` → Injecte la séquence dans le binaire sous GDB.
3. `python3 hackerlab.py pwn find 0x41346141` → Obtient l'offset exact pour écraser l'adresse de retour.
4. `python3 hackerlab.py pwn pack 0x080484b6` → Génère le payload d'adresse Little-Endian.

### 🚩 Scénario 3 : Challenge Web avec JWT
1. `python3 hackerlab.py web jwt-decode "<token>"` → Affiche les claims utilisateurs.
2. `python3 hackerlab.py web jwt-forge '{"typ":"JWT"}' '{"user":"admin","role":"admin"}'` → Génère le token contrefait avec `alg: none`.
