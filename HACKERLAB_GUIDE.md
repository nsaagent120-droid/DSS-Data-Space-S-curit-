# ⚔️ HackerLab CTF Toolkit & Assistant IA — Guide Complet

> Boîte à outils tout-en-un multi-spécialités (**Crypto, Forensics, Reverse, Web, Réseau/PCAP, OSINT**) avec **Assistant d'Analyse et de Méthodologie IA** intégrée pour les compétitions de type HackerLab / CTF.

---

## 📑 Table des matières
1. [Vue d'ensemble de la Boîte à Outils](#1-vue-densemble)
2. [Mode Interactif (TUI)](#2-mode-interactif-tui)
3. [Modules Spécialisés](#3-modules-spécialisés)
   - [🔐 1. Cryptographie & Solveurs (`crypto`)](#-1-cryptographie--solveurs-crypto)
   - [🔬 2. Forensics & Stéganographie (`forensics`)](#-2-forensics--stéganographie-forensics)
   - [⚙️ 3. Reverse Engineering & Binaire (`reverse`)](#-3-reverse-engineering--binaire-reverse)
   - [🌐 4. Sécurité Web & Code Audit (`web`)](#-4-sécurité-web--code-audit-web)
   - [📡 5. Analyse Réseau & PCAP (`pcap`)](#-5-analyse-réseau--pcap-pcap)
   - [🤖 6. Assistant IA & Méthodologies CTF (`ai`)](#-6-assistant-ia--méthodologies-ctf-ai)
4. [Exemples de Scénarios CTF Réels](#4-exemples-de-scénarios-ctf-réels)

---

## 1. Vue d'ensemble

Le script `hackerlab.py` a été développé pour offrir aux compétiteurs une boîte à outils ultra-rapide, sans dépendances externes lourdes, couvrant l'ensemble des catégories classiques d'un **HackerLab / CTF** :

| Domaine | Outils & Capacités Incluses |
|---|---|
| **Cryptographie** | Décodeur multi-formats instantané, Casseur César (25 décalages avec scoring), Déchiffreur Vigenère, Bruteforce XOR 1-octet, Identification de Hashes, Solveurs RSA (p, q, e -> d, racine e, module commun, Fermat). |
| **Forensics** | Identification Magic Bytes / Header corrompu, Calcul d'entropie Shannon (détection de chiffrement/packing), Découpage de fichiers embarqués (*Carving*), Chasseur de flags CTF automatique. |
| **Reverse Engineering** | Checksec ELF (NX, PIE, Canary, RELRO, Stripped), Extracteur de fonctions et symboles clés, Détecteur de packers (UPX). |
| **Sécurité Web** | Inspecteur & Forgeur JWT (`alg: none`), Bibliothèque de payloads SSTI (Jinja2, Twig, ERB, Smarty), Scanner Regex d'audit de code. |
| **Réseau / PCAP** | Parseur PCAP autonome, extraction de requêtes DNS, flux HTTP, identifiants FTP/Basic Auth en clair et flags transitant sur le réseau. |
| **Assistant IA** | Classificateur automatique de challenges avec scoring de confiance, Checklists méthodologiques pas-à-pas par catégorie, Diagnostiqueur heuristique d'encodages inconnus, Générateur de prompts optimisés pour LLM (Claude, ChatGPT, Ollama). |

---

## 2. Mode Interactif (TUI)

Pour lancer le menu interactif guidé :

```bash
python3 hackerlab.py
# ou
python3 hackerlab.py --interactive
```

---

## 3. Modules Spécialisés

### 🔐 1. Cryptographie & Solveurs (`crypto`)

```bash
# Décodage multi-formats instantané (Base64, Hex, Binaire, Morse, ROT13, Decimal...)
python3 hackerlab.py crypto decode "SGFja2VyTGFiIENURg=="

# Casser un Chiffre de César (classement des 25 décalages par probabilité linguistique)
python3 hackerlab.py crypto break-caesar "Kdfnhuode fuBSwr"

# Déchiffrer avec le chiffre de Vigenère
python3 hackerlab.py crypto vigenere "Lxw tglq" "SECRETKEY"

# Bruteforce XOR sur 1 octet
python3 hackerlab.py crypto xor "1b37373331363f78151b7f2b783431333d"

# Identifier le type d'un hash inconnu
python3 hackerlab.py crypto hash-id "5d41402abc4b2a76b9719d911017c592"

# Résoudre un problème RSA classique connaissant p, q, e et c
python3 hackerlab.py crypto rsa-pq -p 61 -q 53 -e 17 -c 2790
```

---

### 🔬 2. Forensics & Stéganographie (`forensics`)

```bash
# Analyse complète : Magic Bytes réels, Entropie Shannon, Fichiers cachés concaténés et Flags
python3 hackerlab.py forensics info image_suspecte.png

# Extraire les chaînes de caractères imprimables (>= 6 caractères)
python3 hackerlab.py forensics strings dump.bin -n 6

# Recherche automatique de motifs de flags (flag{...}, HL{...}, CTF{...})
python3 hackerlab.py forensics flags memory_dump.raw
```

---

### ⚙️ 3. Reverse Engineering & Binaire (`reverse`)

```bash
# Vérifier les mécanismes de sécurité d'un binaire Linux (checksec)
python3 hackerlab.py reverse checksec challenge_binaire

# Extraire les symboles et fonctions intéressantes (main, validate, check, win, system...)
python3 hackerlab.py reverse symbols crackme.elf
```

---

### 🌐 4. Sécurité Web & Code Audit (`web`)

```bash
# Décoder et inspecter un token JWT sans validation
python3 hackerlab.py web jwt-decode "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Forger un JWT non signé avec la faille 'alg: none'
python3 hackerlab.py web jwt-forge '{"typ":"JWT"}' '{"user":"admin","role":"administrator"}'

# Afficher les payloads de test pour les injections de template (SSTI)
python3 hackerlab.py web ssti
```

---

### 📡 5. Analyse Réseau & PCAP (`pcap`)

```bash
# Analyser une capture de trafic réseau PCAP sans installer Wireshark
python3 hackerlab.py pcap analyze capture_reseau.pcap
```

---

### 🤖 6. Assistant IA & Méthodologies CTF (`ai`)

```bash
# Analyser l'énoncé d'un challenge et obtenir une méthodologie d'investigation étape par étape
python3 hackerlab.py ai analyze -t "RSA Strange Primes" -d "On nous a donné p et q très proches avec le ciphertext c"

# Diagnostiquer un texte suspect ou un encodage inconnu
python3 hackerlab.py ai detect "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."

# Générer un prompt LLM optimisé pour faire analyser du code désassemblé par une IA
python3 hackerlab.py ai prompt -c "Reverse" -f "void validate(char *input) { if (input[0] ^ 0x42 == 0x13) ... }"
```

---

## 4. Exemples de Scénarios CTF Réels

### 🚩 Scénario 1 : Vous recevez un fichier `challenge.jpg` sans extension claire
1. `python3 hackerlab.py forensics info challenge.jpg` → Vérifie si les premiers octets correspondent réellement à un JPEG ou s'il s'agit d'un ZIP ou ELF masqué.
2. `python3 hackerlab.py forensics flags challenge.jpg` → Cherche directement si le flag est caché en clair dans le fichier.

### 🚩 Scénario 2 : Vous faites face à un token JWT sur une application web
1. `python3 hackerlab.py web jwt-decode "<token>"` → Affiche les données et vérifie si `alg: none` ou les dates d'expiration sont vulnérables.
2. `python3 hackerlab.py web jwt-forge '{"typ":"JWT"}' '{"user":"admin"}'` → Génère le token d'usurpation d'identité immédiat.

### 🚩 Scénario 3 : Vous êtes bloqué sur un énoncé de challenge
1. `python3 hackerlab.py ai analyze -t "Titre" -d "Énoncé complet"` → L'assistant IA vous donne la catégorie exacte, les outils recommandés et la checklist d'investigation ordonnée pour résoudre le challenge.
