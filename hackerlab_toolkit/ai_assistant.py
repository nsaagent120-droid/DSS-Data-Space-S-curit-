"""
=============================================================================
  Module Assistant IA & Méthodologie CTF - HackerLab Toolkit
=============================================================================
  Description : Moteur d'analyse de challenges, guide méthodologique par
                catégorie, classificateur heuristique et générateur de prompts
                optimisés pour l'assistance par IA (LLM).
=============================================================================
"""

import re

class CTFAIAssistant:
    """Assistant d'analyse et de méthodologie pour les compétitions CTF / HackerLab."""

    CATEGORIES = {
        "crypto": {
            "name": "Cryptographie",
            "keywords": ["rsa", "aes", "des", "xor", "cipher", "chiffrement", "clé", "cle", "modulo", "prime", "hash", "md5", "sha", "vigenere", "cesar", "caesar", "atbash", "affine", "exponent", "pubkey", "private"],
            "tools": ["RsaCtfTool", "CyberChef", "SageMath", "hashcat", "John the Ripper", "dcode.fr", "FeatherDuster"],
            "workflow": [
                "1. Identifier la nature du texte (Base64, Hex, binaire, ASCII).",
                "2. Vérifier si c'est un chiffrement classique (César, Vigenère, Substitution, XOR).",
                "3. Si RSA : noter p, q, n, e, c. Tester si e est petit (e=3), si n est factorisable (factordb.com), ou si Fermat s'applique (p proche de q).",
                "4. Si AES/DES : vérifier le mode d'opération (ECB vs CBC), chercher le vecteur d'initialisation (IV) ou une clé réutilisée.",
                "5. Si XOR : tester le Single-byte XOR puis le XOR à clé répétée (analyse d'indice de coïncidence)."
            ]
        },
        "forensics": {
            "name": "Forensics & Stéganographie",
            "keywords": ["pcap", "wireshark", "memoire", "memory", "dump", "volatility", "image", "png", "jpg", "exif", "metadata", "lsb", "zsteg", "steghide", "audio", "wav", "spectrogramme", "corrompu", "magic bytes"],
            "tools": ["Wireshark / tshark", "zsteg", "steghide", "binwalk", "exiftool", "Volatility 3", "Audacity", "Sonic Visualiser", "xxd / hexedit"],
            "workflow": [
                "1. Vérifier les Magic Bytes avec la commande 'file' ou l'outil Forensics du toolkit.",
                "2. Extraire les métadonnées EXIF avec exiftool (chercher commentaires, coordonnées GPS, auteur).",
                "3. Chercher des fichiers cachés concaténés avec binwalk -e ou 'carve_files'.",
                "4. Si PNG/BMP : tester zsteg, analyser les plans de bits LSB et les canaux alpha.",
                "5. Si Audio (WAV/MP3) : ouvrir dans Audacity / Sonic Visualiser et passer en vue Spectrogramme.",
                "6. Si PCAP : filtrer les protocoles (DNS, HTTP, FTP, ICMP), extraire les objets et chercher les flags dans les flux TCP."
            ]
        },
        "web": {
            "name": "Sécurité Web & API",
            "keywords": ["http", "jwt", "cookie", "sql", "sqli", "injection", "xss", "csrf", "ssti", "lfi", "rfi", "ssrf", "graphql", "idor", "auth", "token", "php", "node", "flask", "django"],
            "tools": ["Burp Suite / OWASP ZAP", "sqlmap", "ffuf / gobuster", "JWT.io", "Postman", "Commix"],
            "workflow": [
                "1. Cartographier l'application (robots.txt, endpoints, code source HTML/JS, cookies).",
                "2. Examiner les tokens d'authentification (si JWT : tester 'alg: none', clé faible avec hashcat).",
                "3. Tester les paramètres d'entrée pour : SQLi (' OR 1=1--), SSTI ({{7*7}}, ${7*7}), LFI (../../../../etc/passwd).",
                "4. Tester les contournements de type juggling (PHP : == vs ===, strcmp).",
                "5. Si upload de fichier : tenter le bypass d'extension (.php5, .phtml, double extension, bypass MIME)."
            ]
        },
        "reverse": {
            "name": "Reverse Engineering",
            "keywords": ["elf", "exe", "binaire", "assembleur", "asm", "ghidra", "ida", "gdb", "radare2", "decompilation", "crackme", "serial", "keygen", "anti-debug", "ptrace", "upx"],
            "tools": ["Ghidra", "IDA Free", "GDB-GEF / Pwndbg", "Radare2 / Cutter", "objdump", "strace / ltrace", "strings"],
            "workflow": [
                "1. Vérifier l'architecture et les protections avec checksec / file.",
                "2. Exécuter 'strings -n 6' pour repérer des constantes ou messages texte utiles.",
                "3. Lancer strace et ltrace pour observer les appels système et fonctions de bibliothèque (strcmp, ptrace).",
                "4. Ouvrir dans Ghidra : repérer la fonction 'main' ou 'validate', renommer les variables et comprendre la logique de validation.",
                "5. Si le binaire est packé (UPX) : décompresser avec 'upx -d'."
            ]
        },
        "pwn": {
            "name": "Exploitation Binaire (Pwn)",
            "keywords": ["buffer overflow", "bof", "rop", "canary", "aslr", "shellcode", "ret2libc", "heap", "use after free", "uaf", "got", "plt", "pwntools"],
            "tools": ["pwntools (Python)", "GDB avec Pwndbg ou GEF", "ROPgadget", "one_gadget", "checksec"],
            "workflow": [
                "1. Lancer 'checksec' pour connaître les protections actives (Canary, NX, PIE, RELRO).",
                "2. Trouver l'offset du débordement avec gdb (pattern create / pattern offset).",
                "3. Si NX désactivé : injecter un shellcode sur la stack.",
                "4. Si NX activé : construire une chaîne ROP (ret2libc, ret2win, execve('/bin/sh')).",
                "5. Si ASLR activé : provoquer un leak d'adresse (puts(puts@got)) pour calculer la base de la libc."
            ]
        },
        "osint": {
            "name": "OSINT & Renseignement",
            "keywords": ["whois", "dns", "geo", "localisation", "social", "twitter", "linkedin", "email", "ip", "asn", "shodan", "censys", "wayback"],
            "tools": ["Shodan", "Censys", "Wayback Machine", "Sherlock", "SpiderFoot", "Epieos", "Google Dorks"],
            "workflow": [
                "1. Collecter les informations initiales (noms d'utilisateurs, domaines, adresses e-mails, images).",
                "2. Google Dorking : site:cible.com filetype:pdf, intitle:index.of, intext:password.",
                "3. Vérifier les archives web (Wayback Machine / archive.today) pour retrouver des pages supprimées.",
                "4. Si image de lieu : chercher des repères visuels (panneaux, architecture, soleil/ombres, Google Lens)."
            ]
        }
    }

    @classmethod
    def analyze_challenge(cls, title, description=""):
        """Analyse l'énoncé d'un challenge et génère un rapport d'aide méthodologique."""
        text = f"{title} {description}".lower()
        scores = {}
        for cat_id, info in cls.CATEGORIES.items():
            count = sum(1 for kw in info["keywords"] if re.search(r"\b" + re.escape(kw) + r"\b", text))
            scores[cat_id] = count

        best_cat = max(scores, key=scores.get)
        confidence = "Haute" if scores[best_cat] >= 3 else ("Moyenne" if scores[best_cat] >= 1 else "Faible")

        cat_info = cls.CATEGORIES[best_cat]

        return {
            "detected_category": cat_info["name"],
            "category_id": best_cat,
            "confidence": confidence,
            "recommended_tools": cat_info["tools"],
            "step_by_step_methodology": cat_info["workflow"]
        }

    @staticmethod
    def generate_ai_prompt(category, context_snippet, goal="Déchiffrer ou comprendre l'algorithme"):
        """Génère un prompt optimisé et sécurisé à soumettre à un LLM (Claude, ChatGPT, Ollama)."""
        prompt = f"""Tu es un expert mondial en cybersécurité et champion de compétitions CTF (HackerLab).
Voici un problème dans la catégorie **{category}**.

### 🎯 Objectif :
{goal}

### 📄 Données / Code / Contexte fourni :
```
{context_snippet}
```

### 🧠 Directives d'analyse :
1. Explique le principe de fonctionnement sous-jacent et identifie la vulnérabilité ou le mécanisme mathématique.
2. Démontre la démarche logique étape par étape pour résoudre ce problème.
3. Fournis un script Python élégant et commenté (utilisant uniquement les librairies standards ou pwntools) permettant de résoudre le challenge.
4. Reste concis, précis et technique.
"""
        return prompt

    @staticmethod
    def heuristic_flag_detector(text):
        """Diagnostique un texte suspect pour déduire son encodage ou type de hash."""
        text_clean = text.strip()
        diagnostics = []

        # 1. Base64
        if re.match(r"^[A-Za-z0-9+/]+={0,2}$", text_clean) and len(text_clean) % 4 == 0 and len(text_clean) >= 8:
            diagnostics.append({"type": "Base64", "confidence": "Élevée", "advice": "Utiliser 'crypto decode' ou base64.b64decode()"})

        # 2. Hexadécimal
        if re.match(r"^[a-fA-F0-9]+$", text_clean) and len(text_clean) % 2 == 0 and len(text_clean) >= 6:
            if len(text_clean) == 32:
                diagnostics.append({"type": "Hash MD5 ou NTLM (ou chaîne Hex)", "confidence": "Élevée", "advice": "Vérifier sur CrackStation ou hashcat"})
            elif len(text_clean) == 64:
                diagnostics.append({"type": "Hash SHA-256 (ou chaîne Hex)", "confidence": "Élevée", "advice": "Consulter les bases de rainbow tables"})
            else:
                diagnostics.append({"type": "Hexadécimal brut (bytes)", "confidence": "Moyenne", "advice": "Convertir via bytes.fromhex()"})

        # 3. JWT
        if len(text_clean.split('.')) == 3 and text_clean.startswith("eyJ"):
            diagnostics.append({"type": "JSON Web Token (JWT)", "confidence": "Certaine", "advice": "Utiliser le module 'web jwt' pour décoder et tester l'algo 'none'"})

        # 4. Binaire
        if set(text_clean).issubset({'0', '1', ' '}) and len(text_clean) >= 7:
            diagnostics.append({"type": "Binaire (0 et 1)", "confidence": "Élevée", "advice": "Convertir par blocs de 8 bits vers ASCII"})

        # 5. Morse
        if set(text_clean).issubset({'.', '-', ' ', '/', '_'}):
            diagnostics.append({"type": "Code Morse", "confidence": "Élevée", "advice": "Décoder via l'outil 'crypto decode'"})

        if not diagnostics:
            diagnostics.append({"type": "Texte chiffré classique (César, Vigenère ou Substitution)", "confidence": "Moyenne", "advice": "Tester 'crypto break-caesar' ou analyse de fréquences"})

        return diagnostics
