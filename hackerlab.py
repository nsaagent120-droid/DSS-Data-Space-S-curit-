#!/usr/bin/env python3
"""
=============================================================================
  HackerLab Toolkit (HL-Tool v2.0) — Boîte à Outils CTF, Scanner & Assistant IA
=============================================================================
  Auteur      : DSS Security / HackerLab Competition Toolkit
  Description : Suite complète d'outils d'investigation et d'assistance IA :
                - Scan de Sécurité Réseau & Web (D-Scan v3.0 intégré)
                - Cryptographie (Décodeur, César, Vigenère, Rail Fence, Affine, Bacon, Hashes, RSA, D-Log)
                - Forensics & Stéganographie (Magic Bytes, Entropie, PNG CRC Fixer, Flags, Carving)
                - Reverse Engineering (ELF checksec, Symboles, UPX)
                - Pwn / Exploitation Math (De Bruijn cyclic pattern, offset finder, p32/p64, badchars)
                - Sécurité Web (JWT decode/forge, SSTI, Audit de code)
                - Analyse Réseau & PCAP (Extraction DNS, HTTP, Credentials)
                - OSINT & Recon (CIDR calculator, Google Dorks, MAC OUI)
                - Wordlist & Dictionnaires (Mutations Leetspeak CTF)
                - Assistant IA & Méthodologies CTF (Diagnostic, Workflow, Prompts)
  Usage       : python3 hackerlab.py [module] [commande] [arguments]
                ou lancer sans argument pour le Mode Interactif !
=============================================================================
"""

import argparse
import json
import os
import subprocess
import sys

# Importation des modules internes
try:
    from hackerlab_toolkit.crypto_tools import MultiDecoder, ClassicalCiphers, HashIdentifier, RSASolver
    from hackerlab_toolkit.forensics_tools import ForensicsAnalyzer
    from hackerlab_toolkit.reversing_tools import ELFAnalyzer
    from hackerlab_toolkit.web_tools import JWTTool, SSTIPayloadHelper, CodeAuditor
    from hackerlab_toolkit.pcap_tools import PCAPAnalyzer
    from hackerlab_toolkit.pwn_tools import PwnHelper
    from hackerlab_toolkit.osint_tools import OSINTToolkit
    from hackerlab_toolkit.wordlist_tools import WordlistMutator
    from hackerlab_toolkit.ai_assistant import CTFAIAssistant
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from hackerlab_toolkit.crypto_tools import MultiDecoder, ClassicalCiphers, HashIdentifier, RSASolver
    from hackerlab_toolkit.forensics_tools import ForensicsAnalyzer
    from hackerlab_toolkit.reversing_tools import ELFAnalyzer
    from hackerlab_toolkit.web_tools import JWTTool, SSTIPayloadHelper, CodeAuditor
    from hackerlab_toolkit.pcap_tools import PCAPAnalyzer
    from hackerlab_toolkit.pwn_tools import PwnHelper
    from hackerlab_toolkit.osint_tools import OSINTToolkit
    from hackerlab_toolkit.wordlist_tools import WordlistMutator
    from hackerlab_toolkit.ai_assistant import CTFAIAssistant

class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"

def banner():
    art = f"""
{Colors.BOLD}{Colors.CYAN}  ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ ██╗      █████╗ ██████╗ 
  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗██║     ██╔══██╗██╔══██╗
  ███████║███████║██║     █████═╝ █████╗  ██████╔╝██║     ███████║██████╔╝
  ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗██║     ██╔══██║██╔══██╗
  ██║  ██║██║  ██║╚██████╗██║ ╚██╗███████╗██║  ██║███████╗██║  ██║██████╔╝
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ {Colors.RESET}
  {Colors.BOLD}{Colors.MAGENTA}⚔️  HACKERLAB CTF TOOLKIT & ASSISTANT IA (v2.0 ULTIMATE){Colors.RESET}
  {Colors.DIM}Boîte à outils multi-spécialités + Scanner de Sécurité Intégré (D-Scan v3.0){Colors.RESET}
"""
    print(art)

# =============================================================================
# GESTIONNAIRES DE COMMANDES
# =============================================================================
def handle_scan(args):
    """Exécute le scanner de sécurité complet scan.py."""
    scan_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan.py")
    cmd = [sys.executable, scan_script] + args.scan_args
    try:
        subprocess.run(cmd)
    except Exception as e:
        print(f"{Colors.RED}[!] Erreur lors de l'exécution du scanner : {e}{Colors.RESET}")

def handle_crypto(args):
    if args.action == "decode":
        text = " ".join(args.text)
        print(f"\n{Colors.CYAN}[*] Décodage multi-formats pour :{Colors.RESET} {text}\n")
        results = MultiDecoder.decode_all(text)
        for fmt, val in results.items():
            print(f"  {Colors.BOLD}{Colors.GREEN}[+] {fmt:<16}:{Colors.RESET} {val}")
        print()

    elif args.action == "break-caesar":
        text = " ".join(args.text)
        print(f"\n{Colors.CYAN}[*] Analyse César pour :{Colors.RESET} {text}\n")
        candidates = ClassicalCiphers.break_caesar(text)
        print(f"{'DÉCALAGE':<12} {'SCORE':<8} {'TEXTE DÉCHIFFRÉ'}")
        print("-" * 65)
        for c in candidates[:6]:
            star = f"{Colors.GREEN}★{Colors.RESET}" if c == candidates[0] else " "
            print(f"ROT-{c['shift']:<2} {star}       {c['score']:<8.2f} {Colors.BOLD}{c['text'][:45]}{Colors.RESET}")
        print()

    elif args.action == "vigenere":
        decrypted = ClassicalCiphers.vigenere_decrypt(args.ciphertext, args.key)
        print(f"\n{Colors.GREEN}[+] Vigenère (Clé: {args.key}) :{Colors.RESET} {Colors.BOLD}{decrypted}{Colors.RESET}\n")

    elif args.action == "rail-fence":
        if args.rails:
            decrypted = ClassicalCiphers.rail_fence_decrypt(args.ciphertext, args.rails)
            print(f"\n{Colors.GREEN}[+] Rail Fence ({args.rails} rails) :{Colors.RESET} {Colors.BOLD}{decrypted}{Colors.RESET}\n")
        else:
            candidates = ClassicalCiphers.break_rail_fence(args.ciphertext)
            print(f"\n{Colors.CYAN}[*] Bruteforce Rail Fence :{Colors.RESET}\n")
            for c in candidates[:5]:
                print(f"  {Colors.GREEN}[+] {c['rails']} rails (Score: {c['score']}) :{Colors.RESET} {c['text']}")
            print()

    elif args.action == "affine":
        if args.a and args.b is not None:
            decrypted = ClassicalCiphers.affine_decrypt(args.ciphertext, args.a, args.b)
            print(f"\n{Colors.GREEN}[+] Chiffre Affine (a={args.a}, b={args.b}) :{Colors.RESET} {Colors.BOLD}{decrypted}{Colors.RESET}\n")
        else:
            candidates = ClassicalCiphers.break_affine(args.ciphertext)
            print(f"\n{Colors.CYAN}[*] Bruteforce Affine :{Colors.RESET}\n")
            for c in candidates[:5]:
                print(f"  {Colors.GREEN}[+] a={c['a']}, b={c['b']} :{Colors.RESET} {Colors.BOLD}{c['text']}{Colors.RESET}")
            print()

    elif args.action == "bacon":
        text = " ".join(args.text)
        decrypted = ClassicalCiphers.bacon_decrypt(text)
        print(f"\n{Colors.GREEN}[+] Décodage Code Bacon :{Colors.RESET} {Colors.BOLD}{decrypted}{Colors.RESET}\n")

    elif args.action == "xor":
        hex_data = args.hex_data.replace(" ", "").replace("0x", "")
        data_bytes = bytes.fromhex(hex_data)
        print(f"\n{Colors.CYAN}[*] Bruteforce XOR sur 1 octet ({len(data_bytes)} octets)...{Colors.RESET}\n")
        res = ClassicalCiphers.single_byte_xor(data_bytes)
        for r in res[:5]:
            print(f"  {Colors.GREEN}[+] Clé {r['key_char']} (0x{r['key']:02x}) :{Colors.RESET} {Colors.BOLD}{r['text']}{Colors.RESET}")
        print()

    elif args.action == "hash-id":
        matches = HashIdentifier.identify(args.hash_str)
        print(f"\n{Colors.CYAN}[*] Identification du hash :{Colors.RESET} {args.hash_str}\n")
        for m in matches:
            print(f"  {Colors.GREEN}[+] Format : {Colors.BOLD}{m['name']}{Colors.RESET} — {m['desc']}")
        print()

    elif args.action == "rsa-pq":
        res = RSASolver.solve_pq(args.p, args.q, args.e, args.c)
        print(f"\n{Colors.CYAN}=== RÉSULTATS RSA (p, q, e, c) ==={Colors.RESET}")
        print(f"  {Colors.GREEN}[+] Modulus (n)       :{Colors.RESET} {res['n']}")
        print(f"  {Colors.GREEN}[+] Clé privée (d)    :{Colors.RESET} {res['d']}")
        print(f"  {Colors.GREEN}[+] Message déchiffré :{Colors.RESET} {Colors.BOLD}{Colors.YELLOW}{res['plaintext']}{Colors.RESET}\n")

    elif args.action == "dlog":
        res = RSASolver.baby_step_giant_step(args.g, args.y, args.p)
        print(f"\n{Colors.CYAN}=== LOGARITHME DISCRET (g^x = y mod p) ==={Colors.RESET}")
        if res is not None:
            print(f"  {Colors.GREEN}[+] Valeur trouvée x = {Colors.BOLD}{Colors.YELLOW}{res}{Colors.RESET}\n")
        else:
            print(f"  {Colors.RED}[!] Pas de solution trouvée dans le corps fini.{Colors.RESET}\n")

def handle_forensics(args):
    filepath = args.file
    if not os.path.exists(filepath):
        print(f"{Colors.RED}[!] Fichier introuvable : {filepath}{Colors.RESET}")
        return

    with open(filepath, "rb") as f:
        data = f.read()

    if args.action == "info":
        magics = ForensicsAnalyzer.identify_magic(data)
        entropy = ForensicsAnalyzer.shannon_entropy(data)
        flags = ForensicsAnalyzer.find_flags(data)
        carved = ForensicsAnalyzer.carve_files(data)

        print(f"\n{Colors.CYAN}=== ANALYSE FORENSICS : {os.path.basename(filepath)} ({len(data)} octets) ==={Colors.RESET}")
        if magics:
            for m in magics:
                print(f"  {Colors.GREEN}[+] Type de fichier (Magic) :{Colors.RESET} {Colors.BOLD}{m['name']}{Colors.RESET} (.{m['ext']})")
        else:
            print(f"  {Colors.YELLOW}[!] Magic Bytes non reconnus (fichier corrompu ou format brut){Colors.RESET}")

        print(f"  {Colors.GREEN}[+] Entropie de Shannon    :{Colors.RESET} {entropy['entropy']}/8.0 — {entropy['interpretation']}")

        if flags:
            print(f"\n{Colors.BOLD}{Colors.GREEN}🚩 FLAGS DÉTECTÉS DANS LE FICHIER :{Colors.RESET}")
            for fl in flags:
                print(f"    ↳ {Colors.BOLD}{Colors.YELLOW}{fl['flag']}{Colors.RESET} (Offset: {fl['offset_hex']})")

        if len(carved) > 1:
            print(f"\n{Colors.CYAN}[*] Fichiers imbriqués découverts ({len(carved)}) :{Colors.RESET}")
            for c in carved:
                print(f"    ↳ {c['type']} à l'offset {c['offset_hex']}")
        print()

    elif args.action == "strings":
        strings = ForensicsAnalyzer.extract_strings(data, min_len=args.min_len)
        print(f"\n{Colors.CYAN}[*] Extraction de {len(strings)} chaînes (longueur >= {args.min_len}) :{Colors.RESET}\n")
        for s in strings[:30]:
            print(f"  {Colors.DIM}{s['offset_hex']:<8}{Colors.RESET} {s['string']}")
        print()

    elif args.action == "flags":
        flags = ForensicsAnalyzer.find_flags(data)
        if flags:
            print(f"\n{Colors.GREEN}[+] Flags trouvés dans {filepath} :{Colors.RESET}")
            for f in flags:
                print(f"  🚩 {Colors.BOLD}{Colors.YELLOW}{f['flag']}{Colors.RESET} (Offset: {f['offset_hex']})")
        else:
            print(f"\n{Colors.YELLOW}[!] Aucun pattern de flag standard détecté.{Colors.RESET}")
        print()

    elif args.action == "fix-png":
        res = ForensicsAnalyzer.fix_png_dimensions(data)
        print(f"\n{Colors.CYAN}=== RÉPARATION DIMENSIONS PNG IHDR (CRC32) ==={Colors.RESET}")
        if "error" in res:
            print(f"  {Colors.RED}[!] {res['error']}{Colors.RESET}\n")
        else:
            print(f"  {Colors.GREEN}[+] Statut :{Colors.RESET} {res['status']}")
            if "corrected_height" in res:
                print(f"  {Colors.GREEN}[+] Dimensions Réelles :{Colors.RESET} {res['corrected_width']} x {Colors.BOLD}{Colors.YELLOW}{res['corrected_height']}{Colors.RESET} px")
                print(f"  💡 Modifiez les octets du fichier à l'offset 0x14 avec la hauteur : {hex(res['corrected_height'])}\n")
            else:
                print(f"  {Colors.GREEN}[+] Dimensions :{Colors.RESET} {res.get('width')} x {res.get('height')} px ({res.get('message')})\n")

def handle_reverse(args):
    filepath = args.file
    if not os.path.exists(filepath):
        print(f"{Colors.RED}[!] Fichier introuvable : {filepath}{Colors.RESET}")
        return

    with open(filepath, "rb") as f:
        data = f.read()

    if args.action == "checksec":
        res = ELFAnalyzer.checksec(data)
        if "error" in res:
            print(f"{Colors.RED}[!] {res['error']}{Colors.RESET}")
            return

        hdr = res["header"]
        prot = res["protections"]
        print(f"\n{Colors.CYAN}=== CHECKSEC & INFORMATIONS ELF : {os.path.basename(filepath)} ==={Colors.RESET}")
        print(f"  {Colors.GREEN}[+] Architecture :{Colors.RESET} {hdr['class']} ({hdr['machine']}) — {hdr['endian']}")
        print(f"  {Colors.GREEN}[+] Entry Point  :{Colors.RESET} {hdr['entry_point']}")
        print("-" * 65)

        can_col = Colors.GREEN if prot["canary"]["enabled"] else Colors.RED
        nx_col = Colors.GREEN if prot["nx"]["enabled"] else Colors.RED
        pie_col = Colors.GREEN if prot["pie"]["enabled"] else Colors.RED
        rel_col = Colors.GREEN if prot["relro"]["level"] == "Full RELRO" else (Colors.YELLOW if prot["relro"]["level"] == "Partial RELRO" else Colors.RED)

        print(f"  • Canary     : {can_col}{'Actif (Stack protection)' if prot['canary']['enabled'] else 'Désactivé'}{Colors.RESET}")
        print(f"  • NX         : {nx_col}{'Actif (Stack non-exécutable)' if prot['nx']['enabled'] else 'Désactivé'}{Colors.RESET}")
        print(f"  • PIE        : {pie_col}{'Actif (ASLR binaire)' if prot['pie']['enabled'] else 'Désactivé'}{Colors.RESET}")
        print(f"  • RELRO      : {rel_col}{prot['relro']['level']}{Colors.RESET}")
        print(f"  • Stripped   : {Colors.CYAN}{'Oui' if prot['stripped']['status'] else 'Non'}{Colors.RESET}")

        packers = ELFAnalyzer.detect_packers(data)
        if packers:
            for p in packers:
                print(f"  ⚠️ {Colors.YELLOW}{p['packer']} détecté ! ({p['solution']}){Colors.RESET}")
        print()

    elif args.action == "symbols":
        syms = ELFAnalyzer.extract_interesting_symbols(data)
        print(f"\n{Colors.CYAN}[*] Symboles et fonctions clés dans {filepath} :{Colors.RESET}\n")
        for s in syms:
            print(f"  {Colors.GREEN}↳{Colors.RESET} {Colors.BOLD}{s}{Colors.RESET}")
        print()

    elif args.action == "die":
        res = ELFAnalyzer.detect_packers(data)
        print(f"\n{Colors.CYAN}=== DÉTECTEUR DE PACKERS & COMPILATEURS (STYLE DETECT IT EASY) ==={Colors.RESET}")
        if res["packers"]:
            for p in res["packers"]:
                print(f"  📦 {Colors.BOLD}{Colors.YELLOW}{p['packer']}{Colors.RESET} (Confiance : {p['confidence']})")
                print(f"     ↳ Solution : {p['solution']}")
        else:
            print(f"  {Colors.GREEN}[+] Aucun packer connu détecté (Binaire probablement natif / non compressé).{Colors.RESET}")

        if res["compilers"]:
            print(f"\n  {Colors.CYAN}[*] Compilateur / Runtime source identifié :{Colors.RESET}")
            for c in res["compilers"]:
                print(f"      ↳ {Colors.BOLD}{c['name']}{Colors.RESET} ({c['desc']})")
        print()

    elif args.action == "unpack":
        print(f"\n{Colors.CYAN}[*] Tentative de dépaquetage automatique sur {filepath}...{Colors.RESET}")
        res = ELFAnalyzer.detect_packers(data)
        if any("UPX" in p["packer"] for p in res["packers"]):
            out_unpacked = filepath + ".unpacked"
            try:
                r = subprocess.run(["upx", "-d", "-o", out_unpacked, filepath], capture_output=True, text=True)
                if r.returncode == 0:
                    print(f"  {Colors.GREEN}[+] Binaire dépaqueté avec succès dans : {out_unpacked}{Colors.RESET}\n")
                else:
                    print(f"  {Colors.YELLOW}[!] Échec de UPX : {r.stderr.strip()}{Colors.RESET}")
                    print(f"  💡 Essayez : upx -d {filepath}\n")
            except FileNotFoundError:
                print(f"  {Colors.YELLOW}[!] L'utilitaire 'upx' n'est pas installé sur le système.{Colors.RESET}")
                print(f"  💡 Installez-le avec : sudo apt install upx-ucl\n")
        else:
            print(f"  {Colors.YELLOW}[!] Aucun packer dépaquetable automatiquement (UPX) détecté.{Colors.RESET}\n")

    elif args.action == "gdb-script":
        info = ELFAnalyzer.parse_elf_header(data)
        ep = info["entry_point"] if info else "0x08048000"
        out_gdb = args.output or "pwndbg_init.gdb"
        ELFAnalyzer.generate_gdb_script(ep, out_gdb)
        print(f"\n{Colors.GREEN}[+] Script GDB + Pwndbg généré dans : {out_gdb}{Colors.RESET}")
        print(f"  💡 Pour lancer l'analyse dynamique avec vos hooks :")
        print(f"     {Colors.CYAN}gdb -x {out_gdb} {filepath}{Colors.RESET}\n")

    elif args.action == "anti-debug":
        antidebugs = ELFAnalyzer.detect_antidebug(data)
        print(f"\n{Colors.CYAN}=== DÉTECTEUR D'ANTI-DÉBOGAGE & ÉVASIONS : {os.path.basename(filepath)} ==={Colors.RESET}")
        if antidebugs:
            for a in antidebugs:
                print(f"  ⚠️ {Colors.YELLOW}[{a['severity']}] {a['type']}{Colors.RESET} : {a['desc']}")
        else:
            print(f"  {Colors.GREEN}[+] Aucun mécanisme d'anti-débogage standard détecté.{Colors.RESET}")
        print()

    elif args.action == "rop":
        info = ELFAnalyzer.parse_elf_header(data)
        base = 0x400000 if (info and info["class"] == "64-bit") else 0x8048000
        gadgets = ELFAnalyzer.find_rop_gadgets(data, base_addr=base)
        print(f"\n{Colors.CYAN}=== ROP GADGETS DISPONIBLES ({len(gadgets)} trouvés) : {os.path.basename(filepath)} ==={Colors.RESET}\n")
        for g in gadgets[:25]:
            print(f"  {Colors.GREEN}{g['vaddr']:<14}{Colors.RESET} : {Colors.BOLD}{g['gadget']:<20}{Colors.RESET} ({g['arch']})")
        if len(gadgets) > 25:
            print(f"\n  {Colors.DIM}... ({len(gadgets) - 25} autres gadgets omis){Colors.RESET}")
        print()

    elif args.action == "audit":
        hashes = ELFAnalyzer.calculate_binary_hashes(data)
        audit_res = ELFAnalyzer.detect_suspicious_sections(data)
        print(f"\n{Colors.CYAN}=== AUDIT DE STRUCTURE & INTÉGRITÉ BINAIRE : {os.path.basename(filepath)} ==={Colors.RESET}")
        print(f"  {Colors.GREEN}[+] SHA-256 :{Colors.RESET} {hashes['sha256']}")
        print(f"  {Colors.GREEN}[+] MD5     :{Colors.RESET} {hashes['md5']}")
        print(f"  {Colors.GREEN}[+] Taille  :{Colors.RESET} {hashes['size_bytes']} octets")
        print("-" * 65)

        if audit_res["anomalies"]:
            for an in audit_res["anomalies"]:
                print(f"  ⚠️ {Colors.YELLOW}[{an['severity']}] {an['type']}{Colors.RESET} : {an['description']}")
        else:
            print(f"  {Colors.GREEN}[+] Aucune anomalie critique de permissions RWX détectée.{Colors.RESET}")

        if audit_res["code_caves"]:
            print(f"\n  {Colors.CYAN}[*] Cavités de code & zones de padding ({audit_res['total_caves_found']} détectées) :{Colors.RESET}")
            for c in audit_res["code_caves"][:5]:
                print(f"      ↳ Offset {c['offset_hex']} : {c['length']} octets ({c['type']})")
        print()

def handle_pwn(args):
    if args.action == "cyclic":
        pattern = PwnHelper.cyclic(args.length)
        print(f"\n{Colors.GREEN}[+] Séquence cyclique De Bruijn ({args.length} octets) :{Colors.RESET}\n{Colors.BOLD}{pattern}{Colors.RESET}\n")

    elif args.action == "find":
        offset = PwnHelper.cyclic_find(args.value)
        print(f"\n{Colors.CYAN}=== CALCULATEUR D'OFFSET (DE BRUIJN) ==={Colors.RESET}")
        if offset != -1:
            print(f"  {Colors.GREEN}[+] Offset exact trouvé :{Colors.RESET} {Colors.BOLD}{Colors.YELLOW}{offset}{Colors.RESET} octets (0x{offset:02x})\n")
        else:
            print(f"  {Colors.RED}[!] Motif introuvable dans la séquence.{Colors.RESET}\n")

    elif args.action == "pack":
        val = int(args.value, 16) if args.value.startswith("0x") else int(args.value)
        p32_hex = PwnHelper.p32(val).hex()
        p64_hex = PwnHelper.p64(val).hex()
        print(f"\n{Colors.CYAN}=== PACKING OCTETS (LITTLE-ENDIAN) ==={Colors.RESET}")
        print(f"  {Colors.GREEN}[+] p32({hex(val)}) :{Colors.RESET} \\x" + "\\x".join(p32_hex[i:i+2] for i in range(0, len(p32_hex), 2)))
        print(f"  {Colors.GREEN}[+] p64({hex(val)}) :{Colors.RESET} \\x" + "\\x".join(p64_hex[i:i+2] for i in range(0, len(p64_hex), 2)) + "\n")

    elif args.action == "badchars":
        hex_data = args.hex_data.replace(" ", "").replace("0x", "").replace("\\x", "")
        raw_b = bytes.fromhex(hex_data)
        bads = PwnHelper.check_badchars(raw_b)
        print(f"\n{Colors.CYAN}=== VÉRIFICATEUR DE BAD CHARACTERS ==={Colors.RESET}")
        if not bads:
            print(f"  {Colors.GREEN}[+] Aucun bad character standard (\\x00, \\x0a, \\x0d) détecté.{Colors.RESET}\n")
        else:
            for b in bads:
                print(f"  ⚠️ {Colors.RED}Badchar détecté à l'offset {b['offset']} : {b['byte']}{Colors.RESET}")
            print()

def handle_web(args):
    if args.action == "jwt-decode":
        res = JWTTool.decode(args.token)
        if "error" in res:
            print(f"{Colors.RED}[!] {res['error']}{Colors.RESET}")
            return
        print(f"\n{Colors.CYAN}=== ANALYSE JSON WEB TOKEN (JWT) ==={Colors.RESET}")
        print(f"  {Colors.GREEN}[+] Header :{Colors.RESET} {json.dumps(res['header'], indent=2)}")
        print(f"  {Colors.GREEN}[+] Payload:{Colors.RESET} {json.dumps(res['payload'], indent=2)}")
        if res.get("timestamps"):
            print(f"  {Colors.GREEN}[+] Dates décodées :{Colors.RESET}")
            for k, v in res["timestamps"].items():
                print(f"      ↳ {k}: {v}")
        if res.get("is_none_alg"):
            print(f"  ⚠️ {Colors.RED}Vulnérabilité 'alg: none' détectée ! Token non signé.{Colors.RESET}")
        print()

    elif args.action == "jwt-forge":
        try:
            h = json.loads(args.header)
            p = json.loads(args.payload)
            forged = JWTTool.forge_none_alg(h, p)
            print(f"\n{Colors.GREEN}[+] JWT forgé (alg: none) :{Colors.RESET}\n{Colors.BOLD}{forged}{Colors.RESET}\n")
        except Exception as e:
            print(f"{Colors.RED}[!] Erreur JSON : {e}{Colors.RESET}")

    elif args.action == "ssti":
        payloads = SSTIPayloadHelper.get_payloads()
        print(f"\n{Colors.CYAN}=== PAYLOADS SSTI (TEMPLATE INJECTION) ==={Colors.RESET}\n")
        for engine, plist in payloads.items():
            print(f"{Colors.BOLD}{Colors.YELLOW}[ {engine} ]{Colors.RESET}")
            for p in plist:
                print(f"  ↳ {p}")
            print()

def handle_pcap(args):
    filepath = args.file
    if not os.path.exists(filepath):
        print(f"{Colors.RED}[!] Fichier introuvable : {filepath}{Colors.RESET}")
        return

    with open(filepath, "rb") as f:
        data = f.read()

    res = PCAPAnalyzer.parse_pcap(data)
    if "error" in res:
        print(f"{Colors.RED}[!] {res['error']}{Colors.RESET}")
        return

    print(f"\n{Colors.CYAN}=== ANALYSE PCAP : {os.path.basename(filepath)} ({res['total_packets']} paquets) ==={Colors.RESET}")
    print(f"  {Colors.GREEN}[+] Protocoles :{Colors.RESET} {res['protocols']}")

    if res["dns_queries"]:
        print(f"\n  {Colors.CYAN}[*] Requêtes DNS ({len(res['dns_queries'])}) :{Colors.RESET}")
        for d in res["dns_queries"]:
            print(f"      ↳ {d}")

    if res["http_requests"]:
        print(f"\n  {Colors.CYAN}[*] Requêtes HTTP :{Colors.RESET}")
        for r in res["http_requests"]:
            print(f"      ↳ {r}")

    if res["credentials_found"]:
        print(f"\n  {Colors.RED}🔑 IDENTIFIANTS EN CLAIR DÉCOUVERTS :{Colors.RESET}")
        for c in res["credentials_found"]:
            print(f"      ↳ {Colors.BOLD}{Colors.YELLOW}{c}{Colors.RESET}")

    if res["flags_found"]:
        print(f"\n  {Colors.GREEN}🚩 FLAGS EXTRAITS DU RÉSEAU :{Colors.RESET}")
        for fl in res["flags_found"]:
            print(f"      ↳ {Colors.BOLD}{Colors.GREEN}{fl}{Colors.RESET}")
    print()

def handle_osint(args):
    if args.action == "cidr":
        res = OSINTToolkit.calculate_cidr(args.cidr_str)
        print(f"\n{Colors.CYAN}=== CALCULATEUR DE SOUS-RÉSEAU CIDR ==={Colors.RESET}")
        for k, v in res.items():
            print(f"  {Colors.GREEN}[+] {k:<22}:{Colors.RESET} {v}")
        print()

    elif args.action == "dorks":
        dorks = OSINTToolkit.generate_dorks(args.domain)
        print(f"\n{Colors.CYAN}=== GOOGLE DORKS POUR : {args.domain} ==={Colors.RESET}\n")
        for d in dorks:
            print(f"  {Colors.BOLD}{Colors.YELLOW}[ {d['name']} ]{Colors.RESET}")
            print(f"  ↳ {d['query']}\n")

    elif args.action == "mac":
        res = OSINTToolkit.lookup_mac_oui(args.mac)
        print(f"\n{Colors.CYAN}=== RECHERCHE CONSTRUCTEUR OUI (MAC) ==={Colors.RESET}")
        print(f"  {Colors.GREEN}[+] MAC       :{Colors.RESET} {res.get('mac')}")
        print(f"  {Colors.GREEN}[+] OUI       :{Colors.RESET} {res.get('oui')}")
        print(f"  {Colors.GREEN}[+] Fabricant :{Colors.RESET} {Colors.BOLD}{res.get('vendor')}{Colors.RESET}\n")

def handle_wordlist(args):
    if args.action == "mutate":
        mutations = WordlistMutator.mutate(args.word, max_variants=args.count)
        print(f"\n{Colors.CYAN}=== MUTATIONS CTF LEETSPEAK ({len(mutations)} variantes) ==={Colors.RESET}\n")
        for m in mutations:
            print(f"  {m}")
        print()

def handle_ai(args):
    if args.action == "analyze":
        analysis = CTFAIAssistant.analyze_challenge(args.title, args.description or "")
        print(f"\n{Colors.CYAN}=== ASSISTANT IA CTF : ANALYSE DU CHALLENGE ==={Colors.RESET}")
        print(f"  {Colors.GREEN}[+] Catégorie Détectée :{Colors.RESET} {Colors.BOLD}{analysis['detected_category']}{Colors.RESET} (Confiance : {analysis['confidence']})")
        print(f"  {Colors.GREEN}[+] Outils Recommandés  :{Colors.RESET} {', '.join(analysis['recommended_tools'])}")
        print(f"\n{Colors.BOLD}{Colors.YELLOW}📋 MÉTHODOLOGIE D'INVESTIGATION CONSEILLÉE :{Colors.RESET}")
        for step in analysis["step_by_step_methodology"]:
            print(f"  {step}")
        print()

    elif args.action == "prompt":
        p = CTFAIAssistant.generate_ai_prompt(args.category, args.context)
        print(f"\n{Colors.CYAN}=== PROMPT OPTIMISÉ POUR LLM (CLAUDE / CHATGPT / OLLAMA) ==={Colors.RESET}\n")
        print(p)

    elif args.action == "detect":
        text = " ".join(args.text)
        diagnostics = CTFAIAssistant.heuristic_flag_detector(text)
        print(f"\n{Colors.CYAN}[*] Diagnostic heuristique pour :{Colors.RESET} {text}\n")
        for d in diagnostics:
            print(f"  {Colors.GREEN}[+] Type pressenti : {Colors.BOLD}{d['type']}{Colors.RESET} ({d['confidence']})")
            print(f"      ↳ Conseil : {d['advice']}")
        print()

# =============================================================================
# MODE INTERACTIF TUI (TERMINAL USER INTERFACE)
# =============================================================================
def interactive_menu():
    banner()
    while True:
        print(f"{Colors.BOLD}{Colors.CYAN}=== MENU PRINCIPAL HACKERLAB TOOLKIT v2.0 ==={Colors.RESET}")
        print(f"  {Colors.GREEN}1.{Colors.RESET} 🛡️  Scanner de Sécurité Intégré (D-Scan v3.0 : Ports, WAF, CMS, Geo, SSL)")
        print(f"  {Colors.GREEN}2.{Colors.RESET} 🔐 Cryptographie (Décodeur, César, Vigenère, Rail Fence, Affine, RSA, DLog)")
        print(f"  {Colors.GREEN}3.{Colors.RESET} 🔬 Forensics & Stégano (Magic Bytes, Entropie, PNG CRC Fixer, Flags)")
        print(f"  {Colors.GREEN}4.{Colors.RESET} ⚙️  Reverse Engineering (ELF checksec, Symboles, UPX)")
        print(f"  {Colors.GREEN}5.{Colors.RESET} 💥 Pwn & Buffer Overflow (Cyclic De Bruijn, Offset finder, p32/p64)")
        print(f"  {Colors.GREEN}6.{Colors.RESET} 🌐 Sécurité Web (JWT decode/forge, Payloads SSTI)")
        print(f"  {Colors.GREEN}7.{Colors.RESET} 📡 Analyse Réseau & PCAP (Extraction DNS, HTTP, Mots de passe)")
        print(f"  {Colors.GREEN}8.{Colors.RESET} 🌍 OSINT & Dictionnaires (CIDR, Google Dorks, OUI MAC, Leetspeak)")
        print(f"  {Colors.GREEN}9.{Colors.RESET} 🤖 Assistant IA & Méthodologie CTF (Conseils de résolution, Prompts LLM)")
        print(f"  {Colors.RED}0.{Colors.RESET} Quitter\n")

        choice = input(f"{Colors.BOLD}Choisissez une option [0-9] > {Colors.RESET}").strip()

        if choice == "1":
            target = input("Entrez la cible à scanner (IP ou domaine) > ").strip()
            if target:
                scan_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan.py")
                subprocess.run([sys.executable, scan_script, "-t", target, "-A", "--html", f"rapport_{target}.html"])
            input("\nAppuyez sur Entrée pour continuer...")

        elif choice == "2":
            sub = input("Entrez le texte ou hash à analyser > ").strip()
            if sub:
                results = MultiDecoder.decode_all(sub)
                for k, v in results.items():
                    print(f"  [+] {k}: {v}")
                h_matches = HashIdentifier.identify(sub)
                if h_matches:
                    for h in h_matches:
                        print(f"  [+] Hash potentiel : {h['name']} ({h['desc']})")
            input("\nAppuyez sur Entrée pour continuer...")

        elif choice == "3":
            fpath = input("Chemin du fichier à analyser en forensics > ").strip()
            if os.path.exists(fpath):
                with open(fpath, "rb") as f:
                    data = f.read()
                ent = ForensicsAnalyzer.shannon_entropy(data)
                flags = ForensicsAnalyzer.find_flags(data)
                print(f"  [+] Entropie : {ent['entropy']} ({ent['interpretation']})")
                if flags:
                    for fl in flags:
                        print(f"  🚩 Flag : {fl['flag']}")
                else:
                    print("  [!] Aucun flag textuel évident.")
            else:
                print("Fichier introuvable.")
            input("\nAppuyez sur Entrée pour continuer...")

        elif choice == "4":
            fpath = input("Chemin du binaire ELF à analyser > ").strip()
            if os.path.exists(fpath):
                with open(fpath, "rb") as f:
                    data = f.read()
                res = ELFAnalyzer.checksec(data)
                if "error" not in res:
                    print(f"  [+] Arch : {res['header']['class']} ({res['header']['machine']})")
                    print(f"  [+] Protections : {res['protections']}")
            else:
                print("Fichier introuvable.")
            input("\nAppuyez sur Entrée pour continuer...")

        elif choice == "5":
            val = input("Valeur de crash pour trouver l'offset (ex: 'laab' ou 0x61616162) > ").strip()
            if val:
                offset = PwnHelper.cyclic_find(val)
                print(f"  [+] Offset trouvé : {offset} octets")
            input("\nAppuyez sur Entrée pour continuer...")

        elif choice == "6":
            token = input("Entrez le token JWT à inspecter > ").strip()
            if token:
                res = JWTTool.decode(token)
                print(json.dumps(res, indent=2))
            input("\nAppuyez sur Entrée pour continuer...")

        elif choice == "7":
            pcap = input("Chemin du fichier PCAP > ").strip()
            if os.path.exists(pcap):
                with open(pcap, "rb") as f:
                    data = f.read()
                res = PCAPAnalyzer.parse_pcap(data)
                print(json.dumps(res, indent=2))
            else:
                print("Fichier introuvable.")
            input("\nAppuyez sur Entrée pour continuer...")

        elif choice == "8":
            cidr = input("Sous-réseau CIDR (ex: 192.168.1.0/24) ou domaine pour Google Dorks > ").strip()
            if "/" in cidr:
                print(json.dumps(OSINTToolkit.calculate_cidr(cidr), indent=2))
            elif cidr:
                dorks = OSINTToolkit.generate_dorks(cidr)
                for d in dorks:
                    print(f"  [ {d['name']} ] -> {d['query']}")
            input("\nAppuyez sur Entrée pour continuer...")

        elif choice == "9":
            title = input("Titre du challenge CTF > ").strip()
            desc = input("Description ou indices du challenge > ").strip()
            an = CTFAIAssistant.analyze_challenge(title, desc)
            print(f"\nCatégorie : {an['detected_category']}")
            print(f"Outils conseillés : {', '.join(an['recommended_tools'])}")
            print("Méthodologie étape par étape :")
            for st in an["step_by_step_methodology"]:
                print(f"  {st}")
            input("\nAppuyez sur Entrée pour continuer...")

        elif choice == "0":
            print("Au revoir et bonne compétition HackerLab !")
            break
        print("\n" + "="*50 + "\n")

# =============================================================================
# POINT D'ENTRÉE CLI
# =============================================================================
def main():
    if len(sys.argv) == 1 or sys.argv[1] in ["-i", "--interactive"]:
        interactive_menu()
        return

    parser = argparse.ArgumentParser(
        description="HackerLab Toolkit (v2.0) — Suite d'outils CTF multi-spécialités, Scanner & Assistant IA.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="module", help="Module d'outils à exécuter")

    # 1. Module Scanner Intégré
    scan_p = subparsers.add_parser("scan", help="Lancer le scanner de sécurité réseau & web D-Scan v3.0")
    scan_p.add_argument("scan_args", nargs=argparse.REMAINDER, help="Arguments transmis à scan.py (ex: -t cible.com -A)")

    # 2. Module Crypto
    crypto_p = subparsers.add_parser("crypto", help="Outils Cryptographiques & Chiffres classiques")
    crypto_sub = crypto_p.add_subparsers(dest="action")
    
    p_dec = crypto_sub.add_parser("decode", help="Décodage multi-formats (Base64, Hex, Binaire, Morse, ROT13...)")
    p_dec.add_argument("text", nargs="+", help="Texte à décoder")
    
    p_caesar = crypto_sub.add_parser("break-caesar", help="Casser un chiffre de César")
    p_caesar.add_argument("text", nargs="+", help="Texte chiffré")

    p_vig = crypto_sub.add_parser("vigenere", help="Déchiffrer avec Vigenère")
    p_vig.add_argument("ciphertext", help="Texte chiffré")
    p_vig.add_argument("key", help="Clé secrète")

    p_rail = crypto_sub.add_parser("rail-fence", help="Déchiffrer ou casser un Rail Fence")
    p_rail.add_argument("ciphertext", help="Texte chiffré")
    p_rail.add_argument("-r", "--rails", type=int, help="Nombre de rails (optionnel)")

    p_aff = crypto_sub.add_parser("affine", help="Déchiffrer ou casser un chiffre Affine")
    p_aff.add_argument("ciphertext", help="Texte chiffré")
    p_aff.add_argument("-a", type=int, help="Coefficient a")
    p_aff.add_argument("-b", type=int, help="Décalage b")

    p_bac = crypto_sub.add_parser("bacon", help="Déchiffrer le code Bacon")
    p_bac.add_argument("text", nargs="+", help="Texte Bacon (A/B ou Maj/Min)")

    p_xor = crypto_sub.add_parser("xor", help="Bruteforce XOR sur 1 octet")
    p_xor.add_argument("hex_data", help="Données en chaîne hexadécimale")

    p_hash = crypto_sub.add_parser("hash-id", help="Identifier le type d'un hash")
    p_hash.add_argument("hash_str", help="Chaîne du hash")

    p_rsa = crypto_sub.add_parser("rsa-pq", help="Résoudre RSA connaissant p, q, e et c")
    p_rsa.add_argument("-p", type=int, required=True, help="Nombre premier p")
    p_rsa.add_argument("-q", type=int, required=True, help="Nombre premier q")
    p_rsa.add_argument("-e", type=int, default=65537, help="Exposant public e")
    p_rsa.add_argument("-c", type=int, required=True, help="Ciphertext c")

    p_dlog = crypto_sub.add_parser("dlog", help="Résoudre le logarithme discret (g^x = y mod p)")
    p_dlog.add_argument("-g", type=int, required=True, help="Base g")
    p_dlog.add_argument("-y", type=int, required=True, help="Résultat y")
    p_dlog.add_argument("-p", type=int, required=True, help="Modulo premier p")

    # 3. Module Forensics
    for_p = subparsers.add_parser("forensics", help="Outils Forensics & Stéganographie")
    for_sub = for_p.add_subparsers(dest="action")

    p_finfo = for_sub.add_parser("info", help="Inspection complète : Magic bytes, entropie, carving et flags")
    p_finfo.add_argument("file", help="Chemin du fichier")

    p_fstr = for_sub.add_parser("strings", help="Extraire les chaînes imprimables")
    p_fstr.add_argument("file", help="Chemin du fichier")
    p_fstr.add_argument("-n", "--min-len", type=int, default=4, help="Longueur minimale")

    p_fflag = for_sub.add_parser("flags", help="Recherche automatique de motifs de flags CTF")
    p_fflag.add_argument("file", help="Chemin du fichier")

    p_fpng = for_sub.add_parser("fix-png", help="Résoudre les vraies dimensions PNG d'après le CRC32 IHDR")
    p_fpng.add_argument("file", help="Chemin du fichier PNG corrompu")

    # 4. Module Reverse
    rev_p = subparsers.add_parser("reverse", help="Outils de Reverse Engineering & Binaire")
    rev_sub = rev_p.add_subparsers(dest="action")

    p_rcheck = rev_sub.add_parser("checksec", help="Vérifier les protections ELF")
    p_rcheck.add_argument("file", help="Chemin du binaire ELF")

    p_rsym = rev_sub.add_parser("symbols", help="Extraire les symboles et fonctions clés")
    p_rsym.add_argument("file", help="Chemin du binaire")

    p_rdie = rev_sub.add_parser("die", help="Détection de Packers & Compilateurs (style Detect It Easy)")
    p_rdie.add_argument("file", help="Chemin du binaire")

    p_runpack = rev_sub.add_parser("unpack", help="Tentative de dépaquetage automatique (UPX)")
    p_runpack.add_argument("file", help="Chemin du binaire")

    p_rgdb = rev_sub.add_parser("gdb-script", help="Générer un script GDB + Pwndbg d'analyse dynamique & OEP")
    p_rgdb.add_argument("file", help="Chemin du binaire")
    p_rgdb.add_argument("-o", "--output", help="Nom du fichier script GDB (défaut: pwndbg_init.gdb)")

    p_rantidebug = rev_sub.add_parser("anti-debug", help="Détecter les mécanismes d'anti-débogage (ptrace, RDTSC, TracerPid)")
    p_rantidebug.add_argument("file", help="Chemin du binaire")

    p_rrop = rev_sub.add_parser("rop", help="Rechercher les ROP Gadgets fondamentaux (pop rdi, ret, syscall)")
    p_rrop.add_argument("file", help="Chemin du binaire")

    p_raudit = rev_sub.add_parser("audit", help="Auditer l'intégrité et détecter les anomalies de sections (RWX, Code Caves)")
    p_raudit.add_argument("file", help="Chemin du binaire")

    # 5. Module Pwn
    pwn_p = subparsers.add_parser("pwn", help="Outils Pwn & Buffer Overflow Math")
    pwn_sub = pwn_p.add_subparsers(dest="action")

    p_pcyc = pwn_sub.add_parser("cyclic", help="Générer une séquence cyclique de De Bruijn")
    p_pcyc.add_argument("length", type=int, default=100, nargs="?", help="Longueur de la séquence (défaut: 100)")

    p_pfind = pwn_sub.add_parser("find", help="Trouver l'offset exact dans la séquence cyclique")
    p_pfind.add_argument("value", help="Valeur hexadécimale (0x61616162) ou chaîne ('baaa')")

    p_ppack = pwn_sub.add_parser("pack", help="Convertir un entier en octets Little-Endian (p32 / p64)")
    p_ppack.add_argument("value", help="Adresse ou valeur (ex: 0x080484b6)")

    p_pbad = pwn_sub.add_parser("badchars", help="Identifier les bad characters dans une séquence hexadécimale")
    p_pbad.add_argument("hex_data", help="Séquence d'octets en hexadécimal")

    # 6. Module Web
    web_p = subparsers.add_parser("web", help="Outils de Sécurité Web & JWT")
    web_sub = web_p.add_subparsers(dest="action")

    p_wjwt = web_sub.add_parser("jwt-decode", help="Décode un JWT sans vérification")
    p_wjwt.add_argument("token", help="Token JWT")

    p_wforge = web_sub.add_parser("jwt-forge", help="Forge un JWT non signé (alg: none)")
    p_wforge.add_argument("header", help="Header JSON")
    p_wforge.add_argument("payload", help="Payload JSON")

    web_sub.add_parser("ssti", help="Afficher les payloads de test SSTI")

    # 7. Module PCAP
    pcap_p = subparsers.add_parser("pcap", help="Analyseur de captures réseau PCAP")
    pcap_sub = pcap_p.add_subparsers(dest="action")

    p_pan = pcap_sub.add_parser("analyze", help="Analyser une capture PCAP")
    p_pan.add_argument("file", help="Chemin du fichier .pcap")

    # 8. Module OSINT & Wordlist
    osint_p = subparsers.add_parser("osint", help="Outils OSINT & Réseau")
    osint_sub = osint_p.add_subparsers(dest="action")

    p_ocidr = osint_sub.add_parser("cidr", help="Calculer les plages d'un sous-réseau CIDR")
    p_ocidr.add_argument("cidr_str", help="Sous-réseau (ex: 192.168.1.0/24)")

    p_odork = osint_sub.add_parser("dorks", help="Générer des Google Dorks de cartographie")
    p_odork.add_argument("domain", help="Nom de domaine cible")

    p_omac = osint_sub.add_parser("mac", help="Résoudre le constructeur d'une adresse MAC (OUI)")
    p_omac.add_argument("mac", help="Adresse MAC (ex: 00:50:56:12:34:56)")

    word_p = subparsers.add_parser("wordlist", help="Générateur de mutations de mots de passe Leetspeak")
    word_sub = word_p.add_subparsers(dest="action")

    p_wmut = word_sub.add_parser("mutate", help="Générer des variantes Leetspeak CTF d'un mot")
    p_wmut.add_argument("word", help="Mot de passe ou terme de base")
    p_wmut.add_argument("-n", "--count", type=int, default=50, help="Nombre max de variantes (défaut: 50)")

    # 9. Module Assistant IA
    ai_p = subparsers.add_parser("ai", help="Assistant IA & Méthodologies CTF")
    ai_sub = ai_p.add_subparsers(dest="action")

    p_aian = ai_sub.add_parser("analyze", help="Classifier un challenge et obtenir une checklist d'investigation")
    p_aian.add_argument("-t", "--title", required=True, help="Titre du challenge")
    p_aian.add_argument("-d", "--description", help="Description ou énoncé du challenge")

    p_aiprompt = ai_sub.add_parser("prompt", help="Générer un prompt LLM optimisé")
    p_aiprompt.add_argument("-c", "--category", required=True, help="Catégorie (Crypto, Reverse, Web...)")
    p_aiprompt.add_argument("-f", "--context", required=True, help="Extrait de code ou données")

    p_aidet = ai_sub.add_parser("detect", help="Diagnostiquer un encodage ou type de hash inconnu")
    p_aidet.add_argument("text", nargs="+", help="Chaîne suspecte")

    args = parser.parse_args()

    if not args.module:
        parser.print_help()
        return

    banner()

    if args.module == "scan":
        handle_scan(args)
    elif args.module == "crypto":
        handle_crypto(args)
    elif args.module == "forensics":
        handle_forensics(args)
    elif args.module == "reverse":
        handle_reverse(args)
    elif args.module == "pwn":
        handle_pwn(args)
    elif args.module == "web":
        handle_web(args)
    elif args.module == "pcap":
        handle_pcap(args)
    elif args.module == "osint":
        handle_osint(args)
    elif args.module == "wordlist":
        handle_wordlist(args)
    elif args.module == "ai":
        handle_ai(args)

if __name__ == "__main__":
    main()
