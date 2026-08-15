#!/usr/bin/env python3
"""
=============================================================================
  HackerLab Toolkit (HL-Tool) — Boîte à Outils CTF & IA pour Compétitions
=============================================================================
  Auteur      : DSS Security / HackerLab Competition Toolkit
  Description : Suite complète d'outils d'investigation et d'assistance IA :
                - Cryptographie (Décodeur, César, Vigenère, XOR, Hashes, RSA)
                - Forensics & Stéganographie (Magic Bytes, Entropie, Flags, Carving)
                - Reverse Engineering (ELF checksec, Symboles, UPX)
                - Sécurité Web (JWT decode/forge, SSTI, Audit de code)
                - Analyse Réseau & PCAP (Extraction DNS, HTTP, Credentials)
                - Assistant IA & Méthodologies CTF (Diagnostic, Workflow, Prompts)
  Usage       : python3 hackerlab.py [module] [commande] [arguments]
                ou lancer sans argument pour le Mode Interactif !
=============================================================================
"""

import argparse
import json
import os
import sys

# Importation des modules internes
try:
    from hackerlab_toolkit.crypto_tools import MultiDecoder, ClassicalCiphers, HashIdentifier, RSASolver
    from hackerlab_toolkit.forensics_tools import ForensicsAnalyzer
    from hackerlab_toolkit.reversing_tools import ELFAnalyzer
    from hackerlab_toolkit.web_tools import JWTTool, SSTIPayloadHelper, CodeAuditor
    from hackerlab_toolkit.pcap_tools import PCAPAnalyzer
    from hackerlab_toolkit.ai_assistant import CTFAIAssistant
except ImportError:
    # Si exécuté depuis un autre dossier
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from hackerlab_toolkit.crypto_tools import MultiDecoder, ClassicalCiphers, HashIdentifier, RSASolver
    from hackerlab_toolkit.forensics_tools import ForensicsAnalyzer
    from hackerlab_toolkit.reversing_tools import ELFAnalyzer
    from hackerlab_toolkit.web_tools import JWTTool, SSTIPayloadHelper, CodeAuditor
    from hackerlab_toolkit.pcap_tools import PCAPAnalyzer
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
  {Colors.BOLD}{Colors.MAGENTA}⚔️  HACKERLAB CTF TOOLKIT & ASSISTANT IA (v1.0){Colors.RESET}
  {Colors.DIM}Boîte à outils multi-spécialités & Méthodologies pour Compétitions HackerLab{Colors.RESET}
"""
    print(art)

# =============================================================================
# GESTIONNAIRES DE COMMANDES
# =============================================================================
def handle_crypto(args):
    if args.action == "decode":
        text = " ".join(args.text)
        print(f"\n{Colors.CYAN}[*] Tentative de décodage multi-formats pour :{Colors.RESET} {text}\n")
        results = MultiDecoder.decode_all(text)
        if not results:
            print(f"{Colors.YELLOW}[!] Aucun format standard décodé.{Colors.RESET}")
        for fmt, val in results.items():
            print(f"  {Colors.BOLD}{Colors.GREEN}[+] {fmt:<16}:{Colors.RESET} {val}")
        print()

    elif args.action == "break-caesar":
        text = " ".join(args.text)
        print(f"\n{Colors.CYAN}[*] Analyse des 25 décalages César pour :{Colors.RESET} {text}\n")
        candidates = ClassicalCiphers.break_caesar(text)
        print(f"{'DÉCALAGE':<12} {'SCORE':<8} {'TEXTE DÉCHIFFRÉ'}")
        print("-" * 65)
        for c in candidates[:6]:
            star = f"{Colors.GREEN}★{Colors.RESET}" if c == candidates[0] else " "
            print(f"ROT-{c['shift']:<2} {star}       {c['score']:<8.2f} {Colors.BOLD}{c['text'][:45]}{Colors.RESET}")
        print()

    elif args.action == "vigenere":
        ciphertext = args.ciphertext
        key = args.key
        decrypted = ClassicalCiphers.vigenere_decrypt(ciphertext, key)
        print(f"\n{Colors.GREEN}[+] Déchiffrement Vigenère (Clé: {key}) :{Colors.RESET} {Colors.BOLD}{decrypted}{Colors.RESET}\n")

    elif args.action == "xor":
        hex_data = args.hex_data.replace(" ", "").replace("0x", "")
        data_bytes = bytes.fromhex(hex_data)
        print(f"\n{Colors.CYAN}[*] Bruteforce XOR sur 1 octet ({len(data_bytes)} octets)...{Colors.RESET}\n")
        res = ClassicalCiphers.single_byte_xor(data_bytes)
        for r in res[:5]:
            print(f"  {Colors.GREEN}[+] Clé {r['key_char']} (0x{r['key']:02x}) :{Colors.RESET} {Colors.BOLD}{r['text']}{Colors.RESET}")
        print()

    elif args.action == "hash-id":
        h = args.hash_str
        matches = HashIdentifier.identify(h)
        print(f"\n{Colors.CYAN}[*] Identification du hash :{Colors.RESET} {h}\n")
        if not matches:
            print(f"{Colors.YELLOW}[!] Type de hash non reconnu.{Colors.RESET}")
        for m in matches:
            print(f"  {Colors.GREEN}[+] Format : {Colors.BOLD}{m['name']}{Colors.RESET} — {m['desc']}")
        print()

    elif args.action == "rsa-pq":
        res = RSASolver.solve_pq(args.p, args.q, args.e, args.c)
        print(f"\n{Colors.CYAN}=== RÉSULTATS RSA (p, q, e, c) ==={Colors.RESET}")
        print(f"  {Colors.GREEN}[+] Modulus (n)       :{Colors.RESET} {res['n']}")
        print(f"  {Colors.GREEN}[+] Clé privée (d)    :{Colors.RESET} {res['d']}")
        print(f"  {Colors.GREEN}[+] Message déchiffré :{Colors.RESET} {Colors.BOLD}{Colors.YELLOW}{res['plaintext']}{Colors.RESET}\n")

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
        min_l = args.min_len
        strings = ForensicsAnalyzer.extract_strings(data, min_len=min_l)
        print(f"\n{Colors.CYAN}[*] Extraction de {len(strings)} chaînes (longueur >= {min_l}) :{Colors.RESET}\n")
        for s in strings[:30]:
            print(f"  {Colors.DIM}{s['offset_hex']:<8}{Colors.RESET} {s['string']}")
        if len(strings) > 30:
            print(f"  {Colors.YELLOW}... ({len(strings) - 30} autres chaînes omises){Colors.RESET}")
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
        print(f"  {Colors.GREEN}[+] Type         :{Colors.RESET} {hdr['type']}")
        print(f"  {Colors.GREEN}[+] Entry Point  :{Colors.RESET} {hdr['entry_point']}")
        print("-" * 65)

        can_col = Colors.GREEN if prot["canary"]["enabled"] else Colors.RED
        nx_col = Colors.GREEN if prot["nx"]["enabled"] else Colors.RED
        pie_col = Colors.GREEN if prot["pie"]["enabled"] else Colors.RED
        rel_col = Colors.GREEN if prot["relro"]["level"] == "Full RELRO" else (Colors.YELLOW if prot["relro"]["level"] == "Partial RELRO" else Colors.RED)

        print(f"  • Canary     : {can_col}{'Actif (Stack protection)' if prot['canary']['enabled'] else 'Désactivé'}{Colors.RESET}")
        print(f"  • NX         : {nx_col}{'Actif (Stack non-exécutable)' if prot['nx']['enabled'] else 'Désactivé (Stack exécutable)'}{Colors.RESET}")
        print(f"  • PIE        : {pie_col}{'Actif (ASLR binaire)' if prot['pie']['enabled'] else 'Désactivé'}{Colors.RESET}")
        print(f"  • RELRO      : {rel_col}{prot['relro']['level']}{Colors.RESET}")
        print(f"  • Stripped   : {Colors.CYAN}{'Oui (Symboles retirés)' if prot['stripped']['status'] else 'Non (Symboles présents)'}{Colors.RESET}")

        packers = ELFAnalyzer.detect_packers(data)
        if packers:
            for p in packers:
                print(f"  ⚠️ {Colors.YELLOW}{p['packer']} détecté ! ({p['solution']}){Colors.RESET}")
        print()

    elif args.action == "symbols":
        syms = ELFAnalyzer.extract_interesting_symbols(data)
        print(f"\n{Colors.CYAN}[*] Symboles et fonctions clés détectés dans {filepath} :{Colors.RESET}\n")
        for s in syms:
            print(f"  {Colors.GREEN}↳{Colors.RESET} {Colors.BOLD}{s}{Colors.RESET}")
        print()

def handle_web(args):
    if args.action == "jwt-decode":
        token = args.token
        res = JWTTool.decode(token)
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
            print(f"\n{Colors.GREEN}[+] JWT forgé avec l'algorithme 'none' :{Colors.RESET}\n{Colors.BOLD}{forged}{Colors.RESET}\n")
        except Exception as e:
            print(f"{Colors.RED}[!] Erreur de parsing JSON : {e}{Colors.RESET}")

    elif args.action == "ssti":
        payloads = SSTIPayloadHelper.get_payloads()
        print(f"\n{Colors.CYAN}=== PAYLOADS DE TEST SSTI (SERVER-SIDE TEMPLATE INJECTION) ==={Colors.RESET}\n")
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

    print(f"\n{Colors.CYAN}=== ANALYSE DE CAPTURE PCAP : {os.path.basename(filepath)} ({res['total_packets']} paquets) ==={Colors.RESET}")
    print(f"  {Colors.GREEN}[+] Répartition des protocoles :{Colors.RESET} {res['protocols']}")

    if res["dns_queries"]:
        print(f"\n  {Colors.CYAN}[*] Requêtes DNS extraites ({len(res['dns_queries'])}) :{Colors.RESET}")
        for d in res["dns_queries"]:
            print(f"      ↳ {d}")

    if res["http_requests"]:
        print(f"\n  {Colors.CYAN}[*] Requêtes HTTP interceptées :{Colors.RESET}")
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

def handle_ai(args):
    if args.action == "analyze":
        title = args.title
        desc = args.description or ""
        analysis = CTFAIAssistant.analyze_challenge(title, desc)

        print(f"\n{Colors.CYAN}=== ASSISTANT IA CTF : ANALYSE DU CHALLENGE ==={Colors.RESET}")
        print(f"  {Colors.GREEN}[+] Catégorie Détectée :{Colors.RESET} {Colors.BOLD}{analysis['detected_category']}{Colors.RESET} (Confiance : {analysis['confidence']})")
        print(f"  {Colors.GREEN}[+] Outils Recommandés  :{Colors.RESET} {', '.join(analysis['recommended_tools'])}")
        print(f"\n{Colors.BOLD}{Colors.YELLOW}📋 MÉTHODOLOGIE D'INVESTIGATION CONSEILLÉE :{Colors.RESET}")
        for step in analysis["step_by_step_methodology"]:
            print(f"  {step}")
        print()

    elif args.action == "prompt":
        cat = args.category
        context = args.context
        p = CTFAIAssistant.generate_ai_prompt(cat, context)
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
        print(f"{Colors.BOLD}{Colors.CYAN}=== MENU PRINCIPAL HACKERLAB TOOLKIT ==={Colors.RESET}")
        print(f"  {Colors.GREEN}1.{Colors.RESET} 🔐 Cryptographie (Décodeur multi-formats, César, Vigenère, XOR, Hashes, RSA)")
        print(f"  {Colors.GREEN}2.{Colors.RESET} 🔬 Forensics & Stégano (Magic Bytes, Entropie, Extraction de flags)")
        print(f"  {Colors.GREEN}3.{Colors.RESET} ⚙️  Reverse Engineering (ELF checksec, Symboles, UPX)")
        print(f"  {Colors.GREEN}4.{Colors.RESET} 🌐 Sécurité Web (JWT decode/forge, Payloads SSTI)")
        print(f"  {Colors.GREEN}5.{Colors.RESET} 📡 Analyse Réseau & PCAP (Extraction DNS, HTTP, Mots de passe)")
        print(f"  {Colors.GREEN}6.{Colors.RESET} 🤖 Assistant IA & Méthodologie CTF (Conseils de résolution, Prompts)")
        print(f"  {Colors.RED}0.{Colors.RESET} Quitter\n")

        choice = input(f"{Colors.BOLD}Choisissez une option [0-6] > {Colors.RESET}").strip()

        if choice == "1":
            print(f"\n{Colors.BOLD}--- MODULE CRYPTOGRAPHIE ---{Colors.RESET}")
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

        elif choice == "2":
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

        elif choice == "3":
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

        elif choice == "4":
            token = input("Entrez le token JWT à inspecter > ").strip()
            if token:
                res = JWTTool.decode(token)
                print(json.dumps(res, indent=2))
            input("\nAppuyez sur Entrée pour continuer...")

        elif choice == "5":
            pcap = input("Chemin du fichier PCAP > ").strip()
            if os.path.exists(pcap):
                with open(pcap, "rb") as f:
                    data = f.read()
                res = PCAPAnalyzer.parse_pcap(data)
                print(json.dumps(res, indent=2))
            else:
                print("Fichier introuvable.")
            input("\nAppuyez sur Entrée pour continuer...")

        elif choice == "6":
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
            print("Au revoir et bonne chance pour le HackerLab !")
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
        description="HackerLab Toolkit — Suite d'outils CTF multi-spécialités & Assistant IA.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="module", help="Module d'outils à exécuter")

    # 1. Module Crypto
    crypto_p = subparsers.add_parser("crypto", help="Outils Cryptographiques & Chiffres classiques")
    crypto_sub = crypto_p.add_subparsers(dest="action")
    
    p_dec = crypto_sub.add_parser("decode", help="Décodage multi-formats (Base64, Hex, Binaire, Morse, ROT13...)")
    p_dec.add_argument("text", nargs="+", help="Texte à décoder")
    
    p_caesar = crypto_sub.add_parser("break-caesar", help="Casser un chiffre de César en testant les 25 décalages")
    p_caesar.add_argument("text", nargs="+", help="Texte chiffré")

    p_vig = crypto_sub.add_parser("vigenere", help="Déchiffrer un texte avec le chiffre de Vigenère")
    p_vig.add_argument("ciphertext", help="Texte chiffré")
    p_vig.add_argument("key", help="Clé secrète")

    p_xor = crypto_sub.add_parser("xor", help="Bruteforce XOR sur 1 octet")
    p_xor.add_argument("hex_data", help="Données en chaîne hexadécimale")

    p_hash = crypto_sub.add_parser("hash-id", help="Identifier le type d'un hash")
    p_hash.add_argument("hash_str", help="Chaîne du hash à analyser")

    p_rsa = crypto_sub.add_parser("rsa-pq", help="Résoudre RSA connaissant p, q, e et le ciphertext c")
    p_rsa.add_argument("-p", type=int, required=True, help="Nombre premier p")
    p_rsa.add_argument("-q", type=int, required=True, help="Nombre premier q")
    p_rsa.add_argument("-e", type=int, default=65537, help="Exposant public e (défaut: 65537)")
    p_rsa.add_argument("-c", type=int, required=True, help="Ciphertext c")

    # 2. Module Forensics
    for_p = subparsers.add_parser("forensics", help="Outils d'investigation Forensics & Stéganographie")
    for_sub = for_p.add_subparsers(dest="action")

    p_finfo = for_sub.add_parser("info", help="Inspection complète : Magic bytes, entropie, carving et flags")
    p_finfo.add_argument("file", help="Chemin du fichier à analyser")

    p_fstr = for_sub.add_parser("strings", help="Extraire les chaînes imprimables d'un fichier")
    p_fstr.add_argument("file", help="Chemin du fichier")
    p_fstr.add_argument("-n", "--min-len", type=int, default=4, help="Longueur minimale de chaîne (défaut: 4)")

    p_fflag = for_sub.add_parser("flags", help="Recherche automatique de motifs de flags CTF")
    p_fflag.add_argument("file", help="Chemin du fichier")

    # 3. Module Reverse
    rev_p = subparsers.add_parser("reverse", help="Outils de Reverse Engineering & Binaire")
    rev_sub = rev_p.add_subparsers(dest="action")

    p_rcheck = rev_sub.add_parser("checksec", help="Vérifier les protections ELF (NX, PIE, Canary, RELRO)")
    p_rcheck.add_argument("file", help="Chemin du binaire ELF")

    p_rsym = rev_sub.add_parser("symbols", help="Extraire les symboles et fonctions clés")
    p_rsym.add_argument("file", help="Chemin du binaire")

    # 4. Module Web
    web_p = subparsers.add_parser("web", help="Outils de Sécurité Web & JWT")
    web_sub = web_p.add_subparsers(dest="action")

    p_wjwt = web_sub.add_parser("jwt-decode", help="Décode un JSON Web Token sans vérification")
    p_wjwt.add_argument("token", help="Token JWT complet")

    p_wforge = web_sub.add_parser("jwt-forge", help="Forge un JWT avec l'algorithme 'none'")
    p_wforge.add_argument("header", help="Header JSON (ex: '{\"typ\":\"JWT\"}')")
    p_wforge.add_argument("payload", help="Payload JSON (ex: '{\"user\":\"admin\"}')")

    web_sub.add_parser("ssti", help="Afficher les payloads de test SSTI (Jinja2, Twig, ERB)")

    # 5. Module PCAP
    pcap_p = subparsers.add_parser("pcap", help="Analyseur de captures réseau PCAP")
    pcap_sub = pcap_p.add_subparsers(dest="action")

    p_pan = pcap_sub.add_parser("analyze", help="Analyser une capture PCAP (protocoles, DNS, HTTP, identifiants)")
    p_pan.add_argument("file", help="Chemin du fichier .pcap")

    # 6. Module Assistant IA
    ai_p = subparsers.add_parser("ai", help="Assistant IA & Méthodologies CTF")
    ai_sub = ai_p.add_subparsers(dest="action")

    p_aian = ai_sub.add_parser("analyze", help="Classifier un challenge et obtenir une checklist d'investigation")
    p_aian.add_argument("-t", "--title", required=True, help="Titre du challenge")
    p_aian.add_argument("-d", "--description", help="Description ou énoncé du challenge")

    p_aiprompt = ai_sub.add_parser("prompt", help="Générer un prompt LLM optimisé pour résoudre un problème")
    p_aiprompt.add_argument("-c", "--category", required=True, help="Catégorie (Crypto, Reverse, Web...)")
    p_aiprompt.add_argument("-f", "--context", required=True, help="Extrait de code ou données")

    p_aidet = ai_sub.add_parser("detect", help="Diagnostiquer un encodage ou type de hash inconnu")
    p_aidet.add_argument("text", nargs="+", help="Chaîne suspecte à diagnostiquer")

    args = parser.parse_args()

    if not args.module:
        parser.print_help()
        return

    banner()

    if args.module == "crypto":
        handle_crypto(args)
    elif args.module == "forensics":
        handle_forensics(args)
    elif args.module == "reverse":
        handle_reverse(args)
    elif args.module == "web":
        handle_web(args)
    elif args.module == "pcap":
        handle_pcap(args)
    elif args.module == "ai":
        handle_ai(args)

if __name__ == "__main__":
    main()
