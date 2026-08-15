#!/usr/bin/env python3
"""
=============================================================================
  Script de Décompilation Headless Ghidra & Perfectionnement Automatique
=============================================================================
  Auteur      : DSS Security / HackerLab Toolkit
  Description : Lance Ghidra en mode sans tête (analyzeHeadless) sur un binaire,
                décompile l'ensemble des fonctions et applique le nettoyeur
                sémantique pour générer un fichier C propre et lisible.
  Usage       : python3 headless_decompile.py <binaire> [--ghidra-path /opt/ghidra]
=============================================================================
"""

import argparse
import os
import subprocess
import sys
import tempfile

try:
    from hackerlab_toolkit.ghidra_cleaner import GhidraDecompilerCleaner
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from hackerlab_toolkit.ghidra_cleaner import GhidraDecompilerCleaner

def find_analyze_headless(custom_path=None):
    """Recherche l'exécutable analyzeHeadless de Ghidra."""
    candidates = []
    if custom_path:
        candidates.append(os.path.join(custom_path, "support", "analyzeHeadless"))
        candidates.append(custom_path)

    # Chemins standards d'installation
    candidates.extend([
        os.path.expanduser("~/ghidra/support/analyzeHeadless"),
        "/opt/ghidra/support/analyzeHeadless",
        "/usr/share/ghidra/support/analyzeHeadless"
    ])

    for c in candidates:
        if os.path.exists(c) and os.access(c, os.X_OK):
            return c

    # Recherche dans le PATH
    import shutil
    in_path = shutil.which("analyzeHeadless")
    if in_path:
        return in_path

    return None

def main():
    parser = argparse.ArgumentParser(description="Décompilation automatique Ghidra Headless + Perfectionnement de Code C")
    parser.add_argument("binary", help="Chemin du fichier binaire ELF/PE à décompiler")
    parser.add_argument("-o", "--output", help="Nom du fichier C de sortie (défaut: <binaire>_perfected.c)")
    parser.add_argument("--ghidra-path", help="Chemin du dossier d'installation de Ghidra")

    args = parser.parse_args()

    if not os.path.exists(args.binary):
        print(f"[!] Erreur : Binaire introuvable : {args.binary}")
        sys.exit(1)

    headless_bin = find_analyze_headless(args.ghidra_path)
    if not headless_bin:
        print("[!] Erreur : 'analyzeHeadless' de Ghidra est introuvable.")
        print("    Veuillez spécifier son chemin avec : --ghidra-path /chemin/vers/ghidra")
        print("    Exemple : python3 headless_decompile.py binaire --ghidra-path /opt/ghidra_11.0")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    java_script = os.path.join(script_dir, "ExportDecompiledC.java")

    with tempfile.TemporaryDirectory() as tmp_proj:
        print(f"[*] Lancement de Ghidra Headless sur {args.binary}...")
        cmd = [
            headless_bin,
            tmp_proj, "TempProject",
            "-import", os.path.abspath(args.binary),
            "-scriptPath", script_dir,
            "-postScript", "ExportDecompiledC.java",
            "-deleteProject"
        ]

        try:
            subprocess.run(cmd, check=True)
        except Exception as e:
            print(f"[!] Erreur d'exécution de Ghidra Headless : {e}")
            sys.exit(1)

        raw_export = os.path.basename(args.binary) + "_decompiled.c"
        if os.path.exists(raw_export):
            with open(raw_export, "r", encoding="utf-8", errors="ignore") as f:
                raw_code = f.read()

            print("[*] Application de la pipeline de perfectionnement sémantique...")
            perfected = GhidraDecompilerCleaner.perfect_code(raw_code)

            out_file = args.output or (os.path.basename(args.binary) + "_perfected.c")
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(perfected["cleaned_code"])

            print(f"[+] Code source C perfectionné avec succès dans : {out_file}")
            # Nettoyer l'export brut
            os.remove(raw_export)
        else:
            print("[!] Le fichier décompilé n'a pas été généré par Ghidra.")

if __name__ == "__main__":
    main()
