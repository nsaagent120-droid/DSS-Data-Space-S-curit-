#!/usr/bin/env bash
# =============================================================================
#  Script d'Installation Automatisé — HackerLab Toolkit & D-Scan
# =============================================================================

set -e

CYAN='\033[0;96m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
RED='\033[0;91m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${BOLD}${CYAN}"
echo "  ================================================================"
echo "    INSTALLATION : HACKERLAB CTF TOOLKIT & D-SCANNER"
echo "    DSS Security / Cybersecurity Mastery Roadmap"
echo "  ================================================================"
echo -e "${RESET}"

# 1. Vérification de Python 3
echo -e "${CYAN}[*] Vérification des prérequis système...${RESET}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Erreur : Python 3 n'est pas installé sur ce système.${RESET}"
    echo "    Veuillez installer Python 3 avec : sudo apt update && sudo apt install -y python3"
    exit 1
fi
PYTHON_VERSION=$(python3 --version)
echo -e "${GREEN}[+] Python 3 détecté : ${PYTHON_VERSION}${RESET}"

# 2. Permissions d'exécution
echo -e "${CYAN}[*] Attribution des permissions d'exécution sur les scripts...${RESET}"
chmod +x hackerlab.py scan.py 2>/dev/null || true
echo -e "${GREEN}[+] Permissions configurées sur hackerlab.py et scan.py${RESET}"

# 3. Compilation du scanner haute performance en C
if [ -d "c_scanner" ]; then
    echo -e "${CYAN}[*] Compilation du moteur réseau C natif (c_scanner)...${RESET}"
    if command -v gcc &> /dev/null; then
        (cd c_scanner && make clean 2>/dev/null && make)
        echo -e "${GREEN}[+] Binaire C compilé avec succès (c_scanner/port_scanner)${RESET}"
    else
        echo -e "${YELLOW}[!] Avertissement : gcc n'est pas installé, la compilation du binaire C est ignorée (scan.py fonctionnera normalement).${RESET}"
    fi
fi

# 4. Création des liens symboliques globaux (si permissions disponibles)
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${CYAN}[*] Création des raccourcis de commande dans ${INSTALL_DIR}...${RESET}"

ln -sf "${SCRIPT_DIR}/hackerlab.py" "${INSTALL_DIR}/hackerlab"
ln -sf "${SCRIPT_DIR}/scan.py" "${INSTALL_DIR}/dscan"

echo -e "${GREEN}[+] Commandes créées :${RESET}"
echo -e "    - ${BOLD}hackerlab${RESET} -> Lance la boîte à outils CTF & IA"
echo -e "    - ${BOLD}dscan${RESET}     -> Lance le scanner de sécurité D-Scan v3.0"

# 5. Vérification du PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo ""
    echo -e "${YELLOW}[!] Note pour un accès global direct :${RESET}"
    echo "    Ajoutez ${INSTALL_DIR} à votre PATH en exécutant :"
    echo -e "    ${BOLD}echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc${RESET}"
fi

echo ""
echo -e "${BOLD}${GREEN}================================================================${RESET}"
echo -e "${BOLD}${GREEN}  ✅ INSTALLATION TERMINÉE AVEC SUCCÈS !${RESET}"
echo -e "${BOLD}${GREEN}================================================================${RESET}"
echo ""
echo "Commandes de démarrage rapide :"
echo -e "  1. Mode interactif :        ${CYAN}python3 hackerlab.py${RESET} ou ${CYAN}hackerlab${RESET}"
echo -e "  2. Scanner une cible :       ${CYAN}python3 scan.py -t <cible> -A --html rapport.html${RESET}"
echo -e "  3. Résoudre un challenge :   ${CYAN}python3 hackerlab.py ai analyze -t \"Titre\" -d \"Enoncé\"${RESET}"
echo ""
