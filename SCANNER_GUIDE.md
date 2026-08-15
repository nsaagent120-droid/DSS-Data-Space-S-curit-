# 🛡️ DSS Ultimate Security Scanner (D-Scan v2.0) — Guide Complet & Référence

> Suite professionnelle d'audit de sécurité réseau, détection de versions (**-sV**), scan UDP (**-sU**), corrélation CVE en temps réel, audit web OWASP, analyse SSL/TLS et génération de rapports multi-formats (HTML, Nmap XML, JSON, Markdown).

---

## 📑 Table des matières
1. [Comparatif avec les Outils Standards (Nmap, Nikto, SSLyze, Masscan)](#1-comparatif-avec-les-outils-standards)
2. [Fonctionnalités Clés](#2-fonctionnalités-clés)
3. [Options et Commandes de `scan.py`](#3-options-et-commandes-de-scanpy)
4. [Moteurs et Protocoles Spécialisés](#4-moteurs-et-protocoles-spécialisés)
   - [Détection de Versions et Corrélation CVE (-sV)](#détection-de-versions-et-corrélation-cve--sv)
   - [Scanner UDP avec Sondes Dédiées (-sU)](#scanner-udp-avec-sondes-dédiées--su)
   - [Modèles de Timing (T1 à T5)](#modèles-de-timing-t1-à-t5)
   - [Audit de Sécurité Web (OWASP, Headers, Cookies, Fichiers Sensibles)](#audit-de-sécurité-web)
   - [Inspection Cryptographique SSL/TLS](#inspection-cryptographique-ssltls)
   - [Traceroute et Diagnostic Réseau](#traceroute-et-diagnostic-réseau)
5. [Formats d'Exportation et Rapports](#5-formats-dexportation-et-rapports)
6. [Moteur C Haute Performance (`c_scanner/`)](#6-moteur-c-haute-performance-c_scanner)
7. [Exemples Concrets d'Utilisation](#7-exemples-concrets-dutilisation)
8. [Éthique et Conformité](#8-éthique-et-conformité)

---

## 1. Comparatif avec les Outils Standards

| Capacité | **DSS Scanner (D-Scan)** | **Nmap** | **Nikto** | **SSLyze** |
|---|:---:|:---:|:---:|:---:|
| **Port Scan TCP & UDP** | ✅ Oui (-sU, TCP) | ✅ Oui | ❌ Non | ❌ Non |
| **Identification de Versions (-sV)** | ✅ Oui (SSH, HTTP, MySQL, Redis, SMTP, FTP...) | ✅ Oui | ⚠️ Basique | ❌ Non |
| **Corrélation Automatique CVE / CVSS** | ✅ Intégrée en temps réel | ⚠️ Requiert scripts NSE | ⚠️ Partiel | ❌ Non |
| **Audit des En-têtes HTTP (OWASP)** | ✅ Complet (CSP, HSTS, XFO...) | ⚠️ Requiert NSE | ✅ Oui | ❌ Non |
| **Audit Fichiers Sensibles (.git, .env, admin)** | ✅ Inclus | ⚠️ Requiert NSE | ✅ Oui | ❌ Non |
| **Inspection SSL/TLS & Suites Crypto** | ✅ Inclus (Protocoles, Validité, Cert) | ⚠️ Basique | ❌ Non | ✅ Spécialisé |
| **Énumération Sous-domaines & Ping Sweep** | ✅ Inclus | ⚠️ Ping sweep seul | ❌ Non | ❌ Non |
| **Dépendances Externes** | 🟢 **0 dépendance** (Python Standard) | 🔴 Binaire C/C++ lourd | 🔴 Dépendances Perl | 🔴 Dépendances Python |
| **Dashboard HTML Interactif Moderne** | ✅ Dashboard Dark Theme & Score Sec | ❌ Requiert XSLT | ❌ Rapport texte/HTML brut | ❌ JSON/texte |
| **Export XML Compatible Nmap** | ✅ Oui (`--xml`) | ✅ Oui | ❌ Non | ❌ Non |

---

## 2. Fonctionnalités Clés

- 🚀 **Zéro dépendance** : Fonctionne immédiatement sur tout système équipé de Python 3 standard (Linux, macOS, Windows).
- ⚡ **Multi-threading Asynchrone** : Pool de threads ajustable pour un scan ultra-rapide sans ralentir le système.
- 🎯 **Corrélation CVE intelligente** : Analyse des bannières récupérées et confrontation avec une base de vulnérabilités connues (CVSS, titre et solution de remédiation).
- 🌐 **Audit Web Exhaustif** : Détection des fuites de configuration (`.env`, `.git/HEAD`, dumps SQL, sauvegardes), en-têtes de sécurité manquants, méthodes HTTP à risque (`TRACE`, `PUT`, `DELETE`), et attributs de cookies (`HttpOnly`, `Secure`).
- 🔒 **Contrôle Cryptographique TLS** : Vérification des versions de protocole (détection de SSLv3/TLS 1.0 dépréciés) et validité temporelle des certificats.
- 📡 **Traceroute TCP/IP** : Mesure de la topologie réseau et latence RTT par incrémentation du TTL.
- 📑 **Rapports Professionnels** : Export en HTML avec calcul de score de sécurité, XML compatible avec les parsers Nmap, JSON pour l'automatisation CI/CD, et Markdown pour la documentation.

---

## 3. Options et Commandes de `scan.py`

```bash
python3 scan.py -t <cible> [options]
```

### 📋 Tableau complet des arguments CLI

```
Options :
  -h, --help            Afficher ce message d'aide et quitter
  -t TARGET, --target TARGET
                        Cible à analyser (ex: 192.168.1.1, scanme.nmap.org, example.com)
  --subnet SUBNET       Balayage complet de sous-réseau CIDR (ex: 192.168.1.0/24)

Modes de Scan :
  -p PORTS, --ports PORTS
                        Ports spécifiques à scanner (ex: 80,443,8080 ou 1-1024)
  --top-ports {20,100,1000}
                        Scanner les X ports les plus fréquents (défaut : 100)
  -sV, --service-version
                        Activer la détection approfondie des versions et corrélation CVE
  -sU, --udp            Activer le scan des ports UDP clés (DNS, SNMP, NTP, DHCP...)
  -T {1,2,3,4,5}, --timing {T1..T5}
                        Modèle de timing : 1=Furtif, 2=Poli, 3=Standard, 4=Agressif, 5=Insane

Modules Avancés :
  --web                 Audit de sécurité web (en-têtes HTTP, cookies, méthodes, fichiers sensibles)
  --ssl-audit           Audit des suites cryptographiques et certificats SSL/TLS
  --traceroute          Calculer la route réseau et le nombre de sauts vers la cible
  --subdomains          Énumération DNS des sous-domaines courants
  -A, --full            Mode complet agressif (Ports TCP + -sV + Web + SSL + Subdomains + Traceroute)

Formats d'Export :
  --json FICHIER        Exporter au format JSON structuré
  --xml FICHIER         Exporter au format XML standard compatible Nmap (-oX)
  --markdown FICHIER    Générer un rapport complet en Markdown
  --html FICHIER        Générer un tableau de bord interactif moderne en HTML
```

---

## 4. Moteurs et Protocoles Spécialisés

### Détection de Versions et Corrélation CVE (-sV)
Le scanner envoie des sondes applicatives ciblées pour extraire les versions réelles des démons distants :
- **SSH** : Parsing RFC du protocole (`SSH-2.0-OpenSSH_...`).
- **HTTP / HTTPS** : Analyse des bannières `Server`, `X-Powered-By`, frameworks applicatifs.
- **FTP / SMTP** : Négociation de session et détection de fonctionnalités (`STARTTLS`, `AUTH`, login anonyme).
- **Bases de Données (MySQL, Redis)** : Décodage du paquet de handshake binaire MySQL v10 et requêtes d'information Redis.
- **CVE Matching** : Détection automatique des versions affectées par des failles critiques (ex: Apache Path Traversal, OpenSSH, Redis Lua sandbox escape).

### Scanner UDP avec Sondes Dédiées (-sU)
Contrairement aux scans UDP aveugles, **D-Scan** envoie de vrais paquets protocolaires :
- **Port 53 (DNS)** : Requête TXT `version.bind`.
- **Port 123 (NTP)** : Requête client NTP v3 standard.
- **Port 161 (SNMP)** : Requête SNMPv1 `get sysDescr` avec la communauté `public`.
- **Port 137 (NetBIOS)** : Requête de statut de nœud NetBIOS.
- **Port 1900 (SSDP/UPnP)** : Requête de découverte M-SEARCH.

### Modèles de Timing (T1 à T5)
| Profil | Nom | Concurrence | Timeout | Pause | Utilisation |
|:---:|---|:---:|:---:|:---:|---|
| **T1** | Sneaky / Furtif | 5 threads | 4.0s | 200ms | Évasion IDS / pare-feu stricts |
| **T2** | Polite / Poli | 15 threads | 2.5s | 50ms | Réduction de charge sur serveurs fragiles |
| **T3** | Normal / Standard | 50 threads | 1.2s | 0ms | Équilibre idéal vitesse / fiabilité |
| **T4** | Aggressive / Rapide | 100 threads | 0.7s | 0ms | Réseaux locaux et connexions rapides |
| **T5** | Insane / Ultra | 200 threads | 0.35s | 0ms | Environnements de lab / CTF ultra-rapides |

---

## 5. Formats d'Exportation et Rapports

### 1. Tableau de Bord HTML Interactif (`--html dashboard.html`)
Génère une page web autonome, responsive, en Dark Mode :
- **Score de Sécurité Dynamique** calculé sur 100 selon le niveau de risque des découvertes.
- **Tableau des CVE & Vulnérabilités** avec criticité et badges colorés.
- **Cartographie des Ports & Services** (TCP & UDP).
- **Audit des En-têtes HTTP & Cookies**.
- **Alertes Fichiers Sensibles Exposés**.

### 2. Rapport XML Compatible Nmap (`--xml report.xml`)
Permet d'importer directement vos résultats de scan dans des outils d'analyse tiers compatibles Nmap (ex: Metasploit `db_import`, Faraday, Dradis, DefectDojo).

### 3. Rapports JSON & Markdown (`--json data.json`, `--markdown report.md`)
Idéal pour l'intégration dans des pipelines d'intégration continue (CI/CD) ou la documentation technique.

---

## 6. Moteur C Haute Performance (`c_scanner/`)

Pour les besoins de scan réseau à très haute cadence ou pour pratiquer la programmation système en C :

```bash
# Compilation optimisée
cd c_scanner
make

# Scan d'un hôte avec capture de bannières et export JSON
./port_scanner -t 127.0.0.1 -s 1 -e 1024 -w 100 -b -o scan_c.json
```

---

## 7. Exemples Concrets d'Utilisation

### Exemple 1 : Reconnaissance complète d'un serveur Web
```bash
python3 scan.py -t mon-serveur.local -A --html rapport_complet.html
```

### Exemple 2 : Scan rapide de 1000 ports avec timing agressif (T4)
```bash
python3 scan.py -t scanme.nmap.org --top-ports 1000 -T4 -sV --markdown synthese.md
```

### Exemple 3 : Scan combiné TCP et UDP avec rapport XML
```bash
python3 scan.py -t 192.168.1.10 -p 21,22,53,80,161,443,3306 -sU -sV --xml audit.xml
```

### Exemple 4 : Balayage d'un sous-réseau entier
```bash
python3 scan.py --subnet 192.168.1.0/24 -T4
```

---

## 8. Éthique et Conformité

> ⚠️ **Usage Légal & Responsable** : Ces outils sont conçus exclusivement pour des audits autorisés, l'évaluation de vos propres infrastructures et les environnements d'apprentissage (CTF, laboratoires). Toute utilisation sans consentement préalable est strictement interdite par la loi.
