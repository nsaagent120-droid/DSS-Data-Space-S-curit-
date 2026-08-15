# 🛡️ DSS Ultimate Security Scanner (D-Scan v3.0) — Guide Complet & Référence

> Suite d'audit de sécurité réseau, reconnaissance OSINT, **géolocalisation IP & ASN**, détection de **WAF & CMS**, scan de versions (**-sV**), scan UDP (**-sU**), corrélation **CVE / CVSS**, audit web OWASP, sécurité email (SPF/DMARC) et rapports multi-formats (**HTML interactif avec carte OSM, XML Nmap, JSON, Markdown**).

---

## 📑 Table des matières
1. [Comparatif avec les Outils de Référence (Nmap, Nikto, SSLyze, WhatWeb, Masscan)](#1-comparatif-avec-les-outils-de-référence)
2. [Fonctionnalités Majeures (v3.0)](#2-fonctionnalités-majeures-v30)
3. [Options et Commandes CLI (`scan.py`)](#3-options-et-commandes-cli-scanpy)
4. [Détail des Modules & Moteurs d'Audit](#4-détail-des-modules--moteurs-daudit)
   - [🌍 Géolocalisation IP, ASN, FAI & Reverse DNS](#-géolocalisation-ip-asn-fai--reverse-dns)
   - [🛡️ Détection de WAF (Web Application Firewall) & CDN](#️-détection-de-waf-web-application-firewall--cdn)
   - [🧩 Fingerprinting CMS & Stack Technologique](#-fingerprinting-cms--stack-technologique)
   - [✉️ Audit DNS & Sécurité Email (SPF / DMARC / MX)](#️-audit-dns--sécurité-email-spf--dmarc--mx)
   - [🔍 Détection de Versions (-sV) & Corrélation CVE](#-détection-de-versions--sv--corrélation-cve)
   - [📡 Scanner UDP avec Sondes Dédiées (-sU)](#-scanner-udp-avec-sondes-dédiées--su)
   - [⚡ Mesure de Latence RTT & Modèles de Timing (T1 à T5)](#-mesure-de-latence-rtt--modèles-de-timing-t1-à-t5)
   - [🔐 Audit Web OWASP, SSL/TLS et Découverte SAN](#-audit-web-owasp-ssltls-et-découverte-san)
5. [Formats de Rapports (HTML, XML Nmap, JSON, MD)](#5-formats-de-rapports)
6. [Moteur C Haute Performance (`c_scanner/`)](#6-moteur-c-haute-performance-c_scanner)
7. [Exemples Concrets d'Audit](#7-exemples-concrets-daudit)
8. [Éthique et Cadre Légal](#8-éthique-et-cadre-légal)

---

## 1. Comparatif avec les Outils de Référence

| Capacité | **DSS Scanner (D-Scan v3.0)** | **Nmap** | **Nikto** | **WhatWeb** | **SSLyze** |
|---|:---:|:---:|:---:|:---:|:---:|
| **Port Scan TCP & UDP avec RTT** | ✅ Oui (Latence RTT) | ✅ Oui | ❌ Non | ❌ Non | ❌ Non |
| **Détection de Versions (-sV)** | ✅ Oui (SSH, HTTP, MySQL, Redis...) | ✅ Oui | ⚠️ Basique | ❌ Non | ❌ Non |
| **Corrélation CVE / CVSS Automatique** | ✅ Temps réel intégrée | ⚠️ Via NSE | ⚠️ Partiel | ❌ Non | ❌ Non |
| **Géolocalisation IP, ASN, FAI & Carte OSM** | ✅ Inclus | ❌ Non | ❌ Non | ⚠️ Partiel | ❌ Non |
| **Détection WAF / CDN (Cloudflare, AWS...)** | ✅ Inclus | ⚠️ Via NSE | ⚠️ Partiel | ✅ Oui | ❌ Non |
| **Fingerprinting CMS & Frameworks** | ✅ Inclus (WordPress, Laravel...) | ❌ Non | ⚠️ Basique | ✅ Spécialisé | ❌ Non |
| **Sécurité Email (SPF, DMARC, MX)** | ✅ Inclus (Anti-Spoofing) | ⚠️ Via NSE | ❌ Non | ❌ Non | ❌ Non |
| **Audit En-têtes HTTP & Fichiers Sensibles** | ✅ Complet (OWASP Top 10) | ⚠️ Via NSE | ✅ Oui | ❌ Non | ❌ Non |
| **Certificats SSL/TLS & Découverte SAN** | ✅ Inclus | ⚠️ Basique | ❌ Non | ❌ Non | ✅ Spécialisé |
| **Dépendances Externes** | 🟢 **0 dépendance** (Python 3 Stdlib) | 🔴 Binaire C++ | 🔴 Perl | 🔴 Ruby | 🔴 Python + deps |
| **Dashboard HTML Interactif (Dark Mode)** | ✅ Dashboard & Score de Sécurité | ❌ Requiert XSLT | ❌ Brut | ❌ Non | ❌ Non |
| **Export XML Compatible Nmap** | ✅ Oui (`--xml`) | ✅ Oui | ❌ Non | ❌ Non | ❌ Non |

---

## 2. Fonctionnalités Majeures (v3.0)

- 🌍 **Renseignement Géographique & OSINT** : Détermination instantanée du pays, ville, coordonnées GPS, FAI, numéro d'AS (ASN) et Reverse DNS.
- 🛡️ **Détection Intelligente de WAF** : Empreintes pour Cloudflare, AWS CloudFront/WAF, Akamai, Imperva, Fastly, Sucuri, ModSecurity, F5 BIG-IP.
- 🧩 **Stack & CMS Fingerprinting** : Détection des technologies web (WordPress, Drupal, Joomla, Laravel, Django, Express, Spring Boot, React, Vue, Nginx, Apache).
- ✉️ **Audit Anti-Usurpation Email** : Vérification stricte des enregistrements DNS **SPF** (`+all` vulnérable, `~all`, `-all`) et **DMARC** (`p=none`, `p=quarantine`, `p=reject`).
- ⏱️ **Mesure de Latence Précise** : Calcul du Round-Trip Time (RTT en millisecondes) pour chaque port ouvert.
- 🔒 **Certificats & Découverte SAN** : Extraction des domaines alternatifs (*Subject Alternative Names*) permettant de découvrir des sous-domaines cachés.

---

## 3. Options et Commandes CLI (`scan.py`)

```bash
python3 scan.py -t <cible> [options]
```

### Tableau des options disponibles :

```
Options Générales :
  -h, --help            Afficher ce message d'aide
  -t TARGET, --target TARGET
                        Cible à analyser (IP ou nom de domaine, ex: scanme.nmap.org)
  --subnet SUBNET       Balayage de sous-réseau CIDR complet (ex: 192.168.1.0/24)

Modes de Scan & Vitesse :
  -p PORTS, --ports PORTS
                        Ports spécifiques ou plages (ex: 80,443,8080 ou 1-1024)
  --top-ports {20,100,1000}
                        Scanner les X ports les plus fréquents (défaut : 100)
  -sV, --service-version
                        Activer la détection approfondie des versions et corrélation CVE
  -sU, --udp            Activer le scan des ports UDP clés (DNS, SNMP, NTP, DHCP...)
  -T {1,2,3,4,5}, --timing {T1..T5}
                        Modèle de timing : 1=Furtif, 2=Poli, 3=Standard, 4=Agressif, 5=Insane

Reconnaissance & OSINT Avancé :
  --geo                 Géolocalisation IP, ASN, FAI et Reverse DNS
  --dns-audit           Audit DNS et sécurité des e-mails (SPF, DMARC, MX)
  --web                 Audit de sécurité web (en-têtes HTTP, cookies, méthodes, fichiers sensibles)
  --ssl-audit           Audit des suites cryptographiques et certificats SSL/TLS
  --traceroute          Calculer la route réseau et le nombre de sauts vers la cible
  --subdomains          Énumération DNS des sous-domaines courants
  -A, --full            Mode agressif complet (Tous les modules activés simultanément)

Exports :
  --json FICHIER        Exporter au format JSON structuré
  --xml FICHIER         Exporter au format XML standard compatible Nmap (-oX)
  --markdown FICHIER    Générer un rapport complet en Markdown
  --html FICHIER        Générer un tableau de bord interactif en HTML
```

---

## 4. Détail des Modules & Moteurs d'Audit

### 🌍 Géolocalisation IP, ASN, FAI & Reverse DNS
- Résout le pays, la région, la ville et le code postal.
- Fournit les coordonnées GPS (Latitude / Longitude) avec lien vers OpenStreetMap.
- Identifie le fournisseur d'accès (FAI) et le Système Autonome (ASN, ex: `AS15169 Google LLC`).
- Gère automatiquement les adresses IP privées (RFC 1918) pour éviter les requêtes externes inutiles.

### 🛡️ Détection de WAF (Web Application Firewall) & CDN
- Analyse les en-têtes HTTP spécifiques (`CF-Ray`, `X-Amz-Cf-Id`, `X-Akamai-Transformed`, `X-Iinfo`, `X-Sucuri-Id`, etc.).
- Identifie les cookies de sécurité spécifiques (ex: F5 `BIGipServer`, Imperva `visid_incap`).

### 🧩 Fingerprinting CMS & Stack Technologique
- Détecte les CMS : WordPress, Joomla!, Drupal, Shopify, Prestashop.
- Identifie les frameworks Backend : Laravel, Django, Spring Boot, Express.js.
- Reconnaît les librairies Frontend : React, Vue.js, Bootstrap, Tailwind CSS, jQuery.

### ✉️ Audit DNS & Sécurité Email (SPF / DMARC / MX)
- **SPF (`v=spf1`)** : Alerte critique si `+all` (permet l'usurpation totale du nom de domaine pour envoyer des spams/phishing au nom de l'entreprise).
- **DMARC (`_dmarc.domaine`)** : Analyse de la stratégie de rejet (`p=reject`, `p=quarantine` ou `p=none`).

---

## 5. Formats de Rapports

### 1. Tableau de Bord HTML Moderne (`--html rapport.html`)
- **Score de Sécurité Global** calculé dynamiquement sur 100.
- **Bloc Géolocalisation & OSINT** avec lien cartographique direct.
- **Badges WAF & Stack Technologique**.
- **Tableau des CVE & Vulnérabilités** avec criticité et solutions de remédiation.
- **Cartographie des Ports & Services Réseau** avec latence en millisecondes.

### 2. Export XML Compatible Nmap (`--xml nmap_out.xml`)
- Totalement compatible avec les outils tiers (Metasploit `db_import`, Faraday, Dradis, DefectDojo).

### 3. Exports JSON & Markdown (`--json data.json`, `--markdown rapport.md`)

---

## 6. Moteur C Haute Performance (`c_scanner/`)

```bash
# Compilation optimisée
cd c_scanner
make

# Scan d'un hôte avec mesure de latence RTT et export JSON
./port_scanner -t 127.0.0.1 -p top20 -b -o scan_c.json
```

---

## 7. Exemples Concrets d'Audit

### Exemple 1 : Audit complet OSINT, Web, DNS et Ports
```bash
python3 scan.py -t example.com -A --html dashboard.html --xml rapport_nmap.xml
```

### Exemple 2 : Audit de géolocalisation et réputation DNS
```bash
python3 scan.py -t cible.com --geo --dns-audit --markdown audit_dns.md
```

### Exemple 3 : Scan rapide de 1000 ports avec timing agressif (T4) et détection de versions (-sV)
```bash
python3 scan.py -t 192.168.1.50 --top-ports 1000 -sV -T4 --json ports.json
```

---

## 8. Éthique et Cadre Légal

> ⚠️ **Avertissement Légal** : Cet outil doit être utilisé uniquement sur des infrastructures dont vous êtes propriétaire ou pour lesquelles vous possédez une autorisation écrite formelle. Le scan ou l'audit non autorisé est passible de sanctions pénales.
