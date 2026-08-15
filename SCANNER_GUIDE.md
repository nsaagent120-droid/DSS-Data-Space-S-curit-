# 🛡️ DSS Security Scanner — Guide d'Utilisation et Référence

> Outils d'audit réseau, scan de ports, énumération de sous-domaines et analyse de vulnérabilités web intégrés au projet **DSS-Data-Space-S-curit-**.

---

## 📋 Table des matières
1. [Vue d'ensemble](#1-vue-densemble)
2. [Scanner Principal en Python (`scan.py`)](#2-scanner-principal-en-python-scanpy)
   - [Fonctionnalités](#fonctionnalités)
   - [Commandes et Options](#commandes-et-options)
   - [Exemples d'utilisation](#exemples-dutilisation)
   - [Formats de Rapports (JSON, Markdown, HTML)](#formats-de-rapports)
3. [Scanner Réseau Haute Performance en C (`c_scanner/`)](#3-scanner-réseau-haute-performance-en-c-c_scanner)
   - [Concepts Système et Sockets](#concepts-système-et-sockets)
   - [Compilation et Exécution](#compilation-et-exécution)
4. [Intégration dans la Roadmap Cybersécurité](#4-intégration-dans-la-roadmap-cybersécurité)
5. [Avertissement Éthique & Légal](#5-avertissement-éthique--légal)

---

## 1. Vue d'ensemble

Le projet dispose de deux outils complémentaires de scan et de reconnaissance :

| Outil | Langage | Objectif principal | Atouts |
|---|---|---|---|
| **`scan.py`** | Python 3 | Audit complet (Ports, Web, Sous-domaines, SSL, Fichiers sensibles) | Zéro dépendance externe, multi-threadé, rapports HTML/MD/JSON interactifs. |
| **`port_scanner`** | C (POSIX) | Scan réseau TCP rapide à bas niveau | Sockets non-bloquants (`select`), multi-threading `pthread`, capture de bannières. |

---

## 2. Scanner Principal en Python (`scan.py`)

### ✨ Fonctionnalités
- **Scan de Ports Multi-threadé** : Détection rapide des ports ouverts avec identification des services et capture de bannières (SSH, HTTP, FTP, SMTP, MySQL, Redis...).
- **Estimation de l'OS** : Analyse heuristique du TTL IP (Linux, Windows, Cisco).
- **Audit Web & OWASP** :
  - Vérification des en-têtes HTTP de sécurité (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).
  - Détection de fuites d'informations serveur (`Server`, `X-Powered-By`).
  - Découverte de fichiers sensibles exposés (`.git/HEAD`, `.env`, `wp-config.php.bak`, `backup.zip`, `/admin/`, etc.).
  - Audit des méthodes HTTP non sécurisées (`TRACE`, `PUT`, `DELETE`).
  - Détection des mauvaises configurations CORS (`Access-Control-Allow-Origin: *`).
- **Inspection SSL/TLS** : Analyse du certificat (émetteur, sujet, validité, jours restants, suite de chiffrement).
- **Énumération de sous-domaines** : Résolution DNS sur les préfixes les plus courants (`api`, `dev`, `staging`, `vpn`, etc.).
- **Découverte d'hôtes (Subnet Ping Sweep)** : Balayage rapide de plages CIDR (ex: `192.168.1.0/24`).
- **Export Multi-format** : Rapports JSON, Markdown et tableau de bord HTML moderne.

---

### ⚙️ Commandes et Options

```bash
python3 scan.py -h
```

| Option | Description |
|---|---|
| `-t, --target <cible>` | Cible à scanner (IP ou nom d'hôte, ex: `scanme.nmap.org` ou `192.168.1.10`) |
| `-p, --ports <liste>` | Ports spécifiques ou plages (ex: `80,443,8080` ou `1-1024`) |
| `--top-ports <20\|100\|1000>` | Scanner les ports les plus fréquents (défaut : `100`) |
| `--all-ports` | Scanner tous les ports de 1 à 65535 |
| `--threads <N>` | Nombre de threads simultanés (défaut : `50`) |
| `--timeout <sec>` | Timeout des connexions réseau en secondes (défaut : `1.5`s) |
| `--web` | Activer l'audit de sécurité des applications web (en-têtes, SSL, fichiers sensibles) |
| `--subdomains` | Activer l'énumération DNS des sous-domaines |
| `--subnet <CIDR>` | Balayer un sous-réseau entier (ex: `192.168.1.0/24`) |
| `--full` | Activer l'ensemble des modules d'analyse |
| `--json <fichier>` | Exporter les résultats au format JSON |
| `--markdown <fichier>` | Exporter le rapport au format Markdown |
| `--html <fichier>` | Générer un rapport interactif complet en HTML |

---

### 🚀 Exemples d'utilisation

#### 1. Scan rapide des 100 ports standards sur une machine locale
```bash
python3 scan.py -t 127.0.0.1
```

#### 2. Scan complet avec rapport HTML, Markdown et JSON
```bash
python3 scan.py -t example.com --full --html report.html --markdown report.md --json report.json
```

#### 3. Audit spécifique d'un serveur Web (ports + vulnérabilités web + SSL)
```bash
python3 scan.py -t mon-serveur.local -p 80,443,8080,8443 --web --html web_audit.html
```

#### 4. Découverte des machines actives sur un réseau local (Ping Sweep)
```bash
python3 scan.py --subnet 192.168.1.0/24 --threads 100
```

---

## 3. Scanner Réseau Haute Performance en C (`c_scanner/`)

Ce module a été conçu pour lier la théorie système enseignée dans la **Phase 0** de la roadmap avec la programmation réseau en C.

### 🧠 Concepts Système et Réseau Utilisés
1. **Sockets BSD / POSIX** (`socket()`, `connect()`, `setsockopt()`).
2. **I/O Non-Bloquantes** : Configuration avec `fcntl(sock, F_SETFL, O_NONBLOCK)` combiné à `select()` pour obtenir des timeouts précis au niveau de la milliseconde sans bloquer le thread.
3. **Multi-threading POSIX (`pthread`)** : Répartition de la plage de ports entre les threads avec synchronisation par **mutex** (`pthread_mutex_lock` / `pthread_mutex_unlock`) pour éviter les *race conditions* lors de l'affichage console.
4. **Capture de bannières (Banner Grabbing)** : Envoi de sondes protocolaires et lecture des réponses du service distant.

### 🛠️ Compilation et Exécution

```bash
# Compilation via Makefile
cd c_scanner
make

# Exécution du scanner
./port_scanner -t 127.0.0.1 -s 1 -e 1024 -w 100 -b
```

#### Options du binaire C :
```
Usage : ./port_scanner -t <cible> [options]

Options :
  -t <host/IP>   Cible à scanner (nom de domaine ou IP)
  -s <port>      Port de départ (défaut : 1)
  -e <port>      Port de fin (défaut : 1024)
  -w <threads>   Nombre de threads ouvriers (défaut : 50)
  -T <ms>        Timeout de connexion en millisecondes (défaut : 1000 ms)
  -b             Activer la capture de bannières (banner grabbing)
  -h             Afficher l'aide
```

---

## 4. Intégration dans la Roadmap Cybersécurité

Ce scanner s'intègre directement dans les phases d'apprentissage du dépôt :

- **Phase 0 (Fondations & C)** : Compréhension des sockets, des descripteurs de fichiers, de la gestion mémoire (`malloc`/`free`) et des threads POSIX (`pthread`).
- **Phase 1 & 2 (Reconnaissance & Surface d'attaque)** : Cartographie des services ouverts, identification des versions logicielles obsolètes et repérage des vecteurs d'entrée.
- **Phase 3 (Audit de code & Web Security)** : Détection des mauvaises configurations de serveurs, des en-têtes HTTP manquants, des fuites de données sensibles (`.git`, `.env`).

---

## 5. Avertissement Éthique & Légal

> ⚠️ **Avertissement Légal** : Ces scripts sont fournis à des fins purement **éducatives**, d'apprentissage et pour l'audit de vos propres systèmes ou d'environnements de test (CTF, laboratoires autorisés). Le scan non autorisé de systèmes tiers sans accord préalable explicite est illégal (Articles 323-1 et suivants du Code pénal en France, lois sur la cybercriminalité internationales).
