# 🛡️ DSS Ultimate Security Scanner (D-Scan v4.0 Enterprise / ASM Edition) — Guide Complet

> Plateforme complète d'**Attack Surface Management (ASM)** et d'audit de sécurité offensif/défensif : Scan réseau, surveillance passive **CT Logs**, extraction de **secrets JavaScript**, détection de **Buckets Cloud**, audit **GraphQL**, dérive pare-feu **IPv4 vs IPv6**, conformité email **MTA-STS/BIMI** et cartographie **MITRE ATT&CK**.

---

## 📑 Table des matières
1. [Nouvelles Fonctionnalités d'Attack Surface Management (ASM v4.0)](#1-nouvelles-fonctionnalités-dattack-surface-management-asm-v40)
2. [Options et Commandes CLI (`scan.py`)](#2-options-et-commandes-cli-scanpy)
3. [Détail des Nouveaux Modules](#3-détail-des-nouveaux-modules)
   - [📜 1. Surveillance Passive des Journaux CT (crt.sh)](#-1-surveillance-passive-des-journaux-ct-crtsh)
   - [🪣 2. Chasseur de Buckets Cloud Orphelins (AWS S3, GCP, Azure)](#-2-chasseur-de-buckets-cloud-orphelins-aws-s3-gcp-azure)
   - [🔑 3. Extracteur de Clés & Secrets JavaScript](#-3-extracteur-de-clés--secrets-javascript)
   - [🔮 4. Introspection & Audit d'API GraphQL](#-4-introspection--audit-dapi-graphql)
   - [🌐 5. Dérive Pare-Feu Double-Stack IPv4 vs IPv6](#-5-dérive-pare-feu-double-stack-ipv4-vs-ipv6)
   - [✉️ 6. Sécurité Email Haute Confiance (MTA-STS, TLS-RPT, BIMI)](#️-6-sécurité-email-haute-confiance-mta-sts-tls-rpt-bimi)
   - [🗺️ 7. Cartographie de la Matrice MITRE ATT&CK](#-7-cartographie-de-la-matrice-mitre-attck)
4. [Exemples d'Exécution](#4-exemples-dexécution)

---

## 1. Nouvelles Fonctionnalités d'Attack Surface Management (ASM v4.0)

| Module ASM | Objectif & Valeur Ajoutée |
|---|---|
| **Surveillance CT Logs** | Cartographie passive et 100 % furtive de tous les sous-domaines historiques sans envoyer de paquet à la cible via les registres mondiaux de certificats. |
| **Cloud Bucket Hunter** | Recherche de conteneurs de stockage ouverts sur **AWS S3, Google Cloud et Azure Blob** avec détection de fuites de données et sauvegardes. |
| **JS Secret Extractor** | Téléchargement et analyse statique des scripts front-end pour extraire les clés API (**Google, AWS, Stripe, GitHub, Slack Webhooks, clés privées RSA**). |
| **GraphQL Introspection** | Détection automatique des points de terminaison GraphQL et extraction du schéma complet de données si l'introspection est active en production. |
| **IPv6 Firewall Drift** | Analyse comparative de la politique de filtrage entre IPv4 et IPv6 pour repérer les ports accidentellement exposés sur IPv6. |
| **MTA-STS & BIMI Audit** | Vérification du chiffrement obligatoire inter-serveurs et de l'authentification de la marque de messagerie. |
| **MITRE ATT&CK Matrix** | Étiquetage automatique de chaque risque identifié avec son identifiant technique officiel MITRE (*T1595, T1190, T1552, T1530...*). |

---

## 2. Options et Commandes CLI (`scan.py`)

```bash
python3 scan.py -t <cible> [options]
```

```
Options ASM & Reconnaissance Avancée :
  --ct-logs             Surveillance passive des sous-domaines via Certificate Transparency (crt.sh)
  --cloud-hunter        Recherche de buckets Cloud publics exposés (AWS S3, GCP, Azure)
  --js-secrets          Extraction de clés d'API et secrets dans les fichiers JavaScript
  --graphql             Audit de points d'API GraphQL et test d'introspection
  --ipv6-drift          Détection de dérive de pare-feu IPv4 vs IPv6
  --email-sec           Audit email avancé (MTA-STS, TLS-RPT, BIMI, SPF, DMARC)
  --geo                 Géolocalisation IP, FAI et ASN
  -A, --full            Mode complet absolu (Tous les modules activés simultanément)

Scan & Timing :
  -p PORTS              Ports spécifiques (ex: 80,443,8080 ou 1-1024)
  --top-ports {20,100,1000}
                        Scanner les X ports les plus fréquents (défaut : 100)
  -sV                   Détection approfondie de versions et CVEs
  -T {1..5}             Modèle de vitesse / timing (1=Furtif à 5=Insane)

Formats d'Export :
  --html FICHIER        Tableau de bord HTML interactif moderne avec Matrice MITRE & Carte OSM
  --xml FICHIER         Export XML standard compatible Nmap (-oX)
  --json FICHIER        Export JSON structuré pour intégration CI/CD
  --markdown FICHIER    Générer un rapport d'audit au format Markdown
```

---

## 3. Détail des Nouveaux Modules

### 📜 1. Surveillance Passive des Journaux CT (crt.sh)
Interroge les registres de transparence de certificats TLS pour identifier tous les environnements créés par l'organisation (`dev-internal.cible.com`, `vpn-old.cible.com`, `staging.cible.com`).

### 🪣 2. Chasseur de Buckets Cloud Orphelins (AWS S3, GCP, Azure)
Génère des permutations intelligentes (`<cible>-backup`, `<cible>-data`, `<cible>-staging`, `<cible>-assets`, `<cible>-logs`) et teste les codes de réponse HTTP sur AWS S3, Google Cloud Storage et Azure Blob.

### 🔑 3. Extracteur de Clés & Secrets JavaScript
Parse le code HTML, identifie les balises `<script src="...">`, télécharge les fichiers JS et applique des expressions régulières pour repérer les identifiants hardcodés par inadvertance.

### 🔮 4. Introspection & Audit d'API GraphQL
Sonde `/graphql`, `/graphiql`, `/api/graphql` et envoie la requête standard `{ __schema { types { name } } }` pour extraire la structure de la base de données.

### 🌐 5. Dérive Pare-Feu Double-Stack IPv4 vs IPv6
Compare l'accessibilité des services entre les enregistrements DNS `A` (IPv4) et `AAAA` (IPv6) pour détecter les failles de configuration de pare-feu.

### 🗺️ 7. Cartographie de la Matrice MITRE ATT&CK
Associe les vulnérabilités découvertes aux techniques d'attaque officielles :
- **T1595.001** : Active Scanning (IP Blocks)
- **T1590.002** : DNS Reconnaissance
- **T1596.001** : Certificate Transparency Logs
- **T1190** : Exploit Public-Facing Application (CVEs)
- **T1552.001** : Credentials in Files & Secrets JS
- **T1530** : Data from Cloud Storage

---

## 4. Exemples d'Exécution

```bash
# 1. Audit complet Attack Surface Management d'un domaine
python3 scan.py -t example.com -A --html dashboard_asm.html --xml audit_nmap.xml

# 2. Chasse aux secrets JavaScript et fuites Cloud
python3 scan.py -t example.com --js-secrets --cloud-hunter --html secrets_report.html

# 3. Cartographie furtive passive (CT Logs) & Audit Email MTA-STS
python3 scan.py -t example.com --ct-logs --email-sec --markdown recon_passive.md
```
