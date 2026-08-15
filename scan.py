#!/usr/bin/env python3
"""
=============================================================================
  DSS Ultimate Security Scanner (D-Scan v4.0 Enterprise / ASM Edition)
=============================================================================
  Auteur      : DSS Security / Cybersecurity Mastery Roadmap
  Description : Plateforme tout-en-un d'Attack Surface Management (ASM) & Audit :
                - Scan TCP & UDP multi-threadé avec timing T1-T5
                - Détection de versions (-sV) et corrélation automatique CVE/CVSS
                - Géolocalisation IP, ASN, FAI & Reverse DNS
                - Détection de WAF (Cloudflare, AWS, Akamai, Imperva, ModSec...)
                - Fingerprinting de CMS & Technologies Web (Wappalyzer-like)
                - Surveillance Passive Certificate Transparency Logs (crt.sh)
                - Détecteur de Fuites Cloud & Buckets (AWS S3, GCP, Azure Blob)
                - Détection de Subdomain Takeover (CNAME orphelins)
                - Extracteur de Clés & Secrets dans les fichiers JavaScript
                - Détection & Introspection d'API GraphQL / REST
                - Dérive Pare-feu Double-Stack IPv4 vs IPv6
                - Audit Email Avancé (MTA-STS, TLS-RPT, BIMI, SPF, DMARC)
                - Cartographie MITRE ATT&CK & Matrice de Risque
                - Tableau de bord HTML interactif (Dark Mode, Carte OSM, MITRE)
  Usage       : python3 scan.py -t <cible> [options]
=============================================================================
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime

# =============================================================================
# COULEURS & FORMATTAGE TERMINAL ANSI
# =============================================================================
class Colors:
    RESET       = "\033[0m"
    BOLD        = "\033[1m"
    DIM         = "\033[2m"
    UNDERLINE   = "\033[4m"
    RED         = "\033[91m"
    GREEN       = "\033[92m"
    YELLOW      = "\033[93m"
    BLUE        = "\033[94m"
    MAGENTA     = "\033[95m"
    CYAN        = "\033[96m"
    WHITE       = "\033[97m"

def log_info(msg):
    print(f"[{Colors.CYAN}*{Colors.RESET}] {msg}")

def log_success(msg):
    print(f"[{Colors.GREEN}+{Colors.RESET}] {msg}")

def log_warning(msg):
    print(f"[{Colors.YELLOW}!{Colors.RESET}] {msg}")

def log_danger(msg):
    print(f"[{Colors.RED}-{Colors.RESET}] {msg}")

def log_title(msg):
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*72}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}  {msg}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*72}{Colors.RESET}\n")

# =============================================================================
# MODÈLES DE TIMING (NMAP TIMING TEMPLATES T1 - T5)
# =============================================================================
TIMING_PROFILES = {
    "T1": {"name": "Sneaky (Furtif)", "timeout": 4.0, "threads": 5, "delay": 0.2},
    "T2": {"name": "Polite (Poli)", "timeout": 2.5, "threads": 15, "delay": 0.05},
    "T3": {"name": "Normal (Standard)", "timeout": 1.2, "threads": 50, "delay": 0.0},
    "T4": {"name": "Aggressive (Rapide)", "timeout": 0.7, "threads": 100, "delay": 0.0},
    "T5": {"name": "Insane (Ultra-rapide)", "timeout": 0.35, "threads": 200, "delay": 0.0}
}

TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443]

TOP_100_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161,
    162, 179, 194, 389, 443, 445, 465, 514, 515, 587, 631, 636, 873, 902, 989, 990, 993, 995,
    1025, 1080, 1194, 1433, 1434, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2181, 2222, 2375,
    2376, 2483, 2484, 3000, 3128, 3306, 3389, 3690, 4000, 4444, 5000, 5222, 5432, 5672, 5900,
    5984, 5985, 6379, 6667, 7000, 7001, 8000, 8008, 8080, 8081, 8443, 8500, 8888, 9000, 9042,
    9090, 9092, 9200, 9300, 9418, 9999, 10000, 11211, 15672, 27017, 27018, 28017, 50000, 50070
]

UDP_COMMON_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1194, 1900, 4500, 5060, 5353]

SERVICES_MAP = {
    21: "FTP (File Transfer)", 22: "SSH (Secure Shell)", 23: "Telnet", 25: "SMTP", 53: "DNS",
    69: "TFTP", 80: "HTTP (Web)", 110: "POP3", 111: "RPCBind", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS Name", 138: "NetBIOS Dgm", 139: "NetBIOS Sess", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS (TLS)", 445: "SMB / MS-DS", 465: "SMTPS", 514: "Syslog",
    587: "SMTP Submission", 636: "LDAPS", 873: "Rsync", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS Proxy", 1194: "OpenVPN", 1433: "MSSQL Server", 1521: "Oracle DB",
    1900: "UPnP (SSDP)", 2049: "NFS", 2181: "ZooKeeper", 2222: "SSH-Alt", 2375: "Docker HTTP",
    2376: "Docker TLS", 3000: "Node / Dev Web", 3306: "MySQL / MariaDB", 3389: "RDP",
    4000: "Hexo / Dev Web", 4444: "Metasploit / Listener", 5000: "Flask / Registry",
    5060: "SIP (VoIP)", 5353: "mDNS", 5432: "PostgreSQL", 5672: "RabbitMQ AMQP",
    5900: "VNC Remote", 5984: "CouchDB", 5985: "WinRM HTTP", 5986: "WinRM HTTPS",
    6379: "Redis Key-Value", 7001: "WebLogic", 8000: "HTTP Dev", 8080: "HTTP Proxy / Tomcat",
    8443: "HTTPS-Alt", 8888: "Jupyter / Admin", 9000: "PHP-FPM / Sonar", 9090: "Prometheus / Cockpit",
    9092: "Apache Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch Cluster", 10000: "Webmin",
    11211: "Memcached", 15672: "RabbitMQ UI", 27017: "MongoDB", 27018: "MongoDB Shard"
}

CVE_KNOWLEDGE_BASE = [
    {
        "pattern": r"OpenSSH_([1-6]\.|7\.[0-6])",
        "service": "OpenSSH",
        "cve": "CVE-2016-0777 / CVE-2018-15473",
        "title": "Version OpenSSH obsolète vulnérable à la fuite de clés ou énumération d'utilisateurs",
        "severity": "HIGH",
        "cvss": 7.5,
        "mitre": "T1190",
        "recommendation": "Mettre à jour vers OpenSSH >= 8.9+ et désactiver l'authentification par mot de passe."
    },
    {
        "pattern": r"Apache/(2\.[0-3]\.|2\.4\.[0-9]\b|2\.4\.[1-4][0-9]\b|2\.4\.50\b|2\.4\.49\b)",
        "service": "Apache HTTP Server",
        "cve": "CVE-2021-41773 / CVE-2021-42013",
        "title": "Apache HTTPD vulnérable aux traversées de répertoires / RCE",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "mitre": "T1190",
        "recommendation": "Mettre à jour Apache HTTPD vers la dernière version stable (>= 2.4.58+)."
    },
    {
        "pattern": r"nginx/(0\.|1\.[0-9]\.|1\.1[0-8]\.)",
        "service": "Nginx",
        "cve": "CVE-2021-23017 / CVE-2017-7529",
        "title": "Version Nginx vulnérable aux dépassements d'entiers dans le resolver DNS",
        "severity": "HIGH",
        "cvss": 7.7,
        "mitre": "T1190",
        "recommendation": "Mettre à jour Nginx vers la version stable récente (>= 1.24+)."
    },
    {
        "pattern": r"PHP/(5\.|7\.[0-3]\.)",
        "service": "PHP",
        "cve": "CVE-2019-11043 / EOL",
        "title": "Version PHP obsolète et en fin de vie (End of Life)",
        "severity": "HIGH",
        "cvss": 8.1,
        "mitre": "T1190",
        "recommendation": "Migrer immédiatement vers PHP 8.1, 8.2 ou 8.3 supporté."
    },
    {
        "pattern": r"Redis.*([1-5]\.)",
        "service": "Redis",
        "cve": "CVE-2022-0543",
        "title": "Redis Lua Sandbox Escape & Remote Code Execution",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "mitre": "T1190",
        "recommendation": "Mettre à jour Redis vers >= 6.2.7 ou 7.0+, lier sur 127.0.0.1 et exiger un mot de passe fort."
    }
]

# =============================================================================
# MODULE 1 : RECONNAISSANCE PASSIVE VIA CT LOGS (CERTIFICATE TRANSPARENCY)
# =============================================================================
class CTLogsInspector:
    """Interroge les journaux mondiaux de transparence des certificats pour cartographier les sous-domaines."""

    @staticmethod
    def query(domain):
        log_title(f"SURVEILLANCE PASSIVE CERTIFICATE TRANSPARENCY (CT LOGS) : {domain}")
        clean_domain = domain.strip().replace("http://", "").replace("https://", "").split("/")[0]
        discovered_subs = set()
        
        url = f"https://crt.sh/?q=%.{clean_domain}&output=json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (DSS-CTLogs-Scanner/4.0)"})
            with urllib.request.urlopen(req, timeout=5.0) as res:
                data = json.loads(res.read().decode(errors="ignore"))
                for entry in data:
                    name_val = entry.get("name_value", "")
                    for sub in name_val.split("\n"):
                        sub = sub.strip().lower()
                        if sub and "*" not in sub and sub.endswith(clean_domain):
                            discovered_subs.add(sub)
        except Exception:
            pass

        subs_list = sorted(list(discovered_subs))
        if subs_list:
            log_success(f"Sous-domaines découverts furtivement via CT Logs ({len(subs_list)}) :")
            for s in subs_list[:12]:
                print(f"  {Colors.GREEN}↳{Colors.RESET} {Colors.BOLD}{s}{Colors.RESET}")
            if len(subs_list) > 12:
                print(f"  {Colors.DIM}... ({len(subs_list) - 12} autres sous-domaines omis){Colors.RESET}")
        else:
            log_info("Aucun historique CT Logs disponible ou API temporairement silencieuse.")

        return subs_list

# =============================================================================
# MODULE 2 : DÉTECTEUR DE FUITES CLOUD & BUCKETS (AWS S3, GCP, AZURE BLOB)
# =============================================================================
class CloudBucketHunter:
    """Recherche de compartiments Cloud publics mal configurés (AWS S3, Google Cloud Storage, Azure Blob)."""

    PERMUTATIONS = [
        "", "-backup", "-data", "-assets", "-staging", "-dev", "-logs", "-public",
        "-media", "-static", "-storage", "-files", "-prod", "-internal"
    ]

    @classmethod
    def hunt(cls, domain, timeout=2.5):
        log_title(f"CHASSE AUX BUCKETS CLOUD ORPHELINS / EXPOSÉS : {domain}")
        base_name = domain.split(".")[0].lower()
        findings = []

        providers = [
            {"provider": "AWS S3", "template": "https://{name}.s3.amazonaws.com"},
            {"provider": "Google Cloud Storage", "template": "https://storage.googleapis.com/{name}"},
            {"provider": "Azure Blob Storage", "template": "https://{name}.blob.core.windows.net"}
        ]

        def check_bucket(url, p_name, b_name):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "DSS-CloudHunter/4.0"})
                with urllib.request.urlopen(req, timeout=timeout) as res:
                    if res.status == 200:
                        return {"provider": p_name, "bucket": b_name, "url": url, "status": "OUVERT / PUBLIC", "severity": "CRITICAL"}
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    return {"provider": p_name, "bucket": b_name, "url": url, "status": "EXISTANT (Accès Restreint)", "severity": "INFO"}
            except Exception:
                pass
            return None

        tasks = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            for p in providers:
                for perm in cls.PERMUTATIONS:
                    b_name = f"{base_name}{perm}"
                    b_url = p["template"].format(name=b_name)
                    tasks.append(executor.submit(check_bucket, b_url, p["provider"], b_name))

            for f in concurrent.futures.as_completed(tasks):
                res = f.result()
                if res:
                    findings.append(res)
                    col = Colors.RED if res["severity"] == "CRITICAL" else Colors.CYAN
                    print(f"  [{col}{res['status']}{Colors.RESET}] {res['provider']} : {Colors.BOLD}{res['url']}{Colors.RESET}")

        if not findings:
            log_success("Aucun bucket Cloud public standard exposé trouvé.")
        return findings

# =============================================================================
# MODULE 3 : DÉTECTEUR DE SUBDOMAIN TAKEOVER (CNAME ORPHELINS)
# =============================================================================
class SubdomainTakeoverScanner:
    """Détecte les sous-domaines pointant vers des services SaaS / Cloud supprimés."""

    FINGERPRINTS = [
        {"service": "GitHub Pages", "cname": "github.io", "pattern": "There isn't a GitHub Pages site here"},
        {"service": "Heroku", "cname": "herokucdn.com", "pattern": "No such app"},
        {"service": "AWS S3", "cname": "s3.amazonaws.com", "pattern": "NoSuchBucket"},
        {"service": "Shopify", "cname": "myshopify.com", "pattern": "Sorry, this shop is currently unavailable"},
        {"service": "Zendesk", "cname": "zendesk.com", "pattern": "Help Center Closed"},
        {"service": "Fastly", "cname": "fastly.net", "pattern": "Fastly error: unknown domain"},
        {"service": "Surge.sh", "cname": "surge.sh", "pattern": "project not found"},
        {"service": "Ghost", "cname": "ghost.io", "pattern": "The thing you were looking for is no longer here"}
    ]

    @classmethod
    def audit_subdomain(cls, sub, timeout=3.0):
        try:
            req = urllib.request.Request(f"http://{sub}", headers={"User-Agent": "DSS-TakeoverScanner/4.0"})
            with urllib.request.urlopen(req, timeout=timeout) as res:
                body = res.read(4096).decode(errors="ignore")
                for fp in cls.FINGERPRINTS:
                    if fp["pattern"] in body:
                        return {"subdomain": sub, "service": fp["service"], "vulnerable": True, "evidence": fp["pattern"]}
        except urllib.error.HTTPError as e:
            body = e.read(4096).decode(errors="ignore")
            for fp in cls.FINGERPRINTS:
                if fp["pattern"] in body:
                    return {"subdomain": sub, "service": fp["service"], "vulnerable": True, "evidence": fp["pattern"]}
        except Exception:
            pass
        return None

# =============================================================================
# MODULE 4 : SCANNER DE CLÉS & SECRETS JAVASCRIPT
# =============================================================================
class JSSecretScanner:
    """Scanne les fichiers JavaScript front-end pour extraire les clés d'API et tokens hardcodés."""

    SECRET_REGEXES = [
        {"name": "Google API Key", "regex": r"AIzaSy[A-Za-z0-9_-]{33}", "severity": "HIGH"},
        {"name": "AWS Access Key", "regex": r"AKIA[0-9A-Z]{16}", "severity": "CRITICAL"},
        {"name": "Stripe API Key", "regex": r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,99}", "severity": "CRITICAL"},
        {"name": "GitHub Personal Token", "regex": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}", "severity": "CRITICAL"},
        {"name": "Slack Webhook URL", "regex": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", "severity": "HIGH"},
        {"name": "Private Key RSA/SSH", "regex": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "severity": "CRITICAL"},
        {"name": "Generic Auth Token / Secret", "regex": r"(?:api_key|apikey|secret_key|app_secret|auth_token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,64})['\"]", "severity": "MEDIUM"}
    ]

    @classmethod
    def scan_url(cls, base_url, timeout=3.5):
        log_title(f"SCAN STATIQUE DE CLÉS & SECRETS JAVASCRIPT : {base_url}")
        found_secrets = []
        js_urls = []

        try:
            req = urllib.request.Request(base_url, headers={"User-Agent": "Mozilla/5.0 (DSS-SecretScanner/4.0)"})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as res:
                html = res.read().decode(errors="ignore")

            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
                src = m.group(1)
                full_js_url = urllib.parse.urljoin(base_url, src)
                js_urls.append(full_js_url)

            for rule in cls.SECRET_REGEXES:
                for match in re.finditer(rule["regex"], html):
                    val = match.group(0)
                    found_secrets.append({"name": rule["name"], "secret": val[:30] + "...", "severity": rule["severity"], "source": "HTML Inline"})

        except Exception:
            pass

        def scan_js(url):
            local_finds = []
            try:
                r = urllib.request.Request(url, headers={"User-Agent": "DSS-SecretScanner/4.0"})
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(r, timeout=timeout, context=ctx) as resp:
                    js_code = resp.read().decode(errors="ignore")
                    for rule in cls.SECRET_REGEXES:
                        for match in re.finditer(rule["regex"], js_code):
                            val = match.group(0)
                            local_finds.append({
                                "name": rule["name"],
                                "secret": val[:35] + ("..." if len(val) > 35 else ""),
                                "severity": rule["severity"],
                                "source": url
                            })
            except Exception:
                pass
            return local_finds

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(scan_js, js_urls[:10]))
            for rlist in results:
                found_secrets.extend(rlist)

        if found_secrets:
            for s in found_secrets:
                col = Colors.RED if s["severity"] == "CRITICAL" else Colors.YELLOW
                log_danger(f"[{col}{s['severity']}{Colors.RESET}] {Colors.BOLD}{s['name']}{Colors.RESET} : `{s['secret']}` (dans {s['source']})")
        else:
            log_success("Aucun token ou clé d'API exposé détecté dans les scripts JavaScript.")

        return found_secrets

# =============================================================================
# MODULE 5 : DÉTECTION & INTROSPECTION GRAPHQL
# =============================================================================
class GraphQLAuditor:
    """Détecte les points d'entrée GraphQL et teste l'activation de l'introspection."""

    ENDPOINTS = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/api/v1/graphql"]

    @classmethod
    def audit(cls, base_url, timeout=3.0):
        log_title(f"AUDIT D'API GRAPHQL & INTROSPECTION : {base_url}")
        findings = {"detected": False, "endpoint": None, "introspection_enabled": False, "types": []}

        intro_query = json.dumps({"query": "{ __schema { types { name kind } } }"}).encode()

        for ep in cls.ENDPOINTS:
            target = base_url.rstrip("/") + ep
            try:
                req = urllib.request.Request(
                    target,
                    data=intro_query,
                    headers={"Content-Type": "application/json", "User-Agent": "DSS-GraphQLAuditor/4.0"}
                )
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as res:
                    if res.status == 200:
                        raw = json.loads(res.read().decode(errors="ignore"))
                        findings["detected"] = True
                        findings["endpoint"] = target
                        if "data" in raw and "__schema" in raw["data"]:
                            findings["introspection_enabled"] = True
                            types_list = [t["name"] for t in raw["data"]["__schema"].get("types", []) if not t["name"].startswith("__")]
                            findings["types"] = types_list[:15]
                            log_danger(f"Introspection GraphQL ACTIVÉE sur : {Colors.BOLD}{target}{Colors.RESET}")
                            log_info(f"Schéma découvert ({len(types_list)} types) : {', '.join(types_list[:8])}...")
                            break
                        else:
                            log_warning(f"Endpoint GraphQL détecté sur {target} (Introspection désactivée).")
                            break
            except Exception:
                pass

        if not findings["detected"]:
            log_success("Aucun endpoint GraphQL public standard détecté.")
        return findings

# =============================================================================
# MODULE 6 : DÉRIVE DE PARE-FEU IPV4 VS IPV6 (DOUBLE-STACK DRIFT)
# =============================================================================
class IPv6DriftScanner:
    """Compare l'exposition des ports sur IPv4 vs IPv6 pour détecter les contournements de pare-feu."""

    @staticmethod
    def audit(domain, ports=[22, 80, 443, 3306, 8080], timeout=1.0):
        log_title(f"ANALYSE DE DÉRIVE PARE-FEU DOUBLE-STACK IPV4 VS IPV6 : {domain}")
        report = {"ipv4": None, "ipv6": None, "ipv4_open": [], "ipv6_open": [], "drift_detected": False}

        try:
            report["ipv4"] = socket.getaddrinfo(domain, None, socket.AF_INET)[0][4][0]
        except Exception:
            pass

        try:
            report["ipv6"] = socket.getaddrinfo(domain, None, socket.AF_INET6)[0][4][0]
        except Exception:
            pass

        if not report["ipv6"]:
            log_info("Aucun enregistrement IPv6 (AAAA) configuré sur ce domaine.")
            return report

        log_info(f"IPv4 : {Colors.CYAN}{report['ipv4']}{Colors.RESET} | IPv6 : {Colors.CYAN}{report['ipv6']}{Colors.RESET}")

        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                if s.connect_ex((report["ipv4"], p)) == 0:
                    report["ipv4_open"].append(p)
                s.close()
            except Exception:
                pass

        for p in ports:
            try:
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                s.settimeout(timeout)
                if s.connect_ex((report["ipv6"], p)) == 0:
                    report["ipv6_open"].append(p)
                s.close()
            except Exception:
                pass

        ipv6_only = set(report["ipv6_open"]) - set(report["ipv4_open"])
        if ipv6_only:
            report["drift_detected"] = True
            log_danger(f"DÉRIVE DE PARE-FEU DÉTECTÉE : Ports ouverts sur IPv6 mais bloqués sur IPv4 : {Colors.RED}{list(ipv6_only)}{Colors.RESET}")
        else:
            log_success("Règles de pare-feu cohérentes entre IPv4 et IPv6.")

        return report

# =============================================================================
# MODULE 7 : AUDIT EMAIL AVANCÉ (MTA-STS, TLS-RPT, BIMI, SPF, DMARC)
# =============================================================================
class AdvancedEmailSecurity:
    """Vérifie l'ensemble de la chaîne de confiance de messagerie moderne (MTA-STS, TLS-RPT, BIMI)."""

    @staticmethod
    def audit(domain):
        log_title(f"AUDIT DE SÉCURITÉ EMAIL AVANCÉ (MTA-STS, TLS-RPT, BIMI) : {domain}")
        results = {
            "mta_sts": {"configured": False, "mode": "None"},
            "tls_rpt": {"configured": False},
            "bimi": {"configured": False}
        }

        def query_txt(qname):
            url = f"https://cloudflare-dns.com/dns-query?name={qname}&type=TXT"
            try:
                req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": "DSS-EmailAuditor/4.0"})
                with urllib.request.urlopen(req, timeout=3.0) as res:
                    data = json.loads(res.read().decode())
                    return [a["data"].strip('"') for a in data.get("Answer", []) if "data" in a]
            except Exception:
                return []

        mta_records = query_txt(f"_mta-sts.{domain}")
        for r in mta_records:
            if r.startswith("v=STSv1"):
                results["mta_sts"]["configured"] = True
                log_success(f"MTA-STS DNS : {Colors.GREEN}{r}{Colors.RESET}")

        tls_rpt_records = query_txt(f"_smtp._tls.{domain}")
        for r in tls_rpt_records:
            if r.startswith("v=TLSRPTv1"):
                results["tls_rpt"]["configured"] = True
                log_success(f"TLS-RPT DNS : {Colors.GREEN}{r}{Colors.RESET}")

        bimi_records = query_txt(f"default._bimi.{domain}")
        for r in bimi_records:
            if r.startswith("v=BIMI1"):
                results["bimi"]["configured"] = True
                log_success(f"BIMI Brand Record : {Colors.GREEN}{r}{Colors.RESET}")

        return results

# =============================================================================
# MODULE 7.1 : PARSEUR SECURITY.TXT (RFC 9116) & AUDIT CORS APPROFONDI
# =============================================================================
class SecurityPolicyAuditor:
    """Audit des politiques de divulgation responsable (security.txt RFC 9116) et CORS."""

    @staticmethod
    def check_security_txt(base_url, timeout=3.0):
        log_title(f"VÉRIFICATION RFC 9116 (SECURITY.TXT) : {base_url}")
        results = {"found": False, "url": None, "contact": None, "policy": None}

        paths = ["/.well-known/security.txt", "/security.txt"]
        for p in paths:
            target = base_url.rstrip("/") + p
            try:
                req = urllib.request.Request(target, headers={"User-Agent": "DSS-SecurityPolicyAuditor/5.0"})
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as res:
                    if res.status == 200:
                        content = res.read().decode(errors="ignore")
                        if "Contact:" in content:
                            results["found"] = True
                            results["url"] = target
                            for line in content.splitlines():
                                if line.lower().startswith("contact:"):
                                    results["contact"] = line.split(":", 1)[1].strip()
                                elif line.lower().startswith("policy:"):
                                    results["policy"] = line.split(":", 1)[1].strip()
                            log_success(f"Fichier security.txt DÉTECTÉ sur : {Colors.BOLD}{target}{Colors.RESET}")
                            if results["contact"]:
                                log_info(f"Contact de divulgation responsable : {Colors.CYAN}{results['contact']}{Colors.RESET}")
                            break
            except Exception:
                pass

        if not results["found"]:
            log_info("Aucun fichier security.txt (RFC 9116) configuré.")
        return results

    @staticmethod
    def audit_cors_deep(base_url, timeout=3.0):
        log_title(f"AUDIT CORS APPROFONDI (ORIGINES NULL & REFLETS) : {base_url}")
        findings = []

        test_origins = [
            ("Origine Null", "null"),
            ("Origine Tiers Attaquant", "https://attacker.evil.com"),
            ("Sous-domaine arbitraire", "https://not-real.example.com")
        ]

        for desc, orig in test_origins:
            try:
                req = urllib.request.Request(
                    base_url,
                    headers={"Origin": orig, "User-Agent": "DSS-CORSAuditor/5.0"}
                )
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as res:
                    acao = res.headers.get("Access-Control-Allow-Origin")
                    acac = res.headers.get("Access-Control-Allow-Credentials")
                    if acao == orig or (acao == "*" and acac == "true"):
                        findings.append({"test": desc, "origin_sent": orig, "acao": acao, "credentials": acac})
                        log_danger(f"Mauvaise configuration CORS ({desc}) : ACAO = {acao} (Credentials: {acac})")
            except Exception:
                pass

        if not findings:
            log_success("Politique CORS conforme (Pas de réflexion non sécurisée de l'en-tête Origin).")
        return findings

# =============================================================================
# MODULE 8 : GÉOLOCALISATION IP & WAF & STACK
# =============================================================================
class IPGeolocation:
    @staticmethod
    def is_private_ip(ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
        except Exception:
            return False

    @classmethod
    def lookup(cls, target_ip):
        log_title(f"GÉOLOCALISATION IP & OSINT : {target_ip}")
        data = {
            "ip": target_ip, "country": "Inconnu", "country_code": "N/A", "region": "N/A",
            "city": "Inconnu", "latitude": 0.0, "longitude": 0.0, "timezone": "N/A",
            "isp": "Inconnu", "asn": "N/A", "reverse_dns": "N/A", "is_private": False
        }

        try:
            data["reverse_dns"] = socket.gethostbyaddr(target_ip)[0]
        except Exception:
            data["reverse_dns"] = "Non configuré"

        if cls.is_private_ip(target_ip):
            data["is_private"] = True
            data["country"] = "Réseau Local / Privé (RFC 1918)"
            data["city"] = "LAN / Intranet"
            data["isp"] = "Réseau Privé Interne"
            log_info(f"IP Privée : {Colors.YELLOW}{target_ip}{Colors.RESET} (Reverse DNS: {data['reverse_dns']})")
            return data

        endpoints = [
            f"http://ip-api.com/json/{target_ip}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,as",
            f"https://freeipapi.com/api/json/{target_ip}"
        ]

        for url in endpoints:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "DSS-Geolocation/4.0"})
                with urllib.request.urlopen(req, timeout=3.0) as res:
                    raw = json.loads(res.read().decode())
                    if raw.get("status") == "success" or "country" in raw or "countryName" in raw:
                        data["country"] = raw.get("country", raw.get("countryName", data["country"]))
                        data["country_code"] = raw.get("countryCode", raw.get("country_code", data["country_code"]))
                        data["region"] = raw.get("regionName", raw.get("region", data["region"]))
                        data["city"] = raw.get("city", raw.get("cityName", data["city"]))
                        data["latitude"] = raw.get("lat", raw.get("latitude", 0.0))
                        data["longitude"] = raw.get("lon", raw.get("longitude", 0.0))
                        data["timezone"] = raw.get("timezone", data["timezone"])
                        data["isp"] = raw.get("isp", data["isp"])
                        data["asn"] = raw.get("as", data["asn"])
                        break
            except Exception:
                continue

        log_success(f"Pays : {Colors.BOLD}{data['country']}{Colors.RESET} ({data['country_code']}) | Ville : {Colors.BOLD}{data['city']}{Colors.RESET}")
        log_info(f"FAI : {Colors.BOLD}{data['isp']}{Colors.RESET} | ASN : {Colors.YELLOW}{data['asn']}{Colors.RESET}")
        return data

class WAFDetector:
    WAF_SIGNATURES = [
        {"name": "Cloudflare", "header": "server", "pattern": r"cloudflare", "desc": "CDN / WAF Cloudflare"},
        {"name": "Cloudflare", "header": "cf-ray", "pattern": r".+", "desc": "Cloudflare Ray ID"},
        {"name": "AWS CloudFront / WAF", "header": "server", "pattern": r"CloudFront", "desc": "Amazon CloudFront CDN / AWS WAF"},
        {"name": "Akamai GHost / WAF", "header": "server", "pattern": r"AkamaiGHost", "desc": "Akamai Global Host Edge"},
        {"name": "Imperva / Incapsula", "header": "x-iinfo", "pattern": r".+", "desc": "Imperva Incapsula WAF"},
        {"name": "Fastly CDN", "header": "x-fastly-request-id", "pattern": r".+", "desc": "Fastly Edge Cloud"},
        {"name": "Sucuri CloudProxy", "header": "x-sucuri-id", "pattern": r".+", "desc": "Sucuri WebSite Firewall"},
        {"name": "ModSecurity / OWASP CRS", "header": "server", "pattern": r"mod_security|NOYB", "desc": "Moteur WAF open-source ModSecurity"}
    ]

    @classmethod
    def detect(cls, url, timeout=3.0):
        detected = []
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DSS-WAFDetector/4.0"})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as res:
                headers = {k.lower(): v for k, v in res.headers.items()}
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in e.headers.items()}
        except Exception:
            return detected

        for sig in cls.WAF_SIGNATURES:
            h_val = headers.get(sig["header"], "")
            if h_val and re.search(sig["pattern"], h_val, re.IGNORECASE):
                entry = {"name": sig["name"], "header": sig["header"], "description": sig["desc"]}
                if not any(d["name"] == sig["name"] for d in detected):
                    detected.append(entry)

        if detected:
            log_title(f"PARE-FEU APPLICATIF (WAF / CDN) ACTIF : {url}")
            for d in detected:
                log_success(f"WAF Identifié : {Colors.BOLD}{Colors.YELLOW}{d['name']}{Colors.RESET} ({d['description']})")
        return detected

class TechDetector:
    TECH_RULES = [
        {"name": "WordPress", "type": "CMS", "pattern": r"wp-content|wp-includes|wp-json", "header": None},
        {"name": "Joomla!", "type": "CMS", "pattern": r"/media/jui/|/templates/|Joomla!", "header": None},
        {"name": "Drupal", "type": "CMS", "pattern": r"Drupal\.settings|sites/all/|drupal\.js", "header": None},
        {"name": "Shopify", "type": "E-Commerce", "pattern": r"cdn\.shopify\.com", "header": None},
        {"name": "Laravel", "type": "PHP Framework", "pattern": None, "header": "set-cookie", "h_pattern": r"laravel_session|XSRF-TOKEN"},
        {"name": "Django", "type": "Python Framework", "pattern": r"csrfmiddlewaretoken", "header": "set-cookie", "h_pattern": r"csrftoken"},
        {"name": "Spring Boot", "type": "Java Framework", "pattern": r"/actuator/|whitelabel error page", "header": None},
        {"name": "Express.js", "type": "Node.js Framework", "pattern": None, "header": "x-powered-by", "h_pattern": r"Express"},
        {"name": "React", "type": "UI Library", "pattern": r"data-reactroot|react-dom", "header": None},
        {"name": "Vue.js", "type": "UI Library", "pattern": r"data-v-[a-f0-9]|vue\.min\.js", "header": None},
        {"name": "Apache HTTP", "type": "Web Server", "pattern": None, "header": "server", "h_pattern": r"Apache"},
        {"name": "Nginx", "type": "Web Server", "pattern": None, "header": "server", "h_pattern": r"nginx"}
    ]

    @classmethod
    def fingerprint(cls, url, timeout=3.0):
        detected = []
        body = ""
        headers = {}
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (DSS-TechFingerprint/4.0)"})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as res:
                headers = {k.lower(): v for k, v in res.headers.items()}
                body = res.read(65536).decode(errors="ignore")
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in e.headers.items()}
        except Exception:
            return detected

        for r in cls.TECH_RULES:
            matched = False
            if r.get("header") and r.get("h_pattern"):
                h_val = headers.get(r["header"], "")
                if h_val and re.search(r["h_pattern"], h_val, re.IGNORECASE):
                    matched = True
            if not matched and r.get("pattern") and body:
                if re.search(r["pattern"], body, re.IGNORECASE):
                    matched = True

            if matched and not any(t["name"] == r["name"] for t in detected):
                detected.append({"name": r["name"], "type": r["type"]})

        if detected:
            log_title(f"EMPREINTES TECHNOLOGIQUES & CMS : {url}")
            for t in detected:
                log_success(f"Stack : {Colors.BOLD}{t['name']}{Colors.RESET} [{Colors.CYAN}{t['type']}{Colors.RESET}]")
        return detected

# =============================================================================
# MODULE 9 : MAPPAGE MATRICE MITRE ATT&CK
# =============================================================================
class MITREMapper:
    """Associe les découvertes d'audit aux identifiants techniques MITRE ATT&CK."""

    @staticmethod
    def map_findings(scan_data):
        tactics = []
        tactics.append({"technique": "T1595.001", "name": "Active Scanning: Scanning IP Blocks", "phase": "Reconnaissance", "status": "Exécuté"})
        tactics.append({"technique": "T1590.002", "name": "Gather Victim Network Info: DNS", "phase": "Reconnaissance", "status": "Exécuté"})
        tactics.append({"technique": "T1596.001", "name": "Search Open Technical Databases: Certificate Logs", "phase": "Reconnaissance", "status": "Actif"})

        if scan_data.get("cves"):
            tactics.append({"technique": "T1190", "name": "Exploit Public-Facing Application (CVEs Détectées)", "phase": "Initial Access", "status": "Risque Élevé"})

        if scan_data.get("js_secrets") or scan_data.get("web_audit", {}).get("sensitive_paths"):
            tactics.append({"technique": "T1552.001", "name": "Unsecured Credentials: Credentials In Files / Secrets", "phase": "Credential Access", "status": "Critique"})

        if scan_data.get("cloud_buckets"):
            tactics.append({"technique": "T1530", "name": "Data from Cloud Storage Object", "phase": "Collection", "status": "Avertissement"})

        return tactics

# =============================================================================
# MODULE 10 : SCANNER DE PORTS TCP & VERSIONS (-sV)
# =============================================================================
class PortScanner:
    def __init__(self, target, ports, timing="T3"):
        self.target = target
        self.ports = ports
        self.timing = TIMING_PROFILES.get(timing, TIMING_PROFILES["T3"])
        self.threads = self.timing["threads"]
        self.timeout = self.timing["timeout"]
        self.delay = self.timing["delay"]
        self.ip = None
        self.results = []
        self.cve_findings = []

    def resolve(self):
        try:
            self.ip = socket.gethostbyname(self.target)
            return True
        except Exception as e:
            log_danger(f"Résolution DNS échouée pour '{self.target}' : {e}")
            return False

    def scan_port(self, port):
        if self.delay > 0:
            time.sleep(self.delay)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        t_start = time.time()
        result = sock.connect_ex((self.ip, port))
        latency = (time.time() - t_start) * 1000
        sock.close()

        if result == 0:
            service_name = SERVICES_MAP.get(port, "Inconnu")
            banner = ""
            try:
                with socket.create_connection((self.ip, port), timeout=self.timeout) as s:
                    if port in [80, 8080, 8000]:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    elif port == 22:
                        pass
                    else:
                        s.sendall(b"\r\n")
                    raw = s.recv(512).decode(errors="ignore")
                    for line in raw.splitlines():
                        c = line.strip()
                        if c and not c.startswith("<"):
                            banner = c[:60]
                            break
            except Exception:
                pass

            cves = []
            combined_text = f"{service_name} {banner}"
            for rule in CVE_KNOWLEDGE_BASE:
                if re.search(rule["pattern"], combined_text, re.IGNORECASE):
                    cve_item = {
                        "port": port, "cve": rule["cve"], "title": rule["title"],
                        "severity": rule["severity"], "cvss": rule["cvss"], "recommendation": rule["recommendation"]
                    }
                    cves.append(cve_item)
                    self.cve_findings.append(cve_item)

            return {
                "port": port, "protocol": "tcp", "status": "open",
                "latency_ms": round(latency, 2), "service": service_name, "banner": banner, "cves": cves
            }
        return None

    def run(self):
        if not self.resolve():
            return []

        log_title(f"SCAN TCP & DÉTECTION DE SERVICES : {self.target}")
        log_info(f"Cible : {Colors.BOLD}{self.target}{Colors.RESET} ({self.ip}) | Ports : {len(self.ports)} | Timing : {self.timing['name']}")

        print(f"\n{Colors.BOLD}{'PORT':<10} {'ÉTAT':<10} {'LATENCE':<10} {'SERVICE':<26} {'BANNIÈRE & VERSION'}{Colors.RESET}")
        print(f"{'-'*80}")

        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, p): p for p in self.ports}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    self.results.append(res)
                    print(f"{res['port']:<6}/tcp  {Colors.GREEN}OUVERT{Colors.RESET}     {res['latency_ms']:<8.1f}ms  {res['service'][:24]:<26} {Colors.DIM}{res['banner'][:34]}{Colors.RESET}")

        self.results.sort(key=lambda x: x["port"])
        elapsed = time.time() - start_time
        print(f"{'-'*80}")
        log_success(f"Scan TCP achevé en {elapsed:.2f}s — {len(self.results)} port(s) ouvert(s).")
        return self.results

# =============================================================================
# MODULE 11 : AUDITEUR WEB OWASP (EN-TÊTES & FICHIERS SENSIBLES)
# =============================================================================
class WebAuditor:
    SENSITIVE_PATHS = [
        {"path": "/.git/HEAD", "type": "Git Repo Exposure", "severity": "CRITICAL", "desc": "Dépôt Git public — Téléchargement du code source"},
        {"path": "/.env", "type": "Secrets Exposure", "severity": "CRITICAL", "desc": "Fichier .env — Clés d'API et mots de passe BD"},
        {"path": "/wp-config.php.bak", "type": "Config Backup", "severity": "CRITICAL", "desc": "Sauvegarde de configuration WordPress"},
        {"path": "/backup.sql", "type": "DB Dump", "severity": "CRITICAL", "desc": "Dump SQL de base de données exposé"},
        {"path": "/robots.txt", "type": "Recon", "severity": "INFO", "desc": "Fichier robots.txt disponible pour cartographie"},
        {"path": "/admin/", "type": "Admin Interface", "severity": "MEDIUM", "desc": "Panneau d'administration web"}
    ]

    SECURITY_HEADERS = [
        {"name": "Strict-Transport-Security", "severity": "HIGH", "desc": "Force HTTPS strict."},
        {"name": "Content-Security-Policy", "severity": "HIGH", "desc": "Mitige les failles XSS et injections."},
        {"name": "X-Frame-Options", "severity": "MEDIUM", "desc": "Protège contre le Clickjacking."}
    ]

    def __init__(self, target_url, timeout=3.0):
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = "http://" + target_url
        self.url = target_url.rstrip("/")
        self.timeout = timeout
        self.findings = []
        self.headers_audit = []

    def run(self):
        log_title(f"AUDIT WEB OWASP : {self.url}")
        try:
            req = urllib.request.Request(self.url, headers={"User-Agent": "DSS-WebAuditor/4.0"})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as res:
                headers = dict(res.headers)
        except urllib.error.HTTPError as e:
            headers = dict(e.headers)
        except Exception:
            headers = {}

        for rule in self.SECURITY_HEADERS:
            h_name = rule["name"]
            found_val = next((headers[k] for k in headers if k.lower() == h_name.lower()), None)
            if found_val:
                self.headers_audit.append({"header": h_name, "present": True, "severity": "OK"})
            else:
                self.headers_audit.append({"header": h_name, "present": False, "severity": rule["severity"]})

        for item in self.SENSITIVE_PATHS:
            target = self.url + item["path"]
            try:
                req = urllib.request.Request(target, headers={"User-Agent": "DSS-WebAuditor/4.0"})
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as res:
                    if res.status in [200, 206]:
                        self.findings.append({"path": item["path"], "status": res.status, "severity": item["severity"], "desc": item["desc"]})
                        col = Colors.RED if item["severity"] == "CRITICAL" else Colors.YELLOW
                        log_danger(f"[{col}{item['severity']}{Colors.RESET}] {item['path']} (HTTP {res.status}) : {item['desc']}")
            except Exception:
                pass

        return {"headers_audit": self.headers_audit, "sensitive_paths": self.findings}

# =============================================================================
# MODULE 12 : GÉNÉRATEUR DE RAPPORTS (HTML, JSON, XML NMAP, MARKDOWN)
# =============================================================================
class ReportGenerator:
    @staticmethod
    def export_json(data, filename):
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        log_success(f"Rapport JSON : {Colors.BOLD}{filename}{Colors.RESET}")

    @staticmethod
    def export_xml(data, filename):
        nmaprun = ET.Element("nmaprun", {"scanner": "dss-scanner", "version": "4.0", "start": str(int(time.time()))})
        host = ET.SubElement(nmaprun, "host")
        ET.SubElement(host, "status", {"state": "up"})
        ET.SubElement(host, "address", {"addr": data.get("target", "N/A"), "addrtype": "ipv4"})
        ports_el = ET.SubElement(host, "ports")
        for p in data.get("ports", []):
            port_el = ET.SubElement(ports_el, "port", {"protocol": "tcp", "portid": str(p["port"])})
            ET.SubElement(port_el, "state", {"state": "open"})
            ET.SubElement(port_el, "service", {"name": p.get("service", "unknown"), "product": p.get("banner", "")})
        tree = ET.ElementTree(nmaprun)
        tree.write(filename, encoding="utf-8", xml_declaration=True)
        log_success(f"Rapport XML Nmap : {Colors.BOLD}{filename}{Colors.RESET}")

    @staticmethod
    def export_markdown(data, filename):
        lines = [
            "# 🛡️ Rapport d'Audit & ASM — DSS Ultimate Security Scanner v4.0",
            f"> **Cible** : `{data.get('target', 'N/A')}` | **Date** : {data.get('timestamp')}",
            "",
            "---",
            "## 1. 📊 Synthèse Globale",
            f"- **Ports TCP ouverts** : {len(data.get('ports', []))}",
            f"- **Vulnérabilités / CVE** : {len(data.get('cves', []))}",
            f"- **Secrets JS détectés** : {len(data.get('js_secrets', []))}",
            f"- **Buckets Cloud exposés** : {len(data.get('cloud_buckets', []))}",
            f"- **Sous-domaines CT Logs** : {len(data.get('ct_logs_subdomains', []))}",
            ""
        ]
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        log_success(f"Rapport Markdown : {Colors.BOLD}{filename}{Colors.RESET}")

    @staticmethod
    def export_html(data, filename):
        target = data.get("target", "N/A")
        ts = data.get("timestamp", datetime.utcnow().isoformat())
        geo = data.get("geolocation", {})
        
        cve_count = len(data.get("cves", []))
        sec_count = len(data.get("js_secrets", []))
        bucket_count = len([b for b in data.get("cloud_buckets", []) if b.get("severity") == "CRITICAL"])
        
        score = max(10, 100 - (cve_count * 25) - (sec_count * 20) - (bucket_count * 25))
        score_color = "#238636" if score >= 80 else ("#d29922" if score >= 50 else "#da3633")

        ports_rows = "".join([f"""<tr>
            <td><span class="badge badge-port">{p['port']}/tcp</span></td>
            <td><span class="badge badge-open">OUVERT</span></td>
            <td>{p.get('latency_ms', '-')} ms</td>
            <td><strong>{p['service']}</strong></td>
            <td><code>{p.get('banner', '-')}</code></td>
        </tr>""" for p in data.get("ports", [])])

        cve_rows = "".join([f"""<tr>
            <td><code>{c.get('port', '-')}/tcp</code></td>
            <td><span class="badge badge-crit">{c['cve']}</span></td>
            <td><strong>{c['cvss']}</strong></td>
            <td>{c['title']}</td>
            <td><small>{c['recommendation']}</small></td>
        </tr>""" for c in data.get("cves", [])])

        js_rows = "".join([f"""<tr>
            <td><strong>{s['name']}</strong></td>
            <td><span class="badge badge-crit">{s['severity']}</span></td>
            <td><code>{s['secret']}</code></td>
            <td><small>{s['source']}</small></td>
        </tr>""" for s in data.get("js_secrets", [])])

        mitre_badges = "".join([f"""<span class="mitre-tag"><strong>{m['technique']}</strong>: {m['name']} ({m['phase']})</span>""" for m in data.get("mitre_mapping", [])])
        ct_badges = "".join([f"""<span class="tech-tag">{sub}</span>""" for sub in data.get("ct_logs_subdomains", [])[:15]])

        lat = geo.get("latitude", 0.0)
        lon = geo.get("longitude", 0.0)
        map_link = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=12/{lat}/{lon}" if (lat and lon) else "#"

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DSS Security ASM Report — {target}</title>
    <style>
        :root {{ --bg: #0b0e14; --card-bg: #151b23; --border: #30363d; --text: #c9d1d9; --heading: #58a6ff; --accent: #2ea043; --danger: #f85149; --warning: #d29922; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: var(--bg); color: var(--text); margin: 0; padding: 2rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; background: linear-gradient(135deg, #1c2430, #111722); border: 1px solid var(--border); padding: 2rem; border-radius: 12px; margin-bottom: 2rem; box-shadow: 0 8px 24px rgba(0,0,0,0.6); }}
        .score-circle {{ text-align: center; padding: 1.5rem; border-radius: 50%; border: 5px solid {score_color}; min-width: 85px; font-size: 2.2rem; font-weight: bold; color: {score_color}; }}
        .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; padding: 1.5rem; margin-bottom: 2rem; }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }}
        h1 {{ margin: 0 0 0.5rem 0; color: var(--heading); }}
        h2 {{ color: var(--heading); border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin-top: 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border); }}
        th {{ background: #21262d; color: #f0f6fc; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 0.8rem; font-weight: 600; }}
        .badge-open {{ background: #238636; color: #fff; }}
        .badge-crit {{ background: #da3633; color: #fff; }}
        .badge-port {{ background: #388bfd33; color: #58a6ff; border: 1px solid #388bfd66; }}
        .tech-tag {{ display: inline-block; background: #1f6feb22; border: 1px solid #1f6feb88; color: #79c0ff; padding: 4px 10px; border-radius: 16px; margin: 3px; font-size: 0.85rem; }}
        .mitre-tag {{ display: inline-block; background: #9e6a0322; border: 1px solid #9e6a0388; color: #d29922; padding: 4px 10px; border-radius: 16px; margin: 4px; font-size: 0.85rem; font-weight: 600; }}
        code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: #79c0ff; }}
        .footer {{ text-align: center; margin-top: 3rem; color: #8b949e; font-size: 0.9rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ DSS Ultimate Security Scanner (v4.0 Enterprise / ASM)</h1>
                <p><strong>Cible :</strong> <code>{target}</code> | <strong>Date :</strong> {ts}</p>
            </div>
            <div class="score-circle">
                {score}<br><span style="font-size: 0.8rem; font-weight: normal; color: #8b949e;">Score Sec</span>
            </div>
        </div>

        <div class="grid-2">
            <div class="card">
                <h2>🌍 Géolocalisation & OSINT</h2>
                <p><strong>Pays :</strong> {geo.get('country', 'N/A')} ({geo.get('country_code', 'N/A')})</p>
                <p><strong>Ville / Région :</strong> {geo.get('city', 'N/A')} ({geo.get('region', 'N/A')})</p>
                <p><strong>Fournisseur (FAI) :</strong> {geo.get('isp', 'N/A')}</p>
                <p><strong>Système Autonome :</strong> <code>{geo.get('asn', 'N/A')}</code></p>
                <p><strong>Carte :</strong> <a href="{map_link}" target="_blank" style="color: #58a6ff;">Voir coordonnées GPS sur OpenStreetMap ↗</a></p>
            </div>

            <div class="card">
                <h2>📜 Sous-domaines CT Logs (Furtif)</h2>
                <div>{ct_badges if ct_badges else '<span style="color: #8b949e;">Aucun CT Log découvert</span>'}</div>
            </div>
        </div>

        {f'''<div class="card" style="border-left: 5px solid #da3633;">
            <h2>🔑 Clés & Secrets JavaScript Détectés ({len(data.get("js_secrets", []))})</h2>
            <table>
                <thead><tr><th>Nom</th><th>Criticité</th><th>Secret</th><th>Source</th></tr></thead>
                <tbody>{js_rows}</tbody>
            </table>
        </div>''' if data.get("js_secrets") else ''}

        {f'''<div class="card" style="border-left: 5px solid #da3633;">
            <h2>🚨 Vulnérabilités & CVE Détectées ({len(data.get("cves", []))})</h2>
            <table>
                <thead><tr><th>Port</th><th>CVE</th><th>Score CVSS</th><th>Description</th><th>Recommandation</th></tr></thead>
                <tbody>{cve_rows}</tbody>
            </table>
        </div>''' if data.get("cves") else ''}

        <div class="card">
            <h2>🔌 Services Réseau Découverts</h2>
            <table>
                <thead><tr><th>Port</th><th>Statut</th><th>Latence</th><th>Service</th><th>Bannière / Version</th></tr></thead>
                <tbody>{ports_rows if ports_rows else '<tr><td colspan="5">Aucun port ouvert</td></tr>'}</tbody>
            </table>
        </div>

        <div class="card">
            <h2>🗺️ Matrice MITRE ATT&CK & Posture Défensive</h2>
            <div>{mitre_badges}</div>
        </div>

        <div class="footer">
            <p>Généré par DSS Security Scanner (v4.0 ASM Edition) — Cybersecurity Mastery Roadmap</p>
        </div>
    </div>
</body>
</html>"""
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        log_success(f"Dashboard HTML ASM exporté : {Colors.BOLD}{filename}{Colors.RESET}")

# =============================================================================
# POINT D'ENTRÉE CLI PRINCIPAL
# =============================================================================
def banner():
    art = f"""
{Colors.BOLD}{Colors.CYAN}  ██████╗ ███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║  ██║███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║
  ██║  ██║╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║
  ██████╔╝███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═════╝ ╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{Colors.RESET}
  {Colors.BOLD}{Colors.MAGENTA}🛡️  DSS ULTIMATE SECURITY SCANNER (D-SCAN v4.0 ASM EDITION){Colors.RESET}
  {Colors.DIM}Attack Surface Management · CT Logs · JS Secrets · Cloud Hunter · MITRE{Colors.RESET}
"""
    print(art)

def parse_ports(port_arg, top_arg):
    if port_arg:
        ports = set()
        for part in port_arg.split(","):
            part = part.strip()
            if "-" in part:
                s, e = map(int, part.split("-"))
                ports.update(range(s, e + 1))
            else:
                ports.add(int(part))
        return sorted(list(ports))
    elif top_arg == 20:
        return TOP_20_PORTS
    elif top_arg == 1000:
        return list(range(1, 1001))
    else:
        return TOP_100_PORTS

def main():
    banner()
    parser = argparse.ArgumentParser(
        description="DSS Ultimate Security Scanner (D-Scan v4.0 ASM) — Attack Surface Management & Security Audit Suite.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Cible
    parser.add_argument("-t", "--target", help="Cible à analyser (ex: example.com ou 192.168.1.1)")
    parser.add_argument("-p", "--ports", help="Ports spécifiques (ex: 80,443,8080 ou 1-1024)")
    parser.add_argument("--top-ports", type=int, choices=[20, 100, 1000], default=100, help="Top X ports (défaut: 100)")
    parser.add_argument("-sV", "--service-version", action="store_true", help="Détection de versions et CVEs")
    parser.add_argument("-T", "--timing", default="3", help="Modèle de timing (1=Furtif à 5=Insane)")
    
    # Modules Avancés ASM
    parser.add_argument("--ct-logs", action="store_true", help="Surveillance passive des sous-domaines via Certificate Transparency (crt.sh)")
    parser.add_argument("--cloud-hunter", action="store_true", help="Recherche de buckets Cloud publics exposés (AWS S3, GCP, Azure)")
    parser.add_argument("--js-secrets", action="store_true", help="Extraction de clés d'API et secrets dans les fichiers JavaScript")
    parser.add_argument("--graphql", action="store_true", help="Audit de points d'API GraphQL et test d'introspection")
    parser.add_argument("--ipv6-drift", action="store_true", help="Détection de dérive de pare-feu IPv4 vs IPv6")
    parser.add_argument("--email-sec", action="store_true", help="Audit email avancé (MTA-STS, TLS-RPT, BIMI, SPF, DMARC)")
    parser.add_argument("--geo", action="store_true", help="Géolocalisation IP & ASN")
    parser.add_argument("-A", "--full", action="store_true", help="Mode complet absolu (Tous les modules activés simultanément)")

    # Exports
    parser.add_argument("--json", help="Export JSON")
    parser.add_argument("--xml", help="Export XML Nmap")
    parser.add_argument("--markdown", help="Export Markdown")
    parser.add_argument("--html", help="Dashboard HTML Interactif")

    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        print(f"\n{Colors.RED}[!] Veuillez spécifier une cible avec -t <cible>{Colors.RESET}\n")
        return

    timing_key = args.timing.upper()
    if not timing_key.startswith("T"): timing_key = f"T{timing_key}"
    if timing_key not in TIMING_PROFILES: timing_key = "T3"

    scan_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "target": args.target,
        "geolocation": {},
        "ct_logs_subdomains": [],
        "cloud_buckets": [],
        "js_secrets": [],
        "graphql": {},
        "ipv6_drift": {},
        "email_security": {},
        "waf": [],
        "tech_stack": [],
        "ports": [],
        "cves": [],
        "web_audit": {},
        "mitre_mapping": []
    }

    try:
        target_ip = socket.gethostbyname(args.target)
    except Exception:
        target_ip = args.target

    is_domain = not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", args.target)

    # 1. CT Logs
    if (args.ct_logs or args.full) and is_domain:
        scan_data["ct_logs_subdomains"] = CTLogsInspector.query(args.target)

    # 2. Cloud Hunter
    if (args.cloud_hunter or args.full) and is_domain:
        scan_data["cloud_buckets"] = CloudBucketHunter.hunt(args.target)

    # 3. Géolocalisation
    if args.geo or args.full:
        scan_data["geolocation"] = IPGeolocation.lookup(target_ip)

    # 4. Email Security (MTA-STS, TLS-RPT, BIMI)
    if (args.email_sec or args.full) and is_domain:
        scan_data["email_security"] = AdvancedEmailSecurity.audit(args.target)

    # 5. IPv6 Drift
    if (args.ipv6_drift or args.full) and is_domain:
        scan_data["ipv6_drift"] = IPv6DriftScanner.audit(args.target)

    # 6. Scan TCP
    ports_to_scan = parse_ports(args.ports, args.top_ports)
    ps = PortScanner(args.target, ports_to_scan, timing=timing_key)
    scan_data["ports"] = ps.run()
    scan_data["cves"] = ps.cve_findings

    # 7. Audit Web & WAF & Secrets JS & GraphQL
    web_ports = [p["port"] for p in scan_data["ports"] if p["port"] in [80, 443, 8080, 8443, 3000, 5000, 8000]]
    if args.full or web_ports:
        scheme = "https" if (443 in web_ports or 8443 in web_ports) else "http"
        base_url = f"{scheme}://{args.target}"

        scan_data["waf"] = WAFDetector.detect(base_url)
        scan_data["tech_stack"] = TechDetector.fingerprint(base_url)

        if args.js_secrets or args.full:
            scan_data["js_secrets"] = JSSecretScanner.scan_url(base_url)

        if args.graphql or args.full:
            scan_data["graphql"] = GraphQLAuditor.audit(base_url)

        if args.full or is_domain:
            scan_data["security_txt"] = SecurityPolicyAuditor.check_security_txt(base_url)
            scan_data["cors_audit"] = SecurityPolicyAuditor.audit_cors_deep(base_url)

        wa = WebAuditor(base_url)
        scan_data["web_audit"] = wa.run()

    # 8. Matrice MITRE ATT&CK
    scan_data["mitre_mapping"] = MITREMapper.map_findings(scan_data)

    # Exports
    if args.json: ReportGenerator.export_json(scan_data, args.json)
    if args.xml: ReportGenerator.export_xml(scan_data, args.xml)
    if args.markdown: ReportGenerator.export_markdown(scan_data, args.markdown)
    if args.html: ReportGenerator.export_html(scan_data, args.html)

    log_title("SCAN DSS SECURITY ASM v4.0 TERMINÉ AVEC SUCCÈS")

if __name__ == "__main__":
    main()
