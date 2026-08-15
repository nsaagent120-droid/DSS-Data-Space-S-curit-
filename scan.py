#!/usr/bin/env python3
"""
=============================================================================
  DSS Ultimate Security Scanner (D-Scan v3.0) — Suite Tout-en-Un d'Audit
=============================================================================
  Auteur      : DSS Security / Cybersecurity Mastery Roadmap
  Description : Alternative ultra-puissante à Nmap, Nikto, SSLyze et WhatWeb :
                - Scan TCP & UDP multi-threadé avec timing T1-T5
                - Détection de versions (-sV) et corrélation automatique CVE/CVSS
                - Géolocalisation IP, ASN, FAI & Reverse DNS
                - Détection de WAF (Cloudflare, AWS, Akamai, Imperva, ModSec...)
                - Fingerprinting de CMS & Technologies Web (Wappalyzer-like)
                - Audit DNS & Sécurité Email (SPF, DMARC, MX, NS)
                - Inspection SSL/TLS, suites de chiffrement et découverte SAN
                - Découverte d'hôtes (Ping sweep) & Traceroute TCP/IP
                - Rapports avancés : Dashboard HTML interactif (avec carte OSM),
                  XML compatible Nmap (-oX), JSON et Markdown.
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
    BG_RED      = "\033[41m"
    BG_GREEN    = "\033[42m"
    BG_BLUE     = "\033[44m"
    BG_MAGENTA  = "\033[45m"

def log_info(msg):
    print(f"[{Colors.CYAN}*{Colors.RESET}] {msg}")

def log_success(msg):
    print(f"[{Colors.GREEN}+{Colors.RESET}] {msg}")

def log_warning(msg):
    print(f"[{Colors.YELLOW}!{Colors.RESET}] {msg}")

def log_danger(msg):
    print(f"[{Colors.RED}-{Colors.RESET}] {msg}")

def log_title(msg):
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}  {msg}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}\n")

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

# =============================================================================
# BASE DE DONNÉES DES PORTS & SERVICES CONNUS
# =============================================================================
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
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Non-chiffré)",
    25: "SMTP (Mail Transfer)",
    53: "DNS (Domain Name System)",
    69: "TFTP",
    80: "HTTP (World Wide Web)",
    110: "POP3 (Post Office Protocol)",
    111: "RPCBind",
    123: "NTP (Network Time Protocol)",
    135: "MSRPC (Microsoft RPC)",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP (Mail Access)",
    161: "SNMP (Simple Network Mgmt)",
    389: "LDAP (Directory Service)",
    443: "HTTPS (TLS/SSL Secure Web)",
    445: "SMB / Microsoft-DS",
    465: "SMTPS (SMTP over SSL)",
    514: "Syslog",
    587: "SMTP Submission",
    636: "LDAPS (LDAP over SSL)",
    873: "Rsync",
    993: "IMAPS (IMAP over SSL)",
    995: "POP3S (POP3 over SSL)",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    1900: "UPnP (SSDP Discovery)",
    2049: "NFS (Network File System)",
    2181: "Apache ZooKeeper",
    2222: "SSH Alternatif",
    2375: "Docker Daemon (Insecure)",
    2376: "Docker Daemon (TLS)",
    3000: "Node.js / React / Grafana Dev",
    3306: "MySQL / MariaDB Database",
    3389: "RDP (Remote Desktop Protocol)",
    4000: "Hexo / Web Dev Server",
    4444: "Metasploit / Selenium / Listener",
    5000: "Flask / Docker Registry / UPnP",
    5060: "SIP (VoIP)",
    5353: "mDNS (Multicast DNS)",
    5432: "PostgreSQL Database",
    5672: "RabbitMQ AMQP",
    5900: "VNC Remote Desktop",
    5984: "CouchDB",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
    6379: "Redis In-Memory Key-Value",
    7001: "Oracle WebLogic",
    8000: "HTTP Dev (Django/Python)",
    8080: "HTTP Proxy / Tomcat / Spring",
    8443: "HTTPS Alternatif / Plesk",
    8888: "Jupyter Notebook / Web Admin",
    9000: "PHP-FPM / SonarQube / MinIO",
    9090: "Prometheus / Cockpit Web UI",
    9092: "Apache Kafka",
    9200: "Elasticsearch REST API",
    9300: "Elasticsearch Cluster",
    10000: "Webmin / Virtualmin",
    11211: "Memcached Database",
    15672: "RabbitMQ Management UI",
    27017: "MongoDB NoSQL Database",
    27018: "MongoDB Shard",
    28017: "MongoDB Web Status"
}

# Base de connaissances CVE
CVE_KNOWLEDGE_BASE = [
    {
        "pattern": r"OpenSSH_([1-6]\.|7\.[0-6])",
        "service": "OpenSSH",
        "cve": "CVE-2016-0777 / CVE-2018-15473",
        "title": "Version OpenSSH obsolète vulnérable à la fuite de clés ou énumération d'utilisateurs",
        "severity": "HIGH",
        "cvss": 7.5,
        "recommendation": "Mettre à jour vers OpenSSH >= 8.9+ et désactiver l'authentification par mot de passe."
    },
    {
        "pattern": r"Apache/(2\.[0-3]\.|2\.4\.[0-9]\b|2\.4\.[1-4][0-9]\b|2\.4\.50\b|2\.4\.49\b)",
        "service": "Apache HTTP Server",
        "cve": "CVE-2021-41773 / CVE-2021-42013",
        "title": "Apache HTTPD vulnérable aux traversées de répertoires / RCE",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "recommendation": "Mettre à jour Apache HTTPD vers la dernière version stable (>= 2.4.58+)."
    },
    {
        "pattern": r"nginx/(0\.|1\.[0-9]\.|1\.1[0-8]\.)",
        "service": "Nginx",
        "cve": "CVE-2021-23017 / CVE-2017-7529",
        "title": "Version Nginx vulnérable aux dépassements d'entiers dans le resolver DNS",
        "severity": "HIGH",
        "cvss": 7.7,
        "recommendation": "Mettre à jour Nginx vers la version stable récente (>= 1.24+)."
    },
    {
        "pattern": r"PHP/(5\.|7\.[0-3]\.)",
        "service": "PHP",
        "cve": "CVE-2019-11043 / EOL",
        "title": "Version PHP obsolète et en fin de vie (End of Life)",
        "severity": "HIGH",
        "cvss": 8.1,
        "recommendation": "Migrer immédiatement vers PHP 8.1, 8.2 ou 8.3 supporté."
    },
    {
        "pattern": r"vsftpd 2\.3\.4",
        "service": "vsftpd",
        "cve": "CVE-2011-2523",
        "title": "vsftpd 2.3.4 Backdoor Smiley Face",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "recommendation": "Supprimer vsftpd 2.3.4 et installer vsftpd >= 3.0.5."
    },
    {
        "pattern": r"ProFTPD 1\.3\.[35]",
        "service": "ProFTPD",
        "cve": "CVE-2015-3306",
        "title": "ProFTPD mod_copy Arbitrary File Copy & RCE",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "recommendation": "Mettre à jour ProFTPD vers la dernière version stable."
    },
    {
        "pattern": r"Redis.*([1-5]\.)",
        "service": "Redis",
        "cve": "CVE-2022-0543",
        "title": "Redis Lua Sandbox Escape & Remote Code Execution",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "recommendation": "Mettre à jour Redis vers >= 6.2.7 ou 7.0+, lier sur 127.0.0.1 et exiger un mot de passe fort."
    },
    {
        "pattern": r"Samba 3\.|Samba 4\.[0-9]\.",
        "service": "Samba",
        "cve": "CVE-2017-7494 (SambaCry)",
        "title": "SambaCry Remote Code Execution via shared library upload",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "recommendation": "Mettre à jour Samba vers une version maintenue."
    }
]

# =============================================================================
# MODULE 1 : GÉOLOCALISATION IP, ASN & RENSEIGNEMENT RÉSEAU (OSINT)
# =============================================================================
class IPGeolocation:
    """Géolocalisation IP, résolution ASN, Fournisseur d'accès (FAI) et métadonnées géographiques."""

    @staticmethod
    def is_private_ip(ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
        except Exception:
            return False

    @classmethod
    def lookup(cls, target_ip):
        log_title(f"GÉOLOCALISATION IP & RENSEIGNEMENT RÉSEAU : {target_ip}")
        data = {
            "ip": target_ip,
            "country": "Inconnu",
            "country_code": "N/A",
            "region": "N/A",
            "city": "Inconnu",
            "postal": "N/A",
            "latitude": 0.0,
            "longitude": 0.0,
            "timezone": "N/A",
            "isp": "Inconnu",
            "asn": "N/A",
            "org": "Inconnu",
            "reverse_dns": "N/A",
            "is_private": False,
            "status": "success"
        }

        # Reverse DNS lookup
        try:
            rdns = socket.gethostbyaddr(target_ip)[0]
            data["reverse_dns"] = rdns
        except Exception:
            data["reverse_dns"] = "Non configuré / Timeout"

        # Vérification IP privée / RFC 1918
        if cls.is_private_ip(target_ip):
            data["is_private"] = True
            data["country"] = "Réseau Local / Privé (RFC 1918)"
            data["city"] = "LAN / Intranet"
            data["isp"] = "Réseau Privé Interne"
            data["org"] = "Réseau Privé Interne"
            log_info(f"Adresse IP privée / locale détectée : {Colors.YELLOW}{target_ip}{Colors.RESET}")
            log_info(f"Reverse DNS : {Colors.CYAN}{data['reverse_dns']}{Colors.RESET}")
            return data

        # Interrogation des services d'information géographique (multi-fournisseurs)
        endpoints = [
            f"http://ip-api.com/json/{target_ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as",
            f"https://freeipapi.com/api/json/{target_ip}",
            f"https://ipwhois.app/json/{target_ip}"
        ]

        for url in endpoints:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "DSS-Security-Geolocation/3.0"})
                with urllib.request.urlopen(req, timeout=3.5) as res:
                    raw = json.loads(res.read().decode())
                    if raw.get("status") == "success" or "country" in raw or "countryName" in raw:
                        data["country"] = raw.get("country", raw.get("countryName", data["country"]))
                        data["country_code"] = raw.get("countryCode", raw.get("country_code", data["country_code"]))
                        data["region"] = raw.get("regionName", raw.get("region", data["region"]))
                        data["city"] = raw.get("city", raw.get("cityName", data["city"]))
                        data["postal"] = raw.get("zip", raw.get("zipCode", data["postal"]))
                        data["latitude"] = raw.get("lat", raw.get("latitude", 0.0))
                        data["longitude"] = raw.get("lon", raw.get("longitude", 0.0))
                        data["timezone"] = raw.get("timezone", raw.get("timeZone", data["timezone"]))
                        data["isp"] = raw.get("isp", raw.get("ispName", data["isp"]))
                        data["org"] = raw.get("org", raw.get("organisation", data["org"]))
                        data["asn"] = raw.get("as", raw.get("asn", data["asn"]))
                        break
            except Exception:
                continue

        # Affichage clair et structuré
        log_success(f"Pays : {Colors.BOLD}{data['country']}{Colors.RESET} ({data['country_code']}) | Ville : {Colors.BOLD}{data['city']}{Colors.RESET} ({data['region']})")
        log_info(f"Coordonnées GPS : {Colors.CYAN}{data['latitude']}, {data['longitude']}{Colors.RESET} | Fuseau : {data['timezone']}")
        log_info(f"Fournisseur (FAI) : {Colors.BOLD}{data['isp']}{Colors.RESET} | Org : {data['org']}")
        log_info(f"Système Autonome (ASN) : {Colors.YELLOW}{data['asn']}{Colors.RESET}")
        log_info(f"Reverse DNS (PTR) : {Colors.CYAN}{data['reverse_dns']}{Colors.RESET}")

        return data

# =============================================================================
# MODULE 2 : DÉTECTION DE WAF (WEB APPLICATION FIREWALL) & CDN
# =============================================================================
class WAFDetector:
    """Détecteur d'empreintes de WAF (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity...)."""

    WAF_SIGNATURES = [
        {"name": "Cloudflare", "header": "server", "pattern": r"cloudflare", "desc": "CDN / WAF Cloudflare"},
        {"name": "Cloudflare", "header": "cf-ray", "pattern": r".+", "desc": "En-tête de routage Cloudflare Ray ID"},
        {"name": "AWS CloudFront / WAF", "header": "server", "pattern": r"CloudFront", "desc": "Amazon CloudFront CDN / AWS WAF"},
        {"name": "AWS CloudFront", "header": "x-amz-cf-id", "pattern": r".+", "desc": "Amazon CloudFront ID"},
        {"name": "Akamai GHost / WAF", "header": "server", "pattern": r"AkamaiGHost", "desc": "Akamai Global Host Edge"},
        {"name": "Akamai", "header": "x-akamai-transformed", "pattern": r".+", "desc": "Akamai Edge Header"},
        {"name": "Imperva / Incapsula", "header": "x-iinfo", "pattern": r".+", "desc": "Imperva Incapsula WAF"},
        {"name": "Imperva / Incapsula", "header": "x-cdn", "pattern": r"Incapsula", "desc": "Imperva Incapsula CDN"},
        {"name": "Fastly CDN", "header": "x-fastly-request-id", "pattern": r".+", "desc": "Fastly Edge Cloud"},
        {"name": "Sucuri CloudProxy", "header": "x-sucuri-id", "pattern": r".+", "desc": "Sucuri WebSite Firewall"},
        {"name": "F5 BIG-IP ASM", "header": "set-cookie", "pattern": r"BIGipServer|TS[0-9a-f]{8}", "desc": "F5 BIG-IP Application Security Manager"},
        {"name": "LiteSpeed Web Server", "header": "server", "pattern": r"LiteSpeed|OpenLiteSpeed", "desc": "LiteSpeed avec protection anti-DDoS"},
        {"name": "Varnish Cache", "header": "x-varnish", "pattern": r".+", "desc": "Accélérateur HTTP Varnish Cache"},
        {"name": "ModSecurity / OWASP CRS", "header": "server", "pattern": r"mod_security|NOYB", "desc": "Moteur WAF open-source ModSecurity"}
    ]

    @classmethod
    def detect(cls, url, timeout=3.0):
        detected = []
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DSS-WAFDetector/3.0"})
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
                entry = {"name": sig["name"], "header": sig["header"], "value": h_val, "description": sig["desc"]}
                if not any(d["name"] == sig["name"] for d in detected):
                    detected.append(entry)

        if detected:
            log_title(f"DÉTECTION DE PARE-FEU APPLICATIF (WAF / CDN) : {url}")
            for d in detected:
                log_success(f"WAF / Protection active identifiée : {Colors.BOLD}{Colors.YELLOW}{d['name']}{Colors.RESET} ({d['description']})")
        return detected

# =============================================================================
# MODULE 3 : DÉTECTION DE TECHNOLOGIES WEB & CMS (WAPPALYZER-LIKE)
# =============================================================================
class TechDetector:
    """Identification de CMS, frameworks frontend/backend, serveurs et librairies."""

    TECH_RULES = [
        {"name": "WordPress", "type": "CMS", "pattern": r"wp-content|wp-includes|wp-json", "header": None},
        {"name": "Joomla!", "type": "CMS", "pattern": r"/media/jui/|/templates/|Joomla!", "header": None},
        {"name": "Drupal", "type": "CMS", "pattern": r"Drupal\.settings|sites/all/|drupal\.js", "header": None},
        {"name": "Shopify", "type": "E-Commerce", "pattern": r"cdn\.shopify\.com", "header": None},
        {"name": "Prestashop", "type": "E-Commerce", "pattern": r"prestashop|presta", "header": None},
        {"name": "Laravel", "type": "PHP Framework", "pattern": None, "header": "set-cookie", "h_pattern": r"laravel_session|XSRF-TOKEN"},
        {"name": "Django", "type": "Python Framework", "pattern": r"csrfmiddlewaretoken", "header": "set-cookie", "h_pattern": r"csrftoken"},
        {"name": "Spring Boot", "type": "Java Framework", "pattern": r"/actuator/|whitelabel error page", "header": None},
        {"name": "Express.js", "type": "Node.js Framework", "pattern": None, "header": "x-powered-by", "h_pattern": r"Express"},
        {"name": "Next.js", "type": "React Framework", "pattern": r"/_next/static|__NEXT_DATA__", "header": None},
        {"name": "React", "type": "UI Library", "pattern": r"data-reactroot|react-dom|react\.production\.min\.js", "header": None},
        {"name": "Vue.js", "type": "UI Library", "pattern": r"data-v-[a-f0-9]|vue\.min\.js|__vue__", "header": None},
        {"name": "Bootstrap", "type": "CSS Framework", "pattern": r"bootstrap(\.min)?\.(css|js)", "header": None},
        {"name": "jQuery", "type": "JS Library", "pattern": r"jquery(\.min)?\.js|jQuery\s*v[0-9\.]+", "header": None},
        {"name": "Tailwind CSS", "type": "CSS Framework", "pattern": r"tailwindcss|font-sans antialiased", "header": None},
        {"name": "Apache HTTP Server", "type": "Web Server", "pattern": None, "header": "server", "h_pattern": r"Apache"},
        {"name": "Nginx", "type": "Web Server", "pattern": None, "header": "server", "h_pattern": r"nginx"},
        {"name": "Microsoft IIS", "type": "Web Server", "pattern": None, "header": "server", "h_pattern": r"Microsoft-IIS"}
    ]

    @classmethod
    def fingerprint(cls, url, timeout=3.0):
        detected = []
        body = ""
        headers = {}
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (DSS-TechFingerprint/3.0)"})
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
            # Test dans les en-têtes
            if r.get("header") and r.get("h_pattern"):
                h_val = headers.get(r["header"], "")
                if h_val and re.search(r["h_pattern"], h_val, re.IGNORECASE):
                    matched = True
            # Test dans le code source HTML
            if not matched and r.get("pattern") and body:
                if re.search(r["pattern"], body, re.IGNORECASE):
                    matched = True

            if matched and not any(t["name"] == r["name"] for t in detected):
                detected.append({"name": r["name"], "type": r["type"]})

        if detected:
            log_title(f"EMPREINTES TECHNOLOGIQUES & CMS DÉTECTÉS : {url}")
            for t in detected:
                log_success(f"Stack identifiée : {Colors.BOLD}{t['name']}{Colors.RESET} [{Colors.CYAN}{t['type']}{Colors.RESET}]")
        return detected

# =============================================================================
# MODULE 4 : AUDIT DNS & SÉCURITÉ EMAIL (SPF, DMARC, MX, NS)
# =============================================================================
class DNSAuditor:
    """Analyse de la configuration DNS et des protections anti-spoofing d'emails (SPF, DMARC, MX)."""

    @staticmethod
    def audit_domain(domain):
        log_title(f"AUDIT DNS & SÉCURITÉ EMAIL (ANTI-SPOOFING) : {domain}")
        results = {
            "domain": domain,
            "mx_records": [],
            "ns_records": [],
            "spf": {"found": False, "record": "", "status": "Manquant", "severity": "HIGH"},
            "dmarc": {"found": False, "record": "", "policy": "none", "status": "Manquant", "severity": "HIGH"},
            "security_alerts": []
        }

        # 1. Vérification MX (Mail Exchange)
        try:
            # Récupération standard des hôtes MX
            mx_hosts = socket.getaddrinfo(domain, 25, socket.AF_INET, socket.SOCK_STREAM)
            unique_ips = list(set([item[4][0] for item in mx_hosts]))
            results["mx_records"] = unique_ips
            log_info(f"Serveurs MX associés : {', '.join(unique_ips) if unique_ips else 'Aucun'}")
        except Exception:
            pass

        # 2. Résolution DNS avancée via DoH (DNS-over-HTTPS Cloudflare/Google) sans dépendances
        def query_doh(qname, qtype="TXT"):
            url = f"https://cloudflare-dns.com/dns-query?name={qname}&type={qtype}"
            try:
                req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": "DSS-DNSAuditor"})
                with urllib.request.urlopen(req, timeout=3.0) as res:
                    data = json.loads(res.read().decode())
                    answers = data.get("Answer", [])
                    return [a["data"].strip('"') for a in answers if "data" in a]
            except Exception:
                return []

        # Interrogation SPF
        txt_records = query_doh(domain, "TXT")
        for rec in txt_records:
            if rec.startswith("v=spf1"):
                results["spf"]["found"] = True
                results["spf"]["record"] = rec
                if "+all" in rec:
                    results["spf"]["status"] = "DANGEREUX (+all autorise l'usurpation totale)"
                    results["spf"]["severity"] = "CRITICAL"
                    results["security_alerts"].append("Enregistrement SPF permissive (+all) : permet l'usurpation d'identité d'email !")
                elif "~all" in rec or "-all" in rec:
                    results["spf"]["status"] = "CONFORME (Softfail/Hardfail)"
                    results["spf"]["severity"] = "OK"
                break

        if not results["spf"]["found"]:
            results["security_alerts"].append("Enregistrement SPF absent : Risque élevé de phishing / usurpation de domaine !")
            log_danger(f"SPF : {Colors.RED}ABSENT{Colors.RESET} (Vulnérable à l'usurpation d'e-mails)")
        else:
            col = Colors.GREEN if results["spf"]["severity"] == "OK" else Colors.RED
            log_success(f"SPF : {col}{results['spf']['record']}{Colors.RESET} ({results['spf']['status']})")

        # Interrogation DMARC (_dmarc.domain)
        dmarc_records = query_doh(f"_dmarc.{domain}", "TXT")
        for rec in dmarc_records:
            if rec.startswith("v=DMARC1"):
                results["dmarc"]["found"] = True
                results["dmarc"]["record"] = rec
                if "p=reject" in rec:
                    results["dmarc"]["policy"] = "reject"
                    results["dmarc"]["status"] = "OPTIMAL (Rejet strict des emails frauduleux)"
                    results["dmarc"]["severity"] = "OK"
                elif "p=quarantine" in rec:
                    results["dmarc"]["policy"] = "quarantine"
                    results["dmarc"]["status"] = "BON (Mise en quarantaine)"
                    results["dmarc"]["severity"] = "OK"
                elif "p=none" in rec:
                    results["dmarc"]["policy"] = "none"
                    results["dmarc"]["status"] = "FAIBLE (Mode surveillance p=none, pas de blocage)"
                    results["dmarc"]["severity"] = "MEDIUM"
                    results["security_alerts"].append("DMARC en mode 'p=none' : les e-mails falsifiés ne sont pas bloqués.")
                break

        if not results["dmarc"]["found"]:
            results["security_alerts"].append("Enregistrement DMARC absent : Aucune politique de rejet des e-mails frauduleux.")
            log_danger(f"DMARC : {Colors.RED}ABSENT{Colors.RESET} (Aucune politique DMARC configurée)")
        else:
            col = Colors.GREEN if results["dmarc"]["severity"] == "OK" else Colors.YELLOW
            log_success(f"DMARC : {col}{results['dmarc']['record']}{Colors.RESET} ({results['dmarc']['status']})")

        return results

# =============================================================================
# MODULE 5 : DÉCOUVERTE SAN & AUDIT SSL/TLS AVANCÉ
# =============================================================================
class TLSInspector:
    """Analyse exhaustive de la configuration TLS, certificats et Subject Alternative Names (SAN)."""

    TLS_VERSIONS = [
        ("SSLv3", getattr(ssl, "PROTOCOL_SSLv23", None), "CRITICAL", "Protocole obsolète vulnérable à POODLE"),
        ("TLS 1.0", getattr(ssl, "PROTOCOL_TLSv1", None), "HIGH", "Obsolète et déprécié par le RFC 8996 (vulnérable à BEAST)"),
        ("TLS 1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None), "HIGH", "Obsolète et déprécié"),
        ("TLS 1.2", getattr(ssl, "PROTOCOL_TLSv1_2", None), "OK", "Protocole sécurisé standard"),
        ("TLS 1.3", getattr(ssl, "PROTOCOL_TLS_CLIENT", None), "EXCELLENT", "Dernière norme TLS sécurisée et rapide")
    ]

    @staticmethod
    def audit_tls(hostname, port=443, timeout=3.0):
        log_title(f"AUDIT CRYPTOGRAPHIQUE SSL / TLS & SAN : {hostname}:{port}")
        report = {
            "supported_protocols": [],
            "certificate": {},
            "sans_discovered": [],
            "vulnerabilities": [],
            "grade": "A"
        }

        # 1. Versions de protocole
        for v_name, proto, risk, desc in TLSInspector.TLS_VERSIONS:
            if proto is None:
                continue
            try:
                ctx = ssl.SSLContext(proto)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=timeout) as s:
                    with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                        report["supported_protocols"].append({
                            "version": v_name,
                            "negotiated": ss.version(),
                            "status": "SUPPORTÉ",
                            "risk": risk,
                            "description": desc
                        })
                        if risk in ["CRITICAL", "HIGH"]:
                            report["vulnerabilities"].append(f"Protocole non sécurisé actif : {v_name} ({desc})")
                            report["grade"] = "F" if risk == "CRITICAL" else "C"
            except Exception:
                report["supported_protocols"].append({
                    "version": v_name,
                    "status": "NON SUPPORTÉ",
                    "risk": "OK"
                })

        # 2. Analyse certificat & SAN
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                    cert = ss.getpeercert(binary_form=False)
                    cipher = ss.cipher()
                    subject = dict(x[0] for x in cert.get('subject', [])) if cert else {}
                    issuer = dict(x[0] for x in cert.get('issuer', [])) if cert else {}
                    not_after = cert.get('notAfter')
                    
                    # Découverte des noms alternatifs (SAN)
                    sans = []
                    for k, v in cert.get('subjectAltName', []):
                        if k == 'DNS':
                            sans.append(v)
                    report["sans_discovered"] = sans

                    days_left = None
                    if not_after:
                        exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp_date - datetime.utcnow()).days

                    report["certificate"] = {
                        "subject": subject.get('commonName', hostname),
                        "issuer": issuer.get('organizationName', issuer.get('commonName', 'Inconnu')),
                        "valid_until": not_after,
                        "days_remaining": days_left,
                        "cipher": cipher[0] if cipher else "N/A",
                        "tls_version": ss.version()
                    }

                    log_success(f"Certificat émis pour : {Colors.BOLD}{report['certificate']['subject']}{Colors.RESET} par {report['certificate']['issuer']}")
                    log_info(f"Protocole négocié : {ss.version()} | Suite de chiffrement : {report['certificate']['cipher']}")
                    
                    if sans:
                        log_success(f"Noms alternatifs (SAN) découverts ({len(sans)}) : {Colors.CYAN}{', '.join(sans[:6])}{'...' if len(sans) > 6 else ''}{Colors.RESET}")

                    if days_left is not None:
                        if days_left < 0:
                            report["vulnerabilities"].append(f"Le certificat SSL a expiré depuis {abs(days_left)} jours !")
                            report["grade"] = "F"
                            log_danger(f"Le certificat a expiré depuis {abs(days_left)} jours !")
                        elif days_left < 15:
                            report["vulnerabilities"].append(f"Le certificat SSL expire dans {days_left} jours.")
                            log_warning(f"Le certificat expire dans {days_left} jours !")
                        else:
                            log_info(f"Validité : {days_left} jours restants (Expire le {not_after})")
        except Exception as e:
            report["certificate"] = {"error": str(e)}

        return report

# =============================================================================
# MODULE 6 : SONDES DE SERVICES & VERSIONS (-sV)
# =============================================================================
class ServiceFingerprinter:
    """Sondes et analyseurs de protocoles pour identifier précisément les versions logicielles."""

    @staticmethod
    def probe_ssh(ip, port, timeout=1.5):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                raw = s.recv(256)
                banner = raw.decode(errors="ignore").strip()
                if banner.startswith("SSH-"):
                    return {"protocol": "SSH", "banner": banner, "version": banner.split()[0]}
        except Exception:
            pass
        return None

    @staticmethod
    def probe_http(ip, port, ssl_mode=False, timeout=1.5):
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            if ssl_mode:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock)
            
            req = b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nUser-Agent: Mozilla/5.0 DSS-Scanner/3.0\r\n\r\n"
            sock.sendall(req)
            sock.settimeout(timeout)
            resp = sock.recv(1024).decode(errors="ignore")
            sock.close()

            server = ""
            powered = ""
            for line in resp.split("\r\n"):
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                elif line.lower().startswith("x-powered-by:"):
                    powered = line.split(":", 1)[1].strip()

            banner_parts = []
            if server: banner_parts.append(f"Server: {server}")
            if powered: banner_parts.append(f"Powered-by: {powered}")
            
            if banner_parts:
                return {"protocol": "HTTPS" if ssl_mode else "HTTP", "banner": " | ".join(banner_parts), "server": server, "powered": powered}
        except Exception:
            pass
        return None

    @staticmethod
    def probe_ftp(ip, port, timeout=1.5):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                raw = s.recv(512).decode(errors="ignore").strip()
                if raw.startswith("220"):
                    s.sendall(b"USER anonymous\r\n")
                    r2 = s.recv(256).decode(errors="ignore")
                    anon_allowed = False
                    if "331" in r2:
                        s.sendall(b"PASS anonymous@example.com\r\n")
                        r3 = s.recv(256).decode(errors="ignore")
                        if "230" in r3:
                            anon_allowed = True
                    s.sendall(b"QUIT\r\n")
                    banner = raw[4:].strip()
                    if anon_allowed:
                        banner += " [⚠️ Anonymous Login Allowed]"
                    return {"protocol": "FTP", "banner": banner}
        except Exception:
            pass
        return None

    @staticmethod
    def probe_smtp(ip, port, timeout=1.5):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                banner = s.recv(512).decode(errors="ignore").strip()
                if banner.startswith("220"):
                    s.sendall(b"EHLO dss-security.local\r\n")
                    ehlo_resp = s.recv(1024).decode(errors="ignore")
                    s.sendall(b"QUIT\r\n")
                    features = []
                    if "STARTTLS" in ehlo_resp: features.append("STARTTLS")
                    if "AUTH" in ehlo_resp: features.append("AUTH")
                    f_str = f" ({','.join(features)})" if features else ""
                    return {"protocol": "SMTP", "banner": f"{banner[4:].strip()}{f_str}"}
        except Exception:
            pass
        return None

    @staticmethod
    def probe_mysql(ip, port, timeout=1.5):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                data = s.recv(256)
                if len(data) > 5 and data[4] == 0x0a:
                    null_idx = data.find(b"\x00", 5)
                    if null_idx != -1:
                        ver = data[5:null_idx].decode(errors="ignore")
                        return {"protocol": "MySQL", "banner": f"MySQL Protocol v10 (Version: {ver})", "version": ver}
        except Exception:
            pass
        return None

    @staticmethod
    def probe_redis(ip, port, timeout=1.5):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.sendall(b"INFO\r\n")
                resp = s.recv(1024).decode(errors="ignore")
                if "redis_version:" in resp:
                    for line in resp.splitlines():
                        if line.startswith("redis_version:"):
                            ver = line.split(":")[1].strip()
                            return {"protocol": "Redis", "banner": f"Redis Server v{ver} (No Auth)", "version": ver}
                elif "NOAUTH" in resp:
                    return {"protocol": "Redis", "banner": "Redis Server (Authentication Required)"}
        except Exception:
            pass
        return None

    @classmethod
    def identify(cls, ip, port, timeout=1.5):
        if port in [22, 2222]:
            res = cls.probe_ssh(ip, port, timeout)
            if res: return res
        elif port in [80, 8080, 8000, 3000, 5000, 9000]:
            res = cls.probe_http(ip, port, ssl_mode=False, timeout=timeout)
            if res: return res
        elif port in [443, 8443, 9443]:
            res = cls.probe_http(ip, port, ssl_mode=True, timeout=timeout)
            if res: return res
        elif port == 21:
            res = cls.probe_ftp(ip, port, timeout)
            if res: return res
        elif port in [25, 587]:
            res = cls.probe_smtp(ip, port, timeout)
            if res: return res
        elif port == 3306:
            res = cls.probe_mysql(ip, port, timeout)
            if res: return res
        elif port == 6379:
            res = cls.probe_redis(ip, port, timeout)
            if res: return res

        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n\r\n")
                raw = s.recv(512).decode(errors="ignore")
                for line in raw.splitlines():
                    clean = line.strip()
                    if clean and not clean.startswith("<") and len(clean) > 3:
                        return {"protocol": "Service", "banner": clean[:70]}
        except Exception:
            pass

        return {"protocol": SERVICES_MAP.get(port, "Inconnu"), "banner": ""}

# =============================================================================
# MODULE 7 : SCANNER UDP AVEC SONDES PROTOCOLAIRES (-sU)
# =============================================================================
class UDPScanner:
    UDP_PROBES = {
        53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
        123: b"\x1b" + 47 * b"\0",
        161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
        137: b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
        1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
    }

    def __init__(self, target_ip, ports=None, timeout=1.5):
        self.target_ip = target_ip
        self.ports = ports or UDP_COMMON_PORTS
        self.timeout = timeout
        self.open_ports = []

    def probe_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        probe = self.UDP_PROBES.get(port, b"\x00\x00\x00\x00\x00\x00")
        try:
            sock.sendto(probe, (self.target_ip, port))
            data, _ = sock.recvfrom(1024)
            service = SERVICES_MAP.get(port, "UDP Service")
            sock.close()
            return {
                "port": port,
                "protocol": "udp",
                "status": "open",
                "service": service,
                "banner": data[:60].decode(errors="ignore").strip()
            }
        except Exception:
            pass
        finally:
            sock.close()
        return None

    def run(self):
        log_title(f"SCAN UDP PROTOCÔLAIRE (-sU) : {self.target_ip}")
        log_info(f"Test de {len(self.ports)} ports UDP clés avec sondes protocolaires...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(self.probe_port, self.ports))

        for r in results:
            if r:
                self.open_ports.append(r)
                log_success(f"Port UDP Détecté Ouvert : {Colors.BOLD}{r['port']}/udp{Colors.RESET} ({r['service']})")

        if not self.open_ports:
            log_info("Aucune réponse explicite sur les sondes UDP (ports filtrés ou silencieux).")
        return self.open_ports

# =============================================================================
# MODULE 8 : SCANNER DE PORTS TCP & CORRÉLATEUR CVE
# =============================================================================
class PortScanner:
    def __init__(self, target, ports, timing="T3", grab_banners=True):
        self.target = target
        self.ports = ports
        self.timing = TIMING_PROFILES.get(timing, TIMING_PROFILES["T3"])
        self.threads = self.timing["threads"]
        self.timeout = self.timing["timeout"]
        self.delay = self.timing["delay"]
        self.grab_banners = grab_banners
        self.ip = None
        self.hostname = None
        self.results = []
        self.cve_findings = []
        self.ttl = None

    def resolve(self):
        try:
            self.ip = socket.gethostbyname(self.target)
            try:
                self.hostname = socket.gethostbyaddr(self.ip)[0]
            except Exception:
                self.hostname = self.target
            return True
        except socket.gaierror as e:
            log_danger(f"Résolution DNS échouée pour '{self.target}' : {e}")
            return False

    def estimate_os(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.ip, self.ports[0] if self.ports else 80))
            self.ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            s.close()
        except Exception:
            pass

        if self.ttl is not None:
            if self.ttl <= 64:
                return f"Linux / FreeBSD / macOS / Android (TTL: {self.ttl})"
            elif self.ttl <= 128:
                return f"Microsoft Windows (TTL: {self.ttl})"
            elif self.ttl <= 255:
                return f"Cisco IOS / Equipement Réseau / Solaris (TTL: {self.ttl})"
        return "Indéterminé"

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
            service_info = ServiceFingerprinter.identify(self.ip, port, timeout=self.timeout)
            service_name = service_info.get("protocol", SERVICES_MAP.get(port, "Inconnu"))
            banner = service_info.get("banner", "")

            # Corrélation CVE
            cves = []
            combined_text = f"{service_name} {banner}"
            for rule in CVE_KNOWLEDGE_BASE:
                if re.search(rule["pattern"], combined_text, re.IGNORECASE):
                    cve_item = {
                        "port": port,
                        "cve": rule["cve"],
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "cvss": rule["cvss"],
                        "recommendation": rule["recommendation"]
                    }
                    cves.append(cve_item)
                    self.cve_findings.append(cve_item)

            return {
                "port": port,
                "protocol": "tcp",
                "status": "open",
                "latency_ms": round(latency, 2),
                "service": service_name,
                "banner": banner,
                "cves": cves
            }
        return None

    def run(self):
        if not self.resolve():
            return []

        log_info(f"Cible : {Colors.BOLD}{self.target}{Colors.RESET} ({self.ip})")
        log_info(f"Ports : {len(self.ports)} | Timing : {self.timing['name']} ({self.threads} threads, {self.timeout}s timeout)")
        os_guess = self.estimate_os()
        log_info(f"OS présumé : {Colors.CYAN}{os_guess}{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}{'PORT':<10} {'ÉTAT':<10} {'LATENCE':<10} {'SERVICE':<26} {'BANNIÈRE & VERSION'}{Colors.RESET}")
        print(f"{'-'*80}")

        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, p): p for p in self.ports}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    self.results.append(res)
                    port_str = f"{res['port']}/tcp"
                    status_str = f"{Colors.GREEN}OUVERT{Colors.RESET}"
                    lat_str = f"{res['latency_ms']:.1f}ms"
                    service_str = res['service'][:24]
                    banner_str = f"{Colors.DIM}{res['banner'][:34]}{Colors.RESET}" if res['banner'] else ""
                    print(f"{port_str:<10} {status_str:<19} {lat_str:<10} {service_str:<26} {banner_str}")

        self.results.sort(key=lambda x: x["port"])
        elapsed = time.time() - start_time
        print(f"{'-'*80}")
        log_success(f"Scan TCP achevé en {elapsed:.2f}s — {len(self.results)} port(s) ouvert(s).")
        
        if self.cve_findings:
            log_title(f"⚠️ VULNÉRABILITÉS & CVE IDENTIFIÉES ({len(self.cve_findings)})")
            for cve in self.cve_findings:
                color = Colors.RED if cve["severity"] == "CRITICAL" else Colors.YELLOW
                print(f"[{color}{cve['severity']}{Colors.RESET}] Port {cve['port']}/tcp : {Colors.BOLD}{cve['cve']}{Colors.RESET} (CVSS {cve['cvss']})")
                print(f"    ↳ {cve['title']}")
                print(f"    💡 Solution : {cve['recommendation']}\n")

        return self.results

# =============================================================================
# MODULE 9 : AUDITEUR WEB OWASP (EN-TÊTES, COOKIES, FICHIERS SENSIBLES)
# =============================================================================
class WebAuditor:
    SENSITIVE_PATHS = [
        {"path": "/.git/HEAD", "type": "Git Repo Exposure", "severity": "CRITICAL", "desc": "Dépôt Git public — Téléchargement de l'historique et du code"},
        {"path": "/.env", "type": "Secrets Exposure", "severity": "CRITICAL", "desc": "Fichier .env — Clés d'API et identifiants de bases de données"},
        {"path": "/.env.local", "type": "Secrets Exposure", "severity": "CRITICAL", "desc": "Environnement local exposé"},
        {"path": "/wp-config.php.bak", "type": "Config Backup", "severity": "CRITICAL", "desc": "Sauvegarde de configuration WordPress"},
        {"path": "/config.json", "type": "Configuration", "severity": "HIGH", "desc": "Configuration applicative JSON"},
        {"path": "/actuator/env", "type": "Spring Actuator", "severity": "CRITICAL", "desc": "Spring Actuator /env fuite de variables critiques"},
        {"path": "/actuator/health", "type": "Spring Actuator", "severity": "MEDIUM", "desc": "Spring Health endpoint exposé"},
        {"path": "/phpinfo.php", "type": "Info Disclosure", "severity": "MEDIUM", "desc": "Page phpinfo() révélant la configuration serveur"},
        {"path": "/server-status", "type": "Info Disclosure", "severity": "MEDIUM", "desc": "Apache mod_status actif"},
        {"path": "/robots.txt", "type": "Recon", "severity": "INFO", "desc": "Fichier robots.txt disponible pour cartographie"},
        {"path": "/sitemap.xml", "type": "Recon", "severity": "INFO", "desc": "Plan du site sitemap.xml"},
        {"path": "/admin/", "type": "Admin Interface", "severity": "MEDIUM", "desc": "Panneau d'administration"},
        {"path": "/admin/login", "type": "Auth Portal", "severity": "MEDIUM", "desc": "Mire d'authentification admin"},
        {"path": "/backup.zip", "type": "Backup Archive", "severity": "HIGH", "desc": "Archive de sauvegarde ZIP téléchargeable"},
        {"path": "/backup.sql", "type": "DB Dump", "severity": "CRITICAL", "desc": "Dump SQL de base de données exposé"},
        {"path": "/api/docs", "type": "API Documentation", "severity": "LOW", "desc": "Documentation OpenAPI / Swagger"},
        {"path": "/swagger.json", "type": "API Definition", "severity": "LOW", "desc": "Fichier de description OpenAPI / Swagger"}
    ]

    SECURITY_HEADERS = [
        {"name": "Strict-Transport-Security", "severity": "HIGH", "desc": "Force HTTPS et protège contre les attaques Man-in-the-Middle."},
        {"name": "Content-Security-Policy", "severity": "HIGH", "desc": "Mitige les failles XSS, injections et chargements de scripts non autorisés."},
        {"name": "X-Frame-Options", "severity": "MEDIUM", "desc": "Protège contre le Clickjacking (UI Redressing)."},
        {"name": "X-Content-Type-Options", "severity": "MEDIUM", "desc": "Empêche l'interprétation abusive des types MIME ('nosniff')."},
        {"name": "Referrer-Policy", "severity": "LOW", "desc": "Contrôle la fuite d'URLs privées dans les en-têtes Referer."},
        {"name": "Permissions-Policy", "severity": "LOW", "desc": "Restreint l'accès aux API du navigateur (micro, caméra, géoloc)."}
    ]

    def __init__(self, target_url, timeout=3.0):
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = "http://" + target_url
        self.url = target_url.rstrip("/")
        self.timeout = timeout
        self.findings = []
        self.headers_audit = []
        self.cookies_audit = []
        self.disclosures = []

    def run(self):
        log_title(f"AUDIT WEB COMPLET (OWASP & CONFIGURATION) : {self.url}")
        self.audit_headers_and_cookies()
        self.audit_methods()
        self.audit_sensitive_paths()
        return {
            "url": self.url,
            "headers_audit": self.headers_audit,
            "cookies_audit": self.cookies_audit,
            "disclosures": self.disclosures,
            "sensitive_paths": self.findings
        }

    def audit_headers_and_cookies(self):
        log_info("Analyse des en-têtes HTTP et des cookies de session...")
        try:
            req = urllib.request.Request(self.url, headers={"User-Agent": "DSS-WebAuditor/3.0"})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as res:
                headers = dict(res.headers)
                cookie_headers = res.headers.get_all("Set-Cookie") or []
        except urllib.error.HTTPError as e:
            headers = dict(e.headers)
            cookie_headers = e.headers.get_all("Set-Cookie") or []
        except Exception as e:
            log_danger(f"Erreur de connexion HTTP : {e}")
            return

        for k in ["server", "x-powered-by", "x-aspnet-version"]:
            val = next((headers[h] for h in headers if h.lower() == k), None)
            if val:
                self.disclosures.append({"header": k, "value": val})
                log_warning(f"Fuite d'en-tête serveur : {Colors.YELLOW}{k}: {val}{Colors.RESET}")

        print(f"\n{Colors.BOLD}{'EN-TÊTE DE SÉCURITÉ':<32} {'STATUT':<15} {'RISQUE'}{Colors.RESET}")
        print(f"{'-'*60}")
        for rule in self.SECURITY_HEADERS:
            h_name = rule["name"]
            found_val = next((headers[k] for k in headers if k.lower() == h_name.lower()), None)
            if found_val:
                print(f"{h_name:<32} {Colors.GREEN}PRÉSENT{Colors.RESET}         {Colors.GREEN}Conforme{Colors.RESET}")
                self.headers_audit.append({"header": h_name, "present": True, "value": found_val, "severity": "OK"})
            else:
                sev_col = Colors.RED if rule["severity"] == "HIGH" else Colors.YELLOW
                print(f"{h_name:<32} {sev_col}ABSENT{Colors.RESET}          {sev_col}{rule['severity']}{Colors.RESET}")
                self.headers_audit.append({"header": h_name, "present": False, "severity": rule["severity"], "description": rule["desc"]})

        for c in cookie_headers:
            is_secure = "secure" in c.lower()
            is_httponly = "httponly" in c.lower()
            is_samesite = "samesite" in c.lower()
            c_name = c.split("=")[0]
            self.cookies_audit.append({
                "cookie": c_name,
                "secure": is_secure,
                "httponly": is_httponly,
                "samesite": is_samesite
            })
            if not is_secure or not is_httponly:
                log_warning(f"Cookie non sécurisé '{c_name}' : Secure={is_secure}, HttpOnly={is_httponly}")

    def audit_methods(self):
        log_info("Audit des méthodes HTTP (OPTIONS, TRACE, PUT, DELETE)...")
        for m in ["OPTIONS", "TRACE", "PUT", "DELETE"]:
            try:
                req = urllib.request.Request(self.url, method=m, headers={"User-Agent": "DSS-WebAuditor"})
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as res:
                    if res.status in [200, 204]:
                        log_danger(f"Méthode HTTP activée : {Colors.RED}{m} (HTTP {res.status}){Colors.RESET}")
            except Exception:
                pass

    def check_path(self, item):
        target = self.url + item["path"]
        try:
            req = urllib.request.Request(target, headers={"User-Agent": "Mozilla/5.0 DSS-WebAuditor"})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as res:
                if res.status in [200, 206]:
                    return {
                        "path": item["path"],
                        "url": target,
                        "status": res.status,
                        "type": item["type"],
                        "severity": item["severity"],
                        "desc": item["desc"]
                    }
        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                return {
                    "path": item["path"],
                    "url": target,
                    "status": e.code,
                    "type": item["type"] + " (Protégé)",
                    "severity": "LOW",
                    "desc": f"Présent mais protégé ({e.code})"
                }
        except Exception:
            pass
        return None

    def audit_sensitive_paths(self):
        log_info(f"Recherche de chemins sensibles ({len(self.SENSITIVE_PATHS)} endpoints)...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(self.check_path, self.SENSITIVE_PATHS))

        for r in results:
            if r:
                self.findings.append(r)
                col = Colors.RED if r["severity"] == "CRITICAL" else Colors.YELLOW
                log_danger(f"[{col}{r['severity']}{Colors.RESET}] {Colors.BOLD}{r['path']}{Colors.RESET} (HTTP {r['status']}) - {r['desc']}")

# =============================================================================
# MODULE 10 : TRACEROUTE TCP/IP
# =============================================================================
class NetworkTracer:
    @staticmethod
    def trace(target_ip, port=None, max_hops=15, timeout=1.0):
        log_title(f"TRACEROUTE & ANALYSE DU CHEMIN RÉSEAU : {target_ip}")
        hops = []
        probe_port = port or 80

        for ttl in range(1, max_hops + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack("I", ttl))
            except Exception:
                pass
            s.settimeout(timeout)
            t_start = time.time()
            try:
                s.connect((target_ip, probe_port))
                rtt = (time.time() - t_start) * 1000
                hops.append({"hop": ttl, "ip": target_ip, "rtt_ms": round(rtt, 2), "status": "Cible atteinte"})
                log_success(f"Saut {ttl:2d} : {Colors.BOLD}{target_ip}{Colors.RESET} (RTT: {rtt:.1f} ms) — [Destination]")
                s.close()
                break
            except (socket.timeout, socket.error):
                rtt = (time.time() - t_start) * 1000
                hops.append({"hop": ttl, "ip": "*", "rtt_ms": None, "status": "Pas de réponse"})
                log_info(f"Saut {ttl:2d} : * * * (TTL {ttl})")
            finally:
                s.close()
        return hops

# =============================================================================
# MODULE 11 : SOUS-DOMAINES & SOUS-RÉSEAUX
# =============================================================================
class SubdomainScanner:
    TOP_SUBS = [
        "www", "mail", "ftp", "admin", "webmail", "smtp", "pop", "ns1", "ns2",
        "api", "dev", "test", "staging", "beta", "vpn", "portal", "secure",
        "cloud", "app", "git", "gitlab", "github", "jira", "confluence",
        "auth", "login", "sso", "cdn", "static", "m", "mobile", "shop",
        "direct", "remote", "server", "dns", "monitor", "grafana", "kibana",
        "jenkins", "ci", "docker", "k8s", "cpanel", "whm", "autodiscover",
        "vault", "db", "mysql", "redis", "elastic", "prometheus"
    ]

    def __init__(self, domain, threads=25):
        self.domain = domain
        self.threads = threads
        self.found = []

    def check(self, sub):
        fqdn = f"{sub}.{self.domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return {"subdomain": fqdn, "ip": ip}
        except Exception:
            return None

    def run(self):
        log_title(f"ÉNUMÉRATION DES SOUS-DOMAINES DNS : {self.domain}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = list(executor.map(self.check, self.TOP_SUBS))
        for r in results:
            if r:
                self.found.append(r)
                log_success(f"Sous-domaine trouvé : {Colors.BOLD}{r['subdomain']:<32}{Colors.RESET} -> {Colors.CYAN}{r['ip']}{Colors.RESET}")
        log_info(f"Total sous-domaines découverts : {len(self.found)}")
        return self.found

class SubnetScanner:
    def __init__(self, cidr, threads=50, timeout=1.0):
        self.cidr = cidr
        self.threads = threads
        self.timeout = timeout
        self.alive = []

    def ping(self, ip_str):
        for p in [80, 443, 22, 445, 135, 8080]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                if s.connect_ex((ip_str, p)) == 0:
                    s.close()
                    try:
                        host = socket.gethostbyaddr(ip_str)[0]
                    except Exception:
                        host = "N/A"
                    return {"ip": ip_str, "status": "up", "hostname": host, "port": p}
                s.close()
            except Exception:
                pass
        return None

    def run(self):
        log_title(f"BALAYAGE RÉSEAU CIDR (PING SWEEP) : {self.cidr}")
        try:
            net = ipaddress.ip_network(self.cidr, strict=False)
            hosts = [str(ip) for ip in net.hosts()]
        except Exception as e:
            log_danger(f"Format CIDR incorrect : {e}")
            return []

        log_info(f"Balayage de {len(hosts)} adresses IP...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.ping, ip) for ip in hosts]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    self.alive.append(res)
                    log_success(f"Hôte Actif : {Colors.BOLD}{res['ip']:<18}{Colors.RESET} ({res['hostname']}) via port {res['port']}")
        return self.alive

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
        nmaprun = ET.Element("nmaprun", {
            "scanner": "dss-scanner",
            "version": "3.0",
            "start": str(int(time.time())),
            "args": f"scan.py -t {data.get('target')}"
        })
        host = ET.SubElement(nmaprun, "host")
        status = ET.SubElement(host, "status", {"state": "up"})
        address = ET.SubElement(host, "address", {"addr": data.get("target", "N/A"), "addrtype": "ipv4"})
        ports_el = ET.SubElement(host, "ports")
        
        for p in data.get("ports", []):
            port_el = ET.SubElement(ports_el, "port", {"protocol": p.get("protocol", "tcp"), "portid": str(p["port"])})
            ET.SubElement(port_el, "state", {"state": p.get("status", "open")})
            ET.SubElement(port_el, "service", {"name": p.get("service", "unknown"), "product": p.get("banner", "")})

        tree = ET.ElementTree(nmaprun)
        tree.write(filename, encoding="utf-8", xml_declaration=True)
        log_success(f"Rapport XML (Format standard Nmap) : {Colors.BOLD}{filename}{Colors.RESET}")

    @staticmethod
    def export_markdown(data, filename):
        lines = [
            "# 🛡️ Rapport d'Audit de Sécurité — DSS Ultimate Security Scanner",
            f"> **Cible** : `{data.get('target', 'N/A')}`",
            f"> **Date** : {data.get('timestamp', datetime.utcnow().isoformat())}",
            "",
            "---",
            "## 1. 📊 Synthèse Exécutive",
            f"- **Ports TCP ouverts** : {len(data.get('ports', []))}",
            f"- **Ports UDP ouverts** : {len(data.get('udp_ports', []))}",
            f"- **Vulnérabilités / CVE** : {len(data.get('cves', []))}",
            f"- **WAF / CDN détecté** : {len(data.get('waf', []))}",
            f"- **Technologies & CMS** : {len(data.get('tech_stack', []))}",
            ""
        ]

        geo = data.get("geolocation", {})
        if geo:
            lines.extend([
                "---",
                "## 🌍 2. Géolocalisation & Renseignement Réseau (OSINT)",
                f"- **Pays / Ville** : {geo.get('country', 'N/A')} ({geo.get('city', 'N/A')})",
                f"- **Fournisseur (FAI)** : {geo.get('isp', 'N/A')}",
                f"- **Système Autonome (ASN)** : `{geo.get('asn', 'N/A')}`",
                f"- **Reverse DNS (PTR)** : `{geo.get('reverse_dns', 'N/A')}`",
                f"- **Coordonnées GPS** : `{geo.get('latitude')}, {geo.get('longitude')}`",
                ""
            ])

        if data.get("waf"):
            lines.extend([
                "---",
                "## 🛡️ 3. Pare-feu Applicatif (WAF / CDN)",
                "| Nom | En-tête de détection | Description |",
                "|---|---|---|"
            ])
            for w in data["waf"]:
                lines.append(f"| **{w['name']}** | `{w['header']}` | {w['description']} |")
            lines.append("")

        if data.get("tech_stack"):
            lines.extend([
                "---",
                "## 🧩 4. Technologies & CMS Détectés",
                "| Composant / Stack | Catégorie |",
                "|---|---|"
            ])
            for t in data["tech_stack"]:
                lines.append(f"| **{t['name']}** | `{t['type']}` |")
            lines.append("")

        dns_sec = data.get("dns_audit", {})
        if dns_sec:
            lines.extend([
                "---",
                "## ✉️ 5. Sécurité Email & DNS (Anti-Spoofing)",
                f"- **SPF Record** : `{dns_sec.get('spf', {}).get('record', 'ABSENT')}` ({dns_sec.get('spf', {}).get('status', 'N/A')})",
                f"- **DMARC Record** : `{dns_sec.get('dmarc', {}).get('record', 'ABSENT')}` ({dns_sec.get('dmarc', {}).get('status', 'N/A')})",
                ""
            ])

        lines.extend([
            "---",
            "## 🔌 6. Ports et Services Réseau Identifiés",
            "| Protocole | Port | Latence | Service | Bannière / Version |",
            "|---|---|---|---|---|"
        ])
        for p in data.get("ports", []):
            lines.append(f"| TCP | `{p['port']}` | {p.get('latency_ms', '-')} ms | {p['service']} | `{p.get('banner', '-')}` |")
        for p in data.get("udp_ports", []):
            lines.append(f"| UDP | `{p['port']}` | - | {p['service']} | `{p.get('banner', '-')}` |")

        if data.get("cves"):
            lines.extend([
                "",
                "---",
                "## 🚨 7. Vulnérabilités & CVE Détectées",
                "| Port | CVE | Criticité | CVSS | Titre | Recommandation |",
                "|---|---|---|---|---|---|"
            ])
            for c in data["cves"]:
                lines.append(f"| `{c.get('port', '-')}` | **{c['cve']}** | `{c['severity']}` | {c['cvss']} | {c['title']} | {c['recommendation']} |")

        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        log_success(f"Rapport Markdown : {Colors.BOLD}{filename}{Colors.RESET}")

    @staticmethod
    def export_html(data, filename):
        target = data.get("target", "N/A")
        ts = data.get("timestamp", datetime.utcnow().isoformat())
        geo = data.get("geolocation", {})
        
        cve_count = len(data.get("cves", []))
        crit_count = sum(1 for c in data.get("cves", []) if c.get("severity") == "CRITICAL")
        exposed_count = len(data.get("web_audit", {}).get("sensitive_paths", []))
        
        score = max(10, 100 - (crit_count * 30) - (cve_count * 10) - (exposed_count * 8))
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
            <td><strong>{c['cvss']}</strong> ({c['severity']})</td>
            <td>{c['title']}</td>
            <td><small>{c['recommendation']}</small></td>
        </tr>""" for c in data.get("cves", [])])

        tech_badges = "".join([f"""<span class="tech-tag"><strong>{t['name']}</strong> <small>({t['type']})</small></span>""" for t in data.get("tech_stack", [])])
        waf_badges = "".join([f"""<span class="waf-tag">🛡️ {w['name']} — {w['description']}</span>""" for w in data.get("waf", [])])

        lat = geo.get("latitude", 0.0)
        lon = geo.get("longitude", 0.0)
        map_link = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=12/{lat}/{lon}" if (lat and lon) else "#"

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DSS Security Report — {target}</title>
    <style>
        :root {{
            --bg: #0b0e14;
            --card-bg: #151b23;
            --border: #30363d;
            --text: #c9d1d9;
            --heading: #58a6ff;
            --accent: #2ea043;
            --danger: #f85149;
            --warning: #d29922;
        }}
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
        .tech-tag {{ display: inline-block; background: #1f6feb22; border: 1px solid #1f6feb88; color: #79c0ff; padding: 6px 12px; border-radius: 20px; margin: 4px; font-size: 0.9rem; }}
        .waf-tag {{ display: inline-block; background: #d2992222; border: 1px solid #d2992288; color: #e3b341; padding: 6px 12px; border-radius: 20px; margin: 4px; font-size: 0.9rem; font-weight: 600; }}
        code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: #79c0ff; }}
        .footer {{ text-align: center; margin-top: 3rem; color: #8b949e; font-size: 0.9rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ DSS Ultimate Security Scanner Report (v3.0)</h1>
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
                <p><strong>Reverse DNS :</strong> <code>{geo.get('reverse_dns', 'N/A')}</code></p>
                <p><strong>Carte :</strong> <a href="{map_link}" target="_blank" style="color: #58a6ff;">Voir les coordonnées GPS sur OpenStreetMap ↗</a></p>
            </div>

            <div class="card">
                <h2>🛡️ WAF & Stack Technologique</h2>
                <p><strong>Pare-feu Applicatif (WAF) :</strong></p>
                <div>{waf_badges if waf_badges else '<span style="color: #8b949e;">Aucun WAF public détecté</span>'}</div>
                <p style="margin-top: 1.5rem;"><strong>Technologies & CMS Détectés :</strong></p>
                <div>{tech_badges if tech_badges else '<span style="color: #8b949e;">Non identifié</span>'}</div>
            </div>
        </div>

        {f'''<div class="card" style="border-left: 5px solid #da3633;">
            <h2>🚨 Vulnérabilités & CVE Détectées ({len(data.get("cves", []))})</h2>
            <table>
                <thead>
                    <tr><th>Port</th><th>CVE</th><th>Score CVSS</th><th>Description</th><th>Recommandation</th></tr>
                </thead>
                <tbody>{cve_rows}</tbody>
            </table>
        </div>''' if data.get("cves") else ''}

        <div class="card">
            <h2>🔌 Services Réseau Découverts (TCP & UDP)</h2>
            <table>
                <thead>
                    <tr><th>Port</th><th>Statut</th><th>Latence</th><th>Service</th><th>Bannière / Version</th></tr>
                </thead>
                <tbody>{ports_rows if ports_rows else '<tr><td colspan="5">Aucun port ouvert détecté</td></tr>'}</tbody>
            </table>
        </div>

        <div class="footer">
            <p>Généré par DSS Security Scanner (D-Scan v3.0) — Cybersecurity Mastery Roadmap</p>
        </div>
    </div>
</body>
</html>"""
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        log_success(f"Tableau de bord HTML interactif : {Colors.BOLD}{filename}{Colors.RESET}")

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
  {Colors.BOLD}{Colors.MAGENTA}🛡️  DSS ULTIMATE SECURITY SCANNER (D-SCAN v3.0 ULTIMATE){Colors.RESET}
  {Colors.DIM}Alternative Nmap / Nikto / SSLyze / WhatWeb — Cybersecurity Roadmap{Colors.RESET}
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
        description="DSS Ultimate Security Scanner (D-Scan v3.0) — Reconnaissance Réseau, OSINT Géolocalisation, Détection WAF/CMS, Versions (-sV), Scan UDP (-sU) & Audit Web.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Cible
    parser.add_argument("-t", "--target", help="Cible à analyser (ex: 192.168.1.1, scanme.nmap.org, example.com)")
    parser.add_argument("--subnet", help="Balayage complet de sous-réseau CIDR (ex: 192.168.1.0/24)")
    
    # Modes de Scan
    parser.add_argument("-p", "--ports", help="Ports spécifiques à scanner (ex: 80,443,8080 ou 1-1024)")
    parser.add_argument("--top-ports", type=int, choices=[20, 100, 1000], default=100, help="Scanner les X ports les plus fréquents (défaut: 100)")
    parser.add_argument("-sV", "--service-version", action="store_true", help="Activer la détection approfondie des versions et corrélation CVE")
    parser.add_argument("-sU", "--udp", action="store_true", help="Activer le scan des ports UDP clés (DNS, SNMP, NTP, DHCP...)")
    parser.add_argument("-T", "--timing", default="3", help="Modèle de vitesse / timing : 1 (Furtif), 2 (Poli), 3 (Standard), 4 (Agressif), 5 (Insane)")
    
    # Modules OSINT & Reconnaissance avancée
    parser.add_argument("--geo", action="store_true", help="Activer la géolocalisation IP, ASN et FAI")
    parser.add_argument("--dns-audit", action="store_true", help="Audit DNS approfondi et sécurité des e-mails (SPF, DMARC, MX)")
    parser.add_argument("--web", action="store_true", help="Audit web complet (en-têtes HTTP, cookies, méthodes, fichiers exposés)")
    parser.add_argument("--ssl-audit", action="store_true", help="Audit complet des suites cryptographiques et certificats SSL/TLS")
    parser.add_argument("--traceroute", action="store_true", help="Calculer la route réseau et le nombre de sauts vers la cible")
    parser.add_argument("--subdomains", action="store_true", help="Énumération DNS des sous-domaines courants")
    parser.add_argument("-A", "--full", action="store_true", help="Mode agressif complet (Tous les modules activés simultanément)")

    # Formats de sortie
    parser.add_argument("--json", help="Sauvegarder le rapport au format JSON")
    parser.add_argument("--xml", help="Sauvegarder le rapport au format XML standard Nmap (-oX)")
    parser.add_argument("--markdown", help="Générer un rapport au format Markdown")
    parser.add_argument("--html", help="Générer un tableau de bord interactif en HTML")

    args = parser.parse_args()

    if not args.target and not args.subnet:
        parser.print_help()
        print(f"\n{Colors.RED}[!] Spécifiez une cible avec -t <cible> ou un sous-réseau avec --subnet <CIDR>{Colors.RESET}\n")
        sys.exit(1)

    timing_key = args.timing.upper()
    if not timing_key.startswith("T"):
        timing_key = f"T{timing_key}"
    if timing_key not in TIMING_PROFILES:
        timing_key = "T3"

    scan_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "target": args.target or args.subnet,
        "geolocation": {},
        "waf": [],
        "tech_stack": [],
        "dns_audit": {},
        "ports": [],
        "udp_ports": [],
        "cves": [],
        "web_audit": {},
        "ssl_audit": {},
        "traceroute": [],
        "subdomains": [],
        "subnet_hosts": []
    }

    if args.subnet:
        sub_scanner = SubnetScanner(args.subnet, timeout=TIMING_PROFILES[timing_key]["timeout"])
        scan_data["subnet_hosts"] = sub_scanner.run()

    if args.target:
        ports_to_scan = parse_ports(args.ports, args.top_ports)
        
        # 1. Géolocalisation & OSINT
        try:
            target_ip = socket.gethostbyname(args.target)
        except Exception:
            target_ip = args.target

        if args.geo or args.full:
            scan_data["geolocation"] = IPGeolocation.lookup(target_ip)

        # 2. Audit DNS & SPF / DMARC
        if (args.dns_audit or args.full) and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", args.target):
            scan_data["dns_audit"] = DNSAuditor.audit_domain(args.target)

        # 3. Scan TCP & Versions
        log_title(f"SCAN TCP & DÉTECTION DE SERVICES : {args.target}")
        ps = PortScanner(args.target, ports_to_scan, timing=timing_key, grab_banners=True)
        scan_data["ports"] = ps.run()
        scan_data["cves"] = ps.cve_findings

        # 4. Scan UDP (-sU)
        if args.udp or args.full:
            us = UDPScanner(target_ip, timeout=TIMING_PROFILES[timing_key]["timeout"])
            scan_data["udp_ports"] = us.run()

        # 5. Détection WAF & Technologies Web
        web_ports = [p["port"] for p in scan_data["ports"] if p["port"] in [80, 443, 8080, 8443, 3000, 5000, 8000]]
        if args.web or args.full or web_ports:
            scheme = "https" if 443 in web_ports or 8443 in web_ports else "http"
            url = f"{scheme}://{args.target}"
            scan_data["waf"] = WAFDetector.detect(url)
            scan_data["tech_stack"] = TechDetector.fingerprint(url)
            wa = WebAuditor(url)
            scan_data["web_audit"] = wa.run()

        # 6. Audit SSL/TLS & Découverte SAN
        if args.ssl_audit or args.full or any(p["port"] in [443, 8443] for p in scan_data["ports"]):
            scan_data["ssl_audit"] = TLSInspector.audit_tls(args.target)

        # 7. Traceroute
        if args.traceroute or args.full:
            open_port = scan_data["ports"][0]["port"] if scan_data["ports"] else 80
            scan_data["traceroute"] = NetworkTracer.trace(target_ip, port=open_port)

        # 8. Sous-domaines
        if (args.subdomains or args.full) and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", args.target):
            subs = SubdomainScanner(args.target)
            scan_data["subdomains"] = subs.run()

    # Exports
    if args.json:
        ReportGenerator.export_json(scan_data, args.json)
    if args.xml:
        ReportGenerator.export_xml(scan_data, args.xml)
    if args.markdown:
        ReportGenerator.export_markdown(scan_data, args.markdown)
    if args.html:
        ReportGenerator.export_html(scan_data, args.html)

    log_title("SCAN DSS SECURITY TERMINÉ AVEC SUCCÈS")

if __name__ == "__main__":
    main()
