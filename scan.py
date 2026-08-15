#!/usr/bin/env python3
"""
=============================================================================
  DSS Security Scanner - Outil d'Audit et de Scan Réseau & Web
=============================================================================
  Auteur      : DSS Security / Cybersecurity Mastery Roadmap
  Description : Scanner de ports multi-threadé, analyseur de vulnérabilités web,
                reconnaissance de sous-domaines, audit SSL/TLS et découverte d'hôtes.
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
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

# =============================================================================
# COULEURS & FORMATTAGE TERMINAL
# =============================================================================
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
    BG_RED  = "\033[41m"
    BG_BLUE = "\033[44m"

def log_info(msg):
    print(f"[{Colors.CYAN}*{Colors.RESET}] {msg}")

def log_success(msg):
    print(f"[{Colors.GREEN}+{Colors.RESET}] {msg}")

def log_warning(msg):
    print(f"[{Colors.YELLOW}!{Colors.RESET}] {msg}")

def log_danger(msg):
    print(f"[{Colors.RED}-{Colors.RESET}] {msg}")

def log_title(msg):
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}  {msg}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*60}{Colors.RESET}\n")

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

SERVICES_MAP = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Non sécurisé)",
    25: "SMTP (Simple Mail Transfer)",
    53: "DNS (Domain Name System)",
    69: "TFTP (Trivial FTP)",
    80: "HTTP (Web Server)",
    110: "POP3 (Post Office Protocol)",
    111: "RPCBind",
    123: "NTP (Network Time Protocol)",
    135: "MSRPC (Microsoft RPC)",
    139: "NetBIOS Session Service",
    143: "IMAP (Internet Message Access)",
    161: "SNMP (Simple Network Management)",
    389: "LDAP (Lightweight Directory Access)",
    443: "HTTPS (HTTP Secure / SSL)",
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
    2049: "NFS (Network File System)",
    2181: "Apache ZooKeeper",
    2222: "SSH Alternatif",
    2375: "Docker Daemon (Insecure HTTP)",
    2376: "Docker Daemon (TLS)",
    3000: "Node.js / React / Grafana Dev Web",
    3306: "MySQL / MariaDB Database",
    3389: "RDP (Remote Desktop Protocol)",
    4000: "Hexo / Web Dev Server",
    4444: "Metasploit / Selenium / Listener",
    5000: "Flask / Docker Registry / UPnP",
    5432: "PostgreSQL Database",
    5672: "RabbitMQ AMQP",
    5900: "VNC Remote Desktop",
    5984: "CouchDB",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
    6379: "Redis In-Memory Database",
    7001: "Oracle WebLogic",
    8000: "HTTP Dev Server (Django, Python)",
    8080: "HTTP Proxy / Tomcat / Spring",
    8443: "HTTPS Alternatif / Plesk",
    8888: "Jupyter Notebook / HTTP Dev",
    9000: "PHP-FPM / SonarQube / MinIO",
    9090: "Prometheus / Cockpit",
    9092: "Apache Kafka",
    9200: "Elasticsearch REST API",
    9300: "Elasticsearch Cluster",
    10000: "Webmin / Network Services",
    11211: "Memcached Database",
    15672: "RabbitMQ Management UI",
    27017: "MongoDB Database",
    27018: "MongoDB Shard",
    28017: "MongoDB Web Status"
}

# Probes spécifiques pour bannière
PROBES = {
    21: b"QUIT\r\n",
    22: b"SSH-2.0-DSS_Scanner\r\n",
    23: b"\r\n",
    25: b"EHLO dss-security.local\r\n",
    80: b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: DSS-Security-Scanner/1.0\r\n\r\n",
    110: b"QUIT\r\n",
    143: b"a001 LOGOUT\r\n",
    443: b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: DSS-Security-Scanner/1.0\r\n\r\n",
    6379: b"PING\r\n",
    27017: b"\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
}

# =============================================================================
# MODULE 1 : SCANNER DE PORTS MULTI-THREADÉ
# =============================================================================
class PortScanner:
    def __init__(self, target, ports, threads=50, timeout=1.5, grab_banners=True):
        self.target = target
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.grab_banners = grab_banners
        self.ip = None
        self.hostname = None
        self.results = []
        self.ttl = None

    def resolve_target(self):
        try:
            self.ip = socket.gethostbyname(self.target)
            try:
                self.hostname = socket.gethostbyaddr(self.ip)[0]
            except (socket.herror, socket.gaierror):
                self.hostname = self.target
            return True
        except socket.gaierror as e:
            log_danger(f"Impossible de résoudre la cible '{self.target}' : {e}")
            return False

    def estimate_os(self):
        """Estimation approximative de l'OS via le TTL du socket."""
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
                return f"Linux / FreeBSD / Android / macOS (TTL ~ {self.ttl})"
            elif self.ttl <= 128:
                return f"Microsoft Windows (TTL ~ {self.ttl})"
            elif self.ttl <= 255:
                return f"Cisco Router / Solaris / Equipement Réseau (TTL ~ {self.ttl})"
        return "Indéterminé"

    def grab_banner(self, port):
        banner = ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.ip, port))

            # Si c'est du SSL/TLS
            if port in [443, 8443, 993, 995, 465]:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ss = ctx.wrap_socket(s, server_hostname=self.target)
                    ss.sendall(b"HEAD / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                    raw = ss.recv(512)
                    ss.close()
                    for line in raw.decode(errors="ignore").split("\r\n"):
                        if line.lower().startswith("server:"):
                            banner = line.strip()
                            break
                    return banner
                except Exception:
                    pass

            probe = PROBES.get(port, b"HEAD / HTTP/1.0\r\n\r\n")
            try:
                s.sendall(probe)
            except Exception:
                pass

            try:
                raw_data = s.recv(1024)
                if raw_data:
                    lines = raw_data.decode(errors="ignore").splitlines()
                    for line in lines:
                        clean_l = line.strip()
                        if clean_l and not clean_l.startswith("<!DOCTYPE") and not clean_l.startswith("<html"):
                            banner = clean_l[:80]
                            break
            except socket.timeout:
                pass
            s.close()
        except Exception:
            pass
        return banner

    def scan_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        result = sock.connect_ex((self.ip, port))
        sock.close()

        if result == 0:
            service = SERVICES_MAP.get(port, "Service Inconnu")
            banner = ""
            if self.grab_banners:
                banner = self.grab_banner(port)
            return {
                "port": port,
                "status": "open",
                "service": service,
                "banner": banner
            }
        return None

    def run(self):
        if not self.resolve_target():
            return []

        log_info(f"Cible : {Colors.BOLD}{self.target}{Colors.RESET} ({self.ip})")
        log_info(f"Nombre de ports à scanner : {len(self.ports)} | Threads : {self.threads} | Timeout : {self.timeout}s")
        os_guess = self.estimate_os()
        log_info(f"Détection d'OS présumé : {Colors.CYAN}{os_guess}{Colors.RESET}")
        print(f"\n{Colors.BOLD}{'PORT':<10} {'ÉTAT':<10} {'SERVICE':<30} {'BANNIÈRE / DÉTAILS'}{Colors.RESET}")
        print(f"{'-'*75}")

        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in self.ports}
            for future in concurrent.futures.as_completed(future_to_port):
                res = future.result()
                if res:
                    self.results.append(res)
                    port_str = f"{res['port']}/tcp"
                    status_str = f"{Colors.GREEN}OUVERT{Colors.RESET}"
                    service_str = res['service'][:28]
                    banner_str = f"{Colors.DIM}{res['banner'][:35]}{Colors.RESET}" if res['banner'] else ""
                    print(f"{port_str:<10} {status_str:<19} {service_str:<30} {banner_str}")

        self.results.sort(key=lambda x: x["port"])
        elapsed = time.time() - start_time
        print(f"{'-'*75}")
        log_success(f"Scan terminé en {elapsed:.2f}s — {len(self.results)} port(s) ouvert(s) identifié(s).")
        return self.results

# =============================================================================
# MODULE 2 : AUDITEUR WEB & VULNÉRABILITÉS (HTTP/HTTPS)
# =============================================================================
class WebScanner:
    SENSITIVE_PATHS = [
        {"path": "/.git/HEAD", "type": "Information Disclosure", "severity": "CRITICAL", "desc": "Dépôt Git exposé (Code source accessible)"},
        {"path": "/.git/config", "type": "Information Disclosure", "severity": "CRITICAL", "desc": "Configuration Git exposée"},
        {"path": "/.env", "type": "Sensitive Data Exposure", "severity": "CRITICAL", "desc": "Variables d'environnement / Clés API exposées"},
        {"path": "/.env.local", "type": "Sensitive Data Exposure", "severity": "CRITICAL", "desc": "Fichier d'environnement local"},
        {"path": "/wp-config.php.bak", "type": "Sensitive Data Exposure", "severity": "CRITICAL", "desc": "Sauvegarde de configuration WordPress"},
        {"path": "/config.json", "type": "Configuration", "severity": "HIGH", "desc": "Fichier de configuration applicatif"},
        {"path": "/config.php.bak", "type": "Configuration Backup", "severity": "HIGH", "desc": "Sauvegarde de configuration PHP"},
        {"path": "/phpinfo.php", "type": "Information Disclosure", "severity": "MEDIUM", "desc": "Page phpinfo() exposant l'environnement serveur"},
        {"path": "/server-status", "type": "Information Disclosure", "severity": "MEDIUM", "desc": "Apache server-status accessible"},
        {"path": "/.DS_Store", "type": "Information Disclosure", "severity": "LOW", "desc": "Fichier macOS DS_Store (Fuite de structure)"},
        {"path": "/robots.txt", "type": "Reconnaissance", "severity": "INFO", "desc": "Fichier robots.txt disponible"},
        {"path": "/sitemap.xml", "type": "Reconnaissance", "severity": "INFO", "desc": "Plan de site sitemap.xml disponible"},
        {"path": "/admin/", "type": "Admin Interface", "severity": "MEDIUM", "desc": "Interface d'administration potentielle"},
        {"path": "/admin/login", "type": "Admin Interface", "severity": "MEDIUM", "desc": "Mire d'authentification admin"},
        {"path": "/backup.zip", "type": "Backup Exposure", "severity": "HIGH", "desc": "Archive de sauvegarde ZIP exposée"},
        {"path": "/backup.tar.gz", "type": "Backup Exposure", "severity": "HIGH", "desc": "Archive de sauvegarde TAR exposée"},
        {"path": "/api/docs", "type": "API Documentation", "severity": "LOW", "desc": "Documentation Swagger / OpenAPI"},
        {"path": "/swagger.json", "type": "API Definition", "severity": "LOW", "desc": "Spécification d'API Swagger"},
        {"path": "/actuator/health", "type": "Spring Actuator", "severity": "MEDIUM", "desc": "Endpoint Spring Boot Actuator"},
        {"path": "/actuator/env", "type": "Spring Actuator", "severity": "CRITICAL", "desc": "Spring Boot Env (Fuite de tokens)"}
    ]

    SECURITY_HEADERS = [
        {"name": "Strict-Transport-Security", "required": True, "severity": "HIGH", "desc": "HSTS force l'utilisation sécurisée de HTTPS."},
        {"name": "Content-Security-Policy", "required": True, "severity": "HIGH", "desc": "CSP protège contre les attaques XSS et les injections de données."},
        {"name": "X-Frame-Options", "required": True, "severity": "MEDIUM", "desc": "Protège contre le Clickjacking (UI Redressing)."},
        {"name": "X-Content-Type-Options", "required": True, "severity": "MEDIUM", "desc": "Empêche le MIME-sniffing malveillant ('nosniff')."},
        {"name": "Referrer-Policy", "required": False, "severity": "LOW", "desc": "Contrôle les informations transmises dans l'en-tête Referer."},
        {"name": "Permissions-Policy", "required": False, "severity": "LOW", "desc": "Restreint l'accès aux API du navigateur (caméra, géoloc...)."}
    ]

    def __init__(self, url, timeout=4.0):
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        self.base_url = url.rstrip("/")
        self.timeout = timeout
        self.findings = []
        self.headers_audit = []
        self.disclosures = []
        self.ssl_info = {}

    def run_all(self):
        log_title(f"AUDIT DE SÉCURITÉ WEB : {self.base_url}")
        self.check_ssl()
        self.audit_security_headers()
        self.audit_http_methods()
        self.audit_sensitive_paths()
        self.check_cors()
        return {
            "ssl_info": self.ssl_info,
            "headers_audit": self.headers_audit,
            "disclosures": self.disclosures,
            "sensitive_paths": self.findings
        }

    def check_ssl(self):
        parsed = urllib.parse.urlparse(self.base_url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else None)

        if parsed.scheme != "https" and port != 443:
            log_warning("La cible n'utilise pas HTTPS par défaut.")
            self.ssl_info = {"status": "Non-HTTPS", "details": "Connexion HTTP en clair non chiffrée"}
            return

        log_info(f"Inspection du certificat SSL/TLS pour {hostname}...")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port or 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Récupération des infos certificat
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    not_after = cert.get('notAfter')
                    
                    days_left = None
                    if not_after:
                        exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp_date - datetime.utcnow()).days

                    self.ssl_info = {
                        "status": "Valide" if (days_left is None or days_left > 0) else "Expiré",
                        "subject": subject.get('commonName', 'N/A'),
                        "issuer": issuer.get('organizationName', issuer.get('commonName', 'N/A')),
                        "expires": not_after,
                        "days_remaining": days_left,
                        "tls_version": version,
                        "cipher_suite": cipher[0] if cipher else "N/A"
                    }

                    log_success(f"Certificat SSL : Émis pour {Colors.BOLD}{self.ssl_info['subject']}{Colors.RESET} par {self.ssl_info['issuer']}")
                    log_info(f"Protocole : {version} | Suite de chiffrement : {self.ssl_info['cipher_suite']}")
                    if days_left is not None:
                        if days_left < 15:
                            log_danger(f"Attention : Le certificat expire dans {days_left} jours !")
                        else:
                            log_info(f"Validité restante : {days_left} jours (Expire le {not_after})")
        except Exception as e:
            log_warning(f"Impossible d'analyser le certificat SSL/TLS : {e}")
            self.ssl_info = {"status": "Erreur", "error": str(e)}

    def audit_security_headers(self):
        log_info("Vérification des en-têtes HTTP de sécurité...")
        try:
            req = urllib.request.Request(
                self.base_url,
                headers={"User-Agent": "Mozilla/5.0 (Security Auditor - DSS Security)"}
            )
            # Ignorer la validation SSL pour l'audit brut
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as response:
                headers = dict(response.headers)
        except urllib.error.HTTPError as e:
            headers = dict(e.headers)
        except Exception as e:
            log_danger(f"Erreur de connexion HTTP : {e}")
            return

        # Fuite d'informations (Server, X-Powered-By)
        for h in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
            val = next((headers[k] for k in headers if k.lower() == h), None)
            if val:
                self.disclosures.append({"header": h, "value": val})
                log_warning(f"Divulgation de bannière serveur : {Colors.YELLOW}{h}: {val}{Colors.RESET}")

        # En-têtes de protection
        print(f"\n{Colors.BOLD}{'EN-TÊTE DE SÉCURITÉ':<32} {'STATUT':<15} {'NIVEAU DE RISQUE'}{Colors.RESET}")
        print(f"{'-'*65}")
        for rule in self.SECURITY_HEADERS:
            h_name = rule["name"]
            found_val = next((headers[k] for k in headers if k.lower() == h_name.lower()), None)
            
            if found_val:
                status_str = f"{Colors.GREEN}PRÉSENT{Colors.RESET}"
                self.headers_audit.append({"header": h_name, "present": True, "value": found_val, "severity": "OK"})
                print(f"{h_name:<32} {status_str:<24} {Colors.GREEN}Conforme{Colors.RESET}")
            else:
                sev_color = Colors.RED if rule["severity"] == "HIGH" else Colors.YELLOW
                status_str = f"{sev_color}ABSENT{Colors.RESET}"
                self.headers_audit.append({"header": h_name, "present": False, "severity": rule["severity"], "description": rule["desc"]})
                print(f"{h_name:<32} {status_str:<24} {sev_color}{rule['severity']}{Colors.RESET}")

    def audit_http_methods(self):
        log_info("Audit des méthodes HTTP non sécurisées (OPTIONS, TRACE, PUT, DELETE)...")
        methods_to_test = ["OPTIONS", "TRACE", "PUT", "DELETE"]
        enabled_methods = []
        for method in methods_to_test:
            try:
                req = urllib.request.Request(self.base_url, method=method, headers={"User-Agent": "DSS-Security"})
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as res:
                    if res.status in [200, 204]:
                        enabled_methods.append(method)
                        if method in ["TRACE", "PUT", "DELETE"]:
                            log_danger(f"Méthode HTTP potentiellement risquée acceptée : {Colors.RED}{method} ({res.status}){Colors.RESET}")
            except urllib.error.HTTPError as e:
                if e.code in [200, 204]:
                    enabled_methods.append(method)
            except Exception:
                pass
        if not enabled_methods:
            log_success("Méthodes HTTP à risque désactivées ou protégées.")

    def check_cors(self):
        try:
            req = urllib.request.Request(
                self.base_url,
                headers={"Origin": "https://evil-attacker.com", "User-Agent": "DSS-Security"}
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as res:
                acao = res.headers.get("Access-Control-Allow-Origin")
                acac = res.headers.get("Access-Control-Allow-Credentials")
                if acao == "*" or acao == "https://evil-attacker.com":
                    log_danger(f"Mauvaise configuration CORS détectée : ACAO = {acao} (Credentials: {acac})")
        except Exception:
            pass

    def check_path(self, item):
        url = self.base_url + item["path"]
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; DSS-Security-Audit/1.0)"}
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as response:
                status = response.status
                length = len(response.read(1024))
                if status in [200, 206]:
                    return {
                        "path": item["path"],
                        "url": url,
                        "status": status,
                        "size": length,
                        "type": item["type"],
                        "severity": item["severity"],
                        "desc": item["desc"]
                    }
        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                return {
                    "path": item["path"],
                    "url": url,
                    "status": e.code,
                    "size": 0,
                    "type": item["type"] + " (Protégé)",
                    "severity": "LOW",
                    "desc": f"Ressource détectée mais protégée (HTTP {e.code})"
                }
        except Exception:
            pass
        return None

    def audit_sensitive_paths(self):
        log_info(f"Recherche de fichiers sensibles et interfaces d'administration ({len(self.SENSITIVE_PATHS)} chemins)...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(self.check_path, self.SENSITIVE_PATHS))

        for res in results:
            if res:
                self.findings.append(res)
                sev = res["severity"]
                color = Colors.RED if sev == "CRITICAL" else (Colors.YELLOW if sev in ["HIGH", "MEDIUM"] else Colors.CYAN)
                log_danger(f"[{color}{sev}{Colors.RESET}] Trouvé : {Colors.BOLD}{res['path']}{Colors.RESET} (HTTP {res['status']}) - {res['desc']}")

        if not self.findings:
            log_success("Aucun fichier sensible standard exposé publiquement.")

# =============================================================================
# MODULE 3 : SCAN DE SOUS-DOMAINES
# =============================================================================
class SubdomainScanner:
    TOP_SUBDOMAINS = [
        "www", "mail", "ftp", "admin", "webmail", "smtp", "pop", "ns1", "ns2",
        "api", "dev", "test", "staging", "beta", "vpn", "portal", "secure",
        "cloud", "app", "git", "gitlab", "github", "jira", "confluence",
        "auth", "login", "sso", "cdn", "static", "m", "mobile", "shop",
        "direct", "remote", "server", "dns", "monitor", "grafana", "kibana",
        "jenkins", "ci", "docker", "k8s", "cpanel", "whm", "autodiscover"
    ]

    def __init__(self, domain, threads=20):
        self.domain = domain
        self.threads = threads
        self.found = []

    def check_sub(self, sub):
        fqdn = f"{sub}.{self.domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return {"subdomain": fqdn, "ip": ip}
        except Exception:
            return None

    def run(self):
        log_title(f"ÉNUMÉRATION DES SOUS-DOMAINES : {self.domain}")
        log_info(f"Test de {len(self.TOP_SUBDOMAINS)} sous-domaines courants avec {self.threads} threads...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.check_sub, sub) for sub in self.TOP_SUBDOMAINS]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    self.found.append(res)
                    log_success(f"Sous-domaine actif : {Colors.BOLD}{res['subdomain']:<30}{Colors.RESET} -> {Colors.CYAN}{res['ip']}{Colors.RESET}")
        
        log_info(f"Total sous-domaines découverts : {len(self.found)}")
        return self.found

# =============================================================================
# MODULE 4 : SCANNER DE SOUS-RÉSEAU / PING SWEEP
# =============================================================================
class SubnetScanner:
    def __init__(self, cidr, threads=50, timeout=1.0):
        self.cidr = cidr
        self.threads = threads
        self.timeout = timeout
        self.alive_hosts = []

    def ping_host(self, ip_str):
        # On tente une connexion rapide sur les ports communs 80, 443, 22, 445, 135
        probe_ports = [80, 443, 22, 445, 135, 8080]
        for p in probe_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                if s.connect_ex((ip_str, p)) == 0:
                    s.close()
                    try:
                        host = socket.gethostbyaddr(ip_str)[0]
                    except Exception:
                        host = "N/A"
                    return {"ip": ip_str, "status": "up", "hostname": host, "open_probe_port": p}
                s.close()
            except Exception:
                pass
        return None

    def run(self):
        log_title(f"DÉCOUVERTE D'HÔTES RÉSEAU : {self.cidr}")
        try:
            net = ipaddress.ip_network(self.cidr, strict=False)
            hosts = [str(ip) for ip in net.hosts()]
        except Exception as e:
            log_danger(f"Format CIDR invalide : {e}")
            return []

        log_info(f"Balayage de {len(hosts)} adresses IP sur le sous-réseau...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.ping_host, ip) for ip in hosts]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    self.alive_hosts.append(res)
                    log_success(f"Hôte actif trouvé : {Colors.BOLD}{res['ip']:<18}{Colors.RESET} ({res['hostname']}) via port {res['open_probe_port']}")

        log_info(f"Total hôtes actifs découverts : {len(self.alive_hosts)}")
        return self.alive_hosts

# =============================================================================
# MODULE 5 : GÉNÉRATEUR DE RAPPORTS (JSON / MARKDOWN / HTML)
# =============================================================================
class ReportGenerator:
    @staticmethod
    def export_json(data, filename):
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        log_success(f"Rapport JSON exporté avec succès dans : {Colors.BOLD}{filename}{Colors.RESET}")

    @staticmethod
    def export_markdown(data, filename):
        lines = [
            f"# 🛡️ Rapport d'Audit & Scan de Sécurité - DSS Scanner",
            f"> Date du scan : {data.get('timestamp', datetime.utcnow().isoformat())}",
            f"> Cible : `{data.get('target', 'N/A')}`",
            "",
            "---",
            "## 1. 📊 Synthèse Globale",
            f"- **Cible analysée** : {data.get('target')}",
            f"- **Ports ouverts** : {len(data.get('ports', []))}",
            f"- **Sous-domaines découverts** : {len(data.get('subdomains', []))}",
            f"- **Vulnérabilités / Fichiers exposés** : {len(data.get('web_audit', {}).get('sensitive_paths', []))}",
            "",
            "---",
            "## 2. 🔌 Ports et Services Découverts",
            "| Port | État | Service | Bannière / Détails |",
            "|---|---|---|---|"
        ]
        for p in data.get("ports", []):
            lines.append(f"| `{p['port']}/tcp` | **{p['status'].upper()}** | {p['service']} | `{p.get('banner', 'N/A')}` |")
        
        if not data.get("ports"):
            lines.append("| *Aucun port détecté* | - | - | - |")

        # Section Web
        web = data.get("web_audit", {})
        if web:
            lines.extend([
                "",
                "---",
                "## 3. 🌐 Audit Web & Vulnérabilités",
                "### 🔐 En-têtes HTTP de Sécurité",
                "| En-tête | Statut | Risque | Description |",
                "|---|---|---|---|"
            ])
            for h in web.get("headers_audit", []):
                st = "✅ Présent" if h.get("present") else "❌ Absent"
                lines.append(f"| `{h['header']}` | {st} | **{h.get('severity', 'INFO')}** | {h.get('description', h.get('value', ''))} |")

            lines.extend([
                "",
                "### ⚠️ Fichiers Sensibles & Endpoints Exposés",
                "| Chemin | Type | Criticité | Description |",
                "|---|---|---|---|"
            ])
            for s in web.get("sensitive_paths", []):
                lines.append(f"| `{s['path']}` | {s['type']} | **{s['severity']}** | {s['desc']} (HTTP {s['status']}) |")

            if not web.get("sensitive_paths"):
                lines.append("| *Aucune exposition détectée* | - | - | - |")

        # Section Sous-domaines
        if data.get("subdomains"):
            lines.extend([
                "",
                "---",
                "## 4. 🌐 Sous-domaines Découverts",
                "| FQDN | Adresse IP |",
                "|---|---|"
            ])
            for sub in data["subdomains"]:
                lines.append(f"| `{sub['subdomain']}` | `{sub['ip']}` |")

        lines.extend([
            "",
            "---",
            "## 💡 Recommandations de Remédiation",
            "1. **Fermer les ports inutiles** et restreindre l'accès par pare-feu (ex: iptables/UFW).",
            "2. **Ajouter les en-têtes de sécurité HTTP** (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`).",
            "3. **Supprimer ou bloquer l'accès aux fichiers sensibles** (`.git/`, `.env`, sauvegardes `.bak`/`.zip`).",
            "4. **Désactiver la divulgation d'en-têtes de version** (`ServerTokens Prod`, `expose_php = Off`).",
            "",
            "*Généré par DSS Security Scanner — Cybersecurity Mastery Roadmap*"
        ])

        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        log_success(f"Rapport Markdown exporté dans : {Colors.BOLD}{filename}{Colors.RESET}")

    @staticmethod
    def export_html(data, filename):
        target = data.get("target", "N/A")
        ts = data.get("timestamp", datetime.utcnow().isoformat())
        ports_rows = ""
        for p in data.get("ports", []):
            ports_rows += f"""<tr>
                <td><span class="badge badge-port">{p['port']}/tcp</span></td>
                <td><span class="badge badge-open">OUVERT</span></td>
                <td><strong>{p['service']}</strong></td>
                <td><code>{p.get('banner', '-')}</code></td>
            </tr>"""

        headers_rows = ""
        for h in data.get("web_audit", {}).get("headers_audit", []):
            badge = "badge-open" if h.get("present") else ("badge-crit" if h.get("severity") == "HIGH" else "badge-warn")
            st = "PRÉSENT" if h.get("present") else "ABSENT"
            headers_rows += f"""<tr>
                <td><code>{h['header']}</code></td>
                <td><span class="badge {badge}">{st}</span></td>
                <td><span class="badge {badge}">{h.get('severity', 'INFO')}</span></td>
                <td>{h.get('description', h.get('value', ''))}</td>
            </tr>"""

        vuln_rows = ""
        for s in data.get("web_audit", {}).get("sensitive_paths", []):
            badge = "badge-crit" if s['severity'] == "CRITICAL" else ("badge-warn" if s['severity'] == "HIGH" else "badge-info")
            vuln_rows += f"""<tr>
                <td><code>{s['path']}</code></td>
                <td>{s['type']}</td>
                <td><span class="badge {badge}">{s['severity']}</span></td>
                <td>{s['desc']} (HTTP {s['status']})</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport DSS Security - {target}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --heading: #58a6ff;
            --accent: #2ea043;
            --danger: #f85149;
            --warning: #d29922;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 2rem;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1f2937, #111827);
            border: 1px solid var(--border);
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        }}
        .header h1 {{ margin: 0 0 0.5rem 0; color: var(--heading); }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        h2 {{ color: var(--heading); border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin-top: 0; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}
        th, td {{
            text-align: left;
            padding: 10px 14px;
            border-bottom: 1px solid var(--border);
        }}
        th {{ background: #21262d; color: #f0f6fc; }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 600;
        }}
        .badge-open {{ background: #238636; color: #fff; }}
        .badge-crit {{ background: #da3633; color: #fff; }}
        .badge-warn {{ background: #9e6a03; color: #fff; }}
        .badge-info {{ background: #1f6feb; color: #fff; }}
        .badge-port {{ background: #388bfd33; color: #58a6ff; border: 1px solid #388bfd66; }}
        code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: #79c0ff; }}
        .footer {{ text-align: center; margin-top: 3rem; color: #8b949e; font-size: 0.9rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ DSS Security Scanner Report</h1>
            <p><strong>Cible :</strong> <code>{target}</code> | <strong>Date du scan :</strong> {ts}</p>
        </div>

        <div class="card">
            <h2>🔌 Ports & Services Réseau Détectés</h2>
            <table>
                <thead>
                    <tr><th>Port</th><th>Statut</th><th>Service</th><th>Bannière</th></tr>
                </thead>
                <tbody>
                    {ports_rows if ports_rows else '<tr><td colspan="4">Aucun port ouvert détecté</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>🔐 Audit des En-têtes HTTP de Sécurité</h2>
            <table>
                <thead>
                    <tr><th>En-tête</th><th>Statut</th><th>Criticité</th><th>Détails</th></tr>
                </thead>
                <tbody>
                    {headers_rows if headers_rows else '<tr><td colspan="4">Non audité</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>⚠️ Vulnérabilités & Fichiers Sensibles Exposés</h2>
            <table>
                <thead>
                    <tr><th>Chemin</th><th>Type</th><th>Criticité</th><th>Description</th></tr>
                </thead>
                <tbody>
                    {vuln_rows if vuln_rows else '<tr><td colspan="4">Aucun fichier sensible exposé détecté.</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>DSS Security Scanner — Cybersecurity Mastery Roadmap</p>
        </div>
    </div>
</body>
</html>"""
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        log_success(f"Rapport HTML interactif exporté dans : {Colors.BOLD}{filename}{Colors.RESET}")

# =============================================================================
# POINT D'ENTRÉE PRINCIPAL (CLI)
# =============================================================================
def banner():
    art = f"""
{Colors.BOLD}{Colors.CYAN}  ██████╗ ███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║  ██║███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║
  ██║  ██║╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║
  ██████╔╝███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═════╝ ╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{Colors.RESET}
  {Colors.MAGENTA}🛡️  DSS Security Scanner — Audit Réseau & Vulnérabilités Web{Colors.RESET}
  {Colors.DIM}Cybersecurity Mastery Roadmap (De zéro à expert){Colors.RESET}
"""
    print(art)

def parse_ports(port_arg, top_arg):
    if port_arg:
        ports = set()
        for part in port_arg.split(","):
            part = part.strip()
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.update(range(start, end + 1))
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
        description="DSS Security Scanner — Scanner de vulnérabilités, ports et sécurité web.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-t", "--target", help="Cible à analyser (ex: 192.168.1.1, scanme.nmap.org, example.com)")
    parser.add_argument("-p", "--ports", help="Ports spécifiques à scanner (ex: 80,443,8080 ou 1-1024)")
    parser.add_argument("--top-ports", type=int, choices=[20, 100, 1000], default=100, help="Scanner les X ports les plus fréquents (défaut: 100)")
    parser.add_argument("--all-ports", action="store_true", help="Scanner tous les ports de 1 à 65535 (attention : peut prendre du temps)")
    parser.add_argument("--threads", type=int, default=50, help="Nombre de threads concurrents (défaut: 50)")
    parser.add_argument("--timeout", type=float, default=1.5, help="Timeout des connexions réseau en secondes (défaut: 1.5)")
    parser.add_argument("--web", action="store_true", help="Activer l'audit web approfondi (en-têtes HTTP, SSL, fichiers sensibles)")
    parser.add_argument("--subdomains", action="store_true", help="Activer l'énumération des sous-domaines")
    parser.add_argument("--subnet", help="Effectuer un balayage de sous-réseau CIDR (ex: 192.168.1.0/24)")
    parser.add_argument("--json", help="Sauvegarder les résultats dans un fichier JSON")
    parser.add_argument("--markdown", help="Générer un rapport complet en Markdown")
    parser.add_argument("--html", help="Générer un rapport interactif moderne en HTML")
    parser.add_argument("--full", action="store_true", help="Activer tous les modules de scan (ports, web, sous-domaines)")

    args = parser.parse_args()

    if not args.target and not args.subnet:
        parser.print_help()
        print(f"\n{Colors.RED}[!] Veuillez spécifier une cible avec -t <cible> ou un sous-réseau avec --subnet <CIDR>{Colors.RESET}\n")
        sys.exit(1)

    scan_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "target": args.target or args.subnet,
        "ports": [],
        "web_audit": {},
        "subdomains": [],
        "subnet_hosts": []
    }

    # 1. Scan de sous-réseau
    if args.subnet:
        sub_scanner = SubnetScanner(args.subnet, threads=args.threads, timeout=args.timeout)
        scan_data["subnet_hosts"] = sub_scanner.run()

    # 2. Scan de ports
    if args.target:
        if args.all_ports:
            ports_to_scan = list(range(1, 65536))
        else:
            ports_to_scan = parse_ports(args.ports, args.top_ports)

        log_title(f"SCAN DE PORTS & SERVICES : {args.target}")
        ps = PortScanner(args.target, ports_to_scan, threads=args.threads, timeout=args.timeout)
        scan_data["ports"] = ps.run()

        # 3. Énumération de sous-domaines
        if args.subdomains or args.full:
            # Ne tester les sous-domaines que si ce n'est pas une IP pure
            if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", args.target):
                sub_scanner = SubdomainScanner(args.target, threads=min(args.threads, 30))
                scan_data["subdomains"] = sub_scanner.run()

        # 4. Audit Web
        if args.web or args.full or any(p["port"] in [80, 443, 8080, 8443, 3000, 5000, 8000] for p in scan_data["ports"]):
            ws = WebScanner(args.target, timeout=args.timeout * 2)
            scan_data["web_audit"] = ws.run_all()

    # Export des rapports
    if args.json:
        ReportGenerator.export_json(scan_data, args.json)
    if args.markdown:
        ReportGenerator.export_markdown(scan_data, args.markdown)
    if args.html:
        ReportGenerator.export_html(scan_data, args.html)

    log_title("FIN DU SCAN DSS SECURITY")
    print(f"{Colors.GREEN}Scan complété avec succès pour {args.target or args.subnet}.{Colors.RESET}\n")

if __name__ == "__main__":
    main()
