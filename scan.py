#!/usr/bin/env python3
"""
=============================================================================
  DSS Ultimate Security Scanner (D-Scan) - Alternative Moderne à Nmap / Nikto
=============================================================================
  Auteur      : DSS Security / Cybersecurity Mastery Roadmap
  Description : Suite complète d'audit réseau, détection de versions (-sV),
                scan UDP (-sU), corrélation CVE, audit web OWASP, analyse TLS,
                traceroute, énumération DNS et reporting multi-formats (HTML, JSON, XML, MD).
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
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*68}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}  {msg}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*68}{Colors.RESET}\n")

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
# BASE DE DONNÉES DES PORTS & SIGNATURES DE PROTOCOLES
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
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Non chiffré)",
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
    143: "IMAP (Internet Message Access)",
    161: "SNMP (Simple Network Mgmt)",
    389: "LDAP (Directory Service)",
    443: "HTTPS (HTTP Secure / TLS)",
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
    1900: "UPnP (SSDP)",
    2049: "NFS (Network File System)",
    2181: "Apache ZooKeeper",
    2222: "SSH Alternatif",
    2375: "Docker Daemon (Insecure)",
    2376: "Docker Daemon (TLS)",
    3000: "Node.js / React / Grafana Web",
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
    8000: "HTTP Dev Server (Django/Python)",
    8080: "HTTP Proxy / Apache Tomcat",
    8443: "HTTPS Alternatif / Plesk",
    8888: "Jupyter Notebook / Web Admin",
    9000: "PHP-FPM / SonarQube / MinIO",
    9090: "Prometheus / Cockpit Web UI",
    9092: "Apache Kafka",
    9200: "Elasticsearch REST API",
    9300: "Elasticsearch Cluster",
    10000: "Webmin / Virtualmin",
    11211: "Memcached Caching DB",
    15672: "RabbitMQ Management UI",
    27017: "MongoDB NoSQL Database",
    27018: "MongoDB Shard",
    28017: "MongoDB Web Status"
}

# =============================================================================
# BASE DE DONNÉES CVE & VULNÉRABILITÉS CONNUES (CORRÉLATEUR D'AUDIT)
# =============================================================================
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
        "title": "Apache HTTPD vulnérable à des traversées de répertoires / Exécution de code distant (RCE)",
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
        "recommendation": "Mettre à jour Nginx vers la branche mainline ou stable récente (>= 1.24+)."
    },
    {
        "pattern": r"PHP/(5\.|7\.[0-3]\.)",
        "service": "PHP",
        "cve": "CVE-2019-11043 / EOL",
        "title": "Version PHP obsolète et en fin de vie (End of Life) vulnérable à l'exécution de code",
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
        "recommendation": "Mettre à jour Redis vers >= 6.2.7 ou 7.0+, activer l'authentification et lier sur 127.0.0.1."
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
# MODULE 1 : MOTEUR DE DÉTECTION APPROFONDIE DE SERVICES (-sV)
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
            
            req = b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nUser-Agent: Mozilla/5.0 DSS-Scanner/2.0\r\n\r\n"
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
                    # Test d'accès anonyme (purement passif)
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
                if len(data) > 5 and data[4] == 0x0a: # Protocol v10
                    # Version se termine au premier null-byte après l'index 5
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
        # 1. Probes spécialisés
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

        # 2. Sonde générique de repli (Banner Grabbing)
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
# MODULE 2 : CORRÉLATEUR DE VULNÉRABILITÉS & CVE
# =============================================================================
class VulnerabilityCorrelator:
    @staticmethod
    def correlate(banner_text, service_name):
        findings = []
        combined_text = f"{service_name} {banner_text}"
        for rule in CVE_KNOWLEDGE_BASE:
            if re.search(rule["pattern"], combined_text, re.IGNORECASE):
                findings.append({
                    "cve": rule["cve"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "cvss": rule["cvss"],
                    "recommendation": rule["recommendation"]
                })
        return findings

# =============================================================================
# MODULE 3 : SCANNER UDP AVEC SONDES DÉDIÉES (-sU)
# =============================================================================
class UDPScanner:
    """Scanner UDP avec sondes protocolaires authentiques pour chaque service courant."""

    UDP_PROBES = {
        53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03", # DNS version.bind query
        123: b"\x1b" + 47 * b"\0", # NTP v3 client request
        161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", # SNMPv1 get sysDescr
        137: b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01", # NetBIOS Node Status
        1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n" # SSDP UPnP
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
        except socket.timeout:
            pass
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
            log_info("Aucune réponse explicite sur les sondes UDP (les ports peuvent être filtrés ou silencieux).")
        return self.open_ports

# =============================================================================
# MODULE 4 : AUDIT SSL / TLS APPROFONDI & CHIFFREMENT
# =============================================================================
class TLSInspector:
    """Analyse exhaustive de la configuration TLS, certificats et suites cryptographiques."""

    TLS_VERSIONS = [
        ("SSLv3", getattr(ssl, "PROTOCOL_SSLv23", None), "CRITICAL", "Protocole obsolète vulnérable à POODLE"),
        ("TLS 1.0", getattr(ssl, "PROTOCOL_TLSv1", None), "HIGH", "Obsolète et déprécié par le RFC 8996 (vulnérable à BEAST)"),
        ("TLS 1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None), "HIGH", "Obsolète et déprécié"),
        ("TLS 1.2", getattr(ssl, "PROTOCOL_TLSv1_2", None), "OK", "Protocole sécurisé standard"),
        ("TLS 1.3", getattr(ssl, "PROTOCOL_TLS_CLIENT", None), "EXCELLENT", "Dernière norme TLS sécurisée et rapide")
    ]

    @staticmethod
    def audit_tls(hostname, port=443, timeout=3.0):
        log_info(f"Audit SSL/TLS approfondi sur {hostname}:{port}...")
        report = {
            "supported_protocols": [],
            "certificate": {},
            "vulnerabilities": [],
            "grade": "A"
        }

        # 1. Vérification des versions de protocole
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

        # 2. Récupération des métadonnées du certificat
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

                    if days_left is not None and days_left < 0:
                        report["vulnerabilities"].append(f"Le certificat SSL a expiré depuis {abs(days_left)} jours !")
                        report["grade"] = "F"
                    elif days_left is not None and days_left < 15:
                        report["vulnerabilities"].append(f"Le certificat SSL expire bientôt ({days_left} jours)")
        except Exception as e:
            report["certificate"] = {"error": str(e)}

        return report

# =============================================================================
# MODULE 5 : TRACEROUTE & DIAGNOSTIC DE ROUTE RÉSEAU
# =============================================================================
class NetworkTracer:
    """Estimation des sauts réseaux et latence par palier de TTL (Traceroute TCP/IP)."""

    @staticmethod
    def trace(target_ip, port=None, max_hops=15, timeout=1.0):
        log_title(f"TRACEROUTE & ANALYSE DU CHEMIN RÉSEAU : {target_ip}")
        hops = []
        # Utiliser le port fourni ou tester 80, 443, 22
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
                log_success(f"Saut {ttl:2d} : {Colors.BOLD}{target_ip}{Colors.RESET} (RTT: {rtt:.1f} ms) — [Destination atteinte]")
                s.close()
                break
            except (socket.timeout, socket.error):
                rtt = (time.time() - t_start) * 1000
                hops.append({"hop": ttl, "ip": "*", "rtt_ms": None, "status": "Pas de réponse / Saut intermédiaire"})
                log_info(f"Saut {ttl:2d} : * * * (TTL {ttl})")
            finally:
                s.close()
        return hops

# =============================================================================
# MODULE 6 : SCANNER PRINCIPAL (PORTS TCP, OS ESTIMATION, CVE MAPPING)
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
        result = sock.connect_ex((self.ip, port))
        sock.close()

        if result == 0:
            service_info = ServiceFingerprinter.identify(self.ip, port, timeout=self.timeout)
            service_name = service_info.get("protocol", SERVICES_MAP.get(port, "Inconnu"))
            banner = service_info.get("banner", "")

            # Corrélation CVE
            cves = VulnerabilityCorrelator.correlate(banner, service_name)
            for c in cves:
                c["port"] = port
                self.cve_findings.append(c)

            return {
                "port": port,
                "protocol": "tcp",
                "status": "open",
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
        
        print(f"\n{Colors.BOLD}{'PORT':<10} {'ÉTAT':<10} {'SERVICE':<28} {'BANNIÈRE & VERSION'}{Colors.RESET}")
        print(f"{'-'*75}")

        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, p): p for p in self.ports}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    self.results.append(res)
                    port_str = f"{res['port']}/tcp"
                    status_str = f"{Colors.GREEN}OUVERT{Colors.RESET}"
                    service_str = res['service'][:26]
                    banner_str = f"{Colors.DIM}{res['banner'][:36]}{Colors.RESET}" if res['banner'] else ""
                    print(f"{port_str:<10} {status_str:<19} {service_str:<28} {banner_str}")

        self.results.sort(key=lambda x: x["port"])
        elapsed = time.time() - start_time
        print(f"{'-'*75}")
        log_success(f"Scan TCP achevé en {elapsed:.2f}s — {len(self.results)} port(s) ouvert(s).")
        
        # Affichage des alertes CVE détectées
        if self.cve_findings:
            log_title(f"⚠️ VULNÉRABILITÉS & CVE IDENTIFIÉES ({len(self.cve_findings)})")
            for cve in self.cve_findings:
                color = Colors.RED if cve["severity"] == "CRITICAL" else Colors.YELLOW
                print(f"[{color}{cve['severity']}{Colors.RESET}] Port {cve['port']}/tcp : {Colors.BOLD}{cve['cve']}{Colors.RESET} (CVSS {cve['cvss']})")
                print(f"    ↳ {cve['title']}")
                print(f"    💡 Solution : {cve['recommendation']}\n")

        return self.results

# =============================================================================
# MODULE 7 : AUDITEUR WEB AVANCÉ (OWASP TOP 10, HEADERS, PATHS, CORS, COOKIES)
# =============================================================================
class WebAuditor:
    SENSITIVE_PATHS = [
        {"path": "/.git/HEAD", "type": "Git Repo Exposure", "severity": "CRITICAL", "desc": "Dépôt Git public — Téléchargement du code source possible"},
        {"path": "/.env", "type": "Secrets Exposure", "severity": "CRITICAL", "desc": "Fichier .env — Clés d'API, mots de passe de bases de données"},
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
            req = urllib.request.Request(self.url, headers={"User-Agent": "DSS-WebAuditor/2.0"})
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

        # Fuites d'informations
        for k in ["server", "x-powered-by", "x-aspnet-version"]:
            val = next((headers[h] for h in headers if h.lower() == k), None)
            if val:
                self.disclosures.append({"header": k, "value": val})
                log_warning(f"Fuite d'en-tête serveur : {Colors.YELLOW}{k}: {val}{Colors.RESET}")

        # En-têtes de sécurité
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

        # Cookies
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
# MODULE 8 : SOUS-DOMAINES & SOUS-RÉSEAUX
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
# MODULE 9 : GÉNÉRATEUR DE RAPPORTS (HTML, JSON, XML NMAP, MARKDOWN)
# =============================================================================
class ReportGenerator:
    @staticmethod
    def export_json(data, filename):
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        log_success(f"Rapport JSON : {Colors.BOLD}{filename}{Colors.RESET}")

    @staticmethod
    def export_xml(data, filename):
        """Génération d'un rapport XML compatible Nmap."""
        nmaprun = ET.Element("nmaprun", {
            "scanner": "dss-scanner",
            "version": "2.0",
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
            "# 🛡️ Rapport d'Audit & Diagnostic de Sécurité — DSS Security",
            f"> **Cible** : `{data.get('target', 'N/A')}`",
            f"> **Date** : {data.get('timestamp', datetime.utcnow().isoformat())}",
            "",
            "---",
            "## 1. 📊 Synthèse Exécutive",
            f"- **Ports TCP ouverts** : {len(data.get('ports', []))}",
            f"- **Ports UDP ouverts** : {len(data.get('udp_ports', []))}",
            f"- **Vulnérabilités / CVE détectées** : {len(data.get('cves', []))}",
            f"- **Chemins sensibles web exposés** : {len(data.get('web_audit', {}).get('sensitive_paths', []))}",
            "",
            "---",
            "## 2. 🔌 Ports et Services Réseau Identifiés",
            "| Protocole | Port | État | Service Détecté | Bannière / Version |",
            "|---|---|---|---|---|"
        ]

        for p in data.get("ports", []):
            lines.append(f"| TCP | `{p['port']}` | **{p['status'].upper()}** | {p['service']} | `{p.get('banner', '-')}` |")
        for p in data.get("udp_ports", []):
            lines.append(f"| UDP | `{p['port']}` | **{p['status'].upper()}** | {p['service']} | `{p.get('banner', '-')}` |")

        if data.get("cves"):
            lines.extend([
                "",
                "---",
                "## 3. 🚨 Vulnérabilités & CVE Détectées",
                "| Port | CVE | Criticité | CVSS | Titre | Recommandation |",
                "|---|---|---|---|---|---|"
            ])
            for c in data["cves"]:
                lines.append(f"| `{c.get('port', '-')}` | **{c['cve']}** | `{c['severity']}` | {c['cvss']} | {c['title']} | {c['recommendation']} |")

        web = data.get("web_audit", {})
        if web:
            lines.extend([
                "",
                "---",
                "## 4. 🌐 Audit de Sécurité Web (OWASP)",
                "### En-têtes HTTP de Sécurité",
                "| En-tête | Statut | Criticité | Détails |",
                "|---|---|---|---|"
            ])
            for h in web.get("headers_audit", []):
                st = "✅ Présent" if h.get("present") else "❌ Absent"
                lines.append(f"| `{h['header']}` | {st} | **{h.get('severity', 'INFO')}** | {h.get('description', h.get('value', ''))} |")

            if web.get("sensitive_paths"):
                lines.extend([
                    "",
                    "### Fichiers & Endpoints Exposés",
                    "| Chemin | Type | Criticité | Description |",
                    "|---|---|---|---|"
                ])
                for s in web["sensitive_paths"]:
                    lines.append(f"| `{s['path']}` | {s['type']} | **{s['severity']}** | {s['desc']} (HTTP {s['status']}) |")

        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        log_success(f"Rapport Markdown : {Colors.BOLD}{filename}{Colors.RESET}")

    @staticmethod
    def export_html(data, filename):
        target = data.get("target", "N/A")
        ts = data.get("timestamp", datetime.utcnow().isoformat())
        
        # Calcul du score de sécurité (sur 100)
        cve_count = len(data.get("cves", []))
        crit_count = sum(1 for c in data.get("cves", []) if c.get("severity") == "CRITICAL")
        exposed_count = len(data.get("web_audit", {}).get("sensitive_paths", []))
        
        score = max(15, 100 - (crit_count * 30) - (cve_count * 10) - (exposed_count * 10))
        score_color = "#238636" if score >= 80 else ("#d29922" if score >= 50 else "#da3633")

        ports_rows = ""
        for p in data.get("ports", []):
            ports_rows += f"""<tr>
                <td><span class="badge badge-port">{p['port']}/tcp</span></td>
                <td><span class="badge badge-open">OUVERT</span></td>
                <td><strong>{p['service']}</strong></td>
                <td><code>{p.get('banner', '-')}</code></td>
            </tr>"""
        for p in data.get("udp_ports", []):
            ports_rows += f"""<tr>
                <td><span class="badge badge-udp">{p['port']}/udp</span></td>
                <td><span class="badge badge-open">OUVERT</span></td>
                <td><strong>{p['service']}</strong></td>
                <td><code>{p.get('banner', '-')}</code></td>
            </tr>"""

        cve_rows = ""
        for c in data.get("cves", []):
            badge = "badge-crit" if c['severity'] == "CRITICAL" else "badge-warn"
            cve_rows += f"""<tr>
                <td><code>{c.get('port', '-')}/tcp</code></td>
                <td><span class="badge {badge}">{c['cve']}</span></td>
                <td><strong>{c['cvss']}</strong> ({c['severity']})</td>
                <td>{c['title']}</td>
                <td><small>{c['recommendation']}</small></td>
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
    <title>Rapport d'Audit DSS Security — {target}</title>
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
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: linear-gradient(135deg, #1c2430, #111722);
            border: 1px solid var(--border);
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            box-shadow: 0 8px 24px rgba(0,0,0,0.6);
        }}
        .score-circle {{
            text-align: center;
            padding: 1.5rem;
            border-radius: 50%;
            border: 5px solid {score_color};
            min-width: 80px;
            font-size: 2rem;
            font-weight: bold;
            color: {score_color};
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        h1 {{ margin: 0 0 0.5rem 0; color: var(--heading); }}
        h2 {{ color: var(--heading); border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin-top: 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border); }}
        th {{ background: #21262d; color: #f0f6fc; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 0.8rem; font-weight: 600; }}
        .badge-open {{ background: #238636; color: #fff; }}
        .badge-crit {{ background: #da3633; color: #fff; }}
        .badge-warn {{ background: #9e6a03; color: #fff; }}
        .badge-info {{ background: #1f6feb; color: #fff; }}
        .badge-port {{ background: #388bfd33; color: #58a6ff; border: 1px solid #388bfd66; }}
        .badge-udp {{ background: #a371f733; color: #d2a8ff; border: 1px solid #a371f766; }}
        code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: #79c0ff; }}
        .footer {{ text-align: center; margin-top: 3rem; color: #8b949e; font-size: 0.9rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ DSS Ultimate Security Scanner Report</h1>
                <p><strong>Cible :</strong> <code>{target}</code> | <strong>Date :</strong> {ts}</p>
            </div>
            <div class="score-circle">
                {score}<br><span style="font-size: 0.8rem; font-weight: normal; color: #8b949e;">Score Sec</span>
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
                    <tr><th>Port</th><th>Statut</th><th>Service</th><th>Bannière / Version</th></tr>
                </thead>
                <tbody>{ports_rows if ports_rows else '<tr><td colspan="4">Aucun port ouvert détecté</td></tr>'}</tbody>
            </table>
        </div>

        <div class="card">
            <h2>🔐 En-têtes HTTP de Sécurité</h2>
            <table>
                <thead>
                    <tr><th>En-tête</th><th>Statut</th><th>Criticité</th><th>Détails</th></tr>
                </thead>
                <tbody>{headers_rows if headers_rows else '<tr><td colspan="4">Non audité</td></tr>'}</tbody>
            </table>
        </div>

        <div class="card">
            <h2>⚠️ Chemins Sensibles & Endpoints Détectés</h2>
            <table>
                <thead>
                    <tr><th>Chemin</th><th>Type</th><th>Criticité</th><th>Détails</th></tr>
                </thead>
                <tbody>{vuln_rows if vuln_rows else '<tr><td colspan="4">Aucun fichier sensible exposé.</td></tr>'}</tbody>
            </table>
        </div>

        <div class="footer">
            <p>Généré par DSS Security Scanner — Cybersecurity Mastery Roadmap</p>
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
  {Colors.BOLD}{Colors.MAGENTA}🛡️  DSS ULTIMATE SECURITY SCANNER (D-SCAN v2.0){Colors.RESET}
  {Colors.DIM}Alternative Nmap / Nikto / SSLyze — Cybersecurity Mastery Roadmap{Colors.RESET}
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
        description="DSS Ultimate Security Scanner (D-Scan) — Audit Réseau, Détection de Versions (-sV), Scan UDP (-sU), Corrélation CVE & Audit Web OWASP.",
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
    parser.add_argument("-T", "--timing", default="3", help="Modèle de vitesse / timing : 1 (Furtif), 2 (Poli), 3 (Standard), 4 (Agressif), 5 (Insane) ou T1..T5")
    
    # Modules avancés
    parser.add_argument("--web", action="store_true", help="Audit de sécurité des applications web (en-têtes HTTP, cookies, méthodes, fichiers exposés)")
    parser.add_argument("--ssl-audit", action="store_true", help="Audit complet des suites cryptographiques et certificats SSL/TLS")
    parser.add_argument("--traceroute", action="store_true", help="Calculer la route réseau et le nombre de sauts vers la cible")
    parser.add_argument("--subdomains", action="store_true", help="Énumération DNS des sous-domaines courants")
    parser.add_argument("-A", "--full", action="store_true", help="Mode agressif complet (Ports TCP + -sV + Web + SSL + Subdomains + Traceroute)")

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

    scan_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "target": args.target or args.subnet,
        "ports": [],
        "udp_ports": [],
        "cves": [],
        "web_audit": {},
        "ssl_audit": {},
        "traceroute": [],
        "subdomains": [],
        "subnet_hosts": []
    }

    # Normalisation du timing
    timing_key = args.timing.upper()
    if not timing_key.startswith("T"):
        timing_key = f"T{timing_key}"
    if timing_key not in TIMING_PROFILES:
        timing_key = "T3"

    # 1. Sous-réseau (Ping Sweep)
    if args.subnet:
        sub_scanner = SubnetScanner(args.subnet, timeout=TIMING_PROFILES[timing_key]["timeout"])
        scan_data["subnet_hosts"] = sub_scanner.run()

    # 2. Scan sur cible
    if args.target:
        ports_to_scan = parse_ports(args.ports, args.top_ports)
        
        # Scan TCP & Versions
        log_title(f"SCAN TCP & DÉTECTION DE SERVICES : {args.target}")
        ps = PortScanner(args.target, ports_to_scan, timing=timing_key, grab_banners=True)
        scan_data["ports"] = ps.run()
        scan_data["cves"] = ps.cve_findings

        # Scan UDP (-sU)
        if args.udp or args.full:
            us = UDPScanner(ps.ip or args.target, timeout=TIMING_PROFILES[timing_key]["timeout"])
            scan_data["udp_ports"] = us.run()

        # Traceroute
        if args.traceroute or args.full:
            open_port = scan_data["ports"][0]["port"] if scan_data["ports"] else 80
            scan_data["traceroute"] = NetworkTracer.trace(ps.ip or args.target, port=open_port)

        # Audit SSL/TLS
        if args.ssl_audit or args.full or any(p["port"] in [443, 8443] for p in scan_data["ports"]):
            scan_data["ssl_audit"] = TLSInspector.audit_tls(args.target)

        # Énumération Sous-domaines
        if args.subdomains or args.full:
            if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", args.target):
                subs = SubdomainScanner(args.target)
                scan_data["subdomains"] = subs.run()

        # Audit Web
        if args.web or args.full or any(p["port"] in [80, 443, 8080, 8443, 3000, 5000, 8000] for p in scan_data["ports"]):
            wa = WebAuditor(args.target)
            scan_data["web_audit"] = wa.run()

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
