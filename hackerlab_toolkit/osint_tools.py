"""
=============================================================================
  Module OSINT & Réseau - HackerLab Toolkit
=============================================================================
  Description : Calculateur de sous-réseau CIDR, résolution de constructeur OUI
                (adresses MAC) et générateur de Google Dorks de reconnaissance.
=============================================================================
"""

import ipaddress
import urllib.request
import json
import re

class OSINTToolkit:
    @staticmethod
    def calculate_cidr(cidr_str):
        """Calcule les informations détaillées d'un sous-réseau CIDR (ex: 192.168.1.0/24)."""
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            hosts = list(net.hosts())
            return {
                "network_address": str(net.network_address),
                "broadcast_address": str(net.broadcast_address),
                "netmask": str(net.netmask),
                "hostmask": str(net.hostmask),
                "total_ips": net.num_addresses,
                "usable_hosts": len(hosts),
                "first_host": str(hosts[0]) if hosts else "N/A",
                "last_host": str(hosts[-1]) if hosts else "N/A",
                "is_private": net.is_private
            }
        except Exception as e:
            return {"error": f"Format CIDR invalide : {e}"}

    @staticmethod
    def generate_dorks(domain):
        """Génère une liste de Google Dorks ciblés pour cartographier un domaine."""
        dom = domain.strip().replace("http://", "").replace("https://", "").split("/")[0]
        dorks = [
            {"name": "Fichiers de configuration & Secrets", "query": f"site:{dom} ext:env OR ext:yml OR ext:json OR ext:xml intitle:\"index of\""},
            {"name": "Documents & Sauvegardes", "query": f"site:{dom} ext:pdf OR ext:docx OR ext:xlsx OR ext:sql OR ext:bak OR ext:zip"},
            {"name": "Panneaux d'administration & Portails", "query": f"site:{dom} inurl:admin OR inurl:login OR inurl:portal OR inurl:cpanel"},
            {"name": "Répertoires indexés ouverts (Directory Listing)", "query": f"site:{dom} intitle:\"index of /\" OR \"Index of /admin\""},
            {"name": "Points d'API & Swagger", "query": f"site:{dom} inurl:api OR inurl:v1 OR inurl:v2 OR inurl:swagger OR inurl:graphql"},
            {"name": "Mots de passe & Logs exposés", "query": f"site:{dom} \"password\" OR \"user\" OR \"token\" filetype:log OR filetype:txt"}
        ]
        return dorks

    @staticmethod
    def lookup_mac_oui(mac_address):
        """Identifie le constructeur / fabricant d'une adresse MAC via son préfixe OUI."""
        clean_mac = re.sub(r"[^0-9a-fA-F]", "", mac_address)
        if len(clean_mac) < 6:
            return {"error": "Adresse MAC trop courte"}
        oui = clean_mac[:6].upper()
        
        # Base de préfixes connus couramment rencontrés en CTF
        KNOWN_OUIS = {
            "005056": "VMware, Inc.",
            "000C29": "VMware, Inc.",
            "00155D": "Microsoft Corporation (Hyper-V)",
            "080027": "Oracle Corporation (VirtualBox)",
            "525400": "QEMU / KVM Virtual NIC",
            "B827EB": "Raspberry Pi Foundation",
            "D83ADD": "Raspberry Pi Trading Ltd",
            "E45F01": "Raspberry Pi Foundation",
            "001A11": "Google, Inc.",
            "F09FC2": "Ubiquiti Networks Inc.",
            "001422": "Dell Inc.",
            "0025B5": "Cisco Systems, Inc.",
            "708105": "Apple, Inc.",
            "FCFB81": "Apple, Inc.",
            "001E8C": "Cisco Meraki",
            "443839": "Cumulus Networks, Inc."
        }

        vendor = KNOWN_OUIS.get(oui, "Constructeur Inconnu / Non indexé localement")
        return {
            "oui": oui,
            "mac": mac_address,
            "vendor": vendor,
            "is_virtual": any(v in vendor for v in ["VMware", "VirtualBox", "QEMU", "Hyper-V"])
        }
