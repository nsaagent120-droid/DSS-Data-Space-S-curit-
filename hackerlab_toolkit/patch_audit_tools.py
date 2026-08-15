"""
=============================================================================
  Module Audit de Code Source & Patch Diffing - HackerLab Toolkit
=============================================================================
  Description : Linter de sécurité statique pour code C/C++, détection de
                fonctions non sécurisées (strcpy, gets, sprintf, format string),
                et moteur de patch diffing (analyse de correctifs de sécurité).
=============================================================================
"""

import re
import difflib

class SourceCodeAuditor:
    C_DANGEROUS_FUNCS = [
        {"func": "gets", "severity": "CRITICAL", "cwe": "CWE-242", "desc": "Fonction intrinsèquement vulnérable à un Stack Buffer Overflow (jamais sécurisable).", "fix": "Remplacer par fgets(buf, sizeof(buf), stdin)"},
        {"func": "strcpy", "severity": "HIGH", "cwe": "CWE-120", "desc": "Copie sans vérification de taille de destination.", "fix": "Remplacer par strncpy(dst, src, sizeof(dst)-1) ou strlcpy"},
        {"func": "strcat", "severity": "HIGH", "cwe": "CWE-120", "desc": "Concaténation sans vérification de taille restante.", "fix": "Remplacer par strncat(dst, src, sizeof(dst)-strlen(dst)-1)"},
        {"func": "sprintf", "severity": "HIGH", "cwe": "CWE-120", "desc": "Formatage vers buffer sans limite de taille.", "fix": "Remplacer par snprintf(buf, sizeof(buf), ...)"},
        {"func": "vsprintf", "severity": "HIGH", "cwe": "CWE-120", "desc": "Formatage avec va_list sans limite de taille.", "fix": "Remplacer par vsnprintf"},
        {"func": "scanf", "pattern": r'scanf\s*\(\s*["\']%s["\']', "severity": "HIGH", "cwe": "CWE-120", "desc": "Lecture sans spécification de largeur maximale (%s).", "fix": "Spécifier la taille maximale : scanf(\"%127s\", buf)"},
        {"func": "system", "severity": "MEDIUM", "cwe": "CWE-78", "desc": "Exécution de commande shell système.", "fix": "Utiliser execve() avec arguments sous forme de tableau séparé"},
        {"func": "popen", "severity": "MEDIUM", "cwe": "CWE-78", "desc": "Ouverture d'un pipe vers une commande shell.", "fix": "Éviter les concaténations non échappées dans la chaîne de commande"},
        {"func": "alloca", "severity": "MEDIUM", "cwe": "CWE-770", "desc": "Allocation dynamique sur la pile sans vérification de dépassement.", "fix": "Utiliser malloc() avec vérification de retour NULL"}
    ]

    @classmethod
    def audit_c_code(cls, source_code):
        """Analyse statique d'un code source C/C++ pour identifier les faiblesses de sécurité."""
        findings = []
        lines = source_code.splitlines()

        for idx, line in enumerate(lines, 1):
            clean_line = line.strip()
            if clean_line.startswith("//") or clean_line.startswith("/*") or clean_line.startswith("*"):
                continue

            # 1. Fonctions dangereuses
            for rule in cls.C_DANGEROUS_FUNCS:
                pattern = rule.get("pattern", r'\b' + re.escape(rule["func"]) + r'\s*\(')
                if re.search(pattern, line):
                    findings.append({
                        "line": idx,
                        "code": clean_line,
                        "vulnerability": f"Usage de {rule['func']}() ({rule['cwe']})",
                        "severity": rule["severity"],
                        "desc": rule["desc"],
                        "remediation": rule["fix"]
                    })

            # 2. Format String Vulnerabilities : printf(user_buf) sans "%s"
            if re.search(r'\bprintf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)', line):
                findings.append({
                    "line": idx,
                    "code": clean_line,
                    "vulnerability": "Format String Vulnerability (CWE-134)",
                    "severity": "CRITICAL",
                    "desc": "printf() appelé directement avec une variable au lieu d'une chaîne de format littérale.",
                    "remediation": "Utiliser : printf(\"%s\", variable);"
                })

        return findings

    @staticmethod
    def diff_patches(original_code, patched_code):
        """Compare deux versions d'une fonction ou fichier pour identifier les correctifs de sécurité."""
        orig_lines = original_code.splitlines(keepends=True)
        patch_lines = patched_code.splitlines(keepends=True)
        diff = list(difflib.unified_diff(orig_lines, patch_lines, fromfile="vulnerable.c", tofile="patched.c"))

        added_security_checks = []
        for line in diff:
            if line.startswith("+") and not line.startswith("+++"):
                # Détection de checks de sécurité ajoutés (ex: if (len > MAX), if (ptr == NULL))
                if re.search(r'\bif\s*\(.*(<|>|==|!=|NULL|sizeof|strlen)', line):
                    added_security_checks.append(line.strip())

        return {
            "diff_text": "".join(diff),
            "security_checks_introduced": added_security_checks
        }
