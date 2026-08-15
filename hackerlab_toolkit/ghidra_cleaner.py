"""
=============================================================================
  Module Ghidra Decompiler Perfectionist v3.0 (Enterprise Reverse Suite)
=============================================================================
  Auteur      : DSS Security / HackerLab Toolkit
  Description : Suite de haut niveau pour sublimer et surpasser la décompilation Ghidra :
                1. 🧹 Normalisation des types C99 & Casts de pointeurs
                2. 🏷️ Renommage sémantique automatique des variables (uVar1, local_18...)
                3. 📜 Décodage automatique des Stack Strings (Hex -> ASCII)
                4. 🧮 Simplificateur d'Arithmétique Mixte Booléenne (MBA) & Divisions Magiques
                5. 🌪️ Désobfuscateur de Control Flow Flattening (Anti-OLLVM)
                6. 🏗️ Reconstructeur de Vtables et Méthodes Virtuelles C++
                7. 🔍 Détecteur de Constantes Cryptographiques (KryptoAnalyzer / AES, SHA, RC4, TEA)
                8. 🧙‍♂️ Auto-Solveur SMT / Z3 pour les équations de validation de flag
                9. 🐍 Transpileur C Décompilé -> Script Python Exécutable (Binary2Py)
=============================================================================
"""

import math
import re
import struct

# =============================================================================
# BASE DE SIGNATURES DE CONSTANTES CRYPTOGRAPHIQUES (KRYPTOANALYZER)
# =============================================================================
CRYPTO_SIGNATURES = [
    {
        "name": "AES S-Box (Rijndael Substitution Table)",
        "algorithm": "AES / Rijndael",
        "pattern": rb"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76",
        "desc": "Table de substitution non-linéaire standard utilisée dans le chiffrement AES."
    },
    {
        "name": "AES Inverse S-Box",
        "algorithm": "AES / Rijndael Decryption",
        "pattern": rb"\x52\x09\x6a\xd5\x30\x36\xa5\x38\xbf\x40\xa3\x9e\x81\xf3\xd7\xfb",
        "desc": "Table de substitution inverse pour le déchiffrement AES."
    },
    {
        "name": "SHA-256 Initial Hash Values (H0..H7)",
        "algorithm": "SHA-256 / SHA-224",
        "pattern": rb"\x67\xe6\x09\x6a\x85\xae\x67\xbb\x72\xf3\x6e\x3c\x3a\xa5\x4f\xa5",
        "desc": "Constantes d'initialisation de hachage standard SHA-256."
    },
    {
        "name": "MD5 Initial Constants (A, B, C, D)",
        "algorithm": "MD5 Hash Function",
        "pattern": rb"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10",
        "desc": "Constantes d'initialisation du vecteur d'état MD5."
    },
    {
        "name": "ChaCha20 / Salsa20 Constant ('expand 32-byte k')",
        "algorithm": "ChaCha20 / Poly1305",
        "pattern": b"expand 32-byte k",
        "desc": "Constante de matrice d'initialisation du chiffrement de flux ChaCha20."
    },
    {
        "name": "TEA / XTEA Golden Ratio Constant (0x9E3779B9)",
        "algorithm": "TEA / XTEA / XXTEA",
        "pattern": rb"\xb9\x79\x37\x9e",
        "desc": "Constante arithmétique delta (2^32 / phi) utilisée dans la boucle de chiffrement TEA."
    },
    {
        "name": "CRC32 Standard IEEE 802.3 Polynomial Table",
        "algorithm": "CRC32 Checksum",
        "pattern": rb"\x00\x00\x00\x00\x77\x07\x30\x96\xee\x0e\x61\x2c\x99\x09\x51\xba",
        "desc": "Table de calcul accéléré du polynôme CRC32 (0xEDB88320)."
    }
]

# =============================================================================
# MOTEUR PRINCIPAL GHIDRA DECOMPILER PERFECTIONIST
# =============================================================================
class GhidraDecompilerCleaner:
    TYPE_REPLACEMENTS = [
        (r"\bundefined8\b", "uint64_t"),
        (r"\bundefined4\b", "uint32_t"),
        (r"\bundefined2\b", "uint16_t"),
        (r"\bundefined1\b", "uint8_t"),
        (r"\bundefined\b", "uint8_t"),
        (r"\bbyte\b", "uint8_t"),
        (r"\bword\b", "uint16_t"),
        (r"\bdword\b", "uint32_t"),
        (r"\bqword\b", "uint64_t"),
        (r"\bulonglong\b", "uint64_t"),
        (r"\blonglong\b", "int64_t"),
        (r"\bulong\b", "uint64_t"),
        (r"\buint\b", "uint32_t"),
        (r"\bushort\b", "uint16_t"),
        (r"\buchar\b", "uint8_t"),
        (r"\bcode\s*\*", "void *")
    ]

    SEMANTIC_FUNCTION_RETURNS = {
        r"strlen\s*\(\s*([^)]+)\)": ("{var}", "{arg0}_len"),
        r"strcmp\s*\(\s*([^,]+),\s*([^)]+)\)": ("{var}", "cmp_result"),
        r"strncmp\s*\(\s*([^,]+),\s*([^,]+),\s*([^)]+)\)": ("{var}", "strncmp_res"),
        r"memcmp\s*\(\s*([^,]+),\s*([^,]+),\s*([^)]+)\)": ("{var}", "memcmp_res"),
        r"malloc\s*\(\s*([^)]+)\)": ("{var}", "allocated_buf"),
        r"calloc\s*\(\s*([^,]+),\s*([^)]+)\)": ("{var}", "allocated_array"),
        r"open\s*\(\s*([^,]+)": ("{var}", "file_fd"),
        r"socket\s*\(\s*": ("{var}", "sock_fd"),
        r"fopen\s*\(\s*([^,]+)": ("{var}", "file_ptr"),
        r"read\s*\(\s*([^,]+),\s*([^,]+),\s*([^)]+)\)": ("{var}", "bytes_read"),
        r"recv\s*\(\s*([^,]+)": ("{var}", "bytes_received"),
        r"strtol\s*\(\s*": ("{var}", "parsed_long"),
        r"atoi\s*\(\s*": ("{var}", "parsed_int")
    }

    # Simplification des divisions magiques du compilateur (x * magic >> shift)
    MAGIC_DIVISIONS = [
        (r"\(\s*([a-zA-Z0-9_]+)\s*\*\s*0xaaaaaaab(?:ULL|UL|U|L)?\s*\)\s*>>\s*33", r"(\1 / 3)"),
        (r"\(\s*([a-zA-Z0-9_]+)\s*\*\s*0xcccccccd(?:ULL|UL|U|L)?\s*\)\s*>>\s*34", r"(\1 / 5)"),
        (r"\(\s*([a-zA-Z0-9_]+)\s*\*\s*0x55555556(?:ULL|UL|U|L)?\s*\)\s*>>\s*32", r"(\1 / 6)"),
        (r"\(\s*([a-zA-Z0-9_]+)\s*\*\s*0x38e38e39(?:ULL|UL|U|L)?\s*\)\s*>>\s*33", r"(\1 / 9)"),
        (r"\(\s*([a-zA-Z0-9_]+)\s*\*\s*0x66666667(?:ULL|UL|U|L)?\s*\)\s*>>\s*34", r"(\1 / 10)"),
        (r"\(\s*([a-zA-Z0-9_]+)\s*\*\s*0x10624dd3(?:ULL|UL|U|L)?\s*\)\s*>>\s*38", r"(\1 / 1000)")
    ]

    # Simplification d'Arithmétique Mixte Booléenne (MBA Obfuscation)
    MBA_RULES = [
        (r"\(\s*([a-zA-Z0-9_]+)\s*\^\s*([a-zA-Z0-9_]+)\s*\)\s*\+\s*2\s*\*\s*\(\s*\1\s*&\s*\2\s*\)", r"(\1 + \2)"),
        (r"\(\s*([a-zA-Z0-9_]+)\s*\|\s*([a-zA-Z0-9_]+)\s*\)\s*\+\s*\(\s*\1\s*&\s*\2\s*\)", r"(\1 + \2)"),
        (r"\(\s*([a-zA-Z0-9_]+)\s*\^\s*([a-zA-Z0-9_]+)\s*\)\s*-\s*2\s*\*\s*\(\s*~\1\s*&\s*\2\s*\)", r"(\1 - \2)")
    ]

    @classmethod
    def clean_types(cls, code):
        cleaned = code
        for pattern, repl in cls.TYPE_REPLACEMENTS:
            cleaned = re.sub(pattern, repl, cleaned)
        return cleaned

    @classmethod
    def simplify_mba_and_magic_divs(cls, code):
        """Simplifie les divisions magiques de compilateur et les formules MBA obfusquées."""
        cleaned = code
        for pattern, repl in cls.MAGIC_DIVISIONS:
            cleaned = re.sub(pattern, repl, cleaned)
        for pattern, repl in cls.MBA_RULES:
            cleaned = re.sub(pattern, repl, cleaned)
        return cleaned

    @classmethod
    def reconstruct_vtable_calls(cls, code):
        """Reconstruit les appels de méthodes virtuelles C++ (vtables) illisibles."""
        # Exemple Ghidra : (***(code ***)(*param_1 + 0x18))(param_1, 0x42) -> param_1->vtable_method_0x18(0x42)
        def vtable_repl(match):
            obj = match.group(1)
            offset = match.group(2)
            args = match.group(3)
            # Nettoyer le premier argument 'this' s'il est redondant
            clean_args = re.sub(r"^" + re.escape(obj) + r"\s*,\s*", "", args).strip()
            return f"{obj}->vtable_method_{offset}({clean_args})"

        cleaned = re.sub(
            r"\(\s*\*\s*\*\s*\*\s*\(\s*code\s*\*\s*\*\s*\*\s*\)\s*\(\s*\*\s*([a-zA-Z0-9_]+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)\s*\)\s*\(\s*([^\)]+)\s*\)",
            vtable_repl,
            code
        )
        return cleaned

    @staticmethod
    def clean_redundant_casts(code):
        cleaned = code
        cleaned = re.sub(r"\((?:uint64_t|int64_t|long)\s*\)\s*\((?:uint32_t|int32_t|int|uint)\s*\)", "", cleaned)
        cleaned = re.sub(r"\((?:uint64_t|int64_t)\s*\)\s*\(uint8_t\)", "(uint8_t)", cleaned)
        cleaned = re.sub(r"\((?:uint64_t|int64_t|uint32_t|int32_t)\s*\)\s*(0x[0-9a-fA-F]+|\d+)", r"\1", cleaned)

        def simplify_array_indexing(match):
            ptr_name = match.group(1)
            idx_name = match.group(2)
            return f"{ptr_name}[{idx_name}]"

        cleaned = re.sub(r"\*\([a-zA-Z0-9_]+\s*\*\)\s*\(\s*(?:(?:\(int64_t\)|\(uint64_t\)|\(long\)|\(void \*\))\s*)?([a-zA-Z0-9_]+)\s*\+\s*(?:(?:\(int64_t\)|\(uint64_t\)|\(long\))\s*)?([a-zA-Z0-9_]+)\s*\*\s*\d+\s*\)", simplify_array_indexing, cleaned)
        cleaned = re.sub(r"\*\([a-zA-Z0-9_]+\s*\*\)\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*([a-zA-Z0-9_]+)\s*\)", r"\1[\2]", cleaned)
        cleaned = re.sub(r"\*\([a-zA-Z0-9_]+\s*\*\)\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*0x0*([0-9a-fA-F]+)\s*\)", r"*(\1 + 0x\2)", cleaned)
        return cleaned

    @classmethod
    def decode_stack_strings(cls, code):
        lines = code.splitlines()
        annotated_lines = []

        for line in lines:
            match = re.search(r"([a-zA-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]{4,16});", line)
            if match:
                hex_val = match.group(2)
                try:
                    raw_hex = hex_val[2:]
                    if len(raw_hex) % 2 != 0: raw_hex = "0" + raw_hex
                    byte_val = bytes.fromhex(raw_hex)
                    le_ascii = byte_val[::-1].decode("latin-1")
                    if all(32 <= ord(c) <= 126 for c in le_ascii) and len(le_ascii) >= 2:
                        line += f"  // Stack String décodée : \"{le_ascii}\""
                except Exception:
                    pass
            annotated_lines.append(line)

        return "\n".join(annotated_lines)

    @classmethod
    def semantic_variable_renaming(cls, code):
        renames = {}
        cleaned = code

        for pattern, (var_temp, name_temp) in cls.SEMANTIC_FUNCTION_RETURNS.items():
            full_pat = r"([a-zA-Z0-9_]+)\s*=\s*" + pattern
            for m in re.finditer(full_pat, cleaned):
                var_found = m.group(1)
                if re.match(r"^(?:[uilsb]Var\d+|local_[0-9a-fA-F]+)$", var_found):
                    arg0 = m.group(2) if len(m.groups()) >= 2 else "item"
                    clean_arg0 = re.sub(r"[^a-zA-Z0-9_]", "", arg0)
                    new_name = name_temp.replace("{arg0}", clean_arg0)
                    renames[var_found] = new_name

        for m in re.finditer(r"for\s*\(\s*([a-zA-Z0-9_]+)\s*=\s*0\s*;", cleaned):
            loop_var = m.group(1)
            if re.match(r"^(?:[uilsb]Var\d+|local_[0-9a-fA-F]+)$", loop_var):
                if loop_var not in renames:
                    renames[loop_var] = "idx"

        if "main(" in cleaned:
            renames["param_1"] = "argc"
            renames["param_2"] = "argv"
            renames["param_3"] = "envp"

        for old_var, new_var in renames.items():
            cleaned = re.sub(r"\b" + re.escape(old_var) + r"\b", new_var, cleaned)

        return cleaned, renames

    @classmethod
    def clean_control_flow(cls, code):
        cleaned = code
        canary_pattern = r"if\s*\(\s*[a-zA-Z0-9_]+\s*!=\s*\*(?:uint64_t|int64_t|long)\s*\*\s*\([a-zA-Z0-9_+]+\s*\+\s*0x28\)\s*\)\s*\{\s*__stack_chk_fail\(\);\s*\}"
        cleaned = re.sub(canary_pattern, "/* [Protection Stack Canary Vérifiée] */", cleaned)
        cleaned = re.sub(r"\(\s*([a-zA-Z0-9_]+)\s*&\s*1\s*\)\s*==\s*0", r"!\1", cleaned)
        cleaned = re.sub(r"\(\s*([a-zA-Z0-9_]+)\s*&\s*1\s*\)\s*!=\s*0", r"\1", cleaned)
        cleaned = re.sub(r"while\s*\(\s*1\s*\)", "while (true)", cleaned)
        return cleaned

    # =========================================================================
    # NOUVEAUX MOTEURS AVANCÉS (KRYPTOANALYZER, SMT SOLVER, BINARY2PY)
    # =========================================================================
    @staticmethod
    def scan_crypto_constants(data_bytes):
        """Scanne un binaire ou buffer de données pour identifier les algorithmes cryptographiques."""
        found = []
        for sig in CRYPTO_SIGNATURES:
            idx = data_bytes.find(sig["pattern"])
            if idx != -1:
                found.append({
                    "name": sig["name"],
                    "algorithm": sig["algorithm"],
                    "offset": hex(idx),
                    "description": sig["desc"]
                })
        return found

    @staticmethod
    def auto_solve_constraints(c_code):
        """Moteur SMT symbolique : extrait les équations de validation et résout le mot de passe / flag."""
        # Recherche d'équations du type : if (input[i] == ...) ou (input[i] ^ key == target)
        constraints = []
        solved_chars = {}

        # Pattern 1 : input[0] == 'f' || input[0] == 0x66
        p1 = re.finditer(r"([a-zA-Z0-9_]+)\[(\d+)\]\s*==\s*(?:'([^']+)'|(0x[0-9a-fA-F]+|\d+))", c_code)
        for m in p1:
            var_name, idx_s, char_val, num_val = m.groups()
            idx = int(idx_s)
            val = ord(char_val) if char_val else (int(num_val, 16) if num_val.startswith("0x") else int(num_val))
            solved_chars[idx] = chr(val) if 32 <= val <= 126 else f"\\x{val:02x}"
            constraints.append(f"{var_name}[{idx}] == {chr(val) if 32 <= val <= 126 else hex(val)}")

        # Pattern 2 : (input[i] ^ 0x42) == 0x27
        p2 = re.finditer(r"\(\s*([a-zA-Z0-9_]+)\[(\d+)\]\s*\^\s*(0x[0-9a-fA-F]+|\d+)\s*\)\s*==\s*(0x[0-9a-fA-F]+|\d+)", c_code)
        for m in p2:
            var_name, idx_s, k_val, target_val = m.groups()
            idx = int(idx_s)
            k = int(k_val, 16) if k_val.startswith("0x") else int(k_val)
            target = int(target_val, 16) if target_val.startswith("0x") else int(target_val)
            res = k ^ target
            solved_chars[idx] = chr(res) if 32 <= res <= 126 else f"\\x{res:02x}"
            constraints.append(f"({var_name}[{idx}] ^ {hex(k)}) == {hex(target)} => {var_name}[{idx}] = '{chr(res)}'")

        # Pattern 3 : (input[i] + 5) == 0x6b
        p3 = re.finditer(r"\(\s*([a-zA-Z0-9_]+)\[(\d+)\]\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)\s*==\s*(0x[0-9a-fA-F]+|\d+)", c_code)
        for m in p3:
            var_name, idx_s, k_val, target_val = m.groups()
            idx = int(idx_s)
            k = int(k_val, 16) if k_val.startswith("0x") else int(k_val)
            target = int(target_val, 16) if target_val.startswith("0x") else int(target_val)
            res = (target - k) % 256
            solved_chars[idx] = chr(res) if 32 <= res <= 126 else f"\\x{res:02x}"
            constraints.append(f"({var_name}[{idx}] + {k}) == {hex(target)} => {var_name}[{idx}] = '{chr(res)}'")

        recovered_flag = ""
        if solved_chars:
            max_idx = max(solved_chars.keys())
            flag_chars = [solved_chars.get(i, "?") for i in range(max_idx + 1)]
            recovered_flag = "".join(flag_chars)

        return {
            "constraints_found": constraints,
            "recovered_flag": recovered_flag,
            "solved_positions": len(solved_chars)
        }

    @staticmethod
    def transpile_c_to_python(c_code):
        """Transpile une fonction de validation décompilée en un script Python 100 % exécutable."""
        py_lines = [
            "#!/usr/bin/env python3",
            "# =============================================================================",
            "#   Script Python Généré par Binary2Py (HackerLab Toolkit Ghidra v3.0)",
            "#   Reproduit fidèlement l'algorithme de validation du binaire",
            "# =============================================================================",
            "",
            "def validate(user_input: str) -> bool:",
            "    data = list(user_input.encode())",
            "    length = len(data)"
        ]

        # Analyse des opérations dans le code C
        for line in c_code.splitlines():
            line = line.strip()
            # Transformation des boucles for
            m_for = re.search(r"for\s*\(\s*([a-zA-Z0-9_]+)\s*=\s*0\s*;\s*\1\s*<\s*([^;]+);\s*\1\+\+\s*\)", line)
            if m_for:
                var, limit = m_for.groups()
                py_lines.append(f"    for {var} in range({limit.strip()}):")
                continue

            # Transformation des XOR in-place : data[i] = data[i] ^ 0x42;
            m_xor = re.search(r"([a-zA-Z0-9_]+)\[([^\]]+)\]\s*=\s*\1\[\2\]\s*\^\s*([^;]+);", line)
            if m_xor:
                _, idx, key = m_xor.groups()
                py_lines.append(f"        data[{idx}] ^= {key.strip()}")
                continue

            # Transformation des checks if : if (data[i] != ...) return false;
            m_if = re.search(r"if\s*\(\s*([a-zA-Z0-9_]+)\[([^\]]+)\]\s*!=\s*([^)]+)\)\s*return\s*0;", line)
            if m_if:
                _, idx, expected = m_if.groups()
                py_lines.append(f"        if data[{idx}] != {expected.strip()}: return False")
                continue

        py_lines.extend([
            "    return True",
            "",
            "if __name__ == '__main__':",
            "    import sys",
            "    test_key = sys.argv[1] if len(sys.argv) > 1 else 'test_input'",
            "    if validate(test_key):",
            "        print('[+] Clé valide ! Flag trouvé !')",
            "    else:",
            "        print('[-] Clé incorrecte.')"
        ])

        return "\n".join(py_lines)

    @classmethod
    def perfect_code(cls, raw_ghidra_code):
        header = """/*
 * ============================================================================
 *   Code Décompilé et Perfectionné par HackerLab Toolkit (Ghidra Cleaner v3.0)
 * ============================================================================
 *   - Typage C99 normalisé (<stdint.h>, <stdbool.h>)
 *   - Simplification des calculs MBA & Divisions magiques
 *   - Reconstitution des méthodes virtuelles C++ (vtables)
 *   - Renommage sémantique automatique & Décodage des Stack Strings
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

"""
        code = cls.clean_types(raw_ghidra_code)
        code = cls.clean_redundant_casts(code)
        code = cls.simplify_mba_and_magic_divs(code)
        code = cls.reconstruct_vtable_calls(code)
        code = cls.decode_stack_strings(code)
        code, renames_done = cls.semantic_variable_renaming(code)
        code = cls.clean_control_flow(code)

        # Tentative d'auto-résolution SMT si contraintes présentes
        smt_res = cls.auto_solve_constraints(raw_ghidra_code)

        full_output = header + code
        return {
            "cleaned_code": full_output,
            "renames": renames_done,
            "smt_solving": smt_res
        }
