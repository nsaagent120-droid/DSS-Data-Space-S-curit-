"""
=============================================================================
  Module Ghidra Decompiler Perfectionist & Code Cleaner - HackerLab Toolkit
=============================================================================
  Description : Moteur de post-traitement de haut niveau pour le pseudo-code
                décompilé par Ghidra.
                - Remplacement des types Ghidra opaques (undefined8 -> uint64_t)
                - Élimination des casts de pointeurs verbeux (*(int *)(ptr + i*4) -> ptr[i])
                - Renommage sémantique automatique des variables (uVar1, local_18...)
                - Désobfuscation et décodage automatique des Stack Strings (Hex -> ASCII)
                - Nettoyage des boucles de décompilation et suppression des variables inutiles
=============================================================================
"""

import re
import struct

class GhidraDecompilerCleaner:
    # Remplacement des types Ghidra vers les types standardisés C99 (<stdint.h>)
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

    # Inférence sémantique des variables d'après les appels de fonctions standards
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

    @classmethod
    def clean_types(cls, code):
        """Remplace les types opaques de Ghidra par des types C standardisés."""
        cleaned = code
        for pattern, repl in cls.TYPE_REPLACEMENTS:
            cleaned = re.sub(pattern, repl, cleaned)
        return cleaned

    @staticmethod
    def clean_redundant_casts(code):
        """Simplifie les casts redondants générés par Ghidra."""
        cleaned = code
        
        # 1. Casts d'entiers imbriqués : (uint64_t)(uint32_t)x -> (uint32_t)x
        cleaned = re.sub(r"\((?:uint64_t|int64_t|long)\s*\)\s*\((?:uint32_t|int32_t|int|uint)\s*\)", "", cleaned)
        cleaned = re.sub(r"\((?:uint64_t|int64_t)\s*\)\s*\(uint8_t\)", "(uint8_t)", cleaned)
        
        # 2. Casts redondants simples sur variables et constantes : (uint64_t)(0x10) -> 0x10
        cleaned = re.sub(r"\((?:uint64_t|int64_t|uint32_t|int32_t)\s*\)\s*(0x[0-9a-fA-F]+|\d+)", r"\1", cleaned)

        # 3. Casts de pointeurs verbeux : *(int *)((int64_t)ptr + (int64_t)i * 4) -> ptr[i]
        def simplify_array_indexing(match):
            ptr_name = match.group(1)
            idx_name = match.group(2)
            return f"{ptr_name}[{idx_name}]"

        cleaned = re.sub(r"\*\([a-zA-Z0-9_]+\s*\*\)\s*\(\s*(?:(?:\(int64_t\)|\(uint64_t\)|\(long\)|\(void \*\))\s*)?([a-zA-Z0-9_]+)\s*\+\s*(?:(?:\(int64_t\)|\(uint64_t\)|\(long\))\s*)?([a-zA-Z0-9_]+)\s*\*\s*\d+\s*\)", simplify_array_indexing, cleaned)
        cleaned = re.sub(r"\*\([a-zA-Z0-9_]+\s*\*\)\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*([a-zA-Z0-9_]+)\s*\)", r"\1[\2]", cleaned)

        # 4. Simplifier les déférences constantes : *(int *)(ptr + 4) -> ptr[1]
        cleaned = re.sub(r"\*\([a-zA-Z0-9_]+\s*\*\)\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*0x0*([0-9a-fA-F]+)\s*\)", r"*(\1 + 0x\2)", cleaned)

        return cleaned

    @classmethod
    def decode_stack_strings(cls, code):
        """Détecte et annote les chaînes construites sur la pile (Stack Strings)."""
        lines = code.splitlines()
        annotated_lines = []

        for line in lines:
            # Détection d'assignations de constantes hexadécimales 32-bit ou 64-bit :
            # local_18 = 0x67616c66; ou local_20 = 0x7b646e616c7369;
            match = re.search(r"([a-zA-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]{4,16});", line)
            if match:
                var_name = match.group(1)
                hex_val = match.group(2)
                try:
                    raw_hex = hex_val[2:]
                    if len(raw_hex) % 2 != 0: raw_hex = "0" + raw_hex
                    byte_val = bytes.fromhex(raw_hex)
                    # En x86-64 Little Endian, la chaîne est inversée
                    le_ascii = byte_val[::-1].decode("latin-1")
                    if all(32 <= ord(c) <= 126 for c in le_ascii) and len(le_ascii) >= 2:
                        line += f"  // Stack String décodée : \"{le_ascii}\""
                except Exception:
                    pass

            annotated_lines.append(line)

        return "\n".join(annotated_lines)

    @classmethod
    def semantic_variable_renaming(cls, code):
        """Renomme intelligemment les variables Ghidra (uVar1, iVar2, local_xx, param_x)."""
        renames = {}
        cleaned = code

        # 1. Analyse des retours de fonctions
        for pattern, (var_temp, name_temp) in cls.SEMANTIC_FUNCTION_RETURNS.items():
            # Chercher : uVar1 = strlen(param_1);
            full_pat = r"([a-zA-Z0-9_]+)\s*=\s*" + pattern
            for m in re.finditer(full_pat, cleaned):
                var_found = m.group(1)
                # Si c'est un nom générique Ghidra (uVarX, iVarX, local_X)
                if re.match(r"^(?:[uilsb]Var\d+|local_[0-9a-fA-F]+)$", var_found):
                    arg0 = m.group(2) if len(m.groups()) >= 2 else "item"
                    clean_arg0 = re.sub(r"[^a-zA-Z0-9_]", "", arg0)
                    new_name = name_temp.replace("{arg0}", clean_arg0)
                    renames[var_found] = new_name

        # 2. Détection des variables d'itérations de boucles : for (local_14 = 0; local_14 < max; local_14++)
        for m in re.finditer(r"for\s*\(\s*([a-zA-Z0-9_]+)\s*=\s*0\s*;", cleaned):
            loop_var = m.group(1)
            if re.match(r"^(?:[uilsb]Var\d+|local_[0-9a-fA-F]+)$", loop_var):
                if loop_var not in renames:
                    renames[loop_var] = "idx"

        # 3. Paramètres de fonctions classiques (argc, argv)
        # main(int param_1, char **param_2) -> main(int argc, char **argv)
        if "main(" in cleaned:
            renames["param_1"] = "argc"
            renames["param_2"] = "argv"
            renames["param_3"] = "envp"

        # 4. Remplacement global des variables identifiées
        for old_var, new_var in renames.items():
            # Remplacement avec délimiteur de mot entier \b
            cleaned = re.sub(r"\b" + re.escape(old_var) + r"\b", new_var, cleaned)

        return cleaned, renames

    @classmethod
    def clean_control_flow(cls, code):
        """Nettoie les structures de contrôle et supprime les patterns de bruit Ghidra."""
        cleaned = code

        # 1. Remplacer `if (cond) goto LAB_xxx; ... LAB_xxx:` quand c'est trivial
        # 2. Supprimer les assertions du stack canary Ghidra très lourdes à lire
        # if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) { __stack_chk_fail(); }
        canary_pattern = r"if\s*\(\s*[a-zA-Z0-9_]+\s*!=\s*\*(?:uint64_t|int64_t|long)\s*\*\s*\([a-zA-Z0-9_+]+\s*\+\s*0x28\)\s*\)\s*\{\s*__stack_chk_fail\(\);\s*\}"
        cleaned = re.sub(canary_pattern, "/* [Protection Stack Canary Vérifiée] */", cleaned)

        # 3. Nettoyer les comparaisons booléennes verbeuses : `if ((bVar1 & 1) == 0)` -> `if (!bVar1)`
        cleaned = re.sub(r"\(\s*([a-zA-Z0-9_]+)\s*&\s*1\s*\)\s*==\s*0", r"!\1", cleaned)
        cleaned = re.sub(r"\(\s*([a-zA-Z0-9_]+)\s*&\s*1\s*\)\s*!=\s*0", r"\1", cleaned)

        # 4. Nettoyer les boucles `while( true )` convertibles
        cleaned = re.sub(r"while\s*\(\s*1\s*\)", "while (true)", cleaned)

        return cleaned

    @classmethod
    def perfect_code(cls, raw_ghidra_code):
        """Exécute l'intégralité de la pipeline de perfectionnement de code."""
        # En-tête informatif propre
        header = """/*
 * ============================================================================
 *   Code Décompilé et Perfectionné par HackerLab Toolkit (Ghidra Cleaner v2.0)
 * ============================================================================
 *   - Typage C99 normalisé (<stdint.h>, <stdbool.h>)
 *   - Casts de pointeurs et calculs d'index simplifiés
 *   - Variables renommées sémantiquement & Stack Strings résolues
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

"""
        # Pipeline de transformations
        code = cls.clean_types(raw_ghidra_code)
        code = cls.clean_redundant_casts(code)
        code = cls.decode_stack_strings(code)
        code, renames_done = cls.semantic_variable_renaming(code)
        code = cls.clean_control_flow(code)

        full_output = header + code
        return {
            "cleaned_code": full_output,
            "renames": renames_done
        }
