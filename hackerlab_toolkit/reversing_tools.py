"""
=============================================================================
  Module Reverse Engineering & Analyse Binaire - HackerLab Toolkit
=============================================================================
  Description : Inspecteur d'en-têtes ELF/PE, vérification de protections
                de sécurité (checksec : NX, PIE, Canary, RELRO), détection
                de packers (UPX) et extracteur de symboles et fonctions.
=============================================================================
"""

import struct
import re

class ELFAnalyzer:
    @staticmethod
    def parse_elf_header(data_bytes):
        """Parse l'en-tête ELF (32-bit et 64-bit) sans dépendances externes."""
        if len(data_bytes) < 52 or data_bytes[:4] != b"\x7fELF":
            return None

        ei_class = data_bytes[4] # 1 = 32-bit, 2 = 64-bit
        ei_data = data_bytes[5]  # 1 = Little Endian, 2 = Big Endian
        endian = "<" if ei_data == 1 else ">"
        arch_bits = "64-bit" if ei_class == 2 else "32-bit"

        # e_type (2 bytes at offset 16), e_machine (2 bytes at offset 18)
        e_type_val, e_machine_val = struct.unpack(endian + "HH", data_bytes[16:20])
        
        types_map = {1: "REL (Relocatable object)", 2: "EXEC (Executable)", 3: "DYN (Shared object / PIE)", 4: "CORE (Core dump)"}
        machines_map = {
            3: "x86 (Intel 80386)",
            62: "x86-64 (AMD64 / Intel 64)",
            40: "ARM (32-bit)",
            183: "AArch64 (ARM 64-bit)",
            8: "MIPS",
            243: "RISC-V"
        }

        # Entry point
        if ei_class == 2:
            entry_point = struct.unpack(endian + "Q", data_bytes[24:32])[0]
        else:
            entry_point = struct.unpack(endian + "I", data_bytes[24:28])[0]

        return {
            "magic": "ELF",
            "class": arch_bits,
            "endian": "Little Endian" if ei_data == 1 else "Big Endian",
            "type": types_map.get(e_type_val, f"Unknown ({e_type_val})"),
            "machine": machines_map.get(e_machine_val, f"Unknown ({e_machine_val})"),
            "entry_point": hex(entry_point),
            "raw_type_val": e_type_val
        }

    @classmethod
    def checksec(cls, data_bytes):
        """Vérifie les mécanismes de protection d'un binaire Linux (comme checksec)."""
        info = cls.parse_elf_header(data_bytes)
        if not info:
            return {"error": "Format de fichier non ELF"}

        protections = {
            "canary": {"enabled": False, "desc": "Stack Canary / __stack_chk_fail"},
            "nx": {"enabled": True, "desc": "Non-Executable Stack (NX)"},
            "pie": {"enabled": False, "desc": "Position Independent Executable (PIE)"},
            "relro": {"level": "No RELRO", "desc": "Relocation Read-Only"},
            "stripped": {"status": True, "desc": "Symboles de débug"}
        }

        # 1. Stack Canary
        if b"__stack_chk_fail" in data_bytes:
            protections["canary"]["enabled"] = True

        # 2. PIE (DYN type = PIE actif, EXEC = No PIE)
        if info.get("raw_type_val") == 3:
            protections["pie"]["enabled"] = True

        # 3. NX (Recherche de segment GNU_STACK avec flag PF_X)
        # GNU_STACK type = 0x6474e551
        if b"\x51\xe5\x74\x64" in data_bytes or b"\x64\x74\xe5\x51" in data_bytes:
            protections["nx"]["enabled"] = True

        # 4. RELRO (GNU_RELRO header type 0x6474e552)
        if b"\x52\xe5\x74\x64" in data_bytes or b"\x64\x74\xe5\x52" in data_bytes:
            if b"BIND_NOW" in data_bytes or protections["pie"]["enabled"]:
                protections["relro"]["level"] = "Full RELRO"
            else:
                protections["relro"]["level"] = "Partial RELRO"

        # 5. Stripped status
        if b".symtab" in data_bytes or b".strtab" in data_bytes:
            protections["stripped"]["status"] = False

        return {
            "header": info,
            "protections": protections
        }

    @staticmethod
    def detect_packers(data_bytes):
        """Détecte si le binaire a été compressé / protégé avec UPX ou autre packer."""
        findings = []
        if b"UPX!" in data_bytes or b"UPX0" in data_bytes or b"UPX1" in data_bytes:
            findings.append({
                "packer": "UPX (Ultimate Packer for eXecutables)",
                "confidence": "Haute",
                "solution": "Décompresser avec la commande : upx -d <binaire>"
            })
        return findings

    @staticmethod
    def detect_suspicious_sections(data_bytes):
        """Audite la structure d'un binaire ELF pour détecter des sections anormales (ex: RWX) ou des cavités (Code Caves)."""
        findings = []
        # Recherche de segments avec permissions RWX (Read-Write-Execute = 7)
        # Type PT_LOAD avec flags PF_R | PF_W | PF_X
        if b"\x7fELF" in data_bytes[:4]:
            if b"\x07\x00\x00\x00" in data_bytes or b"\x00\x00\x00\x07" in data_bytes:
                findings.append({
                    "type": "Section / Segment RWX",
                    "severity": "HAUTE",
                    "description": "Présence potentielle d'une zone mémoire à la fois inscriptible et exécutable (violation W^X / DEP)."
                })

        # Détection de grandes zones contiguës de null-bytes ou NOPs (Code Caves / Padding)
        cave_pattern = re.compile(b"(\x00{32,}|\x90{16,})")
        caves = []
        for match in cave_pattern.finditer(data_bytes):
            caves.append({
                "offset": match.start(),
                "offset_hex": hex(match.start()),
                "length": len(match.group()),
                "type": "Null-byte cave" if match.group()[0] == 0 else "NOP sled / padding"
            })

        return {
            "anomalies": findings,
            "code_caves": caves[:10],
            "total_caves_found": len(caves)
        }

    @staticmethod
    def calculate_binary_hashes(data_bytes):
        """Calcule les empreintes cryptographiques pour la vérification d'intégrité binaire."""
        import hashlib
        return {
            "md5": hashlib.md5(data_bytes).hexdigest(),
            "sha1": hashlib.sha1(data_bytes).hexdigest(),
            "sha256": hashlib.sha256(data_bytes).hexdigest(),
            "size_bytes": len(data_bytes)
        }
