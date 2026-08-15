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
        """Détecte les packers, obfuscateurs et compilateurs (style Detect It Easy / DIE)."""
        findings = []

        # 1. Signatures de Packers courants
        PACKER_SIGS = [
            {"name": "UPX (Ultimate Packer for eXecutables)", "patterns": [b"UPX!", b"UPX0", b"UPX1", b"UPX2"], "solution": "Dépaqueter avec : upx -d <fichier>"},
            {"name": "PyInstaller (Exécutable Python packé)", "patterns": [b"MEI\x0c\x0b\x0a\x0b", b"pyi-runtime-tmpdir", b"_MEIPASS"], "solution": "Extraire avec : pyinstxtractor.py <fichier>"},
            {"name": "Py2Exe (Python packé Windows)", "patterns": [b"py2exe", b"PYTHON27.DLL", b"PYTHON3.DLL"], "solution": "Extraire les ressources avec un extracteur de bytecode pyc"},
            {"name": "ASPack", "patterns": [b".aspack", b"ASPack"], "solution": "Rechercher l'OEP par tail jump sous GDB/x64dbg"},
            {"name": "PECompact", "patterns": [b"PECompact2", b"PEC2"], "solution": "Placer un breakpoint mémoire sur la section .text"},
            {"name": "Petite", "patterns": [b".petite", b"petite"], "solution": "Dépaquetage dynamique sous débogueur"}
        ]

        for p in PACKER_SIGS:
            for pat in p["patterns"]:
                if pat in data_bytes:
                    findings.append({
                        "packer": p["name"],
                        "confidence": "Haute",
                        "solution": p["solution"]
                    })
                    break

        # 2. Détection de Compilateurs & Langages sources
        COMPILER_SIGS = [
            {"name": "Go (Golang Runtime)", "pattern": b"runtime.buildVersion", "desc": "Binaire compilé en Golang (table de symboles pclntab)"},
            {"name": "Rust (rustc)", "pattern": b"/rustc/", "desc": "Binaire compilé avec le compilateur Rust"},
            {"name": "GCC (GNU C Compiler)", "pattern": b"GCC: (GNU)", "desc": "Binaire C/C++ compilé avec GCC"},
            {"name": "Clang / LLVM", "pattern": b"clang version", "desc": "Binaire compilé avec Clang/LLVM"},
            {"name": "Nim Language", "pattern": b"Nim main", "desc": "Binaire compilé avec Nim"}
        ]

        compilers = []
        for c in COMPILER_SIGS:
            if c["pattern"] in data_bytes:
                compilers.append({"name": c["name"], "desc": c["desc"]})

        return {
            "packers": findings,
            "compilers": compilers
        }

    @staticmethod
    def generate_gdb_script(entry_point_hex, output_filename="script.gdb"):
        """Génère un script GDB automatisé pour l'analyse dynamique et la recherche d'OEP."""
        script_content = f"""# =============================================================================
#  Script GDB d'Analyse Dynamique & Recherche d'OEP (Original Entry Point)
#  Généré par HackerLab Toolkit (HL-Tool)
# =============================================================================

set pagination off
set disassembly-flavor intel

# 1. Point d'arrêt sur le point d'entrée actuel
break *{entry_point_hex}
echo [+] Point d'arret place sur l'Entry Point initial ({entry_point_hex})\\n

# 2. Commande personnalisee pour dumper la memoire dechargee
define dump_text_section
    dump memory dumped_binary.bin $arg0 $arg1
    echo [+] Memoire extraite vers dumped_binary.bin\\n
end

# 3. Commande d'assistance OEP (Trace jusqu'au saut lointain)
define trace_tail_jump
    echo [*] Tracage des instructions pour detecter le Tail Jump...\\n
    stepi 100
end

echo [!] Lancez 'run' puis examinez le flux d'execution.\\n
"""
        with open(output_filename, "w", encoding="utf-8") as f:
            f.write(script_content)
        return output_filename

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
