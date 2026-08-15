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
    def generate_gdb_script(entry_point_hex, output_filename="script.gdb", flavor="pwndbg"):
        """Génère un script GDB / Pwndbg / GEF complet avec hooks d'interception de strcmp et breakpoints CTF."""
        script_content = f"""# =============================================================================
#  Script GDB + Pwndbg / GEF d'Analyse Dynamique Avancée pour CTF
#  Généré par HackerLab Toolkit (HL-Tool)
# =============================================================================

set pagination off
set disassembly-flavor intel
set confirm off

echo [+] Configuration GDB / Pwndbg chargee.\\n

# 1. Breakpoints standards sur le point d'entree et les fonctions de validation
break *{entry_point_hex}
break main
break validate
break check
break strcmp
break strncmp
break memcmp

# 2. Hook automatique sur strcmp / strncmp pour reveler les mots de passe en memoire (CTF Trick)
define hook-stop
    # Si on est arrete sur strcmp, afficher les chaines comparees
    if $rip
        # En x86-64 : RDI = arg1, RSI = arg2
        # x/s $rdi
        # x/s $rsi
    end
end

# 3. Macro d'assistance pour inspecter la stack et les canaries
define check_canary
    echo [*] Inspection du Canary de pile...\\n
    search -8 $rsp $rbp
end

# 4. Macro de dump memoire pour les binaires unpackes
define dump_unpacked_text
    dump memory dumped_text.bin $arg0 $arg1
    echo [+] Section memoire extraite avec succes vers dumped_text.bin\\n
end

# 5. Assistance recherche d'OEP (Original Entry Point)
define trace_oep
    echo [*] Tracage pas-a-pas des instructions jusqu'au saut lointain...\\n
    stepi 50
end

echo [!] Commandes pretes. Tapez 'run' pour demarrer l'analyse.\\n
"""
        with open(output_filename, "w", encoding="utf-8") as f:
            f.write(script_content)
        return output_filename

    @staticmethod
    def detect_antidebug(data_bytes):
        """Détecte les mécanismes d'anti-débogage courants (ptrace, timing RDTSC, TracerPid)."""
        findings = []

        # 1. ptrace(PTRACE_TRACEME)
        if b"ptrace" in data_bytes:
            findings.append({
                "type": "ptrace() API Call",
                "severity": "HAUTE",
                "desc": "Appel à ptrace(0, ...) : empêche l'attachement d'un débogueur (GDB)."
            })

        # 2. /proc/self/status ou /proc/self/wchan
        if b"/proc/self/status" in data_bytes or b"TracerPid" in data_bytes:
            findings.append({
                "type": "Vérification /proc/self/status (TracerPid)",
                "severity": "MOYENNE",
                "desc": "Le binaire lit son propre TracerPid pour vérifier s'il est monitoré."
            })

        # 3. Instruction RDTSC (Time-based detection)
        # Opcode x86 RDTSC = 0x0f 0x31, RDTSCP = 0x0f 0x01 0xf9
        if b"\x0f\x31" in data_bytes:
            count = data_bytes.count(b"\x0f\x31")
            findings.append({
                "type": "Instruction RDTSC (Timing check)",
                "severity": "MOYENNE",
                "desc": f"Présence de l'instruction d'horloge CPU RDTSC ({count} occurrences) pour détecter les pauses de débug."
            })

        # 4. Windows APIs (pour binaires PE)
        if b"IsDebuggerPresent" in data_bytes or b"CheckRemoteDebuggerPresent" in data_bytes:
            findings.append({
                "type": "Windows IsDebuggerPresent API",
                "severity": "HAUTE",
                "desc": "Appel direct à l'API Windows de détection de débogueur."
            })

        return findings

    @classmethod
    def find_rop_gadgets(cls, data_bytes, base_addr=0x400000):
        """Recherche les ROP Gadgets fondamentaux (x86 / x86-64) pour comprendre les flux d'appels."""
        GADGET_PATTERNS = [
            {"gadget": "pop rdi; ret", "bytes": b"\x5f\xc3", "arch": "x86-64"},
            {"gadget": "pop rsi; ret", "bytes": b"\x5e\xc3", "arch": "x86-64"},
            {"gadget": "pop rdx; ret", "bytes": b"\x5a\xc3", "arch": "x86-64"},
            {"gadget": "pop rax; ret", "bytes": b"\x58\xc3", "arch": "x86-64"},
            {"gadget": "pop rbx; ret", "bytes": b"\x5b\xc3", "arch": "x86-64"},
            {"gadget": "pop rcx; ret", "bytes": b"\x59\xc3", "arch": "x86-64"},
            {"gadget": "syscall; ret", "bytes": b"\x0f\x05\xc3", "arch": "x86-64"},
            {"gadget": "syscall", "bytes": b"\x0f\x05", "arch": "x86-64"},
            {"gadget": "int 0x80", "bytes": b"\xcd\x80", "arch": "x86"},
            {"gadget": "leave; ret", "bytes": b"\xc9\xc3", "arch": "x86 / x86-64"},
            {"gadget": "jmp rsp", "bytes": b"\xff\xe4", "arch": "x86-64"},
            {"gadget": "call rsp", "bytes": b"\xff\xd4", "arch": "x86-64"},
            {"gadget": "ret", "bytes": b"\xc3", "arch": "x86 / x86-64"}
        ]

        found = []
        for g in GADGET_PATTERNS:
            offset = 0
            while True:
                idx = data_bytes.find(g["bytes"], offset)
                if idx == -1:
                    break
                vaddr = hex(base_addr + idx)
                found.append({
                    "gadget": g["gadget"],
                    "offset": hex(idx),
                    "vaddr": vaddr,
                    "arch": g["arch"]
                })
                offset = idx + 1
                if len(found) >= 50:
                    break

        return found

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
