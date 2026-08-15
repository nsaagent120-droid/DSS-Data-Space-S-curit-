"""
=============================================================================
  Module Forensics & Stéganographie - HackerLab Toolkit
=============================================================================
  Description : Analyseur de Magic Bytes / Headers de fichiers, extracteur
                de métadonnées EXIF, calcul d'entropie Shannon, découpeur
                de fichiers embarqués (File Carving) et détection de flags CTF.
=============================================================================
"""

import math
import os
import re
import struct

# Signatures Magic Bytes courantes
FILE_SIGNATURES = [
    {"name": "PNG Image", "ext": "png", "magic": b"\x89PNG\r\n\x1a\n", "trailer": b"IEND\xaeB`\x82"},
    {"name": "JPEG Image", "ext": "jpg", "magic": b"\xff\xd8\xff", "trailer": b"\xff\xd9"},
    {"name": "GIF Image (89a)", "ext": "gif", "magic": b"GIF89a", "trailer": b"\x00\x3b"},
    {"name": "GIF Image (87a)", "ext": "gif", "magic": b"GIF87a", "trailer": b"\x00\x3b"},
    {"name": "PDF Document", "ext": "pdf", "magic": b"%PDF-", "trailer": b"%%EOF"},
    {"name": "ZIP Archive / DOCX / APK", "ext": "zip", "magic": b"PK\x03\x04", "trailer": None},
    {"name": "ELF Executable (Linux)", "ext": "elf", "magic": b"\x7fELF", "trailer": None},
    {"name": "PE Executable (Windows EXE/DLL)", "ext": "exe", "magic": b"MZ", "trailer": None},
    {"name": "7-Zip Archive", "ext": "7z", "magic": b"7z\xbc\xaf\x27\x1c", "trailer": None},
    {"name": "GZIP Archive", "ext": "gz", "magic": b"\x1f\x8b\x08", "trailer": None},
    {"name": "TAR Archive", "ext": "tar", "magic": b"ustar", "offset": 257, "trailer": None},
    {"name": "SQLite 3 Database", "ext": "sqlite", "magic": b"SQLite format 3\x00", "trailer": None},
    {"name": "PCAP Network Capture", "ext": "pcap", "magic": b"\xd4\xc3\xb2\xa1", "trailer": None},
    {"name": "PCAP-NG Network Capture", "ext": "pcapng", "magic": b"\n\r\r\n", "trailer": None},
    {"name": "WAV Audio", "ext": "wav", "magic": b"RIFF", "trailer": None},
    {"name": "BMP Image", "ext": "bmp", "magic": b"BM", "trailer": None}
]

class ForensicsAnalyzer:
    @staticmethod
    def identify_magic(file_bytes):
        """Identifie le type réel de fichier basé sur ses premiers octets."""
        matches = []
        for sig in FILE_SIGNATURES:
            offset = sig.get("offset", 0)
            magic = sig["magic"]
            if len(file_bytes) >= offset + len(magic):
                if file_bytes[offset:offset + len(magic)] == magic:
                    matches.append(sig)
        return matches

    @staticmethod
    def shannon_entropy(data_bytes):
        """Calcule l'entropie de Shannon (0.0 à 8.0).
        - 0.0 - 3.0 : Données très structurées / texte répétitif
        - 3.0 - 6.0 : Code source, texte brut, exécutables standards
        - 7.0 - 8.0 : Données chiffrées, compressées ou packées (UPX, AES, ZIP)
        """
        if not data_bytes:
            return 0.0
        entropy = 0.0
        length = len(data_bytes)
        frequencies = [0] * 256
        for b in data_bytes:
            frequencies[b] += 1

        for count in frequencies:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)

        interpretation = "Structuré / Texte brut"
        if entropy > 7.5:
            interpretation = "Très forte entropie (Probablement Chiffré / Compressé / Packé)"
        elif entropy > 6.0:
            interpretation = "Entropie moyenne-haute (Code binaire, exécutable ou archive)"

        return {"entropy": round(entropy, 4), "interpretation": interpretation}

    @staticmethod
    def carve_files(data_bytes):
        """Recherche des fichiers imbriqués cachés (stéganographie par concaténation / zip caché)."""
        found = []
        for sig in FILE_SIGNATURES:
            magic = sig["magic"]
            offset = 0
            while True:
                idx = data_bytes.find(magic, offset)
                if idx == -1:
                    break
                found.append({
                    "type": sig["name"],
                    "offset": idx,
                    "offset_hex": hex(idx),
                    "ext": sig["ext"]
                })
                offset = idx + len(magic)
        return sorted(found, key=lambda x: x["offset"])

    @staticmethod
    def extract_strings(data_bytes, min_len=4):
        """Extrait toutes les chaînes ASCII imprimables."""
        pattern = re.compile(b"[\x20-\x7e]{" + str(min_len).encode() + b",}")
        results = []
        for match in pattern.finditer(data_bytes):
            results.append({
                "offset": match.start(),
                "offset_hex": hex(match.start()),
                "string": match.group().decode("latin-1")
            })
        return results

    @staticmethod
    def find_flags(data_bytes):
        """Recherche automatiquement les formats de flags CTF courants."""
        # Patterns variés : flag{...}, FLAG{...}, HL{...}, hackerlab{...}, ctf{...}
        patterns = [
            rb"(flag\{[^\}\n]{3,80}\})",
            rb"(FLAG\{[^\}\n]{3,80}\})",
            rb"(hl\{[^\}\n]{3,80}\})",
            rb"(HL\{[^\}\n]{3,80}\})",
            rb"(hackerlab\{[^\}\n]{3,80}\})",
            rb"(HackerLab\{[^\}\n]{3,80}\})",
            rb"(ctf\{[^\}\n]{3,80}\})",
            rb"(CTF\{[^\}\n]{3,80}\})"
        ]
        flags_found = []
        for p in patterns:
            for match in re.finditer(p, data_bytes, re.IGNORECASE):
                val = match.group().decode("latin-1", errors="ignore")
                if val not in [f["flag"] for f in flags_found]:
                    flags_found.append({"flag": val, "offset": match.start(), "offset_hex": hex(match.start())})
        return flags_found

    @staticmethod
    def extract_lsb_text(data_bytes, max_bytes=512):
        """Extrait les bits de poids faible (LSB) des octets bruts pour repérer un texte caché."""
        bits = []
        for b in data_bytes:
            bits.append(str(b & 1))
            if len(bits) >= max_bytes * 8:
                break

        # Regroupement en octets
        bit_str = "".join(bits)
        chars = []
        for i in range(0, len(bit_str) - 7, 8):
            byte_val = int(bit_str[i:i+8], 2)
            if 32 <= byte_val <= 126 or byte_val in [10, 13]:
                chars.append(chr(byte_val))
            else:
                break # On s'arrête dès que ce n'est plus du texte ASCII

        extracted = "".join(chars)
        return extracted if len(extracted) >= 4 else ""
