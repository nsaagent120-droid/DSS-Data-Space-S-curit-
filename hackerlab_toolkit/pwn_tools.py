"""
=============================================================================
  Module Pwn & Buffer Overflow Helper - HackerLab Toolkit
=============================================================================
  Description : Générateur de séquences cycliques de De Bruijn (pattern_create),
                calculateur d'offset de crash (pattern_offset), packing/unpacking
                (p32, p64, u32, u64) et vérificateur de badchars en pur Python.
=============================================================================
"""

import struct

class PwnHelper:
    @staticmethod
    def cyclic(length=100):
        """Génère une séquence cyclique de De Bruijn standard (Aa0Aa1Aa2...)."""
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lower = "abcdefghijklmnopqrstuvwxyz"
        digits = "0123456789"
        
        pattern = []
        for u in upper:
            for l in lower:
                for d in digits:
                    pattern.append(u + l + d)
                    if len("".join(pattern)) >= length:
                        return "".join(pattern)[:length]
        return "".join(pattern)[:length]

    @staticmethod
    def cyclic_find(search_val, max_len=8192):
        """Trouve l'offset exact d'une valeur (ex: 'Ba0' ou 0x306141) dans la séquence cyclique."""
        seq = PwnHelper.cyclic(max_len)
        
        # 1. Si search_val est un entier
        if isinstance(search_val, int):
            try:
                # 4 bytes little endian
                needle_le = struct.pack("<I", search_val & 0xffffffff).decode("latin-1")
                idx = seq.find(needle_le)
                if idx != -1: return idx
            except Exception:
                pass
            try:
                # 3 bytes
                needle_3 = struct.pack("<I", search_val & 0xffffffff)[:3].decode("latin-1")
                idx = seq.find(needle_3)
                if idx != -1: return idx
            except Exception:
                pass
        
        # 2. Si search_val est une chaîne hexadécimale (0x...)
        elif isinstance(search_val, str):
            clean_s = search_val.strip()
            if clean_s.startswith("0x") or clean_s.startswith("0X"):
                try:
                    val_int = int(clean_s, 16)
                    return PwnHelper.cyclic_find(val_int, max_len)
                except Exception:
                    pass
            # Recherche textuelle directe
            idx = seq.find(clean_s)
            if idx != -1: return idx
            
            # Recherche inversée (Little-endian text: '0aA' au lieu de 'Aa0')
            idx_rev = seq.find(clean_s[::-1])
            if idx_rev != -1: return idx_rev

        return -1

    @staticmethod
    def p32(val):
        """Convertit un entier 32-bit en octets Little-Endian."""
        return struct.pack("<I", val & 0xffffffff)

    @staticmethod
    def p64(val):
        """Convertit un entier 64-bit en octets Little-Endian."""
        return struct.pack("<Q", val & 0xffffffffffffffff)

    @staticmethod
    def u32(data):
        """Convertit 4 octets Little-Endian en entier 32-bit."""
        return struct.unpack("<I", data[:4])[0]

    @staticmethod
    def u64(data):
        """Convertit 8 octets Little-Endian en entier 64-bit."""
        return struct.unpack("<Q", data[:8])[0]

    @staticmethod
    def check_badchars(data_bytes, badchars=b"\x00\x0a\x0d"):
        """Identifie les octets interdits (bad characters) dans une séquence d'octets."""
        found = []
        for idx, b in enumerate(data_bytes):
            if b in badchars:
                found.append({
                    "offset": idx,
                    "byte": hex(b),
                    "char": repr(chr(b))
                })
        return found
