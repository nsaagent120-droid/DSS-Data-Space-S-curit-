"""
=============================================================================
  Module Cryptographie - HackerLab Toolkit
=============================================================================
  Description : Décodeurs multi-formats, solveurs de chiffres classiques
                (César, Vigenère, XOR, Atbash, Affine), identification de
                hashes et solveurs mathématiques RSA pour CTF.
=============================================================================
"""

import base64
import binascii
import math
import re
import urllib.parse

# =============================================================================
# 1. DÉCODEURS & ENCODEURS MULTI-FORMATS
# =============================================================================
MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--',
    '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
    '9': '----.', '0': '-----', ' ': '/'
}
MORSE_REVERSE = {v: k for k, v in MORSE_CODE_DICT.items()}

class MultiDecoder:
    @staticmethod
    def decode_all(text):
        """Tente de décoder le texte sous tous les formats courants."""
        results = {}
        cleaned = text.strip()

        # 1. Base64
        try:
            b64_pad = cleaned + '=' * (-len(cleaned) % 4)
            b64_dec = base64.b64decode(b64_pad).decode(errors="ignore")
            if b64_dec and any(c.isprintable() for c in b64_dec):
                results["Base64"] = b64_dec
        except Exception:
            pass

        # 2. Base32
        try:
            b32_pad = cleaned.upper() + '=' * (-len(cleaned) % 8)
            b32_dec = base64.b32decode(b32_pad).decode(errors="ignore")
            if b32_dec and any(c.isprintable() for c in b32_dec):
                results["Base32"] = b32_dec
        except Exception:
            pass

        # 3. Base85 / Ascii85
        try:
            b85_dec = base64.b85decode(cleaned.encode()).decode(errors="ignore")
            if b85_dec and any(c.isprintable() for c in b85_dec):
                results["Base85"] = b85_dec
        except Exception:
            pass

        # 4. Hexadécimal
        try:
            hex_clean = cleaned.replace(" ", "").replace("0x", "").replace("\\x", "")
            if len(hex_clean) % 2 == 0:
                hex_dec = bytes.fromhex(hex_clean).decode(errors="ignore")
                if hex_dec and any(c.isprintable() for c in hex_dec):
                    results["Hex"] = hex_dec
        except Exception:
            pass

        # 5. Binaire (8-bit ou 7-bit)
        try:
            bin_clean = cleaned.replace(" ", "")
            if set(bin_clean).issubset({'0', '1'}) and len(bin_clean) >= 7:
                chars = []
                chunk_size = 8 if len(bin_clean) % 8 == 0 else 7
                for i in range(0, len(bin_clean), chunk_size):
                    byte_str = bin_clean[i:i+chunk_size]
                    chars.append(chr(int(byte_str, 2)))
                bin_dec = "".join(chars)
                if any(c.isprintable() for c in bin_dec):
                    results["Binaire"] = bin_dec
        except Exception:
            pass

        # 6. URL Decode
        try:
            url_dec = urllib.parse.unquote(cleaned)
            if url_dec != cleaned:
                results["URL Decode"] = url_dec
        except Exception:
            pass

        # 7. Code Morse
        try:
            if set(cleaned).issubset({'.', '-', ' ', '/', '_'}):
                morse_words = cleaned.replace('_', '-').split(' / ')
                decoded_words = []
                for word in morse_words:
                    letters = [MORSE_REVERSE.get(sym, '') for sym in word.split()]
                    decoded_words.append("".join(letters))
                morse_dec = " ".join(decoded_words).strip()
                if morse_dec:
                    results["Morse"] = morse_dec
        except Exception:
            pass

        # 8. ROT13
        results["ROT13"] = ClassicalCiphers.rot(cleaned, 13)

        # 9. Décimal / Valeurs ASCII séparées par des espaces
        try:
            parts = cleaned.split()
            if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts) and len(parts) > 1:
                results["Decimal ASCII"] = "".join(chr(int(p)) for p in parts)
        except Exception:
            pass

        return results

# =============================================================================
# 2. CHIFFRES CLASSIQUES & CASSEURS CTF
# =============================================================================
class ClassicalCiphers:
    FRENCH_FREQ = {
        'E': 14.7, 'A': 7.6, 'I': 7.5, 'S': 7.9, 'N': 7.1, 'R': 6.5, 'T': 7.2,
        'O': 5.8, 'L': 5.5, 'U': 6.3, 'D': 3.7, 'C': 3.3, 'M': 3.0, 'P': 3.0,
        'V': 1.6, 'G': 1.1, 'B': 0.9, 'F': 1.1, 'Q': 1.4, 'H': 0.7, 'Z': 0.3,
        'X': 0.4, 'Y': 0.3, 'J': 0.3, 'K': 0.1, 'W': 0.1
    }

    @staticmethod
    def rot(text, shift):
        res = []
        for c in text:
            if 'a' <= c <= 'z':
                res.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                res.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
            else:
                res.append(c)
        return "".join(res)

    @classmethod
    def score_text(cls, text):
        """Score basé sur la fréquence des lettres et la présence d'espaces / mots."""
        score = 0.0
        clean = text.upper()
        total_letters = sum(1 for c in clean if 'A' <= c <= 'Z')
        if total_letters == 0: return 0.0

        for c in clean:
            if c in cls.FRENCH_FREQ:
                score += cls.FRENCH_FREQ[c]
            elif c == ' ':
                score += 8.0

        # Bonus si patterns de flag CTF
        if re.search(r"(flag|ctf|hackerlab|hl)\{", text, re.IGNORECASE):
            score += 1000.0

        return score / total_letters

    @classmethod
    def break_caesar(cls, text):
        """Teste toutes les 25 rotations et classe par probabilité linguistique."""
        candidates = []
        for shift in range(1, 26):
            dec = cls.rot(text, shift)
            sc = cls.score_text(dec)
            candidates.append({"shift": shift, "text": dec, "score": round(sc, 2)})
        candidates.sort(key=lambda x: x["score"], reverse=True)
        return candidates

    @staticmethod
    def vigenere_decrypt(ciphertext, key):
        """Déchiffre un texte chiffré par Vigenère avec une clé."""
        res = []
        key = key.upper()
        k_len = len(key)
        k_idx = 0

        for c in ciphertext:
            if 'a' <= c <= 'z':
                shift = ord(key[k_idx % k_len]) - ord('A')
                res.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
                k_idx += 1
            elif 'A' <= c <= 'Z':
                shift = ord(key[k_idx % k_len]) - ord('A')
                res.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
                k_idx += 1
            else:
                res.append(c)
        return "".join(res)

    @staticmethod
    def atbash(text):
        """Chiffre / Déchiffre Atbash (A <-> Z, B <-> Y...)."""
        res = []
        for c in text:
            if 'a' <= c <= 'z':
                res.append(chr(ord('z') - (ord(c) - ord('a'))))
            elif 'A' <= c <= 'Z':
                res.append(chr(ord('Z') - (ord(c) - ord('A'))))
            else:
                res.append(c)
        return "".join(res)

    @staticmethod
    def rail_fence_decrypt(ciphertext, rails):
        """Déchiffre un texte chiffré par transposition Rail Fence (zigzag)."""
        if rails <= 1 or rails >= len(ciphertext):
            return ciphertext

        # Détermination de la grille
        fence = [['\n' for _ in range(len(ciphertext))] for _ in range(rails)]
        row, col = 0, 0
        down = False

        for _ in range(len(ciphertext)):
            if row == 0 or row == rails - 1:
                down = not down
            fence[row][col] = '*'
            col += 1
            row += 1 if down else -1

        idx = 0
        for r in range(rails):
            for c in range(len(ciphertext)):
                if fence[r][c] == '*' and idx < len(ciphertext):
                    fence[r][c] = ciphertext[idx]
                    idx += 1

        result = []
        row, col = 0, 0
        down = False
        for _ in range(len(ciphertext)):
            if row == 0 or row == rails - 1:
                down = not down
            if fence[row][col] != '\n':
                result.append(fence[row][col])
                col += 1
            row += 1 if down else -1

        return "".join(result)

    @classmethod
    def break_rail_fence(cls, ciphertext, max_rails=10):
        """Teste toutes les hauteurs de rails (2 à max_rails) et classe par score."""
        candidates = []
        for r in range(2, min(max_rails + 1, len(ciphertext))):
            dec = cls.rail_fence_decrypt(ciphertext, r)
            sc = cls.score_text(dec)
            candidates.append({"rails": r, "text": dec, "score": round(sc, 2)})
        candidates.sort(key=lambda x: x["score"], reverse=True)
        return candidates

    @staticmethod
    def affine_decrypt(ciphertext, a, b):
        """Déchiffre le chiffre Affine : D(y) = a^-1 * (y - b) mod 26."""
        try:
            a_inv = RSASolver.modinv(a, 26)
        except Exception:
            return ""

        res = []
        for c in ciphertext:
            if 'a' <= c <= 'z':
                y = ord(c) - ord('a')
                res.append(chr((a_inv * (y - b)) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                y = ord(c) - ord('A')
                res.append(chr((a_inv * (y - b)) % 26 + ord('A')))
            else:
                res.append(c)
        return "".join(res)

    @classmethod
    def break_affine(cls, ciphertext):
        """Teste toutes les combinaisons de clés valides (a premier avec 26, b entre 0 et 25)."""
        valid_a = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
        candidates = []
        for a in valid_a:
            for b in range(26):
                dec = cls.affine_decrypt(ciphertext, a, b)
                if dec:
                    sc = cls.score_text(dec)
                    if sc > 2.5 or re.search(r"(flag|ctf|hl)", dec, re.IGNORECASE):
                        candidates.append({"a": a, "b": b, "text": dec, "score": round(sc, 2)})
        candidates.sort(key=lambda x: x["score"], reverse=True)
        return candidates

    @classmethod
    def repeating_key_xor_break(cls, ciphertext_bytes, max_key_len=16):
        """Casse un XOR à clé répétée en estimant la taille de clé (distance de Hamming) et la fréquence."""
        def hamming_distance(b1, b2):
            return sum(bin(x ^ y).count('1') for x, y in zip(b1, b2))

        # Estimation de la longueur de clé (Key size)
        best_keysizes = []
        for ksize in range(2, min(max_key_len + 1, len(ciphertext_bytes) // 4)):
            chunks = [ciphertext_bytes[i:i+ksize] for i in range(0, ksize * 4, ksize)]
            if len(chunks) >= 4:
                dist = (hamming_distance(chunks[0], chunks[1]) +
                        hamming_distance(chunks[1], chunks[2]) +
                        hamming_distance(chunks[2], chunks[3])) / (3.0 * ksize)
                best_keysizes.append((ksize, dist))

        best_keysizes.sort(key=lambda x: x[1])
        candidates = []

        for ksize, _ in best_keysizes[:3]:
            # Découpage en blocs transposés
            blocks = [ciphertext_bytes[i::ksize] for i in range(ksize)]
            key_bytes = []
            for blk in blocks:
                single_results = cls.single_byte_xor(blk)
                if single_results:
                    key_bytes.append(single_results[0]["key"])
                else:
                    key_bytes.append(0)

            guessed_key = bytes(key_bytes)
            # Déchiffrement avec la clé trouvée
            dec = bytes([ciphertext_bytes[i] ^ guessed_key[i % len(guessed_key)] for i in range(len(ciphertext_bytes))])
            dec_text = dec.decode("latin-1", errors="ignore")
            sc = cls.score_text(dec_text)
            candidates.append({
                "keysize": ksize,
                "key_hex": guessed_key.hex(),
                "key_str": "".join(chr(b) if 32 <= b <= 126 else f"\\x{b:02x}" for b in guessed_key),
                "plaintext": dec_text[:120],
                "score": round(sc, 2)
            })

        candidates.sort(key=lambda x: x["score"], reverse=True)
        return candidates

    @staticmethod
    def base64_stego_decode(b64_lines):
        """Extrait les bits d'information cachés dans le padding Base64 (Stéganographie Base64)."""
        B64_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        hidden_bits = []

        for line in b64_lines:
            line = line.strip()
            if not line: continue
            if line.endswith("=="): # 2 caractères de padding = 4 bits inutilisés
                c = line[-3]
                val = B64_TABLE.find(c)
                bits = format(val & 0x0f, '04b')
                hidden_bits.append(bits)
            elif line.endswith("="): # 1 caractère de padding = 2 bits inutilisés
                c = line[-2]
                val = B64_TABLE.find(c)
                bits = format(val & 0x03, '02b')
                hidden_bits.append(bits)

        bit_string = "".join(hidden_bits)
        chars = []
        for i in range(0, len(bit_string) - 7, 8):
            byte_val = int(bit_string[i:i+8], 2)
            if 32 <= byte_val <= 126 or byte_val in [10, 13]:
                chars.append(chr(byte_val))
            else:
                break
        return "".join(chars)

    @staticmethod
    def single_byte_xor(data_bytes):
        """Bruteforce XOR sur 1 octet (0-255) et retourne les meilleurs résultats."""
        candidates = []
        for key in range(256):
            dec_bytes = bytes([b ^ key for b in data_bytes])
            try:
                dec_text = dec_bytes.decode("ascii")
                # Score de validité anglaise/française
                score = sum(1 for c in dec_text if c.isalpha() or c in " .,!?-_")
                if re.search(r"(flag|ctf|hl|hackerlab)", dec_text, re.IGNORECASE):
                    score += 50
                if score > len(dec_text) * 0.7:
                    candidates.append({"key": key, "key_char": chr(key) if 32 <= key <= 126 else hex(key), "text": dec_text, "score": score})
            except Exception:
                pass
        candidates.sort(key=lambda x: x["score"], reverse=True)
        return candidates

# =============================================================================
# 3. IDENTIFICATEUR DE HASHES
# =============================================================================
class HashIdentifier:
    HASH_PATTERNS = [
        {"name": "MD5", "len": 32, "regex": r"^[a-fA-F0-9]{32}$", "desc": "Message Digest 5 (Obsolète, vulnérable aux collisions)"},
        {"name": "NTLM", "len": 32, "regex": r"^[a-fA-F0-9]{32}$", "desc": "Windows NTLM Hash"},
        {"name": "SHA-1", "len": 40, "regex": r"^[a-fA-F0-9]{40}$", "desc": "Secure Hash Algorithm 1 (160 bits)"},
        {"name": "SHA-224", "len": 56, "regex": r"^[a-fA-F0-9]{56}$", "desc": "SHA-2 (224 bits)"},
        {"name": "SHA-256", "len": 64, "regex": r"^[a-fA-F0-9]{64}$", "desc": "SHA-2 (256 bits, standard sécurisé)"},
        {"name": "SHA-384", "len": 96, "regex": r"^[a-fA-F0-9]{96}$", "desc": "SHA-2 (384 bits)"},
        {"name": "SHA-512", "len": 128, "regex": r"^[a-fA-F0-9]{128}$", "desc": "SHA-2 (512 bits)"},
        {"name": "bcrypt", "len": 60, "regex": r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$", "desc": "Blowfish Password Hash"},
        {"name": "MD5-Crypt (Unix)", "len": 34, "regex": r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$", "desc": "Linux /etc/shadow MD5"},
        {"name": "SHA-512-Crypt (Linux shadow)", "len": 106, "regex": r"^\$6\$[a-zA-Z0-9./]{1,16}\$[a-zA-Z0-9./]{86}$", "desc": "Linux /etc/shadow SHA-512"},
        {"name": "JWT (JSON Web Token)", "len": 0, "regex": r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", "desc": "JSON Web Token (RFC 7519)"}
    ]

    @classmethod
    def identify(cls, hash_str):
        h = hash_str.strip()
        matches = []
        for p in cls.HASH_PATTERNS:
            if re.match(p["regex"], h):
                matches.append(p)
        return matches

# =============================================================================
# 4. SOLVEURS MATHÉMATIQUES RSA (CTF SCENARIOS)
# =============================================================================
class RSASolver:
    @staticmethod
    def egcd(a, b):
        """Algorithme d'Euclide étendu : retourne (g, x, y) tel que a*x + b*y = gcd(a, b)."""
        if a == 0:
            return b, 0, 1
        g, y, x = RSASolver.egcd(b % a, a)
        return g, x - (b // a) * y, y

    @staticmethod
    def modinv(a, m):
        """Calcule l'inverse modulaire a^-1 mod m."""
        g, x, _ = RSASolver.egcd(a, m)
        if g != 1:
            raise ValueError(f"Pas d'inverse modulaire pour {a} mod {m}")
        return x % m

    @classmethod
    def solve_pq(cls, p, q, e, c):
        """Résout RSA classique lorsque p, q, e et c sont connus."""
        n = p * q
        phi = (p - 1) * (q - 1)
        d = cls.modinv(e, phi)
        m = pow(c, d, n)
        
        # Décodage en texte si possible
        try:
            hex_m = hex(m)[2:]
            if len(hex_m) % 2 != 0: hex_m = '0' + hex_m
            plaintext = bytes.fromhex(hex_m).decode(errors="ignore")
        except Exception:
            plaintext = str(m)

        return {"n": n, "phi": phi, "d": d, "m": m, "plaintext": plaintext}

    @staticmethod
    def small_e_root(e, c):
        """Attaque sur petit e (quand m^e < n, simple racine e-ième)."""
        # Calcul de la racine e-ième entière
        high = 1
        while high ** e <= c:
            high *= 2
        low = high // 2

        while low < high:
            mid = (low + high) // 2
            mid_pow = mid ** e
            if mid_pow == c:
                hex_m = hex(mid)[2:]
                if len(hex_m) % 2 != 0: hex_m = '0' + hex_m
                return {"m": mid, "plaintext": bytes.fromhex(hex_m).decode(errors="ignore")}
            elif mid_pow < c:
                low = mid + 1
            else:
                high = mid
        return None

    @classmethod
    def common_modulus(cls, n, e1, e2, c1, c2):
        """Attaque à module commun (même n, e1 et e2 premiers entre eux)."""
        g, s1, s2 = cls.egcd(e1, e2)
        if g != 1:
            return None

        if s1 < 0:
            c1 = cls.modinv(c1, n)
            s1 = -s1
        if s2 < 0:
            c2 = cls.modinv(c2, n)
            s2 = -s2

        m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
        hex_m = hex(m)[2:]
        if len(hex_m) % 2 != 0: hex_m = '0' + hex_m
        return {"m": m, "plaintext": bytes.fromhex(hex_m).decode(errors="ignore")}

    @classmethod
    def pollard_p_minus_1(cls, n, b=100000):
        """Factorisation de Pollard p-1 (quand p-1 est B-smooth)."""
        a = 2
        for j in range(2, b):
            a = pow(a, j, n)
            d = math.gcd(a - 1, n)
            if 1 < d < n:
                p = d
                q = n // p
                return p, q
        return None

    @classmethod
    def wiener_attack(cls, e, n):
        """Attaque de Wiener pour RSA quand la clé privée d est petite (d < 1/3 * n^(1/4))."""
        # Fractions continues pour e/n
        def rational_to_contfrac(x, y):
            a = x // y
            pquotients = [a]
            while a * y != x:
                x, y = y, x - a * y
                a = x // y
                pquotients.append(a)
            return pquotients

        def convergents(pquotients):
            conv = []
            for i in range(len(pquotients)):
                p = 0
                q = 1
                for j in range(i, -1, -1):
                    p, q = q, pquotients[j] * q + p
                conv.append((q, p))
            return conv

        frac = rational_to_contfrac(e, n)
        convs = convergents(frac)

        for k, d in convs:
            if k == 0 or d == 0 or d % 2 == 0:
                continue
            phi = (e * d - 1) // k
            # Résolution de x^2 - ((n - phi) + 1)x + n = 0
            s = n - phi + 1
            discr = s * s - 4 * n
            if discr >= 0:
                sq = math.isqrt(discr)
                if sq * sq == discr:
                    p = (s - sq) // 2
                    q = (s + sq) // 2
                    if p * q == n:
                        return {"d": d, "p": p, "q": q, "phi": phi}
        return None
