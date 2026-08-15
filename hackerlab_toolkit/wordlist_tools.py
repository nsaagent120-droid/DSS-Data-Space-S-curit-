"""
=============================================================================
  Module Wordlist & Générateur de Dictionnaires CTF - HackerLab Toolkit
=============================================================================
  Description : Générateur de mutations de mots de passe, règles Leetspeak
                et dictionnaires personnalisés pour épreuves CTF.
=============================================================================
"""

class WordlistMutator:
    LEET_MAP = {
        'a': ['4', '@', 'A'],
        'e': ['3', 'E'],
        'i': ['1', '!', 'I'],
        'o': ['0', 'O'],
        's': ['5', '$', 'S'],
        't': ['7', 'T'],
        'b': ['8', 'B']
    }

    SUFFIXES = ["", "123", "1234", "2024", "2025", "2026", "!", "?", "_admin", "2023", "#", "@@"]

    @classmethod
    def mutate(cls, base_word, max_variants=200):
        """Génère des variantes leetspeak et suffixes courants à partir d'un mot de base."""
        variants = set()
        w = base_word.strip().lower()
        variants.add(w)
        variants.add(w.capitalize())
        variants.add(w.upper())

        # Leetspeak simple
        leet_chars = []
        for c in w:
            if c in cls.LEET_MAP:
                leet_chars.append(cls.LEET_MAP[c][0])
            else:
                leet_chars.append(c)
        leet_w = "".join(leet_chars)
        variants.add(leet_w)
        variants.add(leet_w.capitalize())

        # Combinaisons avec suffixes
        current_list = list(variants)
        for base in current_list:
            for suff in cls.SUFFIXES:
                variants.add(f"{base}{suff}")
                if len(variants) >= max_variants:
                    break

        return sorted(list(variants))
