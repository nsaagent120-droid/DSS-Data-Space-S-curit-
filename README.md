# 🔐 Cybersecurity Mastery Roadmap
### De zéro à expert — Reverse Engineering · Audit de Code · 0-days · Kernel · Firmware

> **Compte d'apprentissage personnel** — Ce dépôt documente mon parcours complet vers l'expertise en cybersécurité offensive et défensive. Chaque section contient les ressources, les outils, les exercices pratiques et les jalons qui me permettent de progresser de façon structurée.

---

## 👤 Profil de départ

| Élément | Détail |
|---|---|
| **Langages maîtrisés** | Python |
| **Environnement** | Linux (Ubuntu 24) |
| **Objectif final** | Expert en RE, audit de code, recherche de 0-days, exploitation kernel/firmware |
| **Durée estimée** | 3 à 5 ans de travail sérieux et régulier |

---

## 🗺️ Vue d'ensemble du parcours

```
PHASE 0 — Fondations (3-6 mois)
├── Langage C / C++
├── Architecture CPU x86-64
├── Assembleur x86
└── Format ELF + outils Linux

PHASE 1 — Reverse Engineering (6-12 mois)
├── Analyse statique (Ghidra, IDA)
├── Analyse dynamique (GDB, strace)
├── CTF Reverse Engineering
└── Crackmes & keygens

PHASE 2 — Exploitation Binaire (6-12 mois)
├── Stack buffer overflow
├── Heap exploitation
├── ROP chains
└── Bypass des protections (ASLR, NX, Canary, PIE)

PHASE 3 — Audit de Code (6-12 mois)
├── Vulnérabilités C/C++ classiques
├── Sécurité web (OWASP Top 10)
├── Outils d'analyse statique
└── Bug bounty méthodologie

PHASE 4 — Recherche de 0-days (1-2 ans)
├── Fuzzing (AFL++, libFuzzer)
├── Analyse de patches (1-day → 0-day)
├── Écriture de PoC
└── Divulgation responsable (CVE)

PHASE 5 — Kernel & Système (1-2 ans)
├── Drivers Linux
├── Exploitation kernel
├── Rootkits
└── Bypass des mécanismes de sécurité OS

PHASE 6 — Firmware & Embarqué (1-2 ans)
├── Architecture ARM / MIPS
├── Extraction et analyse firmware
├── JTAG / UART debug
└── Vulnérabilités IoT
```

---

## 📚 PHASE 0 — Fondations

> **Objectif :** Maîtriser les bases sans lesquelles rien d'autre n'est possible.

### 0.1 — Le langage C

Le C est la lingua franca des systèmes. 90% des binaires analysés en RE sont compilés depuis du C ou C++.

**Concepts à maîtriser :**

- [ ] Types primitifs, tailles, limites (`int`, `char`, `size_t`, `uint64_t`…)
- [ ] Pointeurs : déclaration, déréférencement, arithmétique
- [ ] Tableaux, chaînes de caractères (`char[]`, `\0`, `strlen`)
- [ ] Structures (`struct`, `typedef`, offsets)
- [ ] Allocation dynamique (`malloc`, `free`, `realloc`)
- [ ] Fonctions, passage par valeur vs par pointeur
- [ ] Fichiers et I/O (`fopen`, `fread`, `fwrite`)
- [ ] Compilation (`gcc`, flags, linking)
- [ ] Undefined Behavior : les cas qui créent des vulnérabilités

**Ressources :**
- 📖 *The C Programming Language* — Kernighan & Ritchie (le livre original)
- 🌐 [https://beej.us/guide/bgc/](https://beej.us/guide/bgc/) — Guide C gratuit et excellent
- 🌐 [https://cs50.harvard.edu/x/](https://cs50.harvard.edu/x/) — CS50 Harvard (semaines 1-5)

**Exercices clés :**
```c
// Implémenter soi-même :
// 1. strcpy, strlen, memcpy (sans les utiliser)
// 2. Un allocateur mémoire simple (malloc/free basique)
// 3. Une liste chaînée avec pointeurs
// 4. Un parser de fichier binaire
```

---

### 0.2 — Architecture CPU x86-64

**Registres à mémoriser :**

| Registre | Rôle | Analogie Python |
|---|---|---|
| `RAX` | Valeur de retour | `return value` |
| `RDI` | 1er argument | `args[0]` |
| `RSI` | 2e argument | `args[1]` |
| `RDX` | 3e argument | `args[2]` |
| `RSP` | Sommet de la stack | `stack[-1]` |
| `RBP` | Base du stack frame | `frame pointer` |
| `RIP` | Prochaine instruction | `program counter` |
| `RFLAGS` | Résultats de comparaisons | `condition bits` |

**Concepts à maîtriser :**
- [ ] Organisation de la mémoire d'un processus (stack / heap / .text / .data / .bss)
- [ ] Le stack frame : prologue, épilogue, variables locales
- [ ] Convention d'appel System V AMD64 ABI (Linux)
- [ ] Little-endian vs big-endian
- [ ] Modes d'adressage : immédiat, registre, mémoire, base+offset

---

### 0.3 — Assembleur x86-64

**Instructions essentielles :**

```nasm
; Données
mov  rax, rbx        ; rax = rbx
mov  rax, [rbx]      ; rax = *rbx  (déréférence)
mov  [rax], rbx      ; *rax = rbx  (écrit en mémoire)
lea  rax, [rbx+8]    ; rax = rbx + 8  (adresse, pas valeur)

; Arithmétique
add  rax, 5          ; rax += 5
sub  rax, rbx        ; rax -= rbx
xor  rax, rax        ; rax = 0  (mise à zéro rapide)
imul rax, rbx        ; rax *= rbx

; Comparaison et sauts
cmp  rax, rbx        ; met à jour les flags (rax - rbx)
test rax, rax        ; vérifie si rax == 0
jz   addr            ; saute si ZF=1  (égalité)
jnz  addr            ; saute si ZF=0  (différence)
jg   addr            ; saute si > (signé)
jmp  addr            ; saut inconditionnel

; Stack
push rax             ; empile rax,  RSP -= 8
pop  rbx             ; dépile dans rbx, RSP += 8

; Fonctions
call 0x401234        ; push RIP ; jmp addr
ret                  ; pop RIP  (retour)
```

**Patterns à reconnaître instantanément :**
- [ ] `push rbp / mov rbp, rsp` → début de fonction
- [ ] `pop rbp / ret` → fin de fonction
- [ ] `cmp + jne` → `if/else`
- [ ] `cmp + jge + jmp` → boucle `for`/`while`
- [ ] `jmp [rcx + rax*8]` → `switch` avec jump table
- [ ] `xor rax, rax` → `return 0` ou mise à zéro

---

### 0.4 — Outils Linux fondamentaux

```bash
# Analyse de binaires
file ./binary              # architecture, type
strings ./binary           # toutes les chaînes ASCII
readelf -h ./binary        # ELF header
readelf -S ./binary        # sections
readelf -s ./binary        # symboles
objdump -d -M intel ./binary  # désassemblage
nm ./binary                # symboles + adresses
ldd ./binary               # bibliothèques dynamiques
checksec --file=./binary   # protections actives

# Compilation
gcc -g -o prog prog.c                          # avec symboles debug
gcc -fno-stack-protector -no-pie -o prog prog.c # sans protections (lab)
gcc -O0 -o prog prog.c                         # sans optimisations

# Analyse dynamique
strace ./binary            # syscalls
ltrace ./binary            # appels libc
```

---

## 🔬 PHASE 1 — Reverse Engineering

> **Objectif :** Lire et comprendre n'importe quel binaire sans accès au code source.

### 1.1 — Analyse statique avec Ghidra

**Workflow standard :**
1. `File → Import File` → sélectionner le binaire
2. `Analysis → Auto Analyze` → laisser tourner
3. **Symbol Tree** → lister les fonctions, trouver `main`
4. **Decompiler** → pseudo-C automatique
5. Renommer les fonctions et variables (`L` pour renommer)
6. Suivre les références croisées (`Ctrl+Shift+F`)
7. Chercher les strings intéressantes (`Search → For Strings`)

**Techniques avancées :**
- [ ] Reconstruire des structures (Data Type Manager)
- [ ] Identifier les algorithmes : hash, chiffrement, compression
- [ ] Patcher des instructions directement dans Ghidra
- [ ] Écrire des scripts Ghidra en Python/Java pour automatiser
- [ ] Analyser des binaires obfusqués (anti-debug, anti-disasm)

---

### 1.2 — Analyse dynamique avec GDB + pwndbg

```bash
# Installation pwndbg
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# Commandes GDB essentielles
gdb ./binary
(gdb) break main          # breakpoint sur main
(gdb) run                 # lancer
(gdb) disassemble main    # voir l'ASM
(gdb) info registers      # tous les registres
(gdb) x/20gx $rsp         # 20 qwords depuis RSP
(gdb) x/s $rdi            # string pointée par RDI
(gdb) x/20i $rip          # 20 instructions depuis RIP
(gdb) stepi               # instruction par instruction
(gdb) finish              # exécuter jusqu'au ret
(gdb) telescope $rsp 20   # (pwndbg) déréférence la stack
(gdb) cyclic 100          # (pwndbg) pattern cyclique
(gdb) cyclic -l 0x6161616e # trouver l'offset
```

**Compétences à développer :**
- [ ] Lire la stack frame complète à tout moment
- [ ] Suivre les appels de fonctions imbriqués
- [ ] Identifier les arguments et valeurs de retour
- [ ] Modifier la mémoire et les registres à la volée
- [ ] Scripter GDB avec Python (`gdb.execute`, `gdb.parse_and_eval`)

---

### 1.3 — CTF Reverse Engineering

**Progression suggérée :**

| Niveau | Plateformes | Types de challenges |
|---|---|---|
| Débutant | picoCTF, crackmes.one (easy) | Trouver un mot de passe hardcodé |
| Intermédiaire | HackTheBox RE, crackmes.one (medium) | Algorithmes custom, anti-debug |
| Avancé | pwn.college, CTFtime.org | Obfuscation, packing, VM-based |

**Catégories de challenges RE :**
- [ ] Crackme / Keygen (trouver le bon input)
- [ ] Binaires strippés (sans symboles)
- [ ] Binaires packés (UPX, custom packers)
- [ ] Algorithmes de chiffrement custom
- [ ] Machines virtuelles (interpréteurs custom)
- [ ] Anti-debug (ptrace, timing, checksum)

---

## 💥 PHASE 2 — Exploitation Binaire

> **Objectif :** Transformer une vulnérabilité identifiée en exploit fonctionnel.

### 2.1 — Stack Buffer Overflow

**Mécanisme fondamental :**
```
Stack frame de vulnerable() :
┌─────────────────────────┐  ← Adresses hautes
│  Adresse de retour (RIP)│  ← CIBLE : écraser ici
│  Ancien RBP             │
│  variable locale 2      │
│  variable locale 1      │
│  char buf[N]            │  ← OVERFLOW commence ici
└─────────────────────────┘  ← RSP (adresses basses)

Payload = 'A' * (N + 8) + p64(adresse_cible)
           padding buf    saved_rbp   nouveau RIP
```

**Étapes d'exploitation :**
- [ ] Identifier la fonction vulnérable (Ghidra / audit)
- [ ] Trouver l'offset jusqu'à RIP (cyclic + GDB)
- [ ] Obtenir l'adresse cible (`print &func` dans GDB)
- [ ] Construire le payload avec pwntools
- [ ] Bypass NX → ROP chains
- [ ] Bypass Canary → leak via format string
- [ ] Bypass ASLR → leak d'adresse depuis GOT/stack

---

### 2.2 — Heap Exploitation

**Structures internes de glibc (ptmalloc2) :**
```c
// Chunk malloc en mémoire :
struct malloc_chunk {
    size_t prev_size;   // taille du chunk précédent (si libre)
    size_t size;        // taille + flags (P=prev_in_use, M=mmap, N=non_main)
    // données utilisateur ici (pour un chunk alloué)
    // OU si libre :
    struct malloc_chunk *fd;   // forward pointer (freelist)
    struct malloc_chunk *bk;   // backward pointer (freelist)
};
```

**Techniques à maîtriser :**
- [ ] Heap overflow : déborder d'un chunk vers le suivant
- [ ] Use-After-Free (UAF) : pointer sur mémoire libérée
- [ ] Double-free : libérer deux fois → corruption
- [ ] tcache poisoning (glibc 2.26+)
- [ ] fastbin dup
- [ ] House of Force, House of Spirit, House of Lore

---

### 2.3 — ROP (Return-Oriented Programming)

Quand la stack est non-exécutable (NX/DEP), on chaîne des "gadgets" existants dans le binaire.

```python
from pwn import *
from ROPgadget import *

elf = ELF('./binary')
rop = ROP(elf)

# Trouver des gadgets
# ROPgadget --binary ./binary --rop

# Construire une ROP chain
rop.raw(rop.find_gadget(['pop rdi', 'ret'])[0])
rop.raw(next(elf.search(b'/bin/sh\x00')))
rop.raw(elf.plt['system'])

payload = b'A' * offset + rop.chain()
```

**Techniques ROP :**
- [ ] ret2plt : appeler une fonction de la PLT
- [ ] ret2libc : appeler `system("/bin/sh")`
- [ ] ret2csu : utiliser `__libc_csu_init` comme gadget universel
- [ ] SROP (Sigreturn-Oriented Programming)
- [ ] FSOP (File Stream Oriented Programming)

---

## 🔍 PHASE 3 — Audit de Code

> **Objectif :** Identifier des vulnérabilités dans du code source avant qu'elles ne soient exploitées.

### 3.1 — Vulnérabilités C/C++ à chercher

**Fonctions dangereuses :**

| Fonction | Danger | Alternative sécurisée |
|---|---|---|
| `gets(buf)` | Pas de limite de taille | `fgets(buf, size, stdin)` |
| `strcpy(dst, src)` | Pas de vérification | `strncpy(dst, src, n)` |
| `sprintf(buf, fmt, ...)` | Buffer overflow | `snprintf(buf, n, fmt, ...)` |
| `scanf("%s", buf)` | Pas de limite | `scanf("%255s", buf)` |
| `strcat(dst, src)` | Overflow si dst plein | `strncat(dst, src, n)` |
| `printf(user_input)` | Format string | `printf("%s", user_input)` |
| `malloc(a * b)` | Integer overflow | vérifier avant : `if(a > SIZE_MAX/b)` |

**Checklist d'audit C :**
- [ ] Vérifier toutes les entrées utilisateur (taille, type, contenu)
- [ ] Chercher `gets`, `strcpy`, `sprintf` non bornés
- [ ] Chercher `printf(var)` sans format fixe
- [ ] Vérifier les calculs de taille avant `malloc`
- [ ] Chercher les `free()` non mis à `NULL` après
- [ ] Vérifier les valeurs de retour (`malloc` peut retourner NULL)
- [ ] Chercher les race conditions (threads + données partagées)
- [ ] Vérifier les comparaisons signées/non-signées

---

### 3.2 — Outils d'analyse statique

```bash
# Semgrep — analyse multi-langages
pip install semgrep
semgrep --config=p/c ./src/

# Flawfinder — C/C++ rapide
pip install flawfinder
flawfinder ./src/

# Cppcheck
sudo apt install cppcheck
cppcheck --enable=all ./src/

# CodeQL — GitHub, très puissant
# https://codeql.github.com/docs/

# ASAN/UBSAN — détection runtime
gcc -fsanitize=address,undefined -g -o prog prog.c
./prog  # crashes avec stack traces détaillées
```

---

### 3.3 — Sécurité Web (OWASP Top 10)

- [ ] **A01 — Broken Access Control** : IDOR, élévation de privilèges
- [ ] **A02 — Cryptographic Failures** : mots de passe en clair, TLS faible
- [ ] **A03 — Injection** : SQL, Command, LDAP, XPath
- [ ] **A04 — Insecure Design** : logique métier défaillante
- [ ] **A05 — Security Misconfiguration** : headers, CORS, debug activé
- [ ] **A06 — Vulnerable Components** : dépendances non mises à jour
- [ ] **A07 — Auth Failures** : session fixation, brute force, JWT faible
- [ ] **A08 — Integrity Failures** : deserialization non sécurisée
- [ ] **A09 — Logging Failures** : pas de traces d'intrusion
- [ ] **A10 — SSRF** : forcer le serveur à faire des requêtes internes

---

## 🎯 PHASE 4 — Recherche de 0-days

> **Objectif :** Découvrir des vulnérabilités inconnues dans des logiciels répandus.

### 4.1 — Fuzzing

Le fuzzing consiste à envoyer des entrées aléatoires/malformées jusqu'à provoquer un crash.

```bash
# AFL++ — le fuzzer le plus utilisé
sudo apt install afl++

# Compiler le programme pour AFL
AFL_USE_ASAN=1 afl-clang-fast -o target_fuzz target.c

# Préparer les corpus d'entrée
mkdir -p fuzzing/in fuzzing/out
echo "test" > fuzzing/in/seed

# Lancer le fuzzing
afl-fuzz -i fuzzing/in -o fuzzing/out -- ./target_fuzz @@

# Analyser les crashes
afl-tmin -i crash_file -o minimized -- ./target_fuzz @@
```

**Techniques de fuzzing :**
- [ ] AFL++ (coverage-guided fuzzing)
- [ ] libFuzzer (in-process fuzzing)
- [ ] Boofuzz (fuzzing réseau / protocoles)
- [ ] Honggfuzz (multi-processus)
- [ ] Grammar-based fuzzing (JSON, XML, scripts)
- [ ] Corpus collection et mutation

---

### 4.2 — Analyse de patches (1-day research)

```bash
# Comparer deux versions d'un binaire
bindiff binary_before binary_after    # tool BinDiff de Google

# Ou manuellement avec Ghidra :
# 1. Importer les deux versions
# 2. Comparer les fonctions modifiées
# 3. Comprendre CE QUI a été corrigé
# 4. Chercher des variantes non corrigées
```

**Workflow 1-day :**
1. Surveiller les CVE et patches (NVD, vendor advisories)
2. Télécharger la version avant/après le patch
3. Identifier la fonction modifiée (BinDiff, Ghidra)
4. Comprendre la root cause de la vuln
5. Chercher des variantes similaires dans le même code
6. Écrire un PoC pour la vulnérabilité originale

---

### 4.3 — Écriture de CVE et divulgation responsable

```
Timeline standard :
Jour 0   : Découverte de la vulnérabilité
Jour 1   : Confirmation + écriture du PoC minimal
Jour 2-5 : Contact du vendeur (security@vendor.com)
Jour 7   : Accusé de réception attendu
Jour 90  : Deadline de divulgation (standard industriel)
Jour 90+ : Publication du rapport + PoC (si patch disponible)
```

**Format d'un bon rapport de vulnérabilité :**
- [ ] Résumé exécutif (2-3 phrases)
- [ ] Version(s) affectée(s)
- [ ] Conditions d'exploitation (authentification requise ? réseau ?)
- [ ] Étapes de reproduction détaillées
- [ ] PoC fonctionnel
- [ ] Impact (CVSS score)
- [ ] Suggestion de correctif

---

## 🐧 PHASE 5 — Sécurité Kernel Linux

> **Objectif :** Comprendre et exploiter des vulnérabilités au niveau du noyau.

### 5.1 — Prérequis kernel

- [ ] Comprendre l'espace utilisateur vs espace noyau (ring 0 vs ring 3)
- [ ] Appels système : comment `syscall` transfère le contrôle au kernel
- [ ] Mémoire kernel : pagination, TLB, espace d'adressage kernel
- [ ] Structures kernel importantes : `task_struct`, `cred`, `file`, `sk_buff`
- [ ] Modules kernel : écrire, charger, déboguer (`insmod`, `rmmod`, `dmesg`)

### 5.2 — Écriture d'un module kernel (premier pas)

```c
// hello_kernel.c — Module minimal
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ton_nom");
MODULE_DESCRIPTION("Module d'apprentissage");

static int __init hello_init(void) {
    printk(KERN_INFO "Hello, Kernel!\n");
    return 0;
}

static void __exit hello_exit(void) {
    printk(KERN_INFO "Goodbye, Kernel!\n");
}

module_init(hello_init);
module_exit(hello_exit);
```

```bash
# Compiler et charger
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
sudo insmod hello_kernel.ko
dmesg | tail         # → "Hello, Kernel!"
sudo rmmod hello_kernel
```

### 5.3 — Exploitation kernel

**Vulnérabilités kernel classiques :**
- [ ] Kernel stack overflow
- [ ] Heap overflow kernel (SLUB/SLAB)
- [ ] Use-After-Free kernel
- [ ] Race conditions (TOCTOU)
- [ ] Type confusion
- [ ] Integer overflow dans les syscalls

**Techniques d'exploitation :**
- [ ] `ret2user` : exécuter du shellcode en ring 0 puis revenir en ring 3
- [ ] `ret2usr` avec SMEP/SMAP bypass
- [ ] ROP kernel
- [ ] Heap spraying kernel
- [ ] `modprobe_path` overwrite

**Protections kernel à comprendre :**

| Protection | Description | Bypass |
|---|---|---|
| SMEP | No execute depuis ring 3 en ring 0 | ROP kernel |
| SMAP | No access depuis ring 3 en ring 0 | ROP kernel |
| KASLR | Randomisation de l'adresse de base kernel | Leak kernel |
| KPTI | Séparation des tables de pages kernel/user | — |
| Stack Canary kernel | Canary en espace kernel | Leak |

---

## 📡 PHASE 6 — Firmware & Systèmes Embarqués

> **Objectif :** Analyser et trouver des vulnérabilités dans les firmwares IoT et embarqués.

### 6.1 — Extraction de firmware

```bash
# Outil universel : binwalk
sudo apt install binwalk
pip install binwalk

# Analyser un firmware
binwalk firmware.bin                  # identifier les composants
binwalk -e firmware.bin               # extraire automatiquement
binwalk -M -e firmware.bin           # récursif

# Si chiffré : chercher les clés dans d'autres firmwares du même vendor
# ou dans le bootloader

# Monter un système de fichiers extrait
ls _firmware.bin.extracted/
# squashfs-root/  → système de fichiers complet
```

### 6.2 — Analyse de firmware

```bash
# Chercher des vulnérabilités dans le FS extrait
find . -name "*.conf" -o -name "*.cfg"  # configs
find . -perm -4000                       # binaires SUID
grep -r "password" . --include="*.conf"  # mots de passe hardcodés
grep -r "admin" . --include="*.lua"      # creds hardcodés

# Analyser les binaires ARM avec Ghidra
# File → Import File → choisir ARM little-endian
# ou MIPS selon l'architecture du routeur/device

# Émuler avec QEMU
sudo apt install qemu-user-static
qemu-arm-static -L ./squashfs-root ./squashfs-root/bin/busybox
```

### 6.3 — Architectures embarquées

| Architecture | Appareils typiques | Endianness |
|---|---|---|
| ARM 32-bit | Routeurs anciens, Raspberry Pi | Little ou Big |
| ARM 64-bit (AArch64) | Appareils récents, Apple M-series | Little |
| MIPS 32-bit | Routeurs (TP-Link, Netgear) | Big ou Little |
| PowerPC | Anciens équipements réseau | Big |
| RISC-V | Nouveaux projets open-source | Little |

### 6.4 — Debug hardware

- [ ] **UART** : port série de debug souvent accessible physiquement
- [ ] **JTAG** : debug matériel complet, accès mémoire temps réel
- [ ] **SPI/I2C** : lire les chips mémoire (EEPROM, flash NOR/NAND)
- [ ] **Bus Pirate / OpenOCD** : outils d'interfaçage matériel

```bash
# Trouver les ports UART sur un PCB
# 1. Chercher 3-4 pins alignées (VCC, TX, RX, GND)
# 2. Mesurer avec multimètre : TX oscille, RX stable, GND = 0V
# 3. Connecter avec USB-UART adapter (3.3V !)
# 4. minicom -s → configurer 115200 8N1
minicom -b 115200 -o -D /dev/ttyUSB0
```

---

## 🛠️ Stack d'outils complète

### Outils statiques

| Outil | Usage | Gratuit |
|---|---|---|
| **Ghidra** | Désassembleur + décompilateur | ✅ |
| **IDA Pro** | Standard industrie, décompilateur Hex-Rays | ❌ (IDA Free = limité) |
| **Binary Ninja** | Alternative moderne à IDA | ❌ (Community = limité) |
| **Radare2 / Cutter** | Framework RE CLI + GUI | ✅ |
| **BinDiff** | Comparaison de binaires | ✅ |
| **ROPgadget** | Recherche de gadgets ROP | ✅ |
| **pwntools** | Framework exploit Python | ✅ |

### Outils dynamiques

| Outil | Usage | Gratuit |
|---|---|---|
| **GDB + pwndbg** | Débogueur Linux principal | ✅ |
| **GDB + peda** | Alternative à pwndbg | ✅ |
| **strace** | Trace syscalls | ✅ |
| **ltrace** | Trace appels libc | ✅ |
| **Frida** | Instrumentation dynamique (mobile + desktop) | ✅ |
| **PIN (Intel)** | Framework d'instrumentation | ✅ |
| **DynamoRIO** | Instrumentation dynamique | ✅ |

### Fuzzing

| Outil | Usage | Gratuit |
|---|---|---|
| **AFL++** | Coverage-guided fuzzer | ✅ |
| **libFuzzer** | In-process fuzzer (LLVM) | ✅ |
| **Honggfuzz** | Fuzzer multi-processus | ✅ |
| **Boofuzz** | Fuzzing protocoles réseau | ✅ |

### Environnements de lab

| Outil | Usage |
|---|---|
| **VirtualBox / VMware** | VMs Linux isolées pour tests |
| **QEMU** | Émulation d'architectures ARM, MIPS |
| **Docker** | Environnements reproductibles |
| **GDB server** | Debug distant (kernel, firmware) |

---

## 🏆 Plateformes de pratique

| Plateforme | URL | Spécialité | Niveau |
|---|---|---|---|
| **pwn.college** | https://pwn.college | RE + Exploitation structuré | Débutant → Avancé |
| **picoCTF** | https://picoctf.org | Tous domaines, guidé | Débutant |
| **Crackmes.one** | https://crackmes.one | Reverse Engineering | Débutant → Inter. |
| **HackTheBox** | https://hackthebox.com | Labs réalistes complets | Intermédiaire |
| **CTFtime.org** | https://ctftime.org | Compétitions mondiales | Tous niveaux |
| **ROP Emporium** | https://ropemporium.com | ROP chains progressif | Intermédiaire |
| **pwnable.kr** | https://pwnable.kr | Pwn classiques | Inter. → Avancé |
| **exploit.education** | https://exploit.education | VMs d'exploitation | Débutant → Inter. |
| **VulnHub** | https://vulnhub.com | Machines vulnérables RE | Inter. → Avancé |
| **OSS-Fuzz** | https://google.github.io/oss-fuzz | Fuzzing projets open source | Avancé |

---

## 📖 Bibliothèque de référence

### Livres essentiels

| Titre | Auteur | Phase | Note |
|---|---|---|---|
| *Hacking: The Art of Exploitation* | Jon Erickson | 0-2 | ⭐⭐⭐⭐⭐ La bible |
| *The C Programming Language* | Kernighan & Ritchie | 0 | ⭐⭐⭐⭐⭐ Indispensable |
| *Practical Binary Analysis* | Dennis Andriesse | 1-2 | ⭐⭐⭐⭐⭐ |
| *Practical Malware Analysis* | Sikorski & Honig | 1 | ⭐⭐⭐⭐⭐ |
| *The Shellcoder's Handbook* | Anley et al. | 2-3 | ⭐⭐⭐⭐ |
| *Computer Systems: A Programmer's Perspective* | Bryant & O'Hallaron | 0-1 | ⭐⭐⭐⭐⭐ |
| *Linux Kernel Development* | Robert Love | 5 | ⭐⭐⭐⭐⭐ |
| *A Guide to Kernel Exploitation* | Perla & Oldani | 5 | ⭐⭐⭐⭐ |
| *The Art of Memory Forensics* | Ligh et al. | 5 | ⭐⭐⭐⭐ |
| *Rootkits and Bootkits* | Matrosov et al. | 5-6 | ⭐⭐⭐⭐ |
| *The IoT Hacker's Handbook* | Aditya Gupta | 6 | ⭐⭐⭐⭐ |

### Blogs et ressources en ligne

| Ressource | URL | Spécialité |
|---|---|---|
| Project Zero Blog | https://googleprojectzero.blogspot.com | 0-days, recherche avancée |
| Trail of Bits Blog | https://blog.trailofbits.com | RE, audit, outils |
| LiveOverflow (YouTube) | https://youtube.com/@LiveOverflow | CTF, exploitation, RE |
| ret2systems Blog | https://ret2.systems/blog | Exploitation avancée |
| Phrack Magazine | http://phrack.org | Articles techniques historiques |
| Sam Bowne | https://samsclass.info | Cours sécurité complets gratuits |

---

## 📊 Suivi de progression

### Phase 0 — Fondations
- [ ] Écrire un allocateur mémoire en C
- [ ] Lire 20 fonctions en assembleur x86-64 sans aide
- [ ] Maîtriser les commandes GDB essentielles
- [ ] Analyser un binaire simple avec Ghidra

### Phase 1 — Reverse Engineering
- [ ] Résoudre 5 crackmes niveau Easy sur crackmes.one
- [ ] Résoudre 10 challenges RE sur picoCTF
- [ ] Analyser un vrai malware dans un environnement isolé
- [ ] Écrire un script Python Ghidra pour automatiser une analyse

### Phase 2 — Exploitation
- [ ] Exploiter un stack BOF sans protections
- [ ] Exploiter avec NX activé (ROP chain)
- [ ] Exploiter avec ASLR + NX (leak d'adresse)
- [ ] Exploiter un heap overflow basique
- [ ] Résoudre 5 challenges pwn sur CTFtime

### Phase 3 — Audit
- [ ] Auditer un projet open-source et trouver 1 bug (même mineur)
- [ ] Soumettre un rapport sur un bug bounty program
- [ ] Maîtriser Semgrep et CodeQL
- [ ] Comprendre les 10 vulnérabilités OWASP avec PoC

### Phase 4 — 0-days
- [ ] Fuzzer un programme avec AFL++ et trouver un crash
- [ ] Analyser un patch CVE et comprendre la root cause
- [ ] Écrire un PoC complet pour une vuln existante
- [ ] Trouver et reporter une vraie vulnérabilité (CVE)

### Phase 5 — Kernel
- [ ] Écrire et charger un module kernel fonctionnel
- [ ] Exploiter une vuln kernel dans un CTF
- [ ] Comprendre et bypasser SMEP/SMAP
- [ ] Écrire un rootkit kernel simple (en lab uniquement)

### Phase 6 — Firmware
- [ ] Extraire et analyser un firmware de routeur avec binwalk
- [ ] Trouver des credentials hardcodés dans un firmware
- [ ] Analyser un binaire ARM avec Ghidra
- [ ] Connecter un port UART sur un appareil physique

---

## ⚖️ Éthique et légalité

> Ces connaissances sont des outils. Comme tout outil, leur usage est défini par l'intention.

**Règles non-négociables :**

1. **Tester uniquement sur ce que tu possèdes** ou avec une **autorisation écrite explicite**
2. **CTF et labs** : cibles légitimes par définition, aucune restriction
3. **Bug Bounty** : lire attentivement le scope — certaines cibles sont hors-scope
4. **Divulgation responsable** : contacter le vendeur en privé avant toute publication
5. **Ne jamais** accéder à des systèmes tiers sans permission, même "pour voir"

**Ressources sur la légalité :**
- Computer Fraud and Abuse Act (CFAA) — droit américain
- Directive NIS2 — droit européen
- Cybercriminalité en droit africain (loi Benin 2017-20)

---

## 📁 Structure de ce dépôt

```
📂 cybersecurity-learning/
├── 📄 README.md                    ← ce fichier
├── 📂 phase0-fondations/
│   ├── 📂 c-exercises/             ← exercices C commentés
│   ├── 📂 asm-examples/            ← snippets assembleur annotés
│   └── 📂 gdb-cheatsheet/          ← commandes GDB avec exemples
├── 📂 phase1-reverse-engineering/
│   ├── 📂 crackmes/                ← solutions commentées
│   ├── 📂 ghidra-scripts/          ← scripts d'automatisation
│   └── 📂 writeups/                ← CTF writeups RE
├── 📂 phase2-exploitation/
│   ├── 📂 stack-bof/               ← stack overflow labs
│   ├── 📂 heap/                    ← heap exploitation labs
│   ├── 📂 rop/                     ← ROP chains
│   └── 📂 writeups/                ← CTF writeups pwn
├── 📂 phase3-audit/
│   ├── 📂 vulnerable-patterns/     ← patterns de code dangereux
│   ├── 📂 static-analysis/         ← configs Semgrep/CodeQL
│   └── 📂 reports/                 ← rapports d'audit (anonymisés)
├── 📂 phase4-0days/
│   ├── 📂 fuzzing-setups/          ← configs AFL++
│   ├── 📂 patch-analysis/          ← analyses de CVE
│   └── 📂 pocs/                    ← PoC pour vulns divulguées
├── 📂 phase5-kernel/
│   ├── 📂 modules/                 ← modules kernel expérimentaux
│   └── 📂 writeups/                ← kernel CTF writeups
├── 📂 phase6-firmware/
│   ├── 📂 analysis/                ← analyses de firmware
│   └── 📂 tools/                   ← scripts d'extraction
└── 📂 resources/
    ├── 📄 cheatsheets/             ← anti-sèches rapides
    └── 📄 bookmarks.md             ← liens utiles organisés
```

---

## 🔄 Journal de progression

| Date | Phase | Accomplissement |
|---|---|---|
| 2026-05-28 | Phase 0 | Début du parcours — maîtrise Python acquise |
| … | … | … |

---

<div align="center">

**« La sécurité n'est pas un produit, c'est un processus. »** — Bruce Schneier

*Ce dépôt est en construction permanente. Chaque commit est un pas de plus.*

![Progress](https://img.shields.io/badge/Phase-0%20Fondations-teal)
![Language](https://img.shields.io/badge/Langages-C%20%7C%20Python%20%7C%20ASM-purple)
![Platform](https://img.shields.io/badge/Platform-Linux%20x86--64-orange)

</div>
