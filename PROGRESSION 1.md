# 📚 Les Fondamentaux du Langage C
> Guide complet pour débutants et référence rapide pour développeurs
>
> ✅ Types primitifs | ✅ Variables | ✅ Chaînes de caractères
---
## 📑 Table des matières
- [1. Types primitifs](#1-types-primitifs)
- [2. Variables](#2-variables)
- [3. Chaînes de caractères](#3-chaînes-de-caractères)
- [4. Fiches récapitulatives](#4-fiches-récapitulatives)
---
# 1. Types primitifs
## 1.1 Concept fondamental
Un ordinateur stocke tout en **bits** (0 ou 1). Les types servent à définir :
- **Combien de mémoire** utiliser
- **Comment interpréter** les bits (nombre entier, caractère, etc.)

Bit : 0 ou 1 (unité de base)  
Byte : 8 bits = peut stocker 256 valeurs différentes (2⁸)

text

---
## 1.2 Pourquoi différents types ?
Chaque type correspond à un **compromis entre taille et capacité** :
| Besoin | Type adapté | Taille |
|--------|-------------|--------|
| Compter jusqu'à 100 | `char` | 1 byte |
| Compter jusqu'à 50 000 | `short` ou `int` | 2-4 bytes |
| Manipuler de très grands nombres | `long long` | 8 bytes |
| Économiser la mémoire | `uint8_t`, `int16_t` | 1-2 bytes |
---
## 1.3 Types entiers standards
| Type | Taille (x86) | Taille (x64) | Valeur minimale | Valeur maximale |
|------|-------------|-------------|-----------------|-----------------|
| `char` | 1 byte | 1 byte | -128 | 127 |
| `unsigned char` | 1 byte | 1 byte | 0 | 255 |
| `short` | 2 bytes | 2 bytes | -32 768 | 32 767 |
| `unsigned short` | 2 bytes | 2 bytes | 0 | 65 535 |
| `int` | 4 bytes | 4 bytes | -2 147 483 648 | 2 147 483 647 |
| `unsigned int` | 4 bytes | 4 bytes | 0 | 4 294 967 295 |
| `long` | 4 bytes ⚠️ | **8 bytes** ⚠️ | -2³¹ / -2⁶³ | 2³¹-1 / 2⁶³-1 |
| `unsigned long` | 4 bytes ⚠️ | **8 bytes** ⚠️ | 0 | 2³²-1 / 2⁶⁴-1 |
| `long long` | 8 bytes | 8 bytes | -9.22×10¹⁸ | 9.22×10¹⁸ |
| `unsigned long long` | 8 bytes | 8 bytes | 0 | 1.84×10¹⁹ |
> ⚠️ **Attention** : La taille de `long` et des pointeurs **change** selon l'architecture (32 ou 64 bits)
---
## 1.4 Types à taille garantie (stdint.h)
Pour être **certain de la taille**, utilisez ces types (inclure `<stdint.h>`) :
```c
#include <stdint.h>
// Taille GARANTIE, peu importe la machine
int8_t    a = -128;         // 1 byte signé
uint8_t   b = 255;          // 1 byte non signé
int16_t   c = -32768;       // 2 bytes signé
uint16_t  d = 65535;        // 2 bytes non signé
int32_t   e = -2147483648;  // 4 bytes signé
uint32_t  f = 4294967295;   // 4 bytes non signé
int64_t   g;                // 8 bytes signé
uint64_t  h;                // 8 bytes non signé

> ✅ **Bonne pratique** : Toujours utiliser les types `stdint.h` quand la taille exacte est importante

---

## 1.5 Types flottants

|Type|Taille|Précision|Plage approximative|
|---|---|---|---|
|`float`|4 bytes|6-7 chiffres|±1.2×10⁻³⁸ à ±3.4×10³⁸|
|`double`|8 bytes|15-16 chiffres|±2.2×10⁻³⁰⁸ à ±1.8×10³⁰⁸|
|`long double`|16 bytes|19-20 chiffres|±3.4×10⁻⁴⁹³² à ±1.1×10⁴⁹³²|

c

float  prix   = 19.99f;      // Notez le 'f' à la fin
double precis = 3.14159265359;

---

## 1.6 Limites en hexadécimal

c

UINT8_MAX   = 0xFF                  // 255
UINT16_MAX  = 0xFFFF                // 65 535
UINT32_MAX  = 0xFFFFFFFF            // 4 294 967 295
UINT64_MAX  = 0xFFFFFFFFFFFFFFFF    // 18 446 744 073 709 551 615
INT8_MAX    = 0x7F                  // 127
INT16_MAX   = 0x7FFF                // 32 767
INT32_MAX   = 0x7FFFFFFF            // 2 147 483 647
INT64_MAX   = 0x7FFFFFFFFFFFFFFF    // 9 223 372 036 854 775 807
INT8_MIN    = 0x80                  // -128
INT32_MIN   = 0x80000000            // -2 147 483 648

---

## 1.7 Le dépassement de capacité (overflow)

**Concept crucial en sécurité informatique**

c

#include <stdio.h>
#include <stdint.h>
int main() {
    // OVERFLOW : dépasser la limite maximale
    uint8_t petit = 255;     // Maximum pour 1 byte
    petit = petit + 1;       // Devrait faire 256...
    printf("255 + 1 = %d\n", petit);  // Affiche 0 !
    // Comme un compteur kilométrique qui revient à 0
    
    // UNDERFLOW : passer sous zéro
    uint8_t zero = 0;
    zero = zero - 1;
    printf("0 - 1 = %d\n", zero);  // Affiche 255 !
    
    // Démonstration avec int
    int max_int = 2147483647;  // Maximum int
    max_int = max_int + 1;
    printf("INT_MAX + 1 = %d\n", max_int);  // Devient -2147483648 !
    
    return 0;
}

**Visualisation de l'overflow** :

text

Pour uint8_t (0 à 255) :
  254 → 255 → 0 → 1 → 2
        ↑     ↑
      max   retour à zéro (overflow)
C'est comme une roue qui tourne !

---

## 1.8 Signé vs Non signé

c

#include <stdio.h>
int main() {
    // Mêmes bits, interprétation différente
    signed char   s = -1;    // Signé : -128 à 127
    unsigned char u = 255;   // Non signé : 0 à 255
    
    // En mémoire, c'est EXACTEMENT la même chose :
    // 11111111 en binaire
    
    printf("Signé -1     = %d\n", s);   // -1
    printf("Non signé    = %u\n", u);   // 255
    
    // ⚠️ PIÈGE CLASSIQUE : Comparaison signé/non signé
    unsigned int a = 0;
    int b = -1;
    
    if (a > b) {
        printf("0 > -1 ???\n");  // Ce code s'exécute !
        // Car -1 est converti en non signé → 4294967295
    }
    
    return 0;
}

---

## 1.9 Représentation des nombres négatifs

Les nombres négatifs utilisent le **complément à deux** :

text

Règle : Inverser tous les bits + 1
Exemple pour -3 en 8 bits :
  3     = 00000011
  ~3    = 11111100 (inversion)
  ~3+1  = 11111101 = -3
Décimal → Binaire (8 bits)
  -1    → 11111111
  -2    → 11111110
  -3    → 11111101
  -128  → 10000000

---

# 2. Variables

## 2.1 Concept fondamental

Une variable = une **boîte étiquetée** dans la mémoire de l'ordinateur.

c

// Syntaxe : type nom = valeur;
int age = 25;           // Boîte "age" contenant 25
char lettre = 'A';      // Boîte "lettre" contenant 'A'
float prix = 19.99;     // Boîte "prix" contenant 19.99

**Visualisation mentale de la mémoire** :

text

┌────────────────────────────────────┐
│ Adresse: 0x1000    Nom: age        │
│ Contenu: 25        Type: int       │
│ Taille: 4 bytes                    │
├────────────────────────────────────┤
│ Adresse: 0x1004    Nom: lettre     │
│ Contenu: 'A'       Type: char      │
│ Taille: 1 byte                     │
├────────────────────────────────────┤
│ Adresse: 0x1005    Nom: prix       │
│ Contenu: 19.99     Type: float     │
│ Taille: 4 bytes                    │
└────────────────────────────────────┘

---

## 2.2 Déclaration et initialisation

c

#include <stdio.h>
int main() {
    // 1. Déclaration simple (valeur indéfinie !)
    int a;                          // ⚠️ Contient n'importe quoi
    
    // 2. Déclaration + initialisation
    int b = 10;                     // ✅ Bonne pratique
    
    // 3. Déclaration multiple
    int x, y, z;                    // Trois boîtes vides
    int p = 1, q = 2, r = 3;       // Trois boîtes remplies
    
    // 4. Initialisation tardive
    int score;
    score = 100;                    // Remplir plus tard
    
    // 5. Modification
    score = 200;                    // Changer la valeur
    score = score + 50;             // Utiliser l'ancienne (250)
    score += 50;                    // Équivalent (300)
    score++;                        // Incrémenter (301)
    
    // 6. Constante (ne peut pas changer)
    const int MAX_JOUEURS = 100;
    // MAX_JOUEURS = 200;           // ❌ ERREUR !
    
    return 0;
}

---

## 2.3 Portée des variables

La **portée** définit où une variable existe et est accessible.

c

#include <stdio.h>
// VARIABLE GLOBALE : existe partout, tout le programme
int compteur_global = 0;
void afficher_compteur() {
    // VARIABLE LOCALE à la fonction
    int local_fonction = 10;
    
    printf("Dans fonction : global=%d, local=%d\n", 
           compteur_global, local_fonction);
    
    compteur_global++;  // Peut modifier la globale
}
int main() {
    // VARIABLE LOCALE au main
    int local_main = 20;
    
    printf("Dans main : global=%d, local=%d\n", 
           compteur_global, local_main);
    
    afficher_compteur();
    
    // printf("%d", local_fonction);  // ❌ ERREUR ! N'existe pas ici
    
    return 0;
}

**Règles de portée** :

text

┌─────────────────────────────────────────────┐
│ Variables globales                          │
│  ├─ Existent pendant tout le programme      │
│  └─ Accessibles dans toutes les fonctions   │
│                                             │
│ Variables locales (dans { })                │
│  ├─ Existent seulement dans leur bloc       │
│  └─ Détruites à la sortie du bloc          │
└─────────────────────────────────────────────┘

---

## 2.4 Règles de nommage

c

int main() {
    // ✅ NOMS VALIDES
    int age;
    int nombre2;
    int _compteur;
    int prix_total;         // snake_case
    int prixTotal;          // camelCase
    int nombre_de_joueurs;
    
    // ❌ NOMS INVALIDES
    // int 2nombre;          // Pas de chiffre au début
    // int prix-total;       // Pas de tiret
    // int prix total;       // Pas d'espace
    // int int;              // Mot réservé du langage
    // int @test;            // Pas de symbole spécial
    
    // ⚠️ TECHNiquement valides, MAIS mauvaises pratiques
    int a;                  // Trop court, pas explicite
    int x1, x2, x3;         // Nom pas descriptif
    int thisisaverylongvariablename; // Difficile à lire
    
    // 👍 BONNES PRATIQUES
    int age_utilisateur;    // Descriptif et clair
    int nombre_essais_max;  
    int temperature_moyenne;
    
    return 0;
}

---

## 2.5 Variables et mémoire

c

#include <stdio.h>
int main() {
    int a = 42;
    
    // Informations sur la variable
    printf("Valeur de a  : %d\n", a);
    printf("Adresse de a : %p\n", (void*)&a);  // & = "adresse de"
    printf("Taille de a  : %zu bytes\n", sizeof(a));
    
    // Variables côte à côte en mémoire
    int x = 10, y = 20, z = 30;
    
    printf("\nAdresses mémoire :\n");
    printf("x : %p\n", (void*)&x);
    printf("y : %p\n", (void*)&y);
    printf("z : %p\n", (void*)&z);
    
    // Exemple d'organisation mémoire :
    // x à 0x1000 : 10
    // y à 0x1004 : 20  (4 bytes plus loin car int = 4 bytes)
    // z à 0x1008 : 30
    
    return 0;
}

---

## 2.6 Opérations courantes sur les variables

c

#include <stdio.h>
int main() {
    int a = 10, b = 3;
    
    // Opérations arithmétiques
    int somme      = a + b;    // 13
    int difference = a - b;    // 7
    int produit    = a * b;    // 30
    int quotient   = a / b;    // 3 (division entière !)
    int reste      = a % b;    // 1 (modulo)
    
    // Opérations avec des flottants
    float x = 10.0f, y = 3.0f;
    float div_float = x / y;   // 3.3333...
    
    // Opérations combinées
    a += 5;     // a = a + 5  → 15
    a -= 3;     // a = a - 3  → 12
    a *= 2;     // a = a * 2  → 24
    a /= 4;     // a = a / 4  → 6
    a++;        // a = a + 1  → 7
    b--;        // b = b - 1  → 2
    
    printf("Résultats finaux : a=%d, b=%d\n", a, b);
    
    return 0;
}

---

## 2.7 Exercices pratiques

### Exercice : Échange de variables

c

#include <stdio.h>
int main() {
    int a = 5, b = 10;
    
    printf("Avant : a=%d, b=%d\n", a, b);
    
    // Échange avec variable temporaire
    int temp = a;   // Sauvegarder a
    a = b;          // a prend la valeur de b
    b = temp;       // b prend l'ancienne valeur de a
    
    printf("Après : a=%d, b=%d\n", a, b);
    return 0;
}

### Exercice : Calculer une moyenne

c

#include <stdio.h>
int main() {
    int note1 = 15, note2 = 12, note3 = 18;
    
    int somme = note1 + note2 + note3;
    float moyenne = somme / 3.0f;  // 3.0 pour avoir un float !
    
    printf("Notes : %d, %d, %d\n", note1, note2, note3);
    printf("Somme : %d\n", somme);
    printf("Moyenne : %.2f\n", moyenne);
    
    return 0;
}

---

# 3. Chaînes de caractères

## 3.1 Concept fondamental

En C, **il n'y a PAS de type "string"**. Une chaîne est un **tableau de caractères** terminé par le caractère nul `\0`.

c

char mot[] = "Hello";
// En mémoire :
// ['H']['e']['l']['l']['o']['\0']
//   0    1    2    3    4    5
// Le '\0' (caractère nul, ASCII 0) marque LA FIN de la chaîne

**Visualisation détaillée** :

text

Index:    [0]   [1]   [2]   [3]   [4]   [5]
Valeur:   'H'   'e'   'l'   'l'   'o'   '\0'
ASCII:    72    101   108   108   111   0
Le '\0' dit : "La chaîne s'arrête ici !"

---

## 3.2 Créer des chaînes

c

#include <stdio.h>
int main() {
    // MÉTHODE 1 : Initialisation directe (recommandée)
    char nom[] = "Alice";           
    // Taille automatique : 6 (5 lettres + \0)
    
    // MÉTHODE 2 : Taille fixe avec contenu
    char ville[20] = "Paris";       
    // 20 emplacements réservés, 6 utilisés
    
    // MÉTHODE 3 : Caractère par caractère (rare)
    char code[] = {'O', 'K', '\0'}; 
    // ⚠️ Ne pas oublier le \0 !
    
    // MÉTHODE 4 : Tableau vide à remplir
    char buffer[100] = "";  // Chaîne vide initialisée
    
    // AFFICHAGE
    printf("Nom : %s\n", nom);      // %s pour les chaînes
    printf("Ville : %s\n", ville);
    
    // TAILLE
    printf("Taille de nom : %zu\n", sizeof(nom));  // 6
    
    return 0;
}

---

## 3.3 Le caractère nul '\0'

**Démonstration de son importance :**

c

#include <stdio.h>
int main() {
    // SANS \0 : comportement imprévisible !
    char sans_fin[] = {'B', 'O', 'N', 'J', 'O', 'U', 'R'};
    // ⚠️ PAS de \0 à la fin
    
    char avec_fin[] = "BONJOUR";
    // ✅ \0 ajouté automatiquement
    
    printf("Sans \\0 : %s\n", sans_fin);  
    // Affiche "BONJOUR" puis des caractères aléatoires !
    
    printf("Avec \\0 : %s\n", avec_fin);  
    // Affiche "BONJOUR" correctement
    
    // Visualisation du \0
    char test[] = "OK";
    printf("\nContenu de 'OK' :\n");
    printf("  test[0] = '%c' (ASCII %d)\n", test[0], test[0]); // O=79
    printf("  test[1] = '%c' (ASCII %d)\n", test[1], test[1]); // K=75
    printf("  test[2] = '\\0' (ASCII %d)\n", test[2]);        // \0=0
    
    return 0;
}

---

## 3.4 Manipuler les chaînes (string.h)

La bibliothèque `<string.h>` est **indispensable** pour manipuler les chaînes.

c

#include <stdio.h>
#include <string.h>  // ⚠️ INDISPENSABLE
int main() {
    // === LONGUEUR : strlen() ===
    char msg[] = "Bonjour";
    printf("'%s' fait %zu caractères\n", msg, strlen(msg));
    // strlen ignore le \0 : affiche 7
    
    
    // === COPIE : strcpy() ===
    char source[] = "Hello";
    char destination[20];   // Doit être assez grand !
    strcpy(destination, source);
    printf("Copie : %s\n", destination);
    
    
    // === CONCATÉNATION : strcat() ===
    char debut[50] = "Bonjour ";
    char fin[] = "le monde";
    strcat(debut, fin);
    printf("Concaténé : %s\n", debut);
    // debut contient maintenant "Bonjour le monde"
    
    
    // === COMPARAISON : strcmp() ===
    char a[] = "abc";
    char b[] = "def";
    char c[] = "abc";
    
    printf("\nComparaisons :\n");
    printf("'%s' vs '%s' : %d\n", a, b, strcmp(a, b));  // Négatif
    printf("'%s' vs '%s' : %d\n", a, c, strcmp(a, c));  // 0 = identique
    
    // ⚠️ ERREUR CLASSIQUE : ne pas utiliser == pour comparer !
    if (a == c) {
        // Ça compare les ADRESSES, pas le contenu
    }
    if (strcmp(a, c) == 0) {
        printf("Le contenu est identique ! ✅\n");
    }
    
    
    // === RECHERCHE : strchr(), strstr() ===
    char *position = strchr(msg, 'j');  // Trouver 'j'
    if (position != NULL) {
        printf("'j' trouvé à la position %ld\n", position - msg);
    }
    
    char *sous_chaine = strstr("Hello World", "World");
    if (sous_chaine != NULL) {
        printf("'World' trouvé : %s\n", sous_chaine);
    }
    
    return 0;
}

---

## 3.5 Lire et écrire des chaînes

c

#include <stdio.h>
#include <string.h>
int main() {
    char nom[50];  // Réserver assez de place !
    
    // ✅ BON : fgets() - sécurisé
    printf("Entrez votre nom : ");
    fgets(nom, sizeof(nom), stdin);
    
    // ⚠️ fgets garde le \n (Entrée) à la fin
    // Il faut l'enlever manuellement
    nom[strcspn(nom, "\n")] = '\0';
    
    printf("Bonjour %s !\n", nom);
    
    
    // ❌ DANGEREUX : gets() - NE JAMAIS UTILISER !
    // gets(nom);  // Peut déborder → crash ou hack
    // Cette fonction a été retirée du standard C !
    
    
    // ⚠️ DANGEREUX : scanf("%s") sans limite
    // scanf("%s", nom);  // Débordement possible
    
    // ✅ CORRECT : scanf avec limite explicite
    // scanf("%49s", nom);  // Max 49 caractères + \0
    
    return 0;
}

---

## 3.6 Pièges classiques

c

#include <stdio.h>
#include <string.h>
int main() {
    // PIÈGE 1 : Dépassement de buffer (BUFFER OVERFLOW)
    char petit[5];
    // strcpy(petit, "Cette chaîne est beaucoup trop longue !");
    // ⚠️ CRASH ! Écrase la mémoire adjacente
    // C'est la vulnérabilité #1 en informatique
    
    
    // PIÈGE 2 : Oublier le \0
    char sans_zero[3] = {'O', 'K'};  // PAS de \0
    printf("Sans zero : %s\n", sans_zero);  // Affiche n'importe quoi !
    
    
    // PIÈGE 3 : Confusion caractère et chaîne
    char lettre = 'A';      // Un SEUL caractère (guillemets simples)
    char chaine[] = "A";    // Une chaîne (guillemets doubles)
    
    // 'A'  = 1 byte  (juste le caractère)
    // "A"  = 2 bytes ('A' + '\0')
    printf("Taille 'A' : %zu\n", sizeof('A'));
    printf("Taille \"A\" : %zu\n", sizeof("A"));
    
    
    // PIÈGE 4 : Comparaison avec ==
    char str1[] = "test";
    char str2[] = "test";
    
    if (str1 == str2) {
        printf("Ce message ne s'affichera JAMAIS !\n");
        // Compare les ADRESSES, pas le contenu
    }
    
    if (strcmp(str1, str2) == 0) {
        printf("Le contenu est identique ✅\n");
    }
    
    
    // PIÈGE 5 : strcpy sans vérifier la taille
    char dest[10];
    char source[] = "Une longue chaîne de caractères";
    // strcpy(dest, source);  // ⚠️ DÉPASSEMENT !
    
    // ✅ Solution : utiliser strncpy avec la taille
    strncpy(dest, source, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\0';  // Garantir le \0
    printf("Copie sécurisée : %s\n", dest);
    
    return 0;
}

---

## 3.7 Exercices pratiques

### Exercice 1 : Analyser une chaîne

c

#include <stdio.h>
#include <string.h>
#include <ctype.h>
void analyser_chaine(const char *str) {
    int lettres = 0, chiffres = 0, espaces = 0, autres = 0;
    
    for (int i = 0; str[i] != '\0'; i++) {
        if (isalpha(str[i]))      lettres++;
        else if (isdigit(str[i])) chiffres++;
        else if (str[i] == ' ')   espaces++;
        else                       autres++;
    }
    
    printf("Analyse de '%s' :\n", str);
    printf("  Lettres  : %d\n", lettres);
    printf("  Chiffres : %d\n", chiffres);
    printf("  Espaces  : %d\n", espaces);
    printf("  Autres   : %d\n", autres);
    printf("  Longueur : %zu\n", strlen(str));
}
int main() {
    analyser_chaine("Hello World 123 !");
    return 0;
}

### Exercice 2 : Inverser une chaîne

c

#include <stdio.h>
#include <string.h>
void inverser(char *str) {
    int longueur = strlen(str);
    
    for (int i = 0; i < longueur / 2; i++) {
        // Échanger str[i] et str[longueur-1-i]
        char temp = str[i];
        str[i] = str[longueur - 1 - i];
        str[longueur - 1 - i] = temp;
    }
}
int main() {
    char texte[] = "Bonjour";
    printf("Original : %s\n", texte);
    inverser(texte);
    printf("Inversé  : %s\n", texte);
    return 0;
}

### Exercice 3 : Majuscules/minuscules

c

#include <stdio.h>
#include <ctype.h>
void en_majuscules(char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        str[i] = toupper(str[i]);
    }
}
void en_minuscules(char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        str[i] = tolower(str[i]);
    }
}
int main() {
    char texte[] = "Bonjour Le Monde !";
    
    printf("Original   : %s\n", texte);
    en_majuscules(texte);
    printf("Majuscules : %s\n", texte);
    en_minuscules(texte);
    printf("Minuscules : %s\n", texte);
    
    return 0;
}

### Exercice 4 : Compter les mots

c

#include <stdio.h>
#include <string.h>
int compter_mots(const char *str) {
    int mots = 0;
    int dans_mot = 0;
    
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == ' ' || str[i] == '\n' || str[i] == '\t') {
            dans_mot = 0;
        } else if (dans_mot == 0) {
            dans_mot = 1;
            mots++;
        }
    }
    
    return mots;
}
int main() {
    char phrase[] = "Le renard brun saute par dessus le chien";
    printf("Phrase : %s\n", phrase);
    printf("Nombre de mots : %d\n", compter_mots(phrase));
    return 0;
}

### Exercice 5 : Palindrome

c

#include <stdio.h>
#include <string.h>
#include <ctype.h>
int est_palindrome(const char *str) {
    int debut = 0;
    int fin = strlen(str) - 1;
    
    while (debut < fin) {
        // Ignorer la casse
        if (tolower(str[debut]) != tolower(str[fin])) {
            return 0;  // Pas un palindrome
        }
        debut++;
        fin--;
    }
    
    return 1;  // C'est un palindrome
}
int main() {
    const char *tests[] = {"Radar", "Kayak", "Bonjour", "Laval", NULL};
    
    for (int i = 0; tests[i] != NULL; i++) {
        printf("'%s' est un palindrome : %s\n",
               tests[i],
               est_palindrome(tests[i]) ? "OUI ✅" : "NON ❌");
    }
    
    return 0;
}

---

## 3.8 Table ASCII essentielle

text

┌────────┬──────┬────────┬──────┬────────┬──────┬────────┬──────┐
│ Code   │ Char │ Code   │ Char │ Code   │ Char │ Code   │ Char │
├────────┼──────┼────────┼──────┼────────┼──────┼────────┼──────┤
│ 0      │ \0   │ 32     │ espace│ 48     │ '0'  │ 65     │ 'A'  │
│ 7      │ \a   │ 33     │ '!'   │ 49     │ '1'  │ 66     │ 'B'  │
│ 8      │ \b   │ 34     │ '"'   │ ...    │ ...  │ ...    │ ...  │
│ 9      │ \t   │ 35     │ '#'   │ 57     │ '9'  │ 90     │ 'Z'  │
│ 10     │ \n   │ 39     │ '''   │ 58     │ ':'  │ 97     │ 'a'  │
│ 13     │ \r   │ 44     │ ','   │ 59     │ ';'  │ 98     │ 'b'  │
│ 27     │ ESC  │ 46     │ '.'   │ 64     │ '@'  │ 122    │ 'z'  │
└────────┴──────┴────────┴──────┴────────┴──────┴────────┴──────┘
Règles mnémotechniques :
  '0'-'9' = 48-57  (différence de 48)
  'A'-'Z' = 65-90  (différence de 55)
  'a'-'z' = 97-122 (différence de 87)

---

# 4. Fiches récapitulatives

## 4.1 Types primitifs

text

┌─────────────────────────────────────────────────────────────┐
│                    TYPES C - AIDE MÉMOIRE                   │
├──────────┬──────────┬─────────────────┬────────────────────┤
│ TYPE     │ TAILLE   │ MIN             │ MAX                │
├──────────┼──────────┼─────────────────┼────────────────────┤
│ char     │ 1 byte   │ -128            │ 127                │
│ uchar    │ 1 byte   │ 0               │ 255                │
│ short    │ 2 bytes  │ -32 768         │ 32 767             │
│ ushort   │ 2 bytes  │ 0               │ 65 535             │
│ int      │ 4 bytes  │ -2.147.483.648  │ 2.147.483.647      │
│ uint     │ 4 bytes  │ 0               │ 4.294.967.295      │
│ long*    │ 4 ou 8   │ dépend          │ dépend             │
│ longlong │ 8 bytes  │ -9.22×10¹⁸      │ 9.22×10¹⁸          │
│ pointer* │ 4 ou 8   │ 0               │ 0xFFFF...          │
├──────────┴──────────┴─────────────────┴────────────────────┤
│ * Dépend de l'architecture (32 ou 64 bits)                 │
│                                                            │
│ Types sûrs (taille garantie) :                             │
│   int8_t, uint8_t, int16_t, uint16_t,                     │
│   int32_t, uint32_t, int64_t, uint64_t                    │
└────────────────────────────────────────────────────────────┘

## 4.2 Variables

text

┌────────────────────────────────────────────────────────────────┐
│                      VARIABLES EN C                             │
├────────────────┬───────────────────────────────────────────────┤
│ Déclaration    │ int age;                                      │
│ Initialisation │ int age = 25;                                 ││ Modification   │ age = 26;                                     │
│ Constante      │ const int MAX = 100;                         │
│ Adresse        │ &age (où est stockée la variable)            │
│ Taille         │ sizeof(age) (combien de bytes)               │
├────────────────┼───────────────────────────────────────────────┤
│ Globale        │ Existe partout, tout le programme             │
│ Locale         │ Existe dans son bloc { } uniquement          │
│ Statique       │ static int x; (persiste entre les appels)    │
├────────────────┴───────────────────────────────────────────────┤
│ Règles de nommage :                                            │
│  ✅ age, _compteur, nombre2, prixTotal                        │
│  ❌ 2nombre, prix-total, int, prix total                      │
└────────────────────────────────────────────────────────────────┘

## 4.3 Chaînes de caractères

text

┌─────────────────────────────────────────────────────────────┐
│              CHAÎNES DE CARACTÈRES EN C                      │
├─────────────────────────────────────────────────────────────┤
│ Déclaration          │ char nom[] = "Alice";                │
│ Chaîne vide          │ char buffer[100] = "";               │
│ Longueur             │ strlen(str)                          │
│ Copie                │ strcpy(dest, src)                    │
│ Copie sécurisée      │ strncpy(dest, src, n)                │
│ Concaténation        │ strcat(dest, src)                    │
│ Concat. sécurisée    │ strncat(dest, src, n)                │
│ Comparaison          │ strcmp(s1, s2) == 0                  │
│ Recherche caractère  │ strchr(str, c)                       │
│ Recherche sous-chaîne│ strstr(str, sub)                     │
│ Lecture sécurisée    │ fgets(str, taille, stdin)            │
├─────────────────────────────────────────────────────────────┤
│ ⚠️ PIÈGES À ÉVITER                                          │
│ • gets() → Buffer overflow (supprimé du standard)           │
│ • strcpy/strcat sans vérifier la taille                     │
│ • Oublier le \0 final                                       │
│ • Comparer avec == au lieu de strcmp()                      │
│ • Confondre 'A' (char) et "A" (chaîne)                     │
└─────────────────────────────────────────────────────────────┘

## 4.4 Spécificateurs de format (printf/scanf)

text

┌─────────────────────────────────────────────────────────────┐
│              SPÉCIFICATEURS DE FORMAT                        │
├──────────────┬──────────────────────────────────────────────┤
│ %c           │ Caractère (char)                             │
│ %d, %i       │ Entier signé (int)                           │
│ %u           │ Entier non signé (unsigned int)              │
│ %ld          │ Entier long signé                            │
│ %lu          │ Entier long non signé                        │
│ %lld         │ Entier long long signé                       │
│ %llu         │ Entier long long non signé                   │
│ %x, %X       │ Hexadécimal (minuscule/majuscule)            │
│ %o           │ Octal                                        │
│ %f           │ Float/double (décimal)                       │
│ %e, %E       │ Notation scientifique                        │
│ %s           │ Chaîne de caractères                         │
│ %p           │ Pointeur (adresse)                           │
│ %zu          │ size_t (taille)                              │
│ %%           │ Caractère % littéral                         │
├──────────────┼──────────────────────────────────────────────┤
│ Modificateurs│                                              │
│ %5d          │ Largeur minimum 5                            │
│ %.2f         │ 2 chiffres après la virgule                  │
│ %-10s        │ Aligné à gauche sur 10 caractères            │
│ %05d         │ Remplir avec des zéros (5 chiffres)          │
└──────────────┴──────────────────────────────────────────────┘

---

## 📖 Ressources supplémentaires

- [Documentation officielle C (cppreference.com)](https://en.cppreference.com/w/c)
    
- [Norme C11 (ISO/IEC 9899:2011)](https://www.iso.org/standard/57853.html)
    

---

## 📝 Licence

Ce document est libre de droit. Vous pouvez le partager, le modifier et l'utiliser comme support d'apprentissage.

---

_Dernière mise à jour : Juin 2026_