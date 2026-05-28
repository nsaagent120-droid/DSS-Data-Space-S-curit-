#include <stdio.h>

int main() {
    int age = 25;           // nombre entier
    char lettre = 'A';      // un seul caractère
    float prix = 19.99;     // nombre décimal

    printf("age = %d\n", age);      // %d pour int
    printf("lettre = %c\n", lettre); // %c pour char
    printf("prix = %.2f\n", prix);   // %f pour float

    // Modifier une variable
    age = 30;
    lettre = 'K';
    prix = 75.555;

    printf("nouvel age = %d\n; nouvel lettre %c\n; nouvel prix %2.f\n", age,lettre,prix);

    return 0;
}
