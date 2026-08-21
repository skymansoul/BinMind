/* CWE-122: strcpy with attacker-controlled input */
#include <stdlib.h>
#include <string.h>

void cwe122_strcpy(char *user_input) {
    char *buf = (char *)malloc(128);
    if (buf) {
        strcpy(buf, user_input);  /* unbounded copy �� OVERFLOW */
        free(buf);
    }
}

int main(void) {
    static char in[] =
        "AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGGGGGHHHHHIIIIIJJJJJKKKKKLL"
        "LLLMMMMMNNNNNOOOOOPPPPPQQQQQRRRRRSSSSSTTTTTUUUUUVVVVVWWWWW"
        "XXXXXYYYYYZZZZZaaaaabbbbbcccccdddddeeeeefffff";
    cwe122_strcpy(in);
    return 0;
}
