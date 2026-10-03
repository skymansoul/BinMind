/* CVE-2021-3807 — RE2 regex engine heap buffer overflow
   Type: heap_overflow
   gcc -O0 re2_overflow.c -o re2_overflow

   Simplified: RE2 had an unchecked allocation where the regex compiler
   could request a buffer smaller than needed for the compiled program,
   leading to heap overflow during subsequent writes. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RE2_MAX_PROG 65536

typedef struct { int inst_count; unsigned char *prog; } RegexProg;

int re2_compile(RegexProg *p, int expected_insts) {
    /* BUG: allocates expected_insts * 4 but writes expected_insts * 8 */
    p->prog = (unsigned char *)malloc(expected_insts * 4);
    p->inst_count = expected_insts;

    /* memset overflows: writes expected_insts * 8 > allocated expected_insts * 4 */
    memset(p->prog, 0, expected_insts * 8);
    return 0;
}

int main() {
    RegexProg p = {0};
    re2_compile(&p, 1024);
    free(p.prog);
    return 0;
}
