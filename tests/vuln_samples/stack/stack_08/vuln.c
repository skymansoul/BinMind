/* GENERIC-stack-fgets-offbyone CWE-193: fgets off-by-one: Î´Ô¤ÁônullÖÕÖ¹·û */
#include <stdio.h>
void fo(){char b[64];fgets(b,65,stdin);}
int main(){fo();return 0;}
