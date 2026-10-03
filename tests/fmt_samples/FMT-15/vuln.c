#include <stdio.h>
int main(int c,char**v){char b[64];snprintf(b,63,c>1?v[1]:"%s","x");printf(b);return 0;}