#include <stdio.h>
int main(int c,char**v){char b[256];sprintf(b,"User: %s",c>1?v[1]:"guest");printf(b);return 0;}