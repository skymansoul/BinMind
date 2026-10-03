#include <stdio.h>
void vuln(char *f, int a, int b) { printf(f, a, b); }
int main(){vuln("%7$n",1,2);}