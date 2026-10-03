#include <stdio.h>
void vuln(char *f, int a) { char b[256]; sprintf(b, f, a); }
int main(){vuln("%*d %n", 10);}