#include <stdio.h>
void vuln(char *f) { printf(f); }
int main(){vuln("%x %x %s");}