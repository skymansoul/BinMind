#include <stdio.h>
void vuln(char *u) { printf(u); /* %n in u */ }
int main(){vuln("%x %x %n");}