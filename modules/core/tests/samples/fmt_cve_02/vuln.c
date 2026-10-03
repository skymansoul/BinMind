#include <stdio.h>
void vuln(char *u, int a) { char b[256]; snprintf(b,256,u,a); }
int main(){vuln("%s %s %n",42);}