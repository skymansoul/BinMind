#include <stdio.h>
void vuln(const char *s) { char buf[8]; printf(s); printf("
"); }
int main(int c,char**v) { vuln(c>1?v[1]:"%x%x%x%n"); return 0; }