#include <string.h>
#include <stdio.h>
void vuln(const char *s) { char buf[64]; sprintf(buf,"%s",s); }
int main(int c,char**v) { vuln(c>1?v[1]:"A"*80); return 0; }