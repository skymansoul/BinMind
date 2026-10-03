#include <string.h>
#include <stdio.h>
/* Stack overflow pattern 11: buffer copy without bounds check */
void vuln11(char *s) { char b[104]; strcpy(b,s); puts(b); }
int main(int c,char**v) { if(c>1)vuln11(v[1]); return 0; }
