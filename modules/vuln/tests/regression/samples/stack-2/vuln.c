#include <string.h>
#include <stdio.h>
/* Stack overflow pattern 2: buffer copy without bounds check */
void vuln2(char *s) { char b[32]; strcpy(b,s); puts(b); }
int main(int c,char**v) { if(c>1)vuln2(v[1]); return 0; }
