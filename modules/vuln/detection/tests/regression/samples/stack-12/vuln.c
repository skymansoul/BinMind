#include <string.h>
#include <stdio.h>
/* Stack overflow pattern 12: buffer copy without bounds check */
void vuln12(char *s) { char b[112]; strcpy(b,s); puts(b); }
int main(int c,char**v) { if(c>1)vuln12(v[1]); return 0; }
