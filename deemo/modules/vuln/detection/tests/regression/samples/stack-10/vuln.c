#include <string.h>
#include <stdio.h>
/* Stack overflow pattern 10: buffer copy without bounds check */
void vuln10(char *s) { char b[96]; strcpy(b,s); puts(b); }
int main(int c,char**v) { if(c>1)vuln10(v[1]); return 0; }
