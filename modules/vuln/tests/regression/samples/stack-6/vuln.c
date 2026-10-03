#include <string.h>
#include <stdio.h>
/* Stack overflow pattern 6: buffer copy without bounds check */
void vuln6(char *s) { char b[64]; strcpy(b,s); puts(b); }
int main(int c,char**v) { if(c>1)vuln6(v[1]); return 0; }
