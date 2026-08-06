#include <string.h>
#include <stdio.h>
/* Stack overflow pattern 15: buffer copy without bounds check */
void vuln15(char *s) { char b[136]; strcpy(b,s); puts(b); }
int main(int c,char**v) { if(c>1)vuln15(v[1]); return 0; }
