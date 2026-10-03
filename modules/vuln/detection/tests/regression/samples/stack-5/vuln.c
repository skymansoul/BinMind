#include <string.h>
#include <stdio.h>
/* Stack overflow pattern 5: buffer copy without bounds check */
void vuln5(char *s) { char b[56]; strcpy(b,s); puts(b); }
int main(int c,char**v) { if(c>1)vuln5(v[1]); return 0; }
