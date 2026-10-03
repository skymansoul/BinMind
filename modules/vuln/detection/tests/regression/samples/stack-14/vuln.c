#include <string.h>
#include <stdio.h>
/* Stack overflow pattern 14: buffer copy without bounds check */
void vuln14(char *s) { char b[128]; strcpy(b,s); puts(b); }
int main(int c,char**v) { if(c>1)vuln14(v[1]); return 0; }
