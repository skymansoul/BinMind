#include <stdio.h>
void vuln(char *d) { if(!d) printf("Error: %s %n", d); else printf("%s",d); }
int main(){vuln(0);}