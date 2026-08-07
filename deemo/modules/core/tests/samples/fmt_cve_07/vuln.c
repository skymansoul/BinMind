#include <stdio.h>
void vuln(char *f) { fprintf(stderr, f); }
int main(){vuln("%n %n %n");}