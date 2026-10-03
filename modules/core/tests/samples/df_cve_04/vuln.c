#include <stdlib.h>
void vuln(){void*p=malloc(24);p=realloc(p,128);free(p);free(p);}
int main(){vuln();}