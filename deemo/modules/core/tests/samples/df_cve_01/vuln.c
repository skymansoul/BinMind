#include <stdlib.h>
void vuln(){void*p=malloc(24);free(p);free(p);}
int main(){vuln();}