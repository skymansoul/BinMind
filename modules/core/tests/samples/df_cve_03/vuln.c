#include <stdlib.h>
void vuln(){void*a=malloc(24);void*b=malloc(24);free(a);free(b);free(a);}
int main(){vuln();}