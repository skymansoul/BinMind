#include <stdlib.h>
void vuln(){void*p=malloc(24);void*q=p;free(p);free(q);}
int main(){vuln();}