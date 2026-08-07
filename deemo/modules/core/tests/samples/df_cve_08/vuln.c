#include <stdlib.h>
void myfree(void*p){free(p);}
void vuln(){void*p=malloc(32);free(p);myfree(p);}
int main(){vuln();}