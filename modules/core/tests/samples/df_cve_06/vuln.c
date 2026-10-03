#include <stdlib.h>
void vuln(){for(int i=0;i<2;i++){void*p=malloc(32);free(p);}}
int main(){vuln();}