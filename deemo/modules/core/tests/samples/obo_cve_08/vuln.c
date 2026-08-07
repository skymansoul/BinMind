#include <stdlib.h>
#include <string.h>
void vuln(){char*a=malloc(0);char*b=malloc(32);memset(a,65,25);free(b);}
int main(){vuln();}