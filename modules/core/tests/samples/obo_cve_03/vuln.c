#include <stdlib.h>
#include <string.h>
void vuln(){char*a=malloc(24);char*b=malloc(128);memset(a,65,25);free(b);}
int main(){vuln();}