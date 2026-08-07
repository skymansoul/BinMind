#include <stdlib.h>
#include <string.h>
void vuln(){char*a=malloc(120);char*b=malloc(256);memset(a,65,121);free(b);}
int main(){vuln();}