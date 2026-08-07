#include <stdlib.h>
#include <string.h>
void vuln(){char*a=malloc(56);char*b=malloc(64);memset(a,0x80,57);free(b);}
int main(){vuln();}