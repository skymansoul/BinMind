#include <stdlib.h>
#include <string.h>
void vuln(){char*a=malloc(24);char*b=malloc(248);char*c=malloc(24);memset(a,65,25);free(b);}
int main(){vuln();}