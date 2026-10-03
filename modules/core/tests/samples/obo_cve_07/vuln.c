#include <stdlib.h>
#include <string.h>
void vuln(){char*a=malloc(504);char*b=malloc(32);memset(a,65,505);free(b);}
int main(){vuln();}