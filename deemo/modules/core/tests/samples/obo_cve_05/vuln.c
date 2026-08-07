#include <stdlib.h>
#include <string.h>
void vuln(){char*buf=malloc(248);memset(buf,65,249);}
int main(){vuln();}