#include <stdlib.h>
#include <string.h>
void vuln(){char*buf=malloc(120);memset(buf,65,144);}
int main(){vuln();}