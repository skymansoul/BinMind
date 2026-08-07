#include <stdlib.h>
#include <string.h>
void vuln(){char*b=malloc(96);memset(b,0,48);printf("%s",b+48);}
int main(){vuln();}