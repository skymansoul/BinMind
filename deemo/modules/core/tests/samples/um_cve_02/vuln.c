#include <stdlib.h>
#include <string.h>
void vuln(){char*b=malloc(64);memset(b,0,32);printf("%02x",b[40]);}
int main(){vuln();}