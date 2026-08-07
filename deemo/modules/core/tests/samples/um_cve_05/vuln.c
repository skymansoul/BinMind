#include <stdlib.h>
#include <string.h>
void vuln(){char*b=malloc(256);memset(b,0,128);write(1,b,256);}
int main(){vuln();}