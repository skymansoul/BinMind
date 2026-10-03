#include <stdlib.h>
#include <string.h>
void vuln(){char*b=malloc(64);printf("%02x",b[0]);}
int main(){vuln();}