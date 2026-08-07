#include <stdlib.h>
void vuln(){char*b=malloc(32);b=realloc(b,64);printf("%02x",b[32]);}
int main(){vuln();}