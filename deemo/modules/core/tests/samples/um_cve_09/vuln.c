#include <stdlib.h>
#include <string.h>
void safe(){char*b=malloc(64);memset(b,0xAB,64);printf("%02x",b[0]);}
int main(){safe();}