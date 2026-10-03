#include <stdlib.h>
#include <string.h>
void safe(){char*b=malloc(128);memset(b,0,128);printf("%02x",b[32]);}
int main(){safe();}