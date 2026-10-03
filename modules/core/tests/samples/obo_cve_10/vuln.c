#include <stdlib.h>
#include <string.h>
void safe(){char*buf=malloc(256);memset(buf,65,128);}
int main(){safe();}