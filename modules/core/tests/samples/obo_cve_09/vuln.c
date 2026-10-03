#include <stdlib.h>
#include <string.h>
void safe(){char*buf=malloc(64);memset(buf,65,64);}
int main(){safe();}