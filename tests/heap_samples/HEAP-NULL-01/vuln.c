#include <stdlib.h>
#include <string.h>
void f(){char*b=malloc(1<<30);strcpy(b,"x");free(b);}
int main(){f();return 0;}