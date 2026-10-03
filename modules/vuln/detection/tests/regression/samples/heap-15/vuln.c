#include <stdlib.h>
#include <string.h>
int main() { char*p=malloc(128);int off=100;memcpy(p+off,"overflow",16);free(p);return 0;}
