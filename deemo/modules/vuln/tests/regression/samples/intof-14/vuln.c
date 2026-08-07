#include <stdlib.h>
int main() { char*p=malloc(sizeof(int)*0x40000000*0x10);free(p);return 0;}
