#include <stdlib.h>
#include <string.h>
int main() { unsigned short len=65535; char*p=malloc(len+1); memset(p,0,len+1); free(p); return 0; }
