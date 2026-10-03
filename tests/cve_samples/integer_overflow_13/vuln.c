#include <stdio.h>
#include <stdlib.h>
int main() { long long a=0xFFFFFFFF,b=64; long long d=a-b; char *p=malloc(d>0?d:64); free(p); return 0; }
