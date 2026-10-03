/* UAF loop pattern */
#include <stdio.h>
#include <stdlib.h>
int main() { int *p = malloc(400); for(int i=0;i<100;i++) p[i]=i; free(p); printf("%d",p[50]); return 0; }
