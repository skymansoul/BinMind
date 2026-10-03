#include <stdio.h>
#include <stdlib.h>
void ext(unsigned short n){int sz=n*100;char *p=malloc(sz);free(p);}
int main(){ext(65535);return 0;}
