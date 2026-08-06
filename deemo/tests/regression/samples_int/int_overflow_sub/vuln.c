#include <stdio.h>
#include <stdlib.h>
void reserve(int avail,int used){int left=avail-used;char *b=malloc(left);free(b);}
int main(){reserve(10,100);return 0;}
