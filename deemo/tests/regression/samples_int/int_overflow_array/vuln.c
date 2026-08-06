#include <stdio.h>
#include <stdlib.h>
void matrix(int r,int c){int *m=malloc(r*c*sizeof(int));free(m);}
int main(){matrix(65536,65536);return 0;}
