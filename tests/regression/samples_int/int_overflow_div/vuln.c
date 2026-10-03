#include <stdio.h>
#include <stdlib.h>
void part(int total,int parts){int each=total/parts;char *b=malloc(each);free(b);}
int main(){part(100,0);return 0;}
