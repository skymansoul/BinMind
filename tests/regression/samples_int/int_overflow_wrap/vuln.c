#include <stdio.h>
#include <stdlib.h>
void pad(int len){int sz=len+16;if(sz<len)sz=65536;char *b=malloc(sz);free(b);}
int main(int c,char **v){if(c>1)pad(atoi(v[1]));return 0;}
