#include <stdio.h>
#include <stdlib.h>
void logic(int flag){char *b=malloc(100);if(flag)free(b);strcpy(b,"x");}
int main(int c,char **v){logic(c>1?1:0);return 0;}
