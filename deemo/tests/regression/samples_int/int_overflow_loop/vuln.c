#include <stdio.h>
#include <stdlib.h>
void fill(int n){char *b=malloc(n);for(int i=0;i<=n;i++)b[i]=0;free(b);}
int main(int c,char **v){if(c>1)fill(atoi(v[1]));return 0;}
