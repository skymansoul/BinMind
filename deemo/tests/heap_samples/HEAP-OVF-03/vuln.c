#include <stdlib.h>
void h(int n){char*b=malloc(n*4);b[n*4]=0;free(b);}
int main(int c,char**v){h(c>1?atoi(v[1]):16);return 0;}