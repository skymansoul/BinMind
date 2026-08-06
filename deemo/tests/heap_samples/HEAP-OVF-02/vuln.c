#include <stdlib.h>
#include <string.h>
void g(char*s,int n){char*b=malloc(n);memcpy(b,s,n);b[n]=0;free(b);}
int main(){g("test",4);return 0;}