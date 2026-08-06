#include <stdlib.h>
void f(int n){char*b=malloc(n);free(b);b[0]=0;}
int main(){f(64);return 0;}