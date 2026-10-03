#include <stdlib.h>
void m(int w,int h,int d){size_t sz=w*h*d;char*b=malloc(sz);free(b);}
int main(){m(2048,2048,2048);return 0;}