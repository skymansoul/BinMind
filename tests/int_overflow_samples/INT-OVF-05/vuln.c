#include <stdlib.h>
void k(int w,int h){int sz=w*h;char*b=malloc(sz);b[0]=0;free(b);}
int main(){k(46341,46341);return 0;}