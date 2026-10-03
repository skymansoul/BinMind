#include <stdlib.h>
int main() { unsigned w=1024,h=1024,d=1024;size_t sz=w*h*d;char*p=malloc(sz);free(p);return 0;}
