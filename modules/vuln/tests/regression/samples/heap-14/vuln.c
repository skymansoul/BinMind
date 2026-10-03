#include <unistd.h>
#include <stdlib.h>
#include <string.h>
int main() { size_t sz=0;read(0,&sz,4);char*p=malloc(sz?sz:1);read(0,p,sz*2);free(p);return 0;}
