#include <stdlib.h>
struct S{void*v;int x;};struct L{void*v;int x;long y;long z;};void vuln(){struct S*s=malloc(16);((struct L*)s)->z=1;}
int main(){vuln();}