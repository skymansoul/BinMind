#include <stdlib.h>
struct R{void*v;int x;};struct T{void*v;int x;long y;long z;};void vuln(){struct R*r=malloc(16);((struct T*)r)->z=0;}
int main(){vuln();}