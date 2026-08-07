#include <stdlib.h>
struct C{void*v;int a;int b;};struct E{void*v;long x;long y;long z;};void vuln(){struct C*c=malloc(24);((struct E*)c)->z=0;}
int main(){vuln();}