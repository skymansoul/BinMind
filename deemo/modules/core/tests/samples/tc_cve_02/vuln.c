#include <stdlib.h>
struct B{void*v;int x;};struct D{void*v;int x;long y;};void vuln(){struct B*b=malloc(16);((struct D*)b)->y=0;}
int main(){vuln();}