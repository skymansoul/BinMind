#include <stdlib.h>
struct P{void*v;int x;int y;int z;};struct Q{void*v;int a;int b;int c;int d;int e;};void vuln(){struct P*p=malloc(32);((struct Q*)p)->e=0;}
int main(){vuln();}