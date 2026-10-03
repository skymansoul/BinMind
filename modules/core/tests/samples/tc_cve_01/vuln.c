#include <stdlib.h>
struct A{void*v;int x;};void vuln(){struct A*a=malloc(16);a->v=(void*)0x4000;a->x=42;}
int main(){vuln();}