#include <stdlib.h>
#include <string.h>
struct V{void*v;};void vuln(){struct V*p=malloc(24);p->v=(void*)0x7000;}
int main(){vuln();}