#include <stdlib.h>
#include <string.h>
struct P{short a;int b;long c;char d;};void vuln(){struct P*p=malloc(32);memset(p,0,24);write(1,p,32);}
int main(){vuln();}