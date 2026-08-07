#include <stdlib.h>
#include <string.h>
struct S{char pad[80];int x;};void vuln(){struct S*s=malloc(128);memset(s,0,64);printf("%d",s->x);}
int main(){vuln();}