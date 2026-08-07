#include <stdlib.h>
struct X{void*v;};struct Y{void*v;int a;long b;};void vuln(){struct X*x=malloc(8);((struct Y*)x)->b=0;}
int main(){vuln();}