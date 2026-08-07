#include <stdlib.h>
struct W{void*v;int a;int b;int c;int d;};void safe(){struct W*w=malloc(64);w->a=1;}
int main(){safe();}