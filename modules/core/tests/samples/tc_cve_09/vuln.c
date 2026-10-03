#include <stdlib.h>
struct U{void*v;int x;int y;int z;};void safe(){struct U*u=malloc(32);u->x=42;}
int main(){safe();}