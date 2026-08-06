#include <stdio.h>
void f(){void*q=malloc(8);free(q);printf("%p",q);}
int main(){f();return 0;}