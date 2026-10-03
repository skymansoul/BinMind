/* integer_overflow_15 — 浮点转整数截断 */
#include <stdio.h>
#include <stdlib.h>
int main(){double d=1e20;int n=(int)d;char*p=malloc(n);free(p);return 0;}
