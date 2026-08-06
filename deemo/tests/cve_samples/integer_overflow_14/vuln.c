/* integer_overflow_14 — 宏展开中的溢出 */
#include <stdio.h>
#include <stdlib.h>
#define MUL(a,b) ((a)*(b))
int main(){int*p=calloc(MUL(65535,65535),1);free(p);return 0;}
