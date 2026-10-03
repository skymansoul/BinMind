/* GENERIC-int-cast-trunc CWE-681: size_t截断到int导致大小错误 */
#include <stdlib.h>
#include <string.h>
void trunc_alloc(size_t sz){int n=(int)sz;char*b=malloc(n);memcpy(b,"data",sz);free(b);}
int main(){trunc_alloc(1ULL<<32);return 0;}
