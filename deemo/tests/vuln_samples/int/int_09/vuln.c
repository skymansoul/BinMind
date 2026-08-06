/* GENERIC-int-sub-underflow CWE-191: 无符号减法下溢导致分配过大 */
#include <stdlib.h>
void sub_alloc(size_t a,size_t b){size_t t=a-b;char*m=malloc(t);free(m);}
int main(){sub_alloc(5,10);return 0;}
