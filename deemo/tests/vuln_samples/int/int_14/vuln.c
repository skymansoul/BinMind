/* GENERIC-int-realloc-grow CWE-190: realloc扩大时乘法溢出 */
#include <stdlib.h>
void*grow(void*p,size_t n,size_t factor){return realloc(p,n*factor);}
int main(){void*p=grow(malloc(64),1<<30,4);free(p);return 0;}
