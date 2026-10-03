/* GENERIC-int-safe-assert SAFE: 运行时断言保护——安全不应检出 */
#include <stdlib.h>
#include <assert.h>
void*chk_alloc(size_t c,size_t s){assert(c<1000000&&s<1000000);return malloc(c*s);}
int main(){void*p=chk_alloc(1000,1000);free(p);return 0;}
