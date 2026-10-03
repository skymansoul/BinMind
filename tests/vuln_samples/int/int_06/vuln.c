/* GENERIC-int-safe-size-max SAFE: 正确SIZE_MAX检查——不应检出 */
#include <stdlib.h>
#include <stdint.h>
void*sfa(size_t c,size_t s){if(s&&c>SIZE_MAX/s)return 0;return malloc(c*s);}
int main(){void*p=sfa(100,100);free(p);return 0;}
