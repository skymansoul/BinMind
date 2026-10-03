/* CVE-2020-10757 CWE-190: Ò³¶ÔÆë¼ÆËãÒç³ö */
#include <stdlib.h>
#define PAGE_ALIGN(x)(((x)+4095)&~4095)
void*aligned_alloc(size_t n,size_t sz){return malloc(PAGE_ALIGN(n*sz));}
int main(){void*p=aligned_alloc(1<<28,16);free(p);return 0;}
