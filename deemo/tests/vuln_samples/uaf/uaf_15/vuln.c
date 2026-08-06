/* GENERIC-uaf-safe-guard SAFE: 使用引用计数保护——安全不应检出 */
#include <stdlib.h>
int*rc;void dec(int*p){(*p)--;if(*p==0)free(p);}
int main(){int*ref=malloc(sizeof(int));*ref=1;dec(ref);return 0;}
