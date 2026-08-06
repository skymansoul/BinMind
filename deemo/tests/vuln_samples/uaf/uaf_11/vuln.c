/* GENERIC-uaf-safe-null SAFE: 释放后置NULL——安全模式不应检出 */
#include <stdlib.h>
void sf(char**pp){free(*pp);*pp=NULL;}
int main(){char*b=malloc(128);sf(&b);if(b)b[0]='X';return 0;}
