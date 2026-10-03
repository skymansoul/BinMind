/* GENERIC-uaf-realloc CWE-416: realloc移动后使用旧指针 */
#include <stdlib.h>
char*rs(char*b,size_t n){char*o=b;char*nb=realloc(b,n);if(nb!=o)o[0]='L';return nb;}
int main(){char*b=malloc(64);b=rs(b,256);free(b);return 0;}
