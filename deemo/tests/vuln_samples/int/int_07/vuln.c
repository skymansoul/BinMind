/* GENERIC-int-safe-bounds SAFE: 边界检查正确——安全模式 */
#include <stdlib.h>
#include <string.h>
char*scp(const char*s,size_t mx){size_t l=strlen(s);if(l>=mx)l=mx-1;char*b=malloc(l+1);if(!b)return 0;return b;}
int main(int c,char**v){char*p=scp(c>1?v[1]:"t",128);free(p);return 0;}
