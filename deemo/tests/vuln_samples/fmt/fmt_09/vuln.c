/* GENERIC-fmt-safe-lit SAFE: 安全使用: 格式串字面量——不应检出 */
#include <stdio.h>
void ss(char*n){printf("Hello, %s\n",n);}
int main(int c,char**v){ss(c>1?v[1]:"guest");return 0;}
