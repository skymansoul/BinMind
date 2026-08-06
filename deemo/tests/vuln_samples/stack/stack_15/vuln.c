/* GENERIC-stack-safe-strncpy SAFE: strncpy正确边界检查——安全不应检出 */
#include <string.h>
void sc(char*s){char b[64];strncpy(b,s,sizeof(b)-1);b[63]=0;}
int main(int c,char**v){sc(c>1?v[1]:"test");return 0;}
