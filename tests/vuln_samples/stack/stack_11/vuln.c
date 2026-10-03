/* GENERIC-stack-vsprintf CWE-121: vsprintf向栈缓冲区写入超长格式化数据 */
#include <stdio.h>
#include <stdarg.h>
void vf(const char*f,...){va_list a;va_start(a,f);char b[64];vsprintf(b,f,a);va_end(a);}
int main(int c,char**v){vf(c>1?v[1]:"%s","long_string_here");return 0;}
