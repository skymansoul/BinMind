/* GENERIC-fmt-varargs CWE-134: 自定义varargs函数转发格式串漏洞 */
#include <stdio.h>
#include <stdarg.h>
void vpl(const char*f,...){va_list a;va_start(a,f);vprintf(f,a);va_end(a);}
int main(int c,char**v){vpl(c>1?v[1]:"%s","test");return 0;}
