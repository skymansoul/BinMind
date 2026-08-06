/* GENERIC-fmt-wrap-func CWE-134: 自定义包装函数隐藏格式串漏洞 */
#include <stdio.h>
#include <stdarg.h>
void my_log(int lvl,const char*f,...){va_list a;va_start(a,f);vprintf(f,a);va_end(a);}
int main(int c,char**v){my_log(1,c>1?v[1]:"info: %s","test");return 0;}
