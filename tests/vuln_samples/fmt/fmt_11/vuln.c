/* GENERIC-fmt-wrap CWE-134: 自定义包装函数隐藏格式串漏洞 */
#include <stdio.h>
#include <stdarg.h>
void my_print(const char* f, ...) { va_list a; va_start(a, f); vprintf(f, a); va_end(a); }
int main(int c, char** v) { my_print(c>1?v[1]:"info: %s", "test"); return 0; }