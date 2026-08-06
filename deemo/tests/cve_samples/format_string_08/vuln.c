/* format_string_08 — 通过函数指针间接调用printf
 * CWE-134: fmt_func_ptr指向的printf被传入用户数据
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
typedef int (*fmt_fn)(const char *, ...);
void call_fmt(fmt_fn fn, const char *data) { fn(data); }
int main(int argc, char **argv) { call_fmt((fmt_fn)printf, argc>1?argv[1]:"test"); return 0; }
