/* format_string_11 — vsprintf/vsnprintf等变参函数误用
 * CWE-134: vsprintf的格式参数可控
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdarg.h>
void vlog(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    char buf[256]; vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap); puts(buf);
}
int main(int argc, char **argv) { vlog(argc>1?argv[1]:"%s","data"); return 0; }
