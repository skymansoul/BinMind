/* format_string_04 — snprintf 格式参数可控
 * CWE-134: snprintf(dst, size, user_fmt, ...) 
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
void format_output(const char *fmt, const char *data) {
    char buf[256];
    snprintf(buf, sizeof(buf), fmt, data); /* fmt 可控→信息泄露/任意写 */
    puts(buf);
}
int main(int argc, char **argv) {
    format_output(argc > 1 ? argv[1] : "%s", argc > 2 ? argv[2] : "hello");
    return 0;
}
