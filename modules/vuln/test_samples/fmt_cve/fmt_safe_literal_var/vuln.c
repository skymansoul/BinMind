/* fmt_safe_literal_var — 变量持有的常量格式串 (SAFE)。
 * Expected: SAFE */
#include <stdio.h>

int main(void) {
    char *fmt = "fixed %s";
    printf(fmt, "world");         /* fmt 指向常量 */
    return 0;
}
