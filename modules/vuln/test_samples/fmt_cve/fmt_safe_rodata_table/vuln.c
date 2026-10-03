/* fmt_safe_rodata_table — rodata 表项格式串 (SAFE)。
 * Expected: SAFE */
#include <stdio.h>

static const char *tbl[] = {"item=%d\n", "done\n"};

int main(int argc, char **argv) {
    printf(tbl[0], argc);         /* 常量表项 */
    return 0;
}
