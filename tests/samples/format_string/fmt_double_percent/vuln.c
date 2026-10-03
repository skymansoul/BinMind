#include <stdio.h>
/* FMT-11: %% 转义 — 不应误报双百分号 */
int main(int argc, char **argv) {
    printf("%%s %%n %%d\n");  /* SAFE: 全部转义 */
    return 0;
}
