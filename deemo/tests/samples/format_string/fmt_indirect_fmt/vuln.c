#include <stdio.h>
#include <stdlib.h>
/* FMT-08: 间接格式串 — 格式串来自全局变量/配置文件 */
static const char *g_fmt = NULL;
void load_config(void) { g_fmt = "config: %s\n"; }
void load_user(const char *s) { g_fmt = s; }

int main(int argc, char **argv) {
    if (argc > 1) load_user(argv[1]);
    else load_config();
    printf(g_fmt, "value");  /* VULNERABLE if argc>1 */
    return 0;
}
