/* FP test #3: 内部数据操作 — 污点分析应降权 (无外部输入) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char g_config[128] = "default_config_value_12345";

void internal_process(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    /* 源是全局变量 (内部数据), 非外部输入 → 应被污点过滤器降权 */
    memcpy(buf, g_config, 128); /* 写 128B → 64B, 但数据来自内部 */
    printf("%s\n", buf);
    free(buf);
}

int main(void) {
    internal_process();
    return 0;
}
