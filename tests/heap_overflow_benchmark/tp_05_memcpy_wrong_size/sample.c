/*
 * TP-05: memcpy With Wrong Size (CWE-805)
 *
 * malloc(64) → memcpy(buf, src, 1024) → 拷贝大小远大于分配
 * 静态分析应检测到常数值不匹配
 *
 * 真实漏洞类比: CVE-2018-1000006 (Electron remote code execution)
 */
#include <stdlib.h>
#include <string.h>

static char g_src[2048];

int load_data(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return -1;

    memset(g_src, 0x43, sizeof(g_src));
    memcpy(buf, g_src, 1024);  /* 分配64B但拷贝1024B → 确定性溢出 */

    free(buf);
    return 0;
}

int main(void) {
    return load_data();
}
