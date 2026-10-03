/* HEAPOVERFLOW-016: 路径条件溢出——L4 CFG可达性验证
 * memcpy在不可达基本块中——L4应排除
 * 对比Angr: 符号执行会标记该路径不可达但CFGFast仍报告sink
 * 对比Ghidra: 无路径分析→直接报告为漏洞
 */

#include <stdlib.h>
#include <string.h>

static int g_debug = 0;  /* 始终为0——debug路径不可达 */

void path_sensitive_copy(char *input, int len) {
    char *buf = (char *)malloc(64);
    if (!buf) return;

    if (g_debug) {
        /* 此路径在运行时不可达(g_debug恒为0) */
        /* L4 BFS从入口BB出发→此BB不在可达集合→FILTERED */
        memcpy(buf, input, 1024);  /* 明显的溢出——但在死代码中 */
    }

    /* 可达路径——安全拷贝 */
    if (len > 0 && len <= 64) {
        memcpy(buf, input, len);
    }

    free(buf);
}

int main() {
    char data[50];
    memset(data, 'B', sizeof(data));
    path_sensitive_copy(data, 50);
    return 0;
}
