/* sample19: Double Free — 同一指针被释放两次

 * 漏洞类型: Double Free (UAF 子类)
 * CVE映射: CVE-2023-38408 (OpenSSH PKCS#11 double-free)
 * 触发条件: 代码路径未标记指针已释放, 到达第二个 free(p)
 * 测试价值: DT-HSA freelist 模拟器内置 double-free 检测 → 应标记为 DOUBLED FREE
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cleanup_and_log(char *buf, int do_extra_cleanup) {
    if (!buf) return;

    printf("Cleaning buffer: %s\n", buf);
    free(buf);

    /* [VULN] 额外清理路径再次 free — double free */
    if (do_extra_cleanup) {
        free(buf);
    }
}

int main(int argc, char **argv) {
    char *data = (char *)malloc(256);
    if (!data) return 1;
    strcpy(data, "sensitive_data");
    int extra = (argc > 1) ? 1 : 0;
    cleanup_and_log(data, extra);
    return 0;
}
