/* CVE-2021-35942 (安全陷阱) — add reg,reg 派生的同源分配
 * 漏洞类型: 无溢出 (分配与写入同源, 经 add 指令派生)
 * 触发条件: malloc(n), 拷贝大小 = 同一 n 经 add 运算派生
 * 根因: 无漏洞; 分配大小与写入大小同源
 * 有效原因: 测试 AWSC 对 add reg,reg 指令的追根健全性:
 *   反汇编为 mov rcx,[rbp-8]; add rcx, 0; mov r8, rcx 时,
 *   追根必须回到 n 而非误追 add 的另一操作数
 */
#include <stdlib.h>
#include <string.h>

void safe_add_copy(char *src, size_t n) {
    char *buf = (char *)malloc(n);
    if (!buf) return;
    size_t write_size = n + 0;   /* add 0: 同源派生 */
    memcpy(buf, src, write_size); /* write_size == n, 安全 */
    free(buf);
}

int main() {
    char data[128] = "safe";
    safe_add_copy(data, 64);
    return 0;
}
