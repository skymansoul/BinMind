/* CVE-2020-10757 — Linux kernel mremap 堆溢出
 * mremap 系统调用在跨 VMA 合并时未正确检查页表权限, 导致越界写入.
 * 类型: heap_buffer_overflow / CWE-122
 */
#include <stdlib.h>
#include <string.h>
void mremap_vuln(int old_size, int new_size, int copy_size) {
    char *old = malloc(old_size); memset(old, 'X', old_size);
    char *newbuf = malloc(new_size);
    /* BUG: 若 new_size < copy_size, memcpy 越界写入 newbuf */
    memcpy(newbuf, old, copy_size);
    free(old); free(newbuf);
}
int main(void) {
    mremap_vuln(64, 32, 64);  /* 向 32B 缓冲区写入 64B */
    return 0;
}
