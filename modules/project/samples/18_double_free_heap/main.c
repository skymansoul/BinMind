/* 样本18: Double-free后重用导致的堆损坏 (与溢出相关)
 * 模式: free(buf); free(buf); malloc(...); → 获得重叠内存,
 *   通过重叠指针写入→可能溢出到其他分配
 * CVE参考: CVE-2018-6552 (Apport: double-free导致堆损坏)
 * 为何有效: 测试检测器对free→alloc生命周期追踪的正确性
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *a = (char *)malloc(128);
    char *b = (char *)malloc(128);
    if (!a || !b) return 1;

    /* double free */
    free(a);
    free(a);  /* 漏洞: double free */

    /* 重新分配 — 可能获得与a重叠的内存 */
    char *c = (char *)malloc(128);
    /* 通过c写入, 但c可能与a重叠 → 导致a/b的数据被破坏 */
    memset(c, 'D', 256);  /* 溢出写入 */

    printf("a=%p b=%p c=%p (c可能重叠a)\n",
           (void *)a, (void *)b, (void *)c);
    free(b); free(c);
    return 0;
}
