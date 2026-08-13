/* UAF-09: CVE-2022-25636 (netfilter) 简化复刻
 * CVE: CVE-2022-25636, 内核 netfilter 堆 UAF, 已公开利用链.
 * 触发: 结构体对象经 release() 释放; 随后 use_field() 解引用同一对象
 *       的字段 → UAF. release 内 free(p) 直接释放参数对象.
 * 为何有效: 过程间释放摘要需识别 callee 直接 free 参数(非字段),
 *       且调用方释放后继续使用.
 */
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int len;
    char *data;
} pkt_t;

void release(pkt_t *p) {
    free(p->data);
    free(p);              /* 直接释放参数对象 */
}

void use_field(pkt_t *p) {
    if (p && p->data) {
        p->data[0] = 'X'; /* UAF: p 已释放 */
    }
}

int main(void) {
    pkt_t *p = (pkt_t *)malloc(sizeof(pkt_t));
    if (!p) {
        return 1;
    }
    p->data = (char *)malloc(32);
    release(p);
    use_field(p);         /* UAF */
    return 0;
}
