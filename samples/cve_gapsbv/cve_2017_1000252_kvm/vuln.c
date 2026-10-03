/*
 * CVE-2017-1000252 — Linux KVM: virtio 堆溢出 (CWE-122)
 *
 * Linux kernel 4.13.2 之前: KVM virtio 框架中 virtqueue_pop 未验证
 * 描述符链长度, 攻击者可构造恶意描述符链使内核在堆上越界写入.
 *
 * 触发: 客户机→主机 virtio 请求, 恶意 sg 列表长度超过分配
 *
 * CVSS: 7.8 (High), CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define VIRTIO_MAX_SG 256

typedef struct {
    uint64_t addr;
    uint32_t len;
} scatterlist_t;

int virtqueue_pop(scatterlist_t *sg, unsigned int *num_out,
                  void *data_buf, size_t buf_len) {
    unsigned int count = *num_out;

    /* [VULN] 未验证 count ≤ VIRTIO_MAX_SG 或 count ≤ buf_len/sizeof(sg[0])
     * 攻击者控制 num_out (从共享内存读取), 可达 65535
     */
    if (count > 128) { /* 不充分的检查: 允许 count=200 等 */
        return -1;      /* 但不阻止 128 < count ≤ buf_len/sizeof(sg) 的情况 */
    }

    scatterlist_t *sg_list = (scatterlist_t *)data_buf;

    /* [VULN] sg[i].len 是客户机可控的, 每个都可能 > buf_len
     * 多段累积后总写入量远超分配大小
     */
    size_t total_written = 0;
    for (unsigned int i = 0; i < count; i++) {
        if (sg_list[i].len > buf_len - total_written) {
            /* 安全路径 — 但如果此处被优化掉或绕过, 就溢出 */
            break;
        }
        /* memcpy(sg_list + i, sg, sg_list[i].len); — 累积溢出 */
        total_written += sg_list[i].len;
    }

    /* [VULN] total_written 可能 > buf_len, 后续 memcpy 越界 */
    if (total_written > buf_len) {
        /* 晚来的检查 — 写操作已发生 */
        return -2;
    }
    return 0;
}

int main(void) {
    scatterlist_t sg[300];
    for (int i = 0; i < 300; i++) {
        sg[i].addr = 0x1000 + i * 256;
        sg[i].len = 1024; /* 每段 1KB, 300段 = 300KB — 远超分配 */
    }
    unsigned int num = 300;
    unsigned char buf[4096];
    return virtqueue_pop(sg, &num, buf, sizeof(buf));
}
