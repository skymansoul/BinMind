/* CVE-2023-0179 — Linux kernel netfilter nft_payload 缓冲区溢出
 *
 * 触发条件: nft_payload_copy_vlan 中, VLAN 标签处理的 offset/size
 * 计算错误, 可以在堆上写越界。
 *
 * 测试目标: offset+size 双参数约束分析 —
 * malloc(size) 后的操作 offset+size 可能超出分配范围。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct nft_payload {
    uint8_t *buf;
    uint32_t len;
    uint32_t offset;
};

static int nft_payload_eval(struct nft_payload *pld, const uint8_t *data, uint32_t dlen) {
    uint32_t copy_off, copy_len;

    /* 模拟 VLAN 处理: offset 和 len 来自用户层 */
    copy_off = pld->offset;
    copy_len = pld->len;

    /* BUG: 没有检查 copy_off + copy_len <= dlen */
    if (copy_off >= dlen) return -1;

    pld->buf = (uint8_t *)malloc(pld->len);
    if (!pld->buf) return -1;

    /* 越界拷贝: copy_off + copy_len 可能大于 pld->len */
    memcpy(pld->buf, data + copy_off, copy_len);
    return 0;
}

int main(int argc, char **argv) {
    struct nft_payload pld = {0};
    uint8_t data[1024] = {0};
    if (argc >= 3) {
        pld.offset = (uint32_t)atoi(argv[1]);
        pld.len = (uint32_t)atoi(argv[2]);
    } else {
        pld.offset = 900;
        pld.len = 200;  /* offset+len > 1024, heap overflow */
    }
    nft_payload_eval(&pld, data, 1024);
    free(pld.buf);
    return 0;
}
