/*
 * CVE-2020-28030 — Wireshark Gryphon 协议解析堆溢出 (简化复现)
 * Wireshark < 3.2.8, Gryphon 协议解析器中的堆缓冲区溢出.
 *
 * 漏洞机制:
 *   解析 Gryphon 协议消息时, 消息头中的 length 字段 (攻击者可控)
 *   用于确定后续数据读取量. 若 length 超大,
 *   分配缓冲区后循环写入可能超出分配大小.
 *   本问题普遍存在于协议解析器中的 read_length → malloc → read_data 模式.
 *
 * 本文件简化: 协议解析中的 tlv_len → alloc → memcpy 模式.
 *
 * 影响: 通过恶意 pcap 文件触发 DoS/RCE (Wireshark 或 tshark).
 * 修复: 在分配前验证 length 字段合理性.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* Gryphon 协议消息 (简化) */
typedef struct {
    uint32_t msg_type;
    uint32_t body_len;     /* 声明的消息体长度 — 攻击者可控 */
    uint8_t  body[1024];   /* 实际消息体数据 */
} GryphonMsg;

/*
 * 漏洞函数: 解析 Gryphon 协议消息体
 * 分配 body_len 字节, 但实际从 body 字段中读取的数据
 * 可能由 body_len 和内部计数器共同决定 — 两者可能不一致.
 */
uint8_t *parse_gryphon_body(const GryphonMsg *msg) {
    uint32_t alloc_size = msg->body_len + 16; /* +16 for metadata */
    uint8_t  *buf = (uint8_t *)malloc(alloc_size);
    if (!buf) return NULL;

    /*
     * 漏洞: 循环写入基于 body_len, 但某些子结构
     *       可能包含指向后续数据的指针, 导致
     *       实际写入超出 body_len.
     *
     * 原始 Gryphon 协议中, 消息体可以包含嵌套的 TLV,
     * 每个 TLV 的长度字段独立. 若攻击者使 TLV 总长度
     * 超过外层 body_len 但外层的 malloc 仅基于 body_len,
     * 则溢出.
     */
    uint32_t written  = 0;
    uint32_t consumed = 0;

    /* 模拟处理嵌套 TLV */
    while (consumed < msg->body_len && written < alloc_size) {
        if (consumed + 4 > msg->body_len) break;
        /* TLV 头: type(2) + len(2) = 4字节 */
        uint16_t tlv_len;
        memcpy(&tlv_len, msg->body + consumed + 2, 2);
        consumed += 4;

        /* 漏洞: tlv_len 可能使得 consumed + tlv_len > body_len
         *       外层的 while 检查 consumed < body_len,
         *       但单次迭代内部的 memcpy 不检查! */
        if (consumed + tlv_len > msg->body_len) {
            printf("  [!] TLV claims %u bytes but only %u remain in body\n",
                   tlv_len, msg->body_len - consumed);
            /* 原始代码: 继续拷贝, 导致越界读取 → 写入到 buf 的越界 */
        }

        uint32_t copy_len = (consumed + tlv_len <= msg->body_len)
                            ? tlv_len : msg->body_len - consumed;
        memcpy(buf + written, msg->body + consumed, copy_len);
        written  += tlv_len; /* BUG: 用 tlv_len 而非 copy_len 更新 written! */
        consumed += tlv_len; /* 越界读取 */
    }

    printf("  alloc=%u, written=%u\n", alloc_size, written);
    if (written > alloc_size) {
        printf("  [!] OVERFLOW: written > alloc!\n");
    }
    return buf;
}

int main(void) {
    GryphonMsg msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = 0x01;
    msg.body_len = 128; /* 声明128字节 */
    /* 构造嵌套 TLV, 其中内部 TLV 长度超过外部剩余空间 */
    memset(msg.body, 0x41, sizeof(msg.body));

    printf("[*] Wireshark Gryphon dissector overflow (CVE-2020-28030)\n");
    uint8_t *result = parse_gryphon_body(&msg);
    if (result) {
        printf("[!] Body parsed (potential overflow)\n");
        free(result);
    }
    return 0;
}
