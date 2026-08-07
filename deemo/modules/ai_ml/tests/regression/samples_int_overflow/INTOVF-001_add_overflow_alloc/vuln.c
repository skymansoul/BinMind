/* INTOVF-001: add溢出导致分配不足——最经典的整数溢出→堆溢出链
 * 场景: size = user_size + header_size; buf = malloc(size); memcpy(buf, data, user_size)
 *   若user_size=UINT_MAX-10, header_size=20 → overflow → size=9 → malloc(9) → memcpy(UINT_MAX-10) → 堆溢出
 * 检测器能力: add溢出→结果传递给malloc→CONFIRMED
 * 预期: IntOverflowDeepAnalyzer检测到add+alloc关联, risk>=LIKELY
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define HEADER_SIZE 16

typedef struct {
    uint32_t magic;
    uint32_t length;
    char data[];
} Packet;

Packet *create_packet(size_t user_len, const char *user_data) {
    /* BUG: user_len + HEADER_SIZE可能溢出
     * 若user_len=0xFFFFFFF0 → user_len+16=0x100000000 → 截断为0 → malloc(16) */
    size_t total = user_len + HEADER_SIZE;
    Packet *pkt = (Packet *)malloc(total);
    if (!pkt) return NULL;

    pkt->magic = 0xDEADBEEF;
    pkt->length = (uint32_t)user_len;

    /* BUG: 若total溢出, memcpy写user_len字节到tiny分配 → 堆溢出 */
    memcpy(pkt->data, user_data, user_len);
    return pkt;
}

int main(void) {
    char data[256];
    memset(data, 'A', sizeof(data));
    /* 正常调用 */
    Packet *p = create_packet(128, data);
    if (p) {
        printf("packet: magic=0x%x len=%u\n", p->magic, p->length);
        free(p);
    }
    return 0;
}
