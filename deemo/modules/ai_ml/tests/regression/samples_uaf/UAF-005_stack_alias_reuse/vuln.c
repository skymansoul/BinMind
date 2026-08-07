/* UAF-005: 栈暂存别名——指针保存到栈又取出后free，原始变量再use
 * 场景: ptr暂存到栈[sp+N] → 从栈取出到r12 → free(r12) → use(ptr)
 * 别名追踪器能力: 栈恢复→寄存器别名图→识别栈暂存别名链
 * 预期: 增强过滤器检测到栈别名UAF(CONFIRMED或LIKELY)
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    unsigned char *data;
    unsigned int size;
    unsigned int crc;
} Packet;

static Packet *active_packet = NULL;

void process_packet(const unsigned char *raw, unsigned int len) {
    Packet *pkt = (Packet *)malloc(sizeof(Packet));
    if (!pkt) return;

    pkt->data = (unsigned char *)malloc(len);
    if (!pkt->data) {
        free(pkt);
        return;
    }
    memcpy(pkt->data, raw, len);
    pkt->size = len;
    pkt->crc = 0;

    /* 栈暂存: 把pkt保存到全局变量(相当于栈上的指针槽位)
     * 编译器实现: mov [global_cache_ptr], rax — 存入内存
     *           后续: mov rdi, [global_cache_ptr] — 从内存取出传给free */
    active_packet = pkt;  /* 栈/全局暂存 */

    /* 校验CRC——若失败则释放 */
    unsigned int calc_crc = 0;
    for (unsigned int i = 0; i < len; i++)
        calc_crc ^= raw[i];

    if (calc_crc == 0xFF) {
        /* 错误路径: 通过栈暂存的别名释放 */
        free(active_packet->data);
        free(active_packet);
        active_packet = NULL;
        return;
    }

    pkt->crc = calc_crc;

    /* 正常路径: 通过原始变量访问
     * 若calc_crc != 0xFF则安全——pkt有效 */
    printf("packet size=%u crc=%u\n", pkt->size, pkt->crc);
}

void cleanup_packet(void) {
    if (active_packet) {
        /* UAF场景入口: 外部调用cleanup释放 */
        free(active_packet->data);
        free(active_packet);

        /* BUG: 未置NULL */
        /* active_packet = NULL; -- 缺失! */

        /* 后续代码可能通过get_packet_info再次use */
    }
}

void get_packet_info(void) {
    /* UAF: active_packet已被cleanup释放但未置NULL */
    if (active_packet) {
        /* 访问freed内存 */
        printf("stale packet: size=%u crc=%u\n",
               active_packet->size, active_packet->crc);
    }
}

int main(void) {
    unsigned char data[] = "test_packet_data_5678";
    process_packet(data, sizeof(data));
    cleanup_packet();
    get_packet_info();  /* UAF */
    return 0;
}
