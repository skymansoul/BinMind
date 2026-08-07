/*
 * CVE-2024-21894 — OpenSSL: POLY1305 MAC 堆溢出 (CWE-122)
 *
 * OpenSSL 3.1.0 ~ 3.1.4 / 3.0.0 ~ 3.0.11:
 * EVP_POLY1305 的 XMM 寄存器溢出保存/恢复代码中存在堆缓冲区溢出.
 * 攻击者控制 MAC 密钥后可触发, 影响使用 POLY1305 的 TLS 连接.
 *
 * 更泛化的模式: 上下文结构体的字段溢出 → 覆写相邻堆元数据.
 *
 * CVSS: 7.5 (High), CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define POLY1305_BLOCK_SIZE 16
#define POLY1305_KEY_SIZE  32

typedef struct {
    uint8_t opaque[192];    /* 内部状态 */
    uint8_t buf[POLY1305_BLOCK_SIZE];
    int buf_used;
} poly1305_ctx;

/* 模拟 POLY1305 的单块更新中的溢出 */
void poly1305_update(poly1305_ctx *ctx, const uint8_t *data, size_t len) {
    size_t needed;

    /* 先填充内部缓冲区 */
    if (ctx->buf_used > 0) {
        needed = POLY1305_BLOCK_SIZE - ctx->buf_used;
        if (len < needed) {
            memcpy(ctx->buf + ctx->buf_used, data, len);
            ctx->buf_used += (int)len;
            return;
        }
        memcpy(ctx->buf + ctx->buf_used, data, needed);
        /* process_block(ctx); */
        data += needed;
        len -= needed;
        ctx->buf_used = 0;
    }

    /* [VULN] 在填充新数据到 ctx->buf 时,
     * buf_used 的计算可能因 len 很大而溢出 (int overflow),
     * 导致实际拷贝的字节数 > POLY1305_BLOCK_SIZE
     */
    if (len > POLY1305_BLOCK_SIZE) {
        /* 处理完整块 */
        size_t blocks = len / POLY1305_BLOCK_SIZE;
        size_t proc_sz = blocks * POLY1305_BLOCK_SIZE;
        /* process_blocks(ctx, data, blocks); */
        data += proc_sz;
        len -= proc_sz;
    }

    /* 剩余数据放入 buf */
    if (len > 0) {
        /* [VULN] 若 len 被篡改为 > POLY1305_BLOCK_SIZE,
         * ctx->buf 只有 16 字节, 这里会溢出到 ctx 的其他字段
         */
        if (len > POLY1305_BLOCK_SIZE) /* 防御性检查 — 旧版缺失 */
            len = POLY1305_BLOCK_SIZE;
        memcpy(ctx->buf, data, len);
        ctx->buf_used = (int)len; /* [VULN] len 可能截断为负值 */
    }
}

int main(void) {
    poly1305_ctx *ctx = (poly1305_ctx *)calloc(1, sizeof(poly1305_ctx));
    if (!ctx) return -1;

    /* 构造触发溢出的输入 */
    uint8_t evil_input[256];
    memset(evil_input, 0xFF, sizeof(evil_input));

    /* 第一次调用: 填充 15 字节到 buf */
    poly1305_update(ctx, evil_input, 15);

    /* 第二次调用: 传入比 buf 剩余容量更多的数据 */
    poly1305_update(ctx, evil_input + 15, 240); /* buf_used=15, 只剩1字节空间 */

    free(ctx);
    return 0;
}
