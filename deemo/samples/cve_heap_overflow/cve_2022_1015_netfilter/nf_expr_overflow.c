/*
 * CVE-2022-1015 — Linux kernel netfilter nft_expression 堆溢出 (简化复现)
 * Linux kernel < 5.17, netfilter nf_tables 表达式验证中的堆越界写入.
 *
 * 漏洞机制:
 *   nft_validate_register_store() 和 nft_validate_register_load()
 *   在验证 nf_tables 表达式的寄存器访问时, 对寄存器索引的边界检查
 *   存在逻辑缺陷: 仅验证了单个寄存器偏移, 但未验证多次写入的累积效果.
 *   攻击者可通过构造的 nft 规则使 kernel 向寄存器文件外写入.
 *
 * 本文件简化: 寄存器索引的边界检查遗漏.
 *
 * 影响: 本地提权 (需要 CAP_NET_ADMIN, 可通过用户命名空间获取).
 * 修复: 添加寄存器范围累积验证.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define NFT_REG_SIZE  16   /* 每个寄存器16字节 */
#define NFT_REG_COUNT 4    /* 4个寄存器 (正确值应为更多, 模拟简化) */

/* nft 寄存器文件 (简化) */
typedef struct {
    uint8_t regs[NFT_REG_COUNT * NFT_REG_SIZE]; /* 4*16=64字节 */
} NftRegFile;

/* nft 表达式 (简化) */
typedef struct {
    uint8_t  op;
    uint8_t  dst_reg;     /* 目标寄存器编号 */
    uint8_t  src_reg;     /* 源寄存器编号 */
    uint16_t len;         /* 数据长度 */
    uint8_t  data[64];    /* 内联数据 */
} NftExpr;

/*
 * 漏洞函数: nft_validate_register_store
 * 检查单个表达式的寄存器访问是否在范围内,
 * 但未检查累积写入.
 */
int nft_validate_store(NftExpr *expr) {
    /* 单个寄存器检查: dst_reg < NFT_REG_COUNT */
    if (expr->dst_reg >= NFT_REG_COUNT) {
        printf("  Validation failed: dst_reg=%u >= %u\n",
               expr->dst_reg, NFT_REG_COUNT);
        return -1;
    }

    /*
     * 漏洞: 未检查 dst_reg * NFT_REG_SIZE + len 是否超出 regs[]!
     *       dst_reg=3, len=32 → 写入 regs[48:80], 但 regs 仅64字节
     */
    uint32_t end_offset = expr->dst_reg * NFT_REG_SIZE + expr->len;
    if (end_offset > NFT_REG_COUNT * NFT_REG_SIZE) {
        printf("  [!] Store overflow: reg[%u] + %u bytes = offset %u > %u\n",
               expr->dst_reg, expr->len, end_offset,
               NFT_REG_COUNT * NFT_REG_SIZE);
        /* 原始代码未执行此检查! */
    }
    return 0;
}

void execute_store(NftRegFile *rf, NftExpr *expr) {
    /* 写入到寄存器文件 — 无边界检查!
     * rf 是堆分配的, offset+len 可超越分配边界 */
    uint32_t offset = expr->dst_reg * NFT_REG_SIZE;
    memcpy(rf->regs + offset, expr->data, expr->len); /* 堆溢出! */
}

int main(void) {
    /* 堆分配寄存器文件 — 真实内核中 nft 寄存器文件是堆分配的 */
    NftRegFile *rf = (NftRegFile *)malloc(sizeof(NftRegFile));
    if (!rf) return 1;
    memset(rf, 0, sizeof(NftRegFile));

    /* 攻击者构造恶意表达式:
     *   dst_reg=3 (最后一个寄存器), len=32 (写入32字节)
     *   写入范围: 3*16=48 到 48+32=80, 但 regs 只有 64 字节! */
    NftExpr evil_expr = {
        .op = 0x01, /* NFT_REG_STORE */
        .dst_reg = 3,
        .len     = 32, /* 恶意长度: 超过寄存器剩余空间! */
    };
    memset(evil_expr.data, 0x41, 32);

    printf("[*] Netfilter nft register overflow (CVE-2022-1015)\n");
    printf("  regs size=%zu, write: reg[%u]..reg[%u] (%u bytes)\n",
           sizeof(rf->regs), evil_expr.dst_reg,
           evil_expr.dst_reg * NFT_REG_SIZE + evil_expr.len,
           evil_expr.len);

    if (nft_validate_store(&evil_expr) == 0) {
        printf("  Validation PASSED (vulnerable!)\n");
        execute_store(rf, &evil_expr);
        printf("[!] Malicious store executed (potential overflow)\n");
    }

    free(rf);
    return 0;
}
