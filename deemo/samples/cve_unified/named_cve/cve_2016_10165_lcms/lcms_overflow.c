/*
 * CVE-2016-10165 — LittleCMS2 calloc 整数溢出 → 堆溢出 (简化复现)
 * LittleCMS 2.8 之前, Type_MLU_Read() 中 calloc 整数溢出导致分配过小.
 *
 * 漏洞机制:
 *   MLU (Multilocalized Unicode) 标签读取时:
 *     NumOfRecords = ReadUInt32Number(io);   攻击者可控
 *     SizeOfRec    = ReadUInt32Number(io);   攻击者可控
 *     Mlu = (cmsMLU*)calloc(1, NumOfRecords * SizeOfRec);
 *   若 NumOfRecords * SizeOfRec 回绕为小值, calloc 分配远小于预期的缓冲区.
 *   后续循环写 NumOfRecords * SizeOfRec 字节导致堆溢出.
 *
 * 本文件聚焦: calloc(1, n*m) 在 n=0x40000001, m=4 时回绕为 4,
 *   但后续写入 0x100000004 字节.
 *
 * 影响: 处理恶意 ICC 颜色配置文件时远程代码执行.
 * 修复: 使用 _cmsCalloc + 添加回绕检查.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* 模拟 ICC 文件解析 */
typedef struct {
    uint32_t num_records;   /* 记录数 — 攻击者可控 */
    uint32_t record_size;   /* 每条记录大小 — 攻击者可控 */
    uint8_t  *data;         /* 分配的数据缓冲区 */
} MluTag;

/*
 * 漏洞函数: 解析MLU标签
 * 输入: 原始ICC数据中攻击者控制的 num_records 和 record_size
 */
MluTag *type_mlu_read(uint32_t num_records, uint32_t record_size) {
    MluTag *mlu = (MluTag *)malloc(sizeof(MluTag));
    if (!mlu) return NULL;

    mlu->num_records = num_records;
    mlu->record_size = record_size;

    /*
     * 漏洞: calloc(1, num_records * record_size)
     *   当 num_records=0x40000001, record_size=4:
     *     product = 0x40000001 * 4 = 0x100000004
     *     32位截断 → product = 0x00000004
     *     calloc(1, 4) → 仅分配 4 字节!
     *
     * 后续循环: for(i=0; i<num_records; i++)
     *              memcpy(mlu->data + i*record_size, ...)
     * 实际写入: 0x40000001 * 4 ≈ 16GB 数据到 4 字节缓冲区 → 堆溢出!
     */
    size_t product = (size_t)num_records * (size_t)record_size;
    mlu->data = (uint8_t *)calloc(1, product);
    if (!mlu->data) {
        free(mlu);
        return NULL;
    }

    printf("  [+] calloc(1, %u*%u=%zu) succeeded\n",
           num_records, record_size, product);

    /*
     * 漏洞触发: 向仅有4字节的缓冲区写入 0x40000001 条记录.
     * 在真实利用中, 攻击者会逐步覆盖堆元数据.
     */
    for (uint32_t i = 0; i < num_records; i++) {
        /* 每次迭代写入 record_size 字节到 mlu->data + i*record_size */
        if (i < 4) {
            /* 前几次写入仍在合法范围内 (演示) */
            memset(mlu->data + i * record_size, 0x41 + i, record_size);
        } else {
            /* 越界写入开始! */
            break; /* 演示仅显示漏洞存在, 不实际越界写 */
        }
    }

    printf("  [!] Would overflow at record %u (of %u)\n", 4, num_records);
    return mlu;
}

int main(void) {
    /* 攻击者构造的恶意值 */
    uint32_t evil_n = 0x40000001; /* 16 * 16384 * 16384 + 1 */
    uint32_t evil_m = 4;          /* 每个记录4字节 */

    printf("[*] LittleCMS MLU calloc overflow test\n");
    printf("  num_records=0x%X, record_size=%u\n", evil_n, evil_m);
    printf("  product(32-bit)=0x%zX (wraps!)\n",
           (size_t)evil_n * (size_t)evil_m & 0xFFFFFFFF);

    MluTag *result = type_mlu_read(evil_n, evil_m);
    if (result) {
        free(result->data);
        free(result);
    }
    return 0;
}
