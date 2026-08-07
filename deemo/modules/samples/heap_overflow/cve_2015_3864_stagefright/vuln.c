/*
 * CVE-2015-3864 模式复刻 — Android Stagefright 堆溢出
 * 真实漏洞: libstagefright 解析 MP4 时 size 字段驱动的
 *           越界拷贝, 经彩信远程 RCE (CVE-2015-3864)
 * 触发条件: 样本 size 字段 > 实际分配
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MP4_MAX_SIZE 64

/* 复刻 SampleTable: size 外部可控, 分配按 size 但解析按
   fixed header + size 写入 */
char *parse_sample(const unsigned char *buf, unsigned int size) {
    char *sample = (char *)malloc(MP4_MAX_SIZE);   /* 固定 64B */
    if (!sample) return NULL;
    /* 缺陷: 头 8 字节 + size 数据, size 未校验 */
    memcpy(sample, buf, size + 8);                 /* size 可=0xFFF */
    return sample;
}

int main(int argc, char **argv) {
    unsigned char buf[16];
    memset(buf, 0x5A, 16);
    char *s = parse_sample(buf, 0xFFF);   /* 4095+8 > 64 */
    if (s) free(s);
    return 0;
}
