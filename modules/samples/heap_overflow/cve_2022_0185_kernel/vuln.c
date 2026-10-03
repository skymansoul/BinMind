/*
 * CVE-2022-0185 模式复刻 — legacy_parse_param 堆越界写
 * 真实漏洞: 内核 fs/fs_context.c 参数解析中, 参数长度检查
 *           使用 PAGE_SIZE - 2 - size 而非 PAGE_SIZE - size,
 *           造成最大 2 字节越界写, 可容器逃逸 (CVE-2022-0185)
 * 触发条件: 参数长度恰好超过检查阈值
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAGE_SIZE 4096
#define MAX_PARAM (PAGE_SIZE - 2)   /* 检查阈值: 4094 */

struct param_buf {
    char data[PAGE_SIZE];
    int used;
};

/* 复刻内核逻辑: 检查允许 4094B, 但拷贝写入 data[4093] 后
   再写 NULL 终止符到 data[4094] → 越界 1 字节 */
int parse_param(struct param_buf *pb, const char *key, const char *value) {
    size_t klen = strlen(key);
    size_t vlen = strlen(value);
    if (klen + vlen > MAX_PARAM)     /* 缺陷检查: 未留 NULL 空间 */
        return -1;
    memcpy(pb->data + pb->used, key, klen);      /* used=0 */
    pb->used += klen;
    memcpy(pb->data + pb->used, value, vlen);    /* 写入至 4093 */
    pb->data[pb->used + vlen] = 0;               /* 越界: 位置 4094 */
    return 0;
}

int main(int argc, char **argv) {
    struct param_buf *pb = (struct param_buf *)malloc(PAGE_SIZE);
    if (!pb) return 1;
    pb->used = 0;
    char key[4000], value[128];
    memset(key, 'K', 3999); key[3999] = 0;
    memset(value, 'V', 100); value[100] = 0;
    parse_param(pb, key, value);     /* 4099 > 4094 检查未通过 */
    /* 构造通过检查的边界: klen=3994, vlen=100 → 4094 恰好通过 */
    memset(key, 'K', 3994); key[3994] = 0;
    parse_param(pb, key, value);     /* NULL 写至 data[4094] 越界 */
    free(pb);
    return 0;
}
