/*
 * 模拟 CVE-2020-29370 — kmalloc 堆溢出
 * 内核模块中 size 字段未验证导致与 copy_from_user 的写入不匹配
 * 真实 CVE: Linux kernel < 5.8.15, drivers/usb/core/devio.c
 * 漏洞触发: 用户指定的 size > 实际分配的 buffer → 堆溢出
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ALLOC 256
#define USER_SUPPLIED_SIZE 512  /* 恶意用户提供的 size, 大于分配 */

static char g_buffer[MAX_ALLOC];

void vulnerable_copy(void *user_data, unsigned int user_size) {
    /* 漏洞点: user_size 未经边界检查直接用于 memcpy */
    char *buf = (char *)malloc(MAX_ALLOC);  /* 实际分配 256B */
    if (!buf) return;

    /* 污点: user_data 来自外部, user_size 可控 */
    memcpy(buf, user_data, user_size);  /* 写入 512B → 溢出 256B */

    /* 正常流程继续 */
    memcpy(g_buffer, buf, MAX_ALLOC);
    free(buf);
}

int main(int argc, char **argv) {
    char payload[USER_SUPPLIED_SIZE];
    memset(payload, 'A', sizeof(payload));
    vulnerable_copy(payload, USER_SUPPLIED_SIZE);
    printf("done\n");
    return 0;
}
