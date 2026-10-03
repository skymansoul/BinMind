/*
 * CVE-2019-13139 模式复刻 — Docker cp 命令注入→堆溢出
 * 真实漏洞: docker cp 未正确校验目标路径, 命令注入
 * 本样本复刻其"用户输入直接驱动分配大小"的模式:
 * 未受信任长度驱动 malloc + memcpy, 无上界守卫
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 复刻: 网络报文长度直接驱动堆操作 */
struct packet {
    unsigned int len;
    char body[256];
};

int process_packet(struct packet *p) {
    /* 缺陷: len 由外部输入控制, 未与 sizeof(body) 比较 */
    char *out = (char *)malloc(p->len);
    if (!out) return -1;
    memcpy(out, p->body, p->len);   /* len 可 > 256 */
    free(out);
    return 0;
}

int main(int argc, char **argv) {
    struct packet *p = (struct packet *)malloc(sizeof(struct packet));
    if (!p) return 1;
    p->len = 400;                     /* 外部可控: 400 > 256 */
    memset(p->body, 0x41, 256);
    process_packet(p);
    free(p);
    return 0;
}
