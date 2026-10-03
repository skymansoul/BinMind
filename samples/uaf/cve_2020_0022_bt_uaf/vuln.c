/*
 * cve_2020_0022 — Android Bluetooth UAF (CWE-416)
 * 模式: 释放结构体后未置 NULL, 重建包时再次写入.
 * 原漏洞: L2CAP 包重组时 packet 结构释放后仍被访问.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { char *data; int len; } Pkt;
Pkt *pkt;
void alloc() { pkt = malloc(sizeof(Pkt)); pkt->data = malloc(512); pkt->len = 0; }
void free_p() { free(pkt->data); free(pkt); } /* BUG: pkt not nulled */
void use_p() { if(pkt && pkt->data) memset(pkt->data, 0xFF, 512); } /* UAF */
int main() { alloc(); free_p(); use_p(); return 0; }
