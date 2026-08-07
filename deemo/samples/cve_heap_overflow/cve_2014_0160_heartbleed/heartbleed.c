/*
 * CVE-2014-0160 — Heartbleed (简化复现)
 * OpenSSL 1.0.1 TLS heartbeat 堆越界读取/写入
 *
 * 漏洞机制:
 *   TLS heartbeat 请求包含 payload_length 字段 (16-bit, 攻击者可控).
 *   服务器分配 payload_length+padding 字节的响应缓冲区,
 *   但实际从请求payload中拷贝的是 payload_length 字节 —
 *   问题: 请求实际长度可能远小于 payload_length, 导致memcpy读取
 *   越界内存并返回给攻击者 (信息泄露) 或写入溢出.
 *
 * 本文件聚焦写入溢出视角:
 *   请求声称 payload_length 大值, 服务器尝试向分配的小缓冲区
 *   写入超出分配大小的数据.
 *
 * 影响: 泄漏服务器私钥、会话密钥、用户凭据等多达64KB的堆内存.
 * 修复: OpenSSL 1.0.1g 添加 payload_length 与实际长度的一致性验证.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*  TLS heartbeat 请求结构 (简化) */
typedef struct {
    uint8_t  type;           /* 心跳消息类型 */
    uint16_t payload_length; /* 攻击者声明的payload长度 (可控) */
    uint8_t  payload[64];    /* 实际payload (远小于声明的长度) */
    uint8_t  padding[16];
} HeartbeatRequest;

/* 心跳响应结构 (简化) */
typedef struct {
    uint8_t  type;
    uint16_t length;
    uint8_t  payload[0];     /* 柔性数组 — 实际分配由 payload_length 决定 */
} HeartbeatResponse;

/*
 * 漏洞函数: 响应心跳请求
 * 缺陷: 用请求声明的 payload_length 做 memcpy,
 *       但实际可用 payload 大小远小于声明值.
 *       攻击者设置 payload_length=65535 而实际发送 payload=1字节,
 *       memcpy 从请求结构体之外读取65535字节写入响应缓冲区.
 */
HeartbeatResponse *dtls1_process_heartbeat(HeartbeatRequest *req) {
    /* [1] 分配响应缓冲区: payload_length + padding + header */
    unsigned int payload_len = req->payload_length; /* ⚠️ 攻击者可控, 来自网络 */
    unsigned int alloc_size  = 1 + 2 + payload_len + 16;

    HeartbeatResponse *resp =
        (HeartbeatResponse *)malloc(alloc_size);
    if (!resp) return NULL;

    /* [2] 填充响应头部 */
    resp->type   = req->type;
    resp->length = payload_len;

    /* [3] 漏洞: memcpy 从请求的 payload 字段拷贝 payload_len 字节
     *     但请求实际只有 64 字节 payload 缓冲区.
     *     攻击者声明 payload_len=65535 → 越界读取64KB
     *     → 响应也分配 65535+header 字节 → 写入超量数据
     */
    memcpy(resp->payload, req->payload, payload_len); /* 溢出! */

    return resp;
}

int main(void) {
    HeartbeatRequest *req = (HeartbeatRequest *)calloc(1, sizeof(HeartbeatRequest));
    req->type = 1; /* TLS heartbeat request */
    req->payload_length = 0xFFFF; /* 攻击者: 声明65535字节, 实际只有64 */
    memset(req->payload, 'A', 64);

    HeartbeatResponse *resp = dtls1_process_heartbeat(req);
    if (resp) {
        printf("[!] Heartbeat response allocated: %u bytes claimed payload\n",
               resp->length);
        free(resp);
    }
    free(req);
    return 0;
}
