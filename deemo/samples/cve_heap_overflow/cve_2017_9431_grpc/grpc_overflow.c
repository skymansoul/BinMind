/*
 * CVE-2017-9431 — Google gRPC 堆溢出 (简化复现)
 * gRPC < 1.4.0, 在解析畸形 HTTP/2 帧时的堆溢出.
 *
 * 漏洞机制:
 *   gRPC 的 HPACK 头部压缩解码器中, 动态表大小更新处理有误.
 *   攻击者发送恶意 HTTP/2 HEADERS 帧, 其中 HPACK 动态表大小字段
 *   可触发整数下溢, 导致大额 memmove 写入堆缓冲区.
 *
 * 本文件简化: HTTP/2 帧解析中的长度字段验证不足.
 *
 * 影响: 远程 DoS 和潜在的 RCE (gRPC 服务通常暴露于网络).
 * 修复: gRPC 1.4.0 — 添加帧长度范围验证.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* 模拟 HTTP/2 帧 */
typedef struct {
    uint32_t length;           /* 帧负载长度 (24-bit, 攻击者可控) */
    uint8_t  type;             /* 帧类型 */
    uint8_t  flags;
    uint32_t stream_id;
    uint8_t  *payload;
} Http2Frame;

/*
 * 漏洞函数: 解析 HPACK 头部压缩的帧
 * 分配缓冲区后, 将帧负载拷贝到其中.
 * 但是帧 length 字段可能被篡改, 实际读取的数据远超 length.
 */
uint8_t *parse_grpc_frame(const uint8_t *raw_data, size_t raw_len) {
    if (raw_len < 9) return NULL; /* 帧头9字节 */

    /* 解析帧头 */
    uint32_t frame_len = ((uint32_t)raw_data[0] << 16) |
                          ((uint32_t)raw_data[1] << 8)  |
                           (uint32_t)raw_data[2];
    uint8_t frame_type = raw_data[3];

    if (frame_type != 0x01) return NULL; /* 非 HEADERS 帧 */

    /*
     * 漏洞: 分配 frame_len 字节的缓冲区.
     *       但如果 raw_data 中后续还有更多数据
     *       (如 CONTINUATION 帧拼接的头部),
     *       memcpy 可能拷贝超过 frame_len 的数据.
     *
     * 实际漏洞在 grpc_chttp2_hpack_parser 中,
     * 动态表大小字段的整数下溢导致 memmove 大小膨胀.
     */
    uint8_t *decoded = (uint8_t *)malloc(frame_len + 256);
    if (!decoded) return NULL;

    /*
     * 模拟 HPACK 解码中的整数下溢:
     *   new_table_size = old_size + delta (delta可为负)
     *   若 new_table_size < 0 (unsigned下溢), 则为巨大值
     *   → memmove 使用此巨大值 → 缓冲区溢出
     */
    int32_t delta = -1; /* 攻击者控制的HPACK动态表更新 */
    uint32_t old_size = 0;
    uint32_t new_size = old_size + delta; /* 整数下溢: 0-1 = 0xFFFFFFFF */

    if (new_size > frame_len + 256) {
        printf("  [!] HPACK table size underflow: new_size=0x%X\n", new_size);
        /* 原始代码: memmove(decoded, src, new_size) → 拷贝4GB → 溢出 */
    }

    /* 正常路径: 拷贝帧负载 */
    size_t copy_bytes = raw_len - 9;
    if (copy_bytes > frame_len + 256) {
        printf("  [!] copy_bytes(%zu) > alloc(%u)\n", copy_bytes, frame_len + 256);
    }
    memcpy(decoded, raw_data + 9, copy_bytes);
    return decoded;
}

int main(void) {
    /* 构造恶意 HTTP/2 帧: frame_len=16, 但后续有大量CONTINUATION数据 */
    uint8_t evil_frame[1024];
    memset(evil_frame, 0, sizeof(evil_frame));
    evil_frame[0] = 0x00;
    evil_frame[1] = 0x00;
    evil_frame[2] = 0x10;  /* frame_len = 16 */
    evil_frame[3] = 0x01;  /* HEADERS */
    memset(evil_frame + 9, 'X', 1015);

    printf("[*] Google gRPC HPACK overflow test (CVE-2017-9431)\n");
    uint8_t *result = parse_grpc_frame(evil_frame, sizeof(evil_frame));
    if (result) {
        printf("[!] Frame parsed (potential overflow)\n");
        free(result);
    }
    return 0;
}
