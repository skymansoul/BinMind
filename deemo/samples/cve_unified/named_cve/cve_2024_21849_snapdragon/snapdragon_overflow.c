/*
 * CVE-2024-21849 — Qualcomm Snapdragon 固件堆溢出 (简化复现)
 * 虽然原始漏洞在闭源固件中, 但公开的PoC展示了WLAN帧解析中的
 * 典型堆溢出模式: 帧头长度字段未经验证直接用于分配→拷贝.
 *
 * 漏洞机制 (从公开PoC推断):
 *   WLAN管理帧解析器中, 信息元素 (IE) 的长度字段 (8-bit)
 *   用于计算拷贝大小. 如果 IE 长度设为特殊值 (如 0xFF),
 *   而实际帧中数据不足, 拷贝会越界读取帧缓冲区.
 *   随后通过某种机制将这些数据写入到未预分配的堆区域.
 *
 * 本文件简化: WLAN IE 解析的经典 length→alloc→copy 模式.
 *
 * 影响: 固件级 RCE (通过WiFi, 无需认证).
 * 修复: 添加 IE 长度验证和帧总长度一致性检查.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* WLAN 信息元素 (简化) */
typedef struct {
    uint8_t  element_id;  /* IE 类型 */
    uint8_t  length;      /* IE 数据长度 — 攻击者可控 */
    uint8_t  data[255];   /* 最大255字节 */
} WlanIE;

/* WLAN 管理帧 (简化) */
typedef struct {
    uint8_t  frame_type;
    uint16_t total_len;   /* 帧总长度 */
    uint8_t  *payload;    /* 帧负载 (包含多个IE) */
} WlanMgmtFrame;

/*
 * 漏洞函数: 解析信息元素并复制数据
 * IE 的 length 字段用于确定分配大小,
 * 但未验证 IE 是否完整包含在帧负载中.
 */
uint8_t *parse_wlan_ie(const WlanMgmtFrame *frame) {
    if (frame->total_len < 2) return NULL;
    const uint8_t *pos  = frame->payload;
    size_t         left = frame->total_len - 2; /* 减去帧头 */

    while (left >= 2) {
        uint8_t ie_id  = pos[0];
        uint8_t ie_len = pos[1]; /* 攻击者可控! */
        pos += 2;
        left -= 2;

        /*
         * 漏洞: ie_len 可以是 0~255 的任意值.
         *       如果 ie_len > left (帧中剩余数据),
         *       memcpy 会越界读取 frame->payload 之外的内存.
         *
         *       此外, 如果 ie_len 设为特殊值 (0xFF),
         *       后续 malloc(ie_len) 分配255字节,
         *       但实际可能有更多数据被写入.
         */
        if (ie_id == 0xDD) { /* 厂商特定IE — 攻击目标 */
            uint8_t *ie_buf = (uint8_t *)malloc(ie_len + 4);
            if (!ie_buf) return NULL;

            if (ie_len > left) {
                printf("  [!] IE length(%u) > remaining(%zu) — OVERFLOW!\n",
                       ie_len, left);
                /* 原始代码memcpy(ie_buf, pos, ie_len) — 越界读取! */
            }

            /* 正常情况下拷贝 IE 数据 */
            size_t copy = (ie_len <= left) ? ie_len : left;
            memcpy(ie_buf, pos, copy);
            /* 如果 ie_len > left, 拷贝后在 ie_buf 后有垃圾数据 */

            pos += ie_len;
            left -= (ie_len <= left) ? ie_len : left;
            /* 如果 left < ie_len, left 变为负数 (size_t 下溢!) */

            return ie_buf;
        }

        /* 跳过非目标IE */
        pos += ie_len;
        if (ie_len > left) break;
        left -= ie_len;
    }
    return NULL;
}

int main(void) {
    /* 构造恶意 WLAN 帧:
     *   帧负载包含一个厂商特定IE, 其length=0xFF,
     *   但实际帧中数据远不足255字节 */
    uint8_t evil_frame[64];
    memset(evil_frame, 0, sizeof(evil_frame));
    evil_frame[0] = 0xDD; /* 厂商特定 IE */
    evil_frame[1] = 0xFF; /* 声称255字节, 但实际只有62字节可用 */

    WlanMgmtFrame frame = {
        .frame_type = 0x00, /* 管理帧 */
        .total_len = sizeof(evil_frame),
        .payload    = evil_frame,
    };

    printf("[*] Qualcomm Snapdragon WLAN IE overflow (CVE-2024-21849)\n");
    printf("  Frame total_len=%u, IE claims length=0xFF\n", frame.total_len);

    uint8_t *result = parse_wlan_ie(&frame);
    if (result) {
        printf("[!] IE parsed (potential overflow)\n");
        free(result);
    }
    return 0;
}
