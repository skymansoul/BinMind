/*
 * CVE-2016-2177 — OpenSSL 整数溢出→堆溢出 (CWE-190→CWE-122)
 *
 * OpenSSL 1.0.1/1.0.2: ssl3_read_bytes 中的整数有符号/无符号转换 bug
 * 导致超出预期大小的堆分配, 但后续 memcpy 以原始预期大小为目标,
 * 拷入的却是完整数据 — 堆越界写.
 *
 * 模式: 整数溢出导致分配不足, 后续堆写入溢出 → 堆损坏
 *
 * CVSS: 7.5 (High), CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int process_record(int32_t record_len, const unsigned char *data) {
    /* [VULN] record_len 是攻击者可控的 int32_t,
     * 若为负值, (size_t) 转换变为巨大的无符号值,
     * 但后续检查可能只针对正值
     */
    if (record_len <= 0 || record_len > 16384) {
        return -1; /* 仅检查正值范围 */
    }

    /* record_len 现在是正数, 但向下还有转换问题 */
    size_t alloc_sz = (size_t)record_len + 256;
    unsigned char *buf = (unsigned char *)malloc(alloc_sz);
    if (!buf) return -2;

    /* [VULN] record_len 是正数但 memcpy 使用相同值,
     * 攻击者可能利用 record_len + 256 计算溢出的边缘情况
     * 如 record_len = 0xFFFFFF00 → (size_t) + 256 回绕为 0
     */
    memcpy(buf + 64, data, (size_t)record_len);
    buf[(size_t)record_len + 64] = '\0';

    /* ... use buf ... */
    free(buf);
    return 0;
}

int main(void) {
    unsigned char payload[20000];
    memset(payload, 'X', sizeof(payload));
    return process_record(16384, payload);
}
