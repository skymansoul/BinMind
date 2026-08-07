#!/usr/bin/env python3
"""
ASIP堆溢出CVE样本集 (B) — REAL_CVE + ASIP_CHALLENGE.
拆自 asip_cve_samples.py，保持样本定义不变。
"""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

# 样本定义: (name, source_code, expected_label)
#   expected_label: 'VULN' = 真实漏洞, 'SAFE' = 安全

REAL_CVE = [
    ('cve_31', """
/* CVE-2021-3156: off-by-one in sudo heap */
int main() {
    char *buf = malloc(64);
    char *args = get_user_input();
    memcpy(buf, args, 64);
    buf[64] = '\\0';
    return 0;
}
""", 'VULN'),

    ('cve_32', """
/* CVE-2022-26920: heap overflow in LDAP */
int main(int n) {
    char *buf = malloc(64);
    if (n > 64) n = 64;
    memcpy(buf, src, n);
    return 0;
}
""", 'SAFE'),

    ('cve_33', """
/* CVE-2020-1971: OpenSSL ASN.1 */
int main(int len) {
    char *p = malloc(256);
    if (len > 256) return -1;
    memcpy(p, data, len);
    return 0;
}
""", 'SAFE'),

    ('cve_34', """
/* CVE-2021-4034: Pkexec env overflow */
int main(int argc, char **argv) {
    char *buf = malloc(argc * 8);
    for (int i = 0; i < argc; i++) {
        memcpy(buf + i * 16, argv[i], 16);
    }
    return 0;
}
""", 'VULN'),

    ('cve_35', """
/* CVE-2023-38408: OpenSSH */
int main(int n) {
    if (n < 0) return -1;
    if (n > 4096) return -1;
    char *buf = malloc(4096);
    memcpy(buf, src, n);
    return 0;
}
""", 'SAFE'),

    ('cve_36', """
/* Real: overflow in network parser */
int main(int pkt_len) {
    if (pkt_len < 10) return -1;
    char *hdr = malloc(pkt_len);
    memcpy(hdr, pkt, pkt_len);
    return 0;
}
""", 'SAFE'),

    ('cve_37', """
/* Real: double-copy overflow */
int main() {
    char *buf = malloc(32);
    memcpy(buf, src1, 24);
    memcpy(buf + 24, src2, 16);
    return 0;
}
""", 'VULN'),

    ('cve_38', """
/* Real: struct field access safe */
int main() {
    struct Header { int type; int len; char data[]; };
    struct Header *h = malloc(sizeof(struct Header) + 64);
    h->len = 32;
    memcpy(h->data, src, 32);
    return 0;
}
""", 'SAFE'),

    ('cve_39', """
/* Real: conditional alloc with bound check */
int main(int n) {
    if (n > 0 && n <= 1024) {
        char *buf = malloc(n);
        memcpy(buf, src, n);
    }
    return 0;
}
""", 'SAFE'),

    ('cve_40', """
/* Real: overflow via tainted index */
int main(int idx) {
    char *buf = malloc(64);
    if (idx >= 0 && idx < 64) {
        buf[idx] = 0;
    }
    return 0;
}
""", 'SAFE'),
]

# ASIP挑战样本: 专门针对三个误报根因设计
ASIP_CHALLENGE = [
    # 间接guard保护: 编译器用栈变量中转cmp
    ('cve_41', """
int main(int n) {
    int saved = n;
    if (saved > 64) return -1;
    char *buf = malloc(64);
    memcpy(buf, src, saved);
    return 0;
}
""", 'SAFE'),

    ('cve_42', """
int main(int n) {
    int limit = n;
    if (limit > 128) limit = 128;
    char *buf = malloc(128);
    for (int i = 0; i < limit; i++) {
        buf[i] = src[i];
    }
    return 0;
}
""", 'SAFE'),

    # 条件赋值+路径受限: widen过激进误判
    ('cve_43', """
int main(int n) {
    int sz;
    if (n > 0 && n <= 256) {
        sz = n;
    } else {
        sz = 64;
    }
    char *buf = malloc(256);
    memcpy(buf, src, sz);
    return 0;
}
""", 'SAFE'),

    ('cve_44', """
int main(int mode, int n) {
    int sz;
    if (mode == 1) {
        sz = 32;
    } else {
        sz = n;
        if (sz > 64) sz = 64;
    }
    char *buf = malloc(64);
    memcpy(buf, src, sz);
    return 0;
}
""", 'SAFE'),

    ('cve_45', """
int main(int n) {
    if (n > 100) return -1;
    int sz = n + 8;
    if (sz > 108) sz = 108;
    char *buf = malloc(108);
    memcpy(buf, src, sz);
    return 0;
}
""", 'SAFE'),

    # 不同缓冲区: alloc-write误配对
    ('cve_46', """
int main() {
    char *buf1 = malloc(32);
    char *buf2 = malloc(128);
    memcpy(buf2, src, 64);
    return 0;
}
""", 'SAFE'),

    ('cve_47', """
int main() {
    char *small = malloc(16);
    char *large = malloc(256);
    memcpy(large, src, 200);
    return 0;
}
""", 'SAFE'),

    ('cve_48', """
int main() {
    char *config = malloc(64);
    char *data = malloc(1024);
    memcpy(data, src, 512);
    return 0;
}
""", 'SAFE'),

    ('cve_49', """
int main(int n) {
    if (n > 32) return -1;
    char *tmp = malloc(32);
    char *result = malloc(256);
    memcpy(result, src, n);
    return 0;
}
""", 'SAFE'),

    # 真实VULN: ASIP不得过滤
    ('cve_50', """
int main(int n) {
    int sz = n;
    if (sz < 0) sz = 0;
    char *buf = malloc(sz);
    memcpy(buf, src, n);
    return 0;
}
""", 'VULN'),

    ('cve_51', """
int main() {
    struct Small { int x; int y; };
    struct Small *s = malloc(sizeof(struct Small));
    memcpy(s, data, 32);
    return 0;
}
""", 'VULN'),

    ('cve_52', """
int main() {
    typedef struct { char buf[16]; } Header;
    Header *h = (Header *)malloc(32);
    memcpy(h->buf, src, 64);
    return 0;
}
""", 'VULN'),

    ('cve_53', """
int fill_buf(char *out, int n) {
    if (n > 64) n = 64;
    memcpy(out, src, n);
    return n;
}
int main() {
    char *buf = malloc(32);
    fill_buf(buf, 128);
    return 0;
}
""", 'VULN'),

    ('cve_54', """
int main(int n) {
    char *buf = malloc(32);
    if (n > 0) {
        memcpy(buf, src, n);
    }
    return 0;
}
""", 'VULN'),

    ('cve_55', """
int main(int n) {
    if (n > 1000) n = 1000;
    char *buf = malloc(64);
    for (int i = 0; i < n; i++) {
        buf[i % 64] = src[i];
    }
    return 0;
}
""", 'SAFE'),
]

__all__ = ['REAL_CVE', 'ASIP_CHALLENGE']
