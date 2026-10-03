#!/usr/bin/env python3
"""
ASIP堆溢出CVE样本集(A组) — 基础漏洞+守卫安全+分配器安全(1-30).
"""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

# 样本定义: (name, source_code, expected_label)

BASIC_VULN = [
    ('cve_01', """
int main() {
    char *buf = malloc(32);
    memcpy(buf, src, 64);
    return 0;
}
""", 'VULN'),

    ('cve_02', """
int main(int argc, char **argv) {
    char *buf = malloc(64);
    for (int i = 0; i < 128; i++) {
        buf[i] = argv[1][i];
    }
    return 0;
}
""", 'VULN'),

    ('cve_03', """
int main() {
    char *buf = malloc(16);
    strcpy(buf, "this string is way too long for 16 bytes");
    return 0;
}
""", 'VULN'),

    ('cve_04', """
int main() {
    char *p = malloc(64);
    p[64] = 0;
    return 0;
}
""", 'VULN'),

    ('cve_05', """
int main() {
    char *buf = malloc(32);
    memcpy(buf + 16, src, 32);
    return 0;
}
""", 'VULN'),

    ('cve_06', """
int main(int n) {
    if (n > 128) n = 128;
    char *buf = malloc(64);
    memcpy(buf, src, n);
    return 0;
}
""", 'VULN'),

    ('cve_07', """
int main() {
    char *buf = malloc(64);
    snprintf(buf, 128, "overflow format %s", long_str);
    return 0;
}
""", 'VULN'),

    ('cve_08', """
int main() {
    char *buf = malloc(32);
    strncpy(buf, src, 64);
    return 0;
}
""", 'VULN'),

    ('cve_09', """
int main(int n) {
    char *buf = malloc(n);
    memcpy(buf, src, n * 2);
    return 0;
}
""", 'VULN'),

    ('cve_10', """
int main() {
    char *buf = malloc(8);
    *(int *)(buf + 4) = 0x41414141;
    *(int *)(buf + 8) = 0x42424242;
    return 0;
}
""", 'VULN'),
]

GUARD_SAFE = [
    ('cve_11', """
int main(int n) {
    if (n > 64) return;
    char *buf = malloc(64);
    memcpy(buf, src, n);
    return 0;
}
""", 'SAFE'),

    ('cve_12', """
int main(int n) {
    if (n <= 0 || n > 128) return;
    char *buf = malloc(128);
    memcpy(buf, src, n);
    return 0;
}
""", 'SAFE'),

    ('cve_13', """
int main() {
    int n = get_size();
    if (n > 256) n = 256;
    char *buf = malloc(256);
    memcpy(buf, src, n);
    return 0;
}
""", 'SAFE'),

    ('cve_14', """
int main(int n) {
    if (n > 1024) return -1;
    char *buf = malloc(1024);
    for (int i = 0; i < n; i++) {
        buf[i] = src[i];
    }
    return 0;
}
""", 'SAFE'),

    ('cve_15', """
int main(int n) {
    int sz = n + 8;
    if (sz > 256) return;
    char *buf = malloc(256);
    memcpy(buf, src, sz);
    return 0;
}
""", 'SAFE'),

    ('cve_16', """
int main(int n) {
    if (n < 0 || n > 64) exit(1);
    char *buf = malloc(64);
    memcpy(buf, src, n);
    return 0;
}
""", 'SAFE'),

    ('cve_17', """
int main(int n) {
    if (n > 64) n = 64;
    char *buf = malloc(64);
    memcpy(buf, src, n);
    return 0;
}
""", 'SAFE'),

    ('cve_18', """
int main(int n) {
    int alloc_n = n;
    if (alloc_n > 128) alloc_n = 128;
    char *buf = malloc(alloc_n);
    memcpy(buf, src, alloc_n);
    return 0;
}
""", 'SAFE'),

    ('cve_19', """
int main() {
    char *buf = malloc(32);
    int off = 24;
    if (off + 8 <= 32) {
        memcpy(buf + off, src, 8);
    }
    return 0;
}
""", 'SAFE'),

    ('cve_20', """
int main(int n) {
    if (n > 100) n = 100;
    char *buf = malloc(100);
    for (int i = 0; i < n; i++) {
        buf[i] = 0;
    }
    return 0;
}
""", 'SAFE'),
]

ALLOCATOR_SAFE = [
    ('cve_21', """
int main() {
    char *buf = malloc(17);
    *(int *)(buf + 16) = 0;
    return 0;
}
""", 'VULN'),

    ('cve_22', """
int main() {
    char *buf = malloc(32);
    memcpy(buf, src, 24);
    buf[24] = 0;
    return 0;
}
""", 'SAFE'),

    ('cve_23', """
int main() {
    char *buf = malloc(64);
    buf = realloc(buf, 128);
    memcpy(buf, src, 96);
    return 0;
}
""", 'SAFE'),

    ('cve_24', """
int main() {
    char *buf = malloc(63);
    memcpy(buf, src, 56);
    return 0;
}
""", 'SAFE'),

    ('cve_25', """
int main() {
    struct S { char data[32]; int count; };
    struct S *s = malloc(sizeof(struct S));
    s->count = 0;
    memcpy(s->data, src, 32);
    return 0;
}
""", 'SAFE'),

    ('cve_26', """
int main() {
    char *buf = malloc(8);
    *(int *)buf = 0x41414141;
    return 0;
}
""", 'SAFE'),

    ('cve_27', """
int main() {
    char *buf = malloc(1);
    memcpy(buf, src, 16);
    return 0;
}
""", 'VULN'),

    ('cve_28', """
int main() {
    char *buf = calloc(1, 64);
    memcpy(buf, src, 32);
    return 0;
}
""", 'SAFE'),

    ('cve_29', """
int main() {
    char *buf = malloc(128);
    memcpy(buf, src, 64);
    memcpy(buf + 64, src, 64);
    return 0;
}
""", 'SAFE'),

    ('cve_30', """
int main() {
    char *buf = malloc(32);
    memset(buf, 0, 32);
    return 0;
}
""", 'SAFE'),
]

__all__ = ['BASIC_VULN', 'GUARD_SAFE', 'ALLOCATOR_SAFE']
