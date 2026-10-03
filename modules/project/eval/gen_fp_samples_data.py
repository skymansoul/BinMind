# FP-Reduction 基准样本数据表: 25 个样本的源码与元数据定义
# 每个条目: {cve, vtype, sev, desc, pattern, trigger, fp_note, expected, src}
# 样本语义: fp_heapXX 复刻真实 CVE 溢出模式; fp_safeXX 为通用工具
#   必报而实际安全的写法 (同源耦合/钳位/柔性数组/分配器对齐等)
HEAP_COMMON = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
"""

SAFE_COMMON = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
"""

SAMPLES = {
    "fp_heap01": dict(
        cve="CVE-2017-1000251", vtype="heap_overflow", sev="HIGH",
        desc="BlueZ hci_uart: 从输入解析长度, 未校验即用于 memcpy 写入固定 256B 缓冲区",
        pattern="unchecked_input_length",
        trigger="默认 len=0x400 直接溢出 256B 缓冲; 亦可传参控制长度",
        fp_note="长度受输入控制 → 通用工具将其视为任意大, 必然报警; "
                "但检测器需证明写入量确实可能超过分配量",
        expected="预期检出: 分配=const(256), 写入=输入链, 链不同 → 保留发现",
        src=HEAP_COMMON + """int main(int argc, char **argv) {
    unsigned int len = 0x400;
    if (argc > 1) len = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    static char src[1024];
    memset(src, 'B', sizeof(src));
    memcpy(buf, src, len);
    printf("%c\\n", buf[0]);
    free(buf);
    return 0;
}
"""),
    "fp_heap02": dict(
        cve="CVE-2018-6789", vtype="heap_overflow", sev="HIGH",
        desc="Exim base64 解码: 输出缓冲按输入长度分配, 实际写出量超过分配量",
        pattern="decode_undercount",
        trigger="固定输入 24 字符 → 解码写出 32 字节 > 24B 分配",
        fp_note="循环内多次写入同一缓冲, 总写入量需按迭代次数×每轮写入量计算",
        expected="预期检出: 24 轮 × 2B > 24B 分配 → DEFINITE_OVERFLOW",
        src=HEAP_COMMON + """int main(int argc, char **argv) {
    static const char b64in[] = "QUJDREVGR0hJSktMTU5PUFFSU1RVVg==";
    size_t inlen = strlen(b64in);
    unsigned char *out = (unsigned char *)malloc(inlen);
    if (!out) return 1;
    size_t w = 0;
    for (size_t i = 0; i < inlen; i++) {
        out[w++] = (unsigned char)b64in[i];
        if (i % 3 == 2) out[w++] = 0x00;
    }
    printf("%zu\\n", w);
    free(out);
    return 0;
}
"""),
    "fp_heap03": dict(
        cve="CVE-2021-26708", vtype="heap_overflow", sev="CRITICAL",
        desc="Linux vsock: 数据包长度直接用于 memcpy 到固定小缓冲, 无长度校验",
        pattern="packet_len_unchecked",
        trigger="默认 payload=0x1000 写入 64B 缓冲",
        fp_note="分配量为常数, 写入量为输入链 → 值域可证明溢出",
        expected="预期检出: const(64) vs 输入链 → DEFINITE_OVERFLOW",
        src=HEAP_COMMON + """int main(int argc, char **argv) {
    unsigned int payload = 0x1000;
    if (argc > 1) payload = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(64);
    char *src = (char *)malloc(payload);
    if (!buf || !src) return 1;
    memset(src, 'C', payload);
    memcpy(buf, src, payload);
    printf("%c\\n", buf[0]);
    free(buf); free(src);
    return 0;
}
"""),
    "fp_heap04": dict(
        cve="CVE-2014-0160", vtype="heap_overflow", sev="CRITICAL",
        desc="Heartbleed 模式: 声称长度+1 的写入越过 hdr+payload 分配边界",
        pattern="claimed_len_overflow",
        trigger="默认 payload=0x800: 写入 payload+1 > 分配 hdr+payload",
        fp_note="分配=链+16, 写入=链+1, 指针偏移16 → 16+1>16 证明溢出; "
                "此样本验证耦合判定不会被同链误导",
        expected="预期检出: 同链但偏移不满足 write_le_alloc → 保留发现",
        src=HEAP_COMMON + """int main(int argc, char **argv) {
    unsigned int payload = 0x800;
    if (argc > 1) payload = (unsigned int)atoi(argv[1]);
    unsigned int hdr = 16;
    char *pkt = (char *)malloc(hdr + payload);
    char *pls = (char *)malloc(payload);
    if (!pkt || !pls) return 1;
    memset(pls, 'D', payload);
    memcpy(pkt + hdr, pls, payload + 1);
    printf("%c\\n", pkt[0]);
    free(pkt); free(pls);
    return 0;
}
"""),
    "fp_heap05": dict(
        cve="CVE-2018-4407", vtype="heap_overflow", sev="HIGH",
        desc="Apple 网络栈: 循环将 0x100 字节写入 0x40 字节分配",
        pattern="loop_overrun",
        trigger="默认循环 256 轮写入 64B 缓冲",
        fp_note="循环写入需迭代次数精确化, 保守估计器在此同样检出",
        expected="预期检出: 256 轮 × 1B > 64B → DEFINITE_OVERFLOW",
        src=HEAP_COMMON + """int main(int argc, char **argv) {
    char *buf = (char *)malloc(0x40);
    if (!buf) return 1;
    for (int i = 0; i < 0x100; i++) buf[i] = (char)i;
    printf("%c\\n", buf[0]);
    free(buf);
    return 0;
}
"""),
    "fp_heap06": dict(
        cve="CVE-2021-3712", vtype="heap_overflow", sev="HIGH",
        desc="OpenSSL ASN.1: 长度算术差一, memcpy 写入 n+1 到 n 字节分配",
        pattern="len_arithmetic_offbyone",
        trigger="默认 n=0x100: 写入 n+1 > n",
        fp_note="同链偏移比较: 写入=链+1, 分配=链+0 → 偏移不满足 → 保留",
        expected="预期检出: 同链但 write(0)+ptr(0) ≤ alloc(0) 不成立 → 保留发现",
        src=HEAP_COMMON + """int main(int argc, char **argv) {
    unsigned int n = 0x100;
    if (argc > 1) n = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(n);
    char *src = (char *)malloc(n);
    if (!buf || !src) return 1;
    memset(src, 'E', n);
    memcpy(buf, src, n + 1);
    printf("%c\\n", buf[0]);
    free(buf); free(src);
    return 0;
}
"""),
    "fp_heap07": dict(
        cve="CVE-2018-14618", vtype="heap_overflow", sev="CRITICAL",
        desc="curl: 32 位整数乘法回绕使分配极小, 64 位乘法写入巨大",
        pattern="int_overflow_alloc",
        trigger="默认 n=0x40000000: n*4 回绕为 0, 写入 4GiB",
        fp_note="32 位乘法结果 identity 必须退化 (宽度截断), 防止误耦合为安全",
        expected="预期检出: 分配 identity 未知 → 耦合不成立 → 保留发现",
        src=HEAP_COMMON + """int main(int argc, char **argv) {
    unsigned int n = 0x40000000;
    if (argc > 1) n = (unsigned int)atoi(argv[1]);
    unsigned int alloc_size = n * 4;
    char *buf = (char *)malloc(alloc_size);
    if (!buf) return 1;
    memset(buf, 'F', (size_t)n * 4);
    printf("%c\\n", buf[0]);
    free(buf);
    return 0;
}
"""),
    "fp_heap08": dict(
        cve="CVE-2020-14364", vtype="heap_overflow", sev="HIGH",
        desc="QEMU usb: 分配 len-1 而写入 len, 越界 1 字节",
        pattern="alloc_offbyone",
        trigger="默认 len=0x100: 写入 0x100 到 0xFF 分配",
        fp_note="同链偏移: 分配=链-1, 写入=链+0 → 偏移不满足 → 保留",
        expected="预期检出: write(0) ≤ alloc(-1) 不成立 → 保留发现",
        src=HEAP_COMMON + """int main(int argc, char **argv) {
    unsigned int len = 0x100;
    if (argc > 1) len = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(len - 1);
    char *src = (char *)malloc(len);
    if (!buf || !src) return 1;
    memset(src, 'G', len);
    memcpy(buf, src, len);
    printf("%c\\n", buf[0]);
    free(buf); free(src);
    return 0;
}
"""),
    "fp_heap09": dict(
        cve="CVE-2015-0235", vtype="heap_overflow", sev="CRITICAL",
        desc="GHOST: 无界字符串复制到 1024B 堆缓冲",
        pattern="unbounded_strcpy",
        trigger="默认 2048 字符超长字符串 → strcpy 溢出",
        fp_note="strcpy 无长度参数, 字符串复制大小由内容决定, 保守报告",
        expected="预期检出: strcpy 保守路径 → 发现",
        src=HEAP_COMMON + """int main(int argc, char **argv) {
    char *buf = (char *)malloc(1024);
    if (!buf) return 1;
    char *name = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    if (argc > 1) name = argv[1];
    strcpy(buf, name);
    printf("%c\\n", buf[0]);
    free(buf);
    return 0;
}
"""),
    "fp_heap10": dict(
        cve="CVE-2018-6543", vtype="heap_overflow", sev="HIGH",
        desc="gif2png: 文件头部声明的长度直接用于 memcpy 到 64B 缓冲",
        pattern="file_len_unchecked",
        trigger="默认 fsize=0x1000 写入 64B 分配",
        fp_note="大小来自文件/输入 → 与分配量链不同 → 保留",
        expected="预期检出: const(64) vs 输入链 → 保留发现",
        src=HEAP_COMMON + """int main(int argc, char **argv) {
    static char fdata[0x1000];
    memset(fdata, 'H', sizeof(fdata));
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    size_t fsize = 0x1000;
    if (argc > 1) fsize = (size_t)atoi(argv[1]);
    memcpy(buf, fdata, fsize);
    printf("%c\\n", buf[0]);
    free(buf);
    return 0;
}
"""),
    "fp_heap11": dict(
        cve="CVE-2021-3156", vtype="heap_overflow", sev="CRITICAL",
        desc="sudo: argv 展开循环将 0x200 字节写入 256B 分配",
        pattern="loop_expansion_overrun",
        trigger="默认 count=0x200 → 512B 写入 256B 分配",
        fp_note="循环写入: 迭代数=输入链, 与分配 const(256) 不同链 → 保留",
        expected="预期检出: 循环 512 轮 > 256B → 保留发现",
        src=HEAP_COMMON + """int main(int argc, char **argv) {
    unsigned int count = 0x200;
    if (argc > 1) count = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    for (unsigned int i = 0; i < count; i++) buf[i] = (char)(i + 1);
    printf("%c\\n", buf[0]);
    free(buf);
    return 0;
}
"""),
    "fp_heap12": dict(
        cve="CVE-2019-13117", vtype="heap_overflow", sev="HIGH",
        desc="libxslt: 非严格上界循环 i<=n 写入 n+1 个 int 到 n 个 int 分配",
        pattern="nonstrict_loop_offbyone",
        trigger="默认 n=0x10: 17 个 int 写入 16 个 int 分配",
        fp_note="非严格上界 (i<=n) 的迭代数=bound+1, 循环耦合拒绝该形式 → 保留",
        expected="预期检出: 非严格循环 + 输入链 → 保留发现",
        src=HEAP_COMMON + """int main(int argc, char **argv) {
    unsigned int n = 0x10;
    if (argc > 1) n = (unsigned int)atoi(argv[1]);
    int *buf = (int *)malloc(sizeof(int) * n);
    if (!buf) return 1;
    for (unsigned int i = 0; i <= n; i++) buf[i] = (int)i;
    printf("%d\\n", buf[0]);
    free(buf);
    return 0;
}
"""),
    "fp_heap13": dict(
        cve="CVE-2020-16040", vtype="heap_overflow", sev="HIGH",
        desc="Chrome V8: 步进循环 (i+=4) 的写入扩展越过 0x20 分配",
        pattern="strided_loop_overrun",
        trigger="默认 idx=0x40: 扩展 (0x40-4)+1 > 0x20",
        fp_note="步进循环需偏移扩展模型: (trips-1)*step+1 > alloc → 检出",
        expected="预期检出: extent 模型 → 保留发现",
        src=HEAP_COMMON + """int main(int argc, char **argv) {
    unsigned int idx = 0x40;
    if (argc > 1) idx = (unsigned int)atoi(argv[1]);
    unsigned int cap = 0x20;
    unsigned char *buf = (unsigned char *)malloc(cap);
    if (!buf) return 1;
    for (unsigned int i = 0; i < idx; i += 4) buf[i] = 1;
    printf("%d\\n", buf[0]);
    free(buf);
    return 0;
}
"""),
    "fp_heap14": dict(
        cve="CVE-2018-17456", vtype="heap_overflow", sev="HIGH",
        desc="Git: 网络包长度未校验, memcpy 到固定 0x1000 行缓冲",
        pattern="net_len_unchecked",
        trigger="默认 pktlen=0x2000 写入 0x1000 分配",
        fp_note="写入量=输入链, 分配=const(0x1000) → 保留",
        expected="预期检出: const(0x1000) vs 输入链 → 保留发现",
        src=HEAP_COMMON + """int main(int argc, char **argv) {
    unsigned int pktlen = 0x2000;
    if (argc > 1) pktlen = (unsigned int)atoi(argv[1]);
    char *line = (char *)malloc(0x1000);
    char *recv_buf = (char *)malloc(pktlen);
    if (!line || !recv_buf) return 1;
    memset(recv_buf, 'J', pktlen);
    memcpy(line, recv_buf, pktlen);
    printf("%c\\n", line[0]);
    free(line); free(recv_buf);
    return 0;
}
"""),
    "fp_heap15": dict(
        cve="CVE-2015-0240", vtype="heap_overflow", sev="CRITICAL",
        desc="Samba: 可变长度输入 memcpy 到固定 0x400 缓冲",
        pattern="var_len_to_fixed_buf",
        trigger="默认 len=0x1000 写入 0x400 分配",
        fp_note="写入量=输入链, 分配=const(0x400) → 保留",
        expected="预期检出: const(0x400) vs 输入链 → 保留发现",
        src=HEAP_COMMON + """int main(int argc, char **argv) {
    unsigned int len = 0x1000;
    if (argc > 1) len = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(0x400);
    char *data = (char *)malloc(len);
    if (!buf || !data) return 1;
    memset(data, 'K', len);
    memcpy(buf, data, len);
    printf("%c\\n", buf[0]);
    free(buf); free(data);
    return 0;
}
"""),
# 安全样本 (10, 误报陷阱)
    "fp_safe01": dict(
        cve="无 (同源耦合 idiom)", vtype="safe", sev="NONE",
        desc="分配-写入同源耦合: malloc(n); memcpy(p, src, n), n 受输入控制",
        pattern="size_coupling",
        trigger="任意参数: 写入量恒等于分配量, 运行时永不溢出",
        fp_note="通用工具将 n 视为任意大 → 误报. 值流耦合证明 write≤alloc",
        expected="预期: 0 发现 (L4 值流耦合撤销)",
        src=SAFE_COMMON + """int main(int argc, char **argv) {
    unsigned int n = 0x40;
    if (argc > 1) n = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(n);
    char *src = (char *)malloc(n);
    if (!buf || !src) return 1;
    memset(src, 'a', n);
    memcpy(buf, src, n);
    printf("%c\\n", buf[0]);
    free(buf); free(src);
    return 0;
}
"""),
    "fp_safe02": dict(
        cve="无 (同源耦合循环)", vtype="safe", sev="NONE",
        desc="循环耦合: malloc(n); for(i=0;i<n;i++) buf[i]=c",
        pattern="loop_coupling",
        trigger="任意参数: 总写入 n 字节 = 分配 n 字节",
        fp_note="循环边界与分配同源, 严格上界逐字节写入 → 安全",
        expected="预期: 0 发现 (L6 循环耦合撤销)",
        src=SAFE_COMMON + """int main(int argc, char **argv) {
    unsigned int n = 0x40;
    if (argc > 1) n = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(n);
    if (!buf) return 1;
    for (unsigned int i = 0; i < n; i++) buf[i] = 'b';
    printf("%c\\n", buf[0]);
    free(buf);
    return 0;
}
"""),
    "fp_safe03": dict(
        cve="无 (受界复制)", vtype="safe", sev="NONE",
        desc="strncpy 以分配量 n 为上限复制",
        pattern="bounded_strncpy",
        trigger="任意参数: 写入 ≤ n",
        fp_note="strncpy 大小参数与分配同源 → 安全",
        expected="预期: 0 发现 (L4 值流耦合撤销)",
        src=SAFE_COMMON + """int main(int argc, char **argv) {
    unsigned int n = 0x40;
    if (argc > 1) n = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(n);
    char *src = (char *)malloc(n);
    if (!buf || !src) return 1;
    memset(src, 'c', n);
    strncpy(buf, src, n);
    printf("%c\\n", buf[0]);
    free(buf); free(src);
    return 0;
}
"""),
    "fp_safe04": dict(
        cve="无 (钳位保护)", vtype="safe", sev="NONE",
        desc="输入长度经钳位 (min(n,128)) 后写入 128B 分配",
        pattern="clamped_input",
        trigger="任意参数: 写入 ≤ 128 = 分配",
        fp_note="钳位路径 identity 收敛为 const(128) → 耦合证明安全",
        expected="预期: 0 发现 (L4 值流耦合撤销)",
        src=SAFE_COMMON + """int main(int argc, char **argv) {
    unsigned int n = 0x40;
    if (argc > 1) n = (unsigned int)atoi(argv[1]);
    if (n > 128) n = 128;
    char *buf = (char *)malloc(128);
    char *src = (char *)malloc(128);
    if (!buf || !src) return 1;
    memset(src, 'd', 128);
    memcpy(buf, src, n);
    printf("%c\\n", buf[0]);
    free(buf); free(src);
    return 0;
}
"""),
    "fp_safe05": dict(
        cve="无 (柔性数组)", vtype="safe", sev="NONE",
        desc="结构体柔性数组: malloc(sizeof(Pkt)+len); memcpy(p->data, s, len)",
        pattern="flexible_array",
        trigger="任意参数: 数据区偏移 + len ≤ sizeof+len",
        fp_note="指针偏移补偿: write(0)+ptr_off(4) ≤ alloc(4) → 安全",
        expected="预期: 0 发现 (L4 值流耦合撤销, 偏移感知)",
        src=SAFE_COMMON + """typedef struct {
    unsigned int magic;
    unsigned char data[];
} Pkt;

int main(int argc, char **argv) {
    unsigned int len = 0x40;
    if (argc > 1) len = (unsigned int)atoi(argv[1]);
    Pkt *p = (Pkt *)malloc(sizeof(Pkt) + len);
    char *src = (char *)malloc(len);
    if (!p || !src) return 1;
    memset(src, 'e', len);
    memcpy(p->data, src, len);
    printf("%u\\n", p->magic);
    free(p); free(src);
    return 0;
}
"""),
    "fp_safe06": dict(
        cve="无 (calloc 倍率)", vtype="safe", sev="NONE",
        desc="calloc(n,4) + 循环 n 次写 4B 元素",
        pattern="calloc_scaled_loop",
        trigger="任意参数: 4n 写入 ≤ 4n 分配",
        fp_note="calloc 元素倍率 → 分配 identity scale=4, 循环耦合允许 4B 写入",
        expected="预期: 0 发现 (L6 循环耦合 + scale 感知)",
        src=SAFE_COMMON + """int main(int argc, char **argv) {
    unsigned int n = 0x40;
    if (argc > 1) n = (unsigned int)atoi(argv[1]);
    int *buf = (int *)calloc(n, 4);
    if (!buf) return 1;
    for (unsigned int i = 0; i < n; i++) buf[i] = (int)i;
    printf("%d\\n", buf[0]);
    free(buf);
    return 0;
}
"""),
    "fp_safe07": dict(
        cve="无 (分配器对齐)", vtype="safe", sev="NONE",
        desc="malloc(40) 实际可用 48B (Win堆 16B 对齐), 写入 48B",
        pattern="allocator_alignment",
        trigger="任意参数: 48 ≤ 48 实际可用",
        fp_note="L0 分配器行为修正: 对齐余量消除误报",
        expected="预期: 0 发现 (L0 分配器修正)",
        src=SAFE_COMMON + """int main(int argc, char **argv) {
    char *buf = (char *)malloc(40);
    if (!buf) return 1;
    memset(buf, 'f', 48);
    printf("%c\\n", buf[0]);
    free(buf);
    return 0;
}
"""),
    "fp_safe08": dict(
        cve="无 (早退守卫)", vtype="safe", sev="NONE",
        desc="if (n > 64) return; 早退守卫后 memcpy 到 64B 分配",
        pattern="early_return_guard",
        trigger="任意参数: 到达写入时 n ≤ 64",
        fp_note="前向出口守卫约束 size 上界 → 路径敏感证明安全",
        expected="预期: 0 发现 (L5 路径守卫)",
        src=SAFE_COMMON + """int main(int argc, char **argv) {
    unsigned int n = 0x40;
    if (argc > 1) n = (unsigned int)atoi(argv[1]);
    if (n > 64) return 0;
    char *buf = (char *)malloc(64);
    char *src = (char *)malloc(64);
    if (!buf || !src) return 1;
    memset(src, 'h', 64);
    memcpy(buf, src, n);
    printf("%c\\n", buf[0]);
    free(buf); free(src);
    return 0;
}
"""),
    "fp_safe09": dict(
        cve="无 (realloc 扩容)", vtype="safe", sev="NONE",
        desc="realloc 扩容后按新大小写入",
        pattern="realloc_grow",
        trigger="任意参数: 256 ≤ 256",
        fp_note="realloc 新分配点 size=256, L2 常数比较 → 安全",
        expected="预期: 0 发现 (L2 常数比较)",
        src=SAFE_COMMON + """int main(int argc, char **argv) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    char *nbuf = (char *)realloc(buf, 256);
    if (!nbuf) return 1;
    buf = nbuf;
    static char src[256];
    memset(src, 'i', sizeof(src));
    memcpy(buf, src, 256);
    printf("%c\\n", buf[0]);
    free(buf);
    return 0;
}
"""),
    "fp_safe10": dict(
        cve="无 (有界格式化)", vtype="safe", sev="NONE",
        desc="snprintf 以 128 为上限格式化到 128B 分配",
        pattern="bounded_snprintf",
        trigger="任意参数: 写入 ≤ 127+1 ≤ 128",
        fp_note="snprintf 自带边界 + 常数比较 → 安全",
        expected="预期: 0 发现 (L2/L3)",
        src=SAFE_COMMON + """int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    snprintf(buf, 128, "%s", argc > 1 ? argv[1] : "hi");
    printf("%s\\n", buf);
    free(buf);
    return 0;
}
"""),
}
