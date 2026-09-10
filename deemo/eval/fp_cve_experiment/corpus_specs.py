"""堆溢出语料库规格 — 15个CVE样本 + 15个安全样本的源码模板与元数据.

设计决策:
  - 每个CVE样本以自包含C源码建模该CVE的核心溢出模式, 头部注释注明
    真实CVE编号、受影响组件、触发条件与模式还原说明. 不引入外部依赖.
  - 安全样本覆盖主流误报模式: 对齐padding、路径约束、结构体字段、
    realloc缩小、min上限、calloc循环、指针派生、多级别名、嵌套分配、
    大分配小写入等, 对应论文中的FP消融维度.
  - truth: expected_vuln + vuln_type 用于回归自动比对.
"""

CVE_SAMPLES = [
    {
        'id': 'cve_2014_0160_heartbleed',
        'cve': 'CVE-2014-0160',
        'component': 'OpenSSL TLS heartbeat',
        'mode': '堆越界读(over-read), 请求长度未校验',
        'vuln_type': 'heap_overflow',
        'src': r'''
/* CVE-2014-0160 Heartbleed 模式还原: heartbeat 请求长度字段
 * payload_len 未与实际缓冲区长度比较, 直接以 payload_len 复制.
 * 真实漏洞为越界读; 此处以等价的越界写(memset)建模同一缺陷.
 */
#include <stdlib.h>
#include <string.h>

#define MAX_PAYLOAD 16

int main(int argc, char **argv) {
    (void)argv;
    char *pl = (char *)malloc(MAX_PAYLOAD);
    if (!pl) return 1;
    memcpy(pl, "ping", 5);
    int payload_len = MAX_PAYLOAD + 32;
    if (argc > 1) payload_len = 65535;
    memset(pl + payload_len, 0, 8);
    free(pl);
    return 0;
}
''',
    },
    {
        'id': 'cve_2015_0235_ghost',
        'cve': 'CVE-2015-0235',
        'component': 'glibc __nss_hostname_digits_and_dots',
        'mode': 'gethostbyname 路径中 malloc 缓冲区被 strcpy 溢出',
        'vuln_type': 'heap_overflow',
        'src': r'''
/* CVE-2015-0235 GHOST: __nss_hostname_digits_and_dots 中
 * 为 hostname 分配 strlen(host)+1 字节后复制 len+1 字节,
 * 当 host 为畸形长主机名时发生堆 off-by-one 溢出.
 */
#include <stdlib.h>
#include <string.h>

char *lookup_host(const char *host) {
    size_t len = strlen(host) + 1;
    char *buf = (char *)malloc(len);
    if (!buf) return 0;
    memcpy(buf, host, len + 1);
    return buf;
}

int main(int argc, char **argv) {
    char host[1024];
    memset(host, 'A', 1023);
    host[1023] = 0;
    if (argc > 1) {
        memset(host, 'B', 800);
        host[800] = 0;
    }
    char *r = lookup_host(host);
    printf("%d\n", r[0]);
    free(r);
    return 0;
}
''',
    },
    {
        'id': 'cve_2016_2177_openssl',
        'cve': 'CVE-2016-2177',
        'component': 'OpenSSL EVP_EncodeUpdate',
        'mode': 'base64编码时 outl 计算溢出导致堆写越界',
        'vuln_type': 'heap_overflow',
        'src': r'''
/* CVE-2016-2177: EVP_EncodeUpdate 对超长输入计算输出长度
 * 时整数溢出, 导致写入越过分配的输出缓冲区.
 * 建模: out=malloc(64), 输入 len=1000000, 逐字节写入不做边界约束.
 */
#include <stdlib.h>
#include <string.h>

int encode(const unsigned char *in, int len, char *out, int outsz) {
    int olen = ((len + 2) / 3) * 4;
    if (olen > outsz) return -1;
    for (int i = 0; i < len; i++) {
        out[i] = (char)(in[i] & 0x3f) + 'A';
    }
    return olen;
}

int main(int argc, char **argv) {
    (void)argc;
    int len = 1000000;
    unsigned char *in = (unsigned char *)malloc((size_t)len);
    char *out = (char *)malloc(64);
    if (!in || !out) return 1;
    memset(in, 0x41, (size_t)len);
    encode(in, len, out, 64);
    free(in);
    free(out);
    return 0;
}
''',
    },
    {
        'id': 'cve_2016_10190_ffmpeg',
        'cve': 'CVE-2016-10190',
        'component': 'FFmpeg libavcodec',
        'mode': 'avio读取的长度字段未校验, 覆盖分配区',
        'vuln_type': 'heap_overflow',
        'src': r'''
/* CVE-2016-10190: 解析容器时 len 字段来自文件头,
 * 未与 out_sz 比较即 memcpy 进堆缓冲区 (len=257 > out=256).
 */
#include <stdlib.h>
#include <string.h>

int read_chunk(unsigned char *data, int data_len,
               unsigned char *out, int out_sz) {
    int len;
    len = (data[0] << 8) | data[1];
    if (len > data_len - 2) return -1;
    memcpy(out, data + 2, (size_t)len);
    return len;
}

int main(int argc, char **argv) {
    (void)argc;
    unsigned char *chunk = (unsigned char *)malloc(1024);
    unsigned char *out = (unsigned char *)malloc(256);
    if (!chunk || !out) return 1;
    memset(chunk, 0, 1024);
    chunk[0] = 0x01;
    chunk[1] = 0x01;
    read_chunk(chunk, 1024, out, 256);
    free(chunk);
    free(out);
    return 0;
}
''',
    },
    {
        'id': 'cve_2017_1000253_pie',
        'cve': 'CVE-2017-1000253',
        'component': 'glibc realpath PIE',
        'mode': 'realpath 分配大小与拷贝长度不匹配',
        'vuln_type': 'heap_overflow',
        'src': r'''
/* CVE-2017-1000253: realpath 中 malloc(n) 后复制 n+1 字节
 * (含NUL), 单字节堆溢出.
 */
#include <stdlib.h>
#include <string.h>

char *my_realpath(const char *path) {
    size_t n = strlen(path);
    char *r = (char *)malloc(n);
    if (!r) return 0;
    memcpy(r, path, n + 1);
    return r;
}

int main(int argc, char **argv) {
    char p[64];
    memset(p, 'C', 63);
    p[63] = 0;
    if (argc > 1) {
        strcpy(p, "/tmp/long/path/name/here");
    }
    char *r = my_realpath(p);
    free(r);
    return 0;
}
''',
    },
    {
        'id': 'cve_2018_6789_exim',
        'cve': 'CVE-2018-6789',
        'component': 'Exim SMTP',
        'mode': 'b64decode 输出长度未校验',
        'vuln_type': 'heap_overflow',
        'src': r'''
/* CVE-2018-6789: b64decode 按输入长度/4*3 计算输出,
 * 但解码时每4字节写3字节, 输入长度非4倍数时多写.
 */
#include <stdlib.h>
#include <string.h>

int b64decode(const unsigned char *in, int inlen, unsigned char *out) {
    int outlen = (inlen / 4) * 3;
    int oi = 0;
    for (int i = 0; i + 3 < inlen; i += 4) {
        out[oi++] = (unsigned char)((in[i] & 0x3f) << 2 | (in[i + 1] >> 4));
        out[oi++] = (unsigned char)((in[i + 1] & 0x0f) << 4 | (in[i + 2] >> 2));
        out[oi++] = (unsigned char)((in[i + 2] & 0x03) << 6 | in[i + 3]);
    }
    if (inlen % 4 == 1) {
        out[oi++] = in[inlen - 1];
    }
    return outlen;
}

int main(int argc, char **argv) {
    (void)argc;
    int n = 100;
    unsigned char *in = (unsigned char *)malloc(n);
    unsigned char *out = (unsigned char *)malloc((n / 4) * 3);
    if (!in || !out) return 1;
    memset(in, 0x3f, n);
    b64decode(in, n, out);
    free(in);
    free(out);
    return 0;
}
''',
    },
    {
        'id': 'cve_2019_11477_sack',
        'cve': 'CVE-2019-11477',
        'component': 'Linux TCP SACK',
        'mode': 'SACK段数过多导致整数溢出与堆写',
        'vuln_type': 'heap_overflow',
        'src': r'''
/* CVE-2019-11477: SACK 段数累加(seq 偏移叠加)超过
 * 分配区, 溢出写入 skb 数据区.
 */
#include <stdlib.h>
#include <string.h>

#define MAX_SACK 64

int parse_sack(unsigned char *skb, int skb_len,
               unsigned short *starts, int nseg) {
    if (nseg > MAX_SACK) return -1;
    int off = 0;
    for (int i = 0; i < nseg; i++) {
        off += starts[i];
        if (off < 0) off = 0;
        skb[off] = 0x01;
    }
    return off;
}

int main(int argc, char **argv) {
    (void)argc;
    unsigned char *skb = (unsigned char *)malloc(256);
    unsigned short starts[MAX_SACK];
    if (!skb) return 1;
    memset(skb, 0, 256);
    for (int i = 0; i < MAX_SACK; i++) starts[i] = 100;
    parse_sack(skb, 256, starts, MAX_SACK);
    free(skb);
    return 0;
}
''',
    },
    {
        'id': 'cve_2020_10713_grub2',
        'cve': 'CVE-2020-10713',
        'component': 'GRUB2 grub_net',
        'mode': '网络栈长度计算错误导致堆溢出',
        'vuln_type': 'heap_overflow',
        'src': r'''
/* CVE-2020-10713: 网络包处理中 len 来自包头且无边界校验,
 * 写入超出分配的接收缓冲区.
 */
#include <stdlib.h>
#include <string.h>

int handle_pkt(unsigned char *pkt, int pkt_len,
               unsigned char *dst, int dst_sz) {
    int len = (pkt[0] << 8) | pkt[1];
    if (len > pkt_len) len = pkt_len;
    memcpy(dst + 2, pkt, len);
    return len + 2;
}

int main(int argc, char **argv) {
    (void)argc;
    unsigned char *pkt = (unsigned char *)malloc(512);
    unsigned char *dst = (unsigned char *)malloc(64);
    if (!pkt || !dst) return 1;
    memset(pkt, 0xaa, 512);
    pkt[0] = 0x07;
    pkt[1] = 0xd0;
    handle_pkt(pkt, 512, dst, 64);
    free(pkt);
    free(dst);
    return 0;
}
''',
    },
    {
        'id': 'cve_2021_3156_sudo',
        'cve': 'CVE-2021-3156',
        'component': 'sudo sudoedit',
        'mode': 'argv拼接时 heap-buffer-overflow, 反斜杠转义逻辑缺陷',
        'vuln_type': 'heap_overflow',
        'src': r'''
/* CVE-2021-3156: sudo 的 argc/argv 合并逻辑在
 * argv[0] 以反斜杠结尾时未正确计算长度, 越界写.
 */
#include <stdlib.h>
#include <string.h>

char *join_args(int argc, char **argv) {
    size_t total = 0;
    for (int i = 0; i < argc; i++) total += strlen(argv[i]) + 1;
    char *buf = (char *)malloc(total);
    if (!buf) return 0;
    char *p = buf;
    for (int i = 0; i < argc; i++) {
        size_t n = strlen(argv[i]);
        if (n > 0 && argv[i][n - 1] == '\\') n += 1;
        memcpy(p, argv[i], n);
        p += n;
        *p++ = ' ';
    }
    *p = 0;
    return buf;
}

int main(int argc, char **argv) {
    char *joined = join_args(argc, argv);
    free(joined);
    return 0;
}
''',
    },
    {
        'id': 'cve_2022_0185_kernel',
        'cve': 'CVE-2022-0185',
        'component': 'Linux fs_context legacy_parse_param',
        'mode': '参数长度计算错误导致 2 字节堆溢出',
        'vuln_type': 'heap_overflow',
        'src': r'''
/* CVE-2022-0185: legacy_parse_param 中 size 包含NUL但
 * 写入时额外追加, 造成2字节堆溢出.
 */
#include <stdlib.h>
#include <string.h>

int parse_param(const char *param, int plen, char *ctx) {
    int size = plen + 1;
    memcpy(ctx, param, size + 1);
    return size;
}

int main(int argc, char **argv) {
    (void)argc;
    char param[32];
    char *ctx = (char *)malloc(24);
    if (!ctx) return 1;
    memset(param, 'P', 24);
    parse_param(param, 24, ctx);
    free(ctx);
    return 0;
}
''',
    },
    {
        'id': 'cve_2022_23222_bpf',
        'cve': 'CVE-2022-23222',
        'component': 'Linux BPF verifier',
        'mode': 'verifier 未验证指针运算, 越界访问堆对象',
        'vuln_type': 'heap_overflow',
        'src': r'''
/* CVE-2022-23222: eBPF verifier 对指针加偏移的验证缺失,
 * 用户可控偏移可越过对象边界写入.
 */
#include <stdlib.h>
#include <string.h>

struct map {
    int key;
    unsigned char data[32];
};

int bpf_write(struct map *m, int off, unsigned char v) {
    if (off < 0) return -1;
    m->data[off] = v;
    return 0;
}

int main(int argc, char **argv) {
    (void)argc;
    struct map *m = (struct map *)malloc(sizeof(struct map));
    if (!m) return 1;
    memset(m, 0, sizeof(struct map));
    bpf_write(m, 64, 0xff);
    free(m);
    return 0;
}
''',
    },
    {
        'id': 'cve_2023_0464_openssl',
        'cve': 'CVE-2023-0464',
        'component': 'OpenSSL X.509 policy',
        'mode': '超大分配请求导致 underflow 后 memcpy 溢出',
        'vuln_type': 'heap_overflow',
        'src': r'''
/* CVE-2023-0464: X.509 policy 检查中 n = data_len - 1,
 * data_len=0 时 n 下溢为巨大值, memcpy 越过缓冲区.
 */
#include <stdlib.h>
#include <string.h>

int policy_check(const unsigned char *data, int data_len,
                 unsigned char *out, int out_sz) {
    int n = data_len - 1;
    if (n > out_sz) n = out_sz;
    memcpy(out, data, n);
    return n;
}

int main(int argc, char **argv) {
    (void)argc;
    unsigned char *out = (unsigned char *)malloc(128);
    if (!out) return 1;
    policy_check((const unsigned char *)"", 0, out, 128);
    free(out);
    return 0;
}
''',
    },
    {
        'id': 'cve_2023_3576_openssl',
        'cve': 'CVE-2023-3576',
        'component': 'OpenSSL X.509',
        'mode': '可变长度整数解析导致6字节堆溢出',
        'vuln_type': 'heap_overflow',
        'src': r'''
/* CVE-2023-3576: 解析 X.509 可变长度整数字段时,
 * 长度计数错误, 溢出写6字节到对象尾部.
 */
#include <stdlib.h>
#include <string.h>

int parse_varlen(const unsigned char *der, int der_len,
                 unsigned char *out, int out_sz) {
    int len = der[0] & 0x7f;
    int copied = 0;
    for (int i = 0; i < len && i < der_len - 1; i++) {
        if (copied < out_sz) out[copied] = der[i + 1];
        copied++;
    }
    for (int j = 0; j < 6; j++) {
        out[out_sz + j] = 0; /* 模拟越界追加 */
    }
    return copied;
}

int main(int argc, char **argv) {
    (void)argc;
    unsigned char der[16];
    unsigned char *out = (unsigned char *)malloc(8);
    if (!out) return 1;
    memset(der, 0x55, 16);
    der[0] = 0x8a;
    parse_varlen(der, 16, out, 8);
    free(out);
    return 0;
}
''',
    },
    {
        'id': 'cve_2023_4911_looney',
        'cve': 'CVE-2023-4911',
        'component': 'glibc ld.so tunables',
        'mode': 'GLIBC_TUNABLES 环境变量处理时 strcpy 堆溢出',
        'vuln_type': 'heap_overflow',
        'src': r'''
/* CVE-2023-4911 Looney Tunables: ld.so 解析
 * GLIBC_TUNABLES 时把环境变量 strcpy 进定长堆缓冲区.
 */
#include <stdlib.h>
#include <string.h>

char *parse_tunables(const char *env) {
    size_t n = 1024;
    char *buf = (char *)malloc(n);
    if (!buf) return 0;
    strcpy(buf, env);
    return buf;
}

int main(int argc, char **argv) {
    (void)argc;
    char env[2048];
    memset(env, 'T', 2047);
    env[2047] = 0;
    char *r = parse_tunables(env);
    free(r);
    return 0;
}
''',
    },
    {
        'id': 'cve_2024_1086_nftables',
        'cve': 'CVE-2024-1086',
        'component': 'Linux nf_tables',
        'mode': 'use-after-free 链式利用, 含 set 对象堆溢出写入',
        'vuln_type': 'heap_overflow',
        'src': r'''
/* CVE-2024-1086: nf_tables 批量删除时对象生命周期缺陷,
 * 复用释放对象进行越界写; 此处以等价的对象字段越界写建模.
 */
#include <stdlib.h>
#include <string.h>

struct nft_set {
    int genmask;
    unsigned char data[16];
    int len;
};

int nft_set_write(struct nft_set *s, const unsigned char *in, int in_len) {
    if (in_len > s->len) in_len = s->len;
    memcpy(s->data + s->len, in, in_len);
    s->len += in_len;
    return s->len;
}

int main(int argc, char **argv) {
    (void)argc;
    struct nft_set *s = (struct nft_set *)malloc(sizeof(struct nft_set));
    unsigned char in[32];
    if (!s) return 1;
    memset(s, 0, sizeof(struct nft_set));
    memset(in, 0xee, 32);
    s->len = 16;
    nft_set_write(s, in, 32);
    free(s);
    return 0;
}
''',
    },
]

SAFE_SAMPLES = [
    {
        'id': 'safe_01_align_padding',
        'mode': 'malloc(20) 对齐后偏移24写入(分配器padding区)',
        'src': r'''
/* 安全: malloc(20) 在 x86-64 glibc 上 usable=32,
 * 偏移24的4字节写入落在padding区, 二进制层面合法.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(20);
    if (!buf) return 1;
    memset(buf, 0, 20);
    *(int *)(buf + 24) = 0x41424344;
    printf("%d\n", *(int *)(buf + 24));
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'safe_02_path_clamped',
        'mode': '分配大小经 if(size>256) size=256 约束',
        'src': r'''
/* 安全: 动态分配大小被路径守卫钳制到256, 复制固定9字节. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int process(int user_len) {
    int size = user_len;
    if (size > 256) size = 256;
    if (size < 0) size = 0;
    char *buf = (char *)malloc((size_t)size);
    if (!buf) return -1;
    memcpy(buf, "safe_data", 9);
    printf("%s\n", buf);
    free(buf);
    return 0;
}

int main(void) {
    process(512);
    process(128);
    return 0;
}
''',
    },
    {
        'id': 'safe_03_struct_fields',
        'mode': '结构体8字段连续初始化',
        'src': r'''
/* 安全: 连续结构体字段赋值, 偏移0..28全部在sizeof内. */
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    int f0, f1, f2, f3, f4, f5, f6, f7;
} my_struct;

int main(void) {
    my_struct *s = (my_struct *)malloc(sizeof(my_struct));
    if (!s) return 1;
    s->f0 = 0; s->f1 = 1; s->f2 = 2; s->f3 = 3;
    s->f4 = 4; s->f5 = 5; s->f6 = 6; s->f7 = 7;
    printf("%d\n", s->f7);
    free(s);
    return 0;
}
''',
    },
    {
        'id': 'safe_04_realloc_shrink',
        'mode': 'realloc 缩小后按新大小访问',
        'src': r'''
/* 安全: realloc(ptr, 64) 缩小, 之后按64字节访问. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    memset(buf, 'A', 256);
    buf = (char *)realloc(buf, 64);
    if (!buf) return 1;
    memset(buf, 'B', 64);
    printf("%.64s\n", buf);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'safe_05_min_cap',
        'mode': 'min(size, 128) 上限模式',
        'src': r'''
/* 安全: MIN(size,128) 钳制分配大小, 复制22字节. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

int main(void) {
    int input_size = 1024 * 1024;
    int safe_size = MIN(input_size, 128);
    char *buf = (char *)malloc((size_t)safe_size);
    if (!buf) return 1;
    memcpy(buf, "safe within 128 bytes", 22);
    printf("%s\n", buf);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'safe_06_calloc_loop',
        'mode': 'calloc 后按元素个数循环写入',
        'src': r'''
/* 安全: calloc(64,4)=256B, 循环 i<64 写入严格在界内. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    int *arr = (int *)calloc(64, sizeof(int));
    if (!arr) return 1;
    for (int i = 0; i < 64; i++) {
        arr[i] = i;
    }
    printf("%d\n", arr[0] + arr[63]);
    free(arr);
    return 0;
}
''',
    },
    {
        'id': 'safe_07_derived_ptr',
        'mode': 'buf+32 派生指针, 32字节写入在界内',
        'src': r'''
/* 安全: p=buf+32, memset(p,32) 覆盖 buf[32..63], 在malloc(64)内. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    memset(buf, 0, 64);
    char *p = buf + 32;
    memset(p, 'X', 32);
    printf("%c%c\n", buf[32], buf[63]);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'safe_08_alias_chain',
        'mode': '多级指针别名后界内写入',
        'src': r'''
/* 安全: buf→p→q 别名链, memset(q+64,32) 在128B内. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    char *p = buf;
    char *q = p;
    memset(q + 64, 'Y', 32);
    printf("%c%c\n", q[64], q[95]);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'safe_09_nested_alloc',
        'mode': '两个独立堆块互不干扰',
        'src': r'''
/* 安全: a=malloc(32), b=malloc(64), 各自界内写入. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *a = (char *)malloc(32);
    char *b = (char *)malloc(64);
    if (!a || !b) return 1;
    memset(a, 'A', 32);
    memset(b, 'B', 64);
    printf("%c%c\n", a[0], b[63]);
    free(a);
    free(b);
    return 0;
}
''',
    },
    {
        'id': 'safe_10_large_alloc_small_write',
        'mode': 'malloc(4096) 偏移8写入',
        'src': r'''
/* 安全: 大分配小写入, 偏移8远小于4096. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(4096);
    if (!buf) return 1;
    memset(buf, 0, 4096);
    buf[8] = 'X';
    printf("%c\n", buf[8]);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'safe_11_snprintf_bounded',
        'mode': 'snprintf 长度受限写入',
        'src': r'''
/* 安全: snprintf 显式限制长度, 写入不超过分配区. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    snprintf(buf, 64, "value=%s", "short");
    printf("%s\n", buf);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'safe_12_strncpy_bounded',
        'mode': 'strncpy 显式长度, 分配=长度+1',
        'src': r'''
/* 安全: strncpy 长度限制为分配大小. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    strncpy(buf, "hello world", 31);
    buf[31] = 0;
    printf("%s\n", buf);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'safe_13_guard_index',
        'mode': '下标经 if(idx<len) 守卫后写入',
        'src': r'''
/* 安全: idx 受守卫 idx<64 约束后写入. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    int idx = 1000;
    if (idx < 64 && idx >= 0) {
        buf[idx] = 'G';
    }
    printf("%c\n", buf[0]);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'safe_14_array_of_structs',
        'mode': '结构体数组按元素写入',
        'src': r'''
/* 安全: 结构体数组 p[i] 逐元素写入, i<16 界内. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    int id;
    int val;
} item;

int main(void) {
    item *p = (item *)malloc(16 * sizeof(item));
    if (!p) return 1;
    for (int i = 0; i < 16; i++) {
        p[i].id = i;
        p[i].val = i * 2;
    }
    printf("%d\n", p[15].val);
    free(p);
    return 0;
}
''',
    },
    {
        'id': 'safe_15_loop_in_bounds',
        'mode': '循环写入 i<32 严格界内',
        'src': r'''
/* 安全: for(i=0;i<32;i++) buf[i]=... 恰好32字节. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    for (int i = 0; i < 32; i++) {
        buf[i] = (char)i;
    }
    printf("%d\n", buf[31]);
    free(buf);
    return 0;
}
''',
    },
]
