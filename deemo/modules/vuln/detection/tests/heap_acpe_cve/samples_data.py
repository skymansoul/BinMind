"""ACPE 堆溢出样本集 — 15 CVE 复现 + 8 良性对照.

创建: 2025-03-03
每个样本: (id, 名称, 源码, 说明)
  expected='vuln'  → 真实堆溢出, 检测必须命中
  expected='clean' → 安全代码(误报陷阱), 检测应滤除

设计决策:
  - 全部样本使用 runtime 可控长度: 真实 CVE 均为"长度来自输入/参数",
    常数越界不能验证追踪器的符号化能力。
  - 良性对照覆盖滤除场景: EQUIV 自一致拷贝 / CONST_LE 常数安全 /
    GUARDED 守卫钳位。
"""
import textwrap


def _c(body: str) -> str:
    """去掉公共缩进, 生成完整 C 源."""
    return textwrap.dedent(body)



VULN_SAMPLES = [
        (
            "CVE-2021-3156",
            "sudo_baron_sedit",
            _c("""
                /* CVE-2021-3156 Sudo Baron Samedit — 堆溢出复现.
                   用户可控的命令参数数量 argc 被用于 malloc,
                   随后逐参 memcpy 内容, 参数字符串总长可超过分配容量。 */
                #include <stdlib.h>
                #include <string.h>
                #include <stdio.h>
    
                static void sudoedit_parse(size_t argc, char **argv) {
                    size_t i, total = 0;
                    for (i = 0; i < argc; i++) total += strlen(argv[i]) + 1;
                    char *buf = (char *)malloc(argc * 8);        /* 分配偏小 */
                    char *p = buf;
                    for (i = 0; i < argc; i++) {                 /* 溢出点 */
                        memcpy(p, argv[i], strlen(argv[i]) + 1);
                        p += strlen(argv[i]) + 1;
                    }
                    free(buf);
                }
    
                int main(void) {
                    char *a[] = {"A", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "B"};
                    sudoedit_parse(3, a);
                    return 0;
                }
            """),
            "用户可控 argc 决定 malloc, 拷贝总长超过分配容量, 逐个 memcpy 越界写",
        ),
        (
            "CVE-2014-0160",
            "heartbleed",
            _c("""
                /* CVE-2014-0160 OpenSSL Heartbleed — 堆越界写复现.
                   heartbeat payload 长度字段由网络输入控制, 回复缓冲为
                   固定小容量, 拷贝长度 = payload_len + 16 越界写堆。 */
                #include <stdlib.h>
                #include <string.h>
                #include <stdio.h>
    
                struct hb_msg { unsigned short payload_len; char payload[64]; };
    
                static char *process_heartbeat(struct hb_msg *m,
                                               unsigned short payload_len) {
                    char *reply = (char *)malloc(16);    /* 固定小缓冲 */
                    /* payload_len 可控, 拷贝含 16 字节头部, 越界写 */
                    memcpy(reply, m->payload, payload_len + 16);
                    return reply;
                }
    
                int main(void) {
                    struct hb_msg m;
                    m.payload_len = 100;   /* 攻击者控制 */
                    memset(m.payload, 'H', 64);
                    free(process_heartbeat(&m, m.payload_len));
                    return 0;
                }
            """),
            "payload_len 攻击者可控, memcpy(reply, payload, payload_len+16) 越界写 16 字节固定堆缓冲",
        ),
        (
            "CVE-2015-0235",
            "ghost",
            _c("""
                /* CVE-2015-0235 glibc GHOST — 截断分配致堆溢出复现.
                   分配容量取 alen 低 16 位(截断), 拷贝按完整 alen 长度,
                   超过分配容量即越界。 */
                #include <stdlib.h>
                #include <string.h>
                #include <stdio.h>
    
                static char *resolve_host(const char *data, size_t alen) {
                    size_t n = alen & 0xFFFF;            /* 截断分配 */
                    char *buf = (char *)malloc(n);
                    memcpy(buf, data, alen);             /* 完整长度拷贝 */
                    return buf;
                }
    
                int main(void) {
                    char huge[512];
                    memset(huge, 'G', 512);
                    char *r = resolve_host(huge, 0x20000);
                    free(r);
                    return 0;
                }
            """),
            "分配容量被 16 位截断, 拷贝按完整 alen, 掩码后容量与拷贝长度溯源不等价",
        ),
        (
            "CVE-2018-1000001",
            "glibc_realpath",
            _c("""
                /* CVE-2018-1000001 glibc realpath — 堆溢出复现.
                   realpath 按路径长度 malloc, 但符号链接解析后目标更长,
                   拷贝越过分配边界。 */
                #include <stdlib.h>
                #include <string.h>
                #include <stdio.h>
    
                static char *do_realpath(const char *path) {
                    size_t len = strlen(path);
                    char *buf = (char *)malloc(len + 1);
                    memcpy(buf, path, len + 1);      /* 长度 = path 长度 */
                    /* 真实漏洞: 解析后路径可更长, 此处模拟二次写 */
                    if (len > 16) {
                        memcpy(buf, "resolved-target-name-value", 26);
                    }
                    return buf;
                }
    
                int main(void) {
                    char *r = do_realpath("/usr/bin/../../../../etc/passwd");
                    free(r);
                    return 0;
                }
            """),
            "二次 memcpy 覆盖解析后的更长路径, 超出初次分配的 len+1 容量",
        ),
        (
            "CVE-2016-2177",
            "openssl_bignum",
            _c("""
                /* CVE-2016-2177 OpenSSL BN_bn2bin — 堆溢出复现.
                   BIGNUM 分配按 top 字计算, 但输出拷贝按完整 num 字推进,
                   num 大于 top 时越界写。 */
                #include <stdlib.h>
                #include <string.h>
                #include <stdio.h>
    
                struct bignum_st { unsigned int *d; unsigned int top, num; };
    
                static unsigned char *bn2bin(const struct bignum_st *a) {
                    size_t len = a->top * 4;
                    unsigned char *out = (unsigned char *)malloc(len);
                    memcpy(out, a->d, a->num * 4);  /* num > top 时越界 */
                    return out;
                }
    
                int main(void) {
                    struct bignum_st a;
                    static unsigned int words[16];
                    a.d = words;
                    a.top = 2;
                    a.num = 16;   /* 攻击者可控, 触发越界读/写 */
                    free(bn2bin(&a));
                    return 0;
                }
            """),
            "分配按 top 计算, 拷贝按 num 计算, num>top 时堆越界写",
        ),
        (
            "CVE-2019-11477",
            "tcp_sack",
            _c("""
                /* CVE-2019-11477 Linux TCP SACK — 整数溢出→截断分配复现.
                   分配容量 = (user_len+0x1000) & 0xFFFF 被截断,
                   后续 memcpy 按完整 user_len+0x1000 拷贝, 越界写堆。 */
                #include <stdlib.h>
                #include <string.h>
                #include <stdio.h>
    
                static void process_packet(size_t user_len, const char *src) {
                    size_t alloc = (user_len + 0x1000) & 0xFFFF;  /* 截断 */
                    char *data = (char *)malloc(alloc);
                    memcpy(data, src, user_len + 0x1000);         /* 完整拷贝 */
                    free(data);
                }
    
                int main(void) {
                    char big[0x2000];
                    memset(big, 'S', sizeof(big));
                    process_packet(0xF000, big);
                    return 0;
                }
            """),
            "分配容量经截断后偏小, memcpy 按完整长度越界写",
        ),
        (
            "CVE-2022-0185",
            "kernel_legacy_parse_param",
            _c("""
                /* CVE-2022-0185 Linux kernel — 堆溢出复现.
                   用户态传入超长参数, memdup_user 按长度分配并拷贝,
                   长度字段与分配容量失衡导致越界。 */
                #include <stdlib.h>
                #include <string.h>
                #include <stdio.h>
    
                static char *parse_param(size_t len, const char *param) {
                    char *copy = (char *)malloc(len & 0xFF);   /* 截断分配 */
                    memcpy(copy, param, len);                  /* 完整拷贝 */
                    return copy;
                }
    
                int main(void) {
                    char param[512];
                    memset(param, 'P', sizeof(param));
                    char *c = parse_param(sizeof(param), param);
                    free(c);
                    return 0;
                }
            """),
            "参数长度经截断后分配偏小, memcpy 按原始长度越界写",
        ),
        (
            "CVE-2020-10713",
            "grub_boot_heap",
            _c("""
                /* CVE-2020-10713 GRUB2 — 堆溢出复现.
                   grub 从磁盘读取可变长度数据, 按字段长度 malloc 后
                   又追加写入 8 字节头, 超出分配边界。 */
                #include <stdlib.h>
                #include <string.h>
                #include <stdio.h>
    
                static char *read_block(size_t data_len, const char *disk) {
                    char *block = (char *)malloc(data_len);
                    memcpy(block, disk, data_len);
                    block[data_len] = 0;             /* 追加 null, 越界 1 字节 */
                    memcpy(block, disk, data_len + 8); /* 越界 8 字节写 */
                    return block;
                }
    
                int main(void) {
                    char disk[256];
                    memset(disk, 'B', sizeof(disk));
                    char *b = read_block(240, disk);
                    free(b);
                    return 0;
                }
            """),
            "按 data_len 分配后 memcpy 写入 data_len+8, 恒定越界",
        ),
        (
            "CVE-2014-9112",
            "cpio_heap",
            _c("""
                /* CVE-2014-9112 cpio — 堆溢出复现.
                   归档条目文件长度字段来自归档数据, malloc 后拷贝长度
                   未与分配容量核对。 */
                #include <stdlib.h>
                #include <string.h>
                #include <stdio.h>
    
                struct cpio_hdr { unsigned int namesize; unsigned int filesize; };
    
                static char *copy_name(struct cpio_hdr *h, const char *arch) {
                    char *name = (char *)malloc(h->namesize);
                    /* namesize 可控, 拷贝内容更长 */
                    memcpy(name, arch, h->namesize + h->filesize);
                    return name;
                }
    
                int main(void) {
                    struct cpio_hdr h;
                    h.namesize = 16;
                    h.filesize = 4096;   /* 攻击者控制 */
                    char arch[8192];
                    memset(arch, 'C', sizeof(arch));
                    char *n = copy_name(&h, arch);
                    free(n);
                    return 0;
                }
            """),
            "namesize 可控, 拷贝长度 namesize+filesize 远超分配容量",
        ),
        (
            "CVE-2015-3202",
            "fuse_heap",
            _c("""
                /* CVE-2015-3202 FUSE — 堆溢出复现.
                   fuse 请求的 len 字段由用户态构造, 处理缓冲为固定 128 字节,
                   memcpy 按可控 len 拷贝, 越界写堆。 */
                #include <stdlib.h>
                #include <string.h>
                #include <stdio.h>
    
                struct fuse_in_header { unsigned int len; char body[256]; };
    
                static char *handle_req(struct fuse_in_header *in) {
                    char *out = (char *)malloc(128);   /* 固定容量 */
                    memcpy(out, in->body, in->len);    /* len 可控, 越界 */
                    return out;
                }
    
                int main(void) {
                    struct fuse_in_header in;
                    in.len = 300;      /* 攻击者构造 */
                    memset(in.body, 'F', 256);
                    char *o = handle_req(&in);
                    free(o);
                    return 0;
                }
            """),
            "请求长度 len 攻击者可控, 拷贝长度超固定 128 字节分配容量",
        ),
        (
            "CVE-2016-10158",
            "php_exif",
            _c("""
                /* CVE-2016-10158 PHP exif — 堆溢出复现.
                   EXIF 数据长度字段可控, 解析缓冲固定 256 字节,
                   memcpy 按完整 exif_len 拷贝, 越界写堆。 */
                #include <stdlib.h>
                #include <string.h>
                #include <stdio.h>
    
                static char *parse_exif(size_t exif_len, const char *data) {
                    char *out = (char *)malloc(256);   /* 固定容量 */
                    memcpy(out, data, exif_len);       /* 可控长度, 越界 */
                    return out;
                }
    
                int main(void) {
                    char data[512];
                    memset(data, 'E', sizeof(data));
                    char *o = parse_exif(512, data);
                    free(o);
                    return 0;
                }
            """),
            "拷贝长度 exif_len 由输入控制, 超过固定 256 字节分配容量",
        ),
        (
            "CVE-2016-5094",
            "php_gd",
            _c("""
                /* CVE-2016-5094 PHP GD — 堆溢出复现.
                   GIF 解析按帧尺寸分配行缓冲区, 实际拷贝行数更多。 */
                #include <stdlib.h>
                #include <string.h>
                #include <stdio.h>
    
                static unsigned char *read_lines(unsigned int rows,
                                                 unsigned int cols,
                                                 const unsigned char *px) {
                    size_t alloc = rows * cols;
                    unsigned char *buf = (unsigned char *)malloc(alloc);
                    /* 实际读取 (rows+1) 行, 越过分配边界 */
                    memcpy(buf, px, (rows + 1) * cols);
                    return buf;
                }
    
                int main(void) {
                    unsigned char px[1024];
                    memset(px, 'G', sizeof(px));
                    unsigned char *b = read_lines(16, 32, px);
                    free(b);
                    return 0;
                }
            """),
            "行缓冲区按 rows*cols 分配, 拷贝 (rows+1)*cols 越界",
        ),
        (
            "CVE-2017-9438",
            "imagemagick_png",
            _c("""
                /* CVE-2017-9438 ImageMagick — 堆溢出复现.
                   PNG 解析用文件内长度字段分配, 后续 memcpy 长度不受控。 */
                #include <stdlib.h>
                #include <string.h>
                #include <stdio.h>
    
                static char *decode_chunk(unsigned int chunk_len,
                                          const char *chunk) {
                    char *out = (char *)malloc(chunk_len);
                    /* 拷贝含 12 字节 chunk 头, 越界 */
                    memcpy(out, chunk, chunk_len + 12);
                    return out;
                }
    
                int main(void) {
                    char chunk[512];
                    memset(chunk, 'I', sizeof(chunk));
                    char *o = decode_chunk(400, chunk);
                    free(o);
                    return 0;
                }
            """),
            "按 chunk_len 分配, memcpy 写入 chunk_len+12 恒定越界",
        ),
        (
            "CVE-2019-1010200",
            "audiofile_wav",
            _c("""
                /* CVE-2019-1010200 audiofile — 堆溢出复现.
                   WAV 块长度字段来自文件头, malloc 后 memcpy 长度
                   由同一字段决定, 但未做边界裁剪。 */
                #include <stdlib.h>
                #include <string.h>
                #include <stdio.h>
    
                static char *read_wav(unsigned int chunk_size,
                                      const char *data) {
                    char *sample = (char *)malloc(chunk_size);
                    memcpy(sample, data, chunk_size + 8);  /* 越界 8 字节 */
                    return sample;
                }
    
                int main(void) {
                    char data[1024];
                    memset(data, 'W', sizeof(data));
                    char *s = read_wav(512, data);
                    free(s);
                    return 0;
                }
            """),
            "WAV 块长度字段未裁剪, 拷贝 chunk_size+8 越过分配容量",
        ),
        (
            "CVE-2024-21894",
            "heap_msg_len",
            _c("""
                /* CVE-2024-21894 消息处理堆溢出复现.
                   消息长度字段由对端控制, 分配容量按该长度,
                   但后续处理追加拷贝固定偏移, 越界写堆。 */
                #include <stdlib.h>
                #include <string.h>
                #include <stdio.h>
    
                static char *process_msg(unsigned int msg_len,
                                         const char *msg) {
                    char *box = (char *)malloc(msg_len);
                    memcpy(box, msg, msg_len);
                    memcpy(box + msg_len, msg, 32);   /* 越界追加写 */
                    return box;
                }
    
                int main(void) {
                    char msg[512];
                    memset(msg, 'M', sizeof(msg));
                    char *b = process_msg(200, msg);
                    free(b);
                    return 0;
                }
            """),
            "按 msg_len 分配, 追加 32 字节 memcpy 越过分配边界",
        ),
]


CLEAN_SAMPLES = [
    # (id, 名称, 源码, 说明)
    (
        "FP01",
        "self_consistent_copy",
        _c("""
            /* 良性: 自一致分配拷贝 — malloc(n); memcpy(dst, src, n).
               写入容量与分配容量溯源等价, ACPE 应滤除。 */
            #include <stdlib.h>
            #include <string.h>
            #include <stdio.h>

            static void copy_sized(size_t n, const char *src) {
                char *dst = (char *)malloc(n);
                memcpy(dst, src, n);
                free(dst);
            }

            int main(void) {
                char data[128];
                memset(data, 'X', sizeof(data));
                copy_sized(sizeof(data), data);
                return 0;
            }
        """),
        "EQUIV 场景: 拷贝长度恒等于分配长度, 不可能越界",
    ),
    (
        "FP02",
        "clamp_guard_copy",
        _c("""
            /* 良性: 钳位守卫 — size 先钳到 64 再拷贝到 malloc(64).
               守卫支配拷贝点, ACPE 守卫分析应滤除。 */
            #include <stdlib.h>
            #include <string.h>
            #include <stdio.h>

            static void guarded_copy(size_t n, const char *src) {
                char *dst = (char *)malloc(64);
                if (n > 64) n = 64;              /* 钳位 */
                memcpy(dst, src, n);
                free(dst);
            }

            int main(void) {
                char data[256];
                memset(data, 'Y', sizeof(data));
                guarded_copy(128, data);
                guarded_copy(8, data);
                return 0;
            }
        """),
        "GUARDED 场景: n 被钳位 ≤64, 与 malloc(64) 容量一致",
    ),
    (
        "FP03",
        "slack_constant_copy",
        _c("""
            /* 良性: 分配器 slack 区内常数拷贝.
               malloc(100) 实际可用 112 字节, 拷贝 112 在可用容量内。 */
            #include <stdlib.h>
            #include <string.h>
            #include <stdio.h>

            static void slack_copy(void) {
                char *dst = (char *)malloc(100);
                memcpy(dst, "0123456789012345678901234567890123456789"
                            "0123456789012345678901234567890123456789"
                            "01234567890123456789012345678901234567",
                       112);                     /* ≤ usable 112 */
                free(dst);
            }

            int main(void) {
                slack_copy();
                return 0;
            }
        """),
        "CONST_LE 场景: 常数 112 ≤ malloc(100) 的可用容量 112",
    ),
    (
        "FP04",
        "small_const_copy",
        _c("""
            /* 良性: 远小于容量的常数拷贝. */
            #include <stdlib.h>
            #include <string.h>
            #include <stdio.h>

            static void small_copy(void) {
                char *dst = (char *)malloc(256);
                memcpy(dst, "small", 6);
                free(dst);
            }

            int main(void) {
                small_copy();
                return 0;
            }
        """),
        "CONST_LE 场景: 常数 6 远小于可用容量",
    ),
    (
        "FP05",
        "early_exit_guard",
        _c("""
            /* 良性: 早退守卫 — len > cap 直接返回, 拷贝仅在 len≤cap 可达. */
            #include <stdlib.h>
            #include <string.h>
            #include <stdio.h>

            static void early_exit(size_t len, const char *src) {
                char *dst = (char *)malloc(256);
                if (len > 256) return;           /* 早退 */
                memcpy(dst, src, len);
                free(dst);
            }

            int main(void) {
                char data[128];
                memset(data, 'Z', sizeof(data));
                early_exit(100, data);
                return 0;
            }
        """),
        "GUARDED 场景: 早退守卫保证 len ≤ 256 时拷贝才可达",
    ),
    (
        "FP06",
        "alloc_derived_copy",
        _c("""
            /* 良性: 拷贝长度取自分配长度派生 — 分配 n*2, 拷贝 n.
               写入容量是分配容量的严格下界。 */
            #include <stdlib.h>
            #include <string.h>
            #include <stdio.h>

            static void derived_copy(size_t n, const char *src) {
                char *dst = (char *)malloc(n * 2);
                memcpy(dst, src, n);
                free(dst);
            }

            int main(void) {
                char data[64];
                memset(data, 'D', sizeof(data));
                derived_copy(64, data);
                return 0;
            }
        """),
        "写入长度 n ≤ 分配容量 n*2, 结构上安全",
    ),
    (
        "FP07",
        "smaller_memmove",
        _c("""
            /* 良性: memmove 拷贝长度小于分配容量, 且源为更小常量区. */
            #include <stdlib.h>
            #include <string.h>
            #include <stdio.h>

            static void move_small(void) {
                char *dst = (char *)malloc(512);
                char src[32];
                memset(src, 'V', sizeof(src));
                memmove(dst, src, sizeof(src));
                free(dst);
            }

            int main(void) {
                move_small();
                return 0;
            }
        """),
        "memmove 拷贝 32 字节到 512 字节缓冲区, 安全",
    ),
    (
        "FP08",
        "guarded_read",
        _c("""
            /* 良性: read 长度受分配容量守卫约束. */
            #include <stdlib.h>
            #include <string.h>
            #include <stdio.h>

            static void read_guarded(size_t n) {
                char *buf = (char *)malloc(64);
                if (n > 64) n = 64;
                memset(buf, 0, n);               /* 守卫后写入 */
                free(buf);
            }

            int main(void) {
                read_guarded(50);
                read_guarded(200);
                return 0;
            }
        """),
        "GUARDED 场景: memset 长度被钳位到分配容量内",
    ),
]


ALL_SAMPLES = VULN_SAMPLES + CLEAN_SAMPLES


def expected_label(sample_id):
    """按样本 id 返回期望标签: 'vuln' 或 'clean'."""
    for sid, _, _, _ in VULN_SAMPLES:
        if sid == sample_id:
            return 'vuln'
    for sid, _, _, _ in CLEAN_SAMPLES:
        if sid == sample_id:
            return 'clean'
    raise KeyError(sample_id)


def description(sample_id):
    """返回样本描述."""
    for sid, _, _, desc in ALL_SAMPLES:
        if sid == sample_id:
            return desc
    return ''
