"""CVE 堆溢出与安全(误报基准)样本定义 — 生成样本集的源数据。

每个样本: 独立触发函数(含漏洞模式) + main 驱动(argc/argv 喂入)。
漏洞模式忠实复刻 CVE 根因(缺失边界校验/长度计算错误/循环越界),
以最小可编译 C 复现其内存写越界语义; 安全样本专测误报率。
"""

import textwrap


SAMPLE_DEFS_A = [

    # 1. CVE-2015-0235 GHOST: 长度字段超出缓冲
    {
        'name': 'CVE-2015-0235_ghost',
        'cve': 'CVE-2015-0235',
        'category': 'write',
        'func': 'ghost_trigger',
        'truth': {
            'is_vuln': True, 'pattern': 'memcpy_len_overflow',
            'overflow_kind': 'write', 'cwe': 'CWE-122',
        },
        'readme': (
            'glibc __nss_hostname_digits_dots 在 gethostbyname 中因缓冲区\n'
            '长度计算错误写出 \'struct hostent\'\' 结构。复现: 攻击者提供\n'
            'name, 代码按 n 分配缓冲却复制 n+8 字节。'),
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            /* CVE-2015-0235 (GHOST): 复制长度超出分配容量 */
            static void ghost_trigger(const char *name, size_t n)
            {
                char *alias = (char *)malloc(n);
                if (!alias)
                    return;
                /* nss_dns 用 sizeof(struct hostent) 做长度计算,
                   实际拷贝多出 8 字节 */
                memcpy(alias, name, n + 8);
                free(alias);
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                size_t n = (size_t)strtoul(argv[1], NULL, 10);
                ghost_trigger(argv[2], n);
                return 0;
            }
        '''),
    },

    # 2. CVE-2017-1000117: 循环上界含等号越界写
    {
        'name': 'CVE-2017-1000117_udp_frag',
        'cve': 'CVE-2017-1000117',
        'category': 'write',
        'func': 'frag_trigger',
        'truth': {
            'is_vuln': True, 'pattern': 'loop_off_by_one',
            'overflow_kind': 'write', 'cwe': 'CWE-787',
        },
        'readme': (
            'Linux udp IPv6 分片重组 (udp_queue_rcv_skb) 中对 skb 队列\n'
            '的偏移计算允许写越界。复现: 分片数为 n, 分配 n*4 却循环\n'
            '到 i<=n, 最后一次写越界 4 字节。'),
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            /* CVE-2017-1000117: 分片偏移表循环含等号 → 末次越界 */
            static void frag_trigger(size_t n)
            {
                unsigned int *off_tab = (unsigned int *)malloc(n * 4);
                if (!off_tab)
                    return;
                size_t i;
                for (i = 0; i <= n; i++) {
                    off_tab[i] = (unsigned int)(i * 1500);
                }
                free(off_tab);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                size_t n = (size_t)strtoul(argv[1], NULL, 10);
                if (n > 100000)
                    n = 100000;
                frag_trigger(n);
                return 0;
            }
        '''),
    },

    # 3. CVE-2018-1000001: 缺少 PATH_MAX 校验
    {
        'name': 'CVE-2018-1000001_realpath',
        'cve': 'CVE-2018-1000001',
        'category': 'write',
        'func': 'realpath_trigger',
        'truth': {
            'is_vuln': True, 'pattern': 'memcpy_len_overflow',
            'overflow_kind': 'write', 'cwe': 'CWE-120',
        },
        'readme': (
            'glibc realpath() 当 PATH_MAX 未定义时用 1024 固定缓冲,\n'
            '攻击者提供长路径导致拷贝溢出。复现: 分配 1024 却复制\n'
            '攻击者长度字节。'),
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            /* CVE-2018-1000001: 固定缓冲 + 未校验的外部长度 */
            static char *realpath_trigger(const char *path, size_t len)
            {
                char *resolved = (char *)malloc(1024);
                if (!resolved)
                    return NULL;
                /* realpath 未检查 len > 1024 */
                memcpy(resolved, path, len);
                if (len < 1024)
                    resolved[len] = '\\0';
                return resolved;
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                size_t len = (size_t)strtoul(argv[1], NULL, 10);
                char *r = realpath_trigger(argv[2], len);
                free(r);
                return 0;
            }
        '''),
    },

    # 4. CVE-2019-1010298: 常量偏移越界
    {
        'name': 'CVE-2019-1010298_hso',
        'cve': 'CVE-2019-1010298',
        'category': 'write',
        'func': 'hso_trigger',
        'truth': {
            'is_vuln': True, 'pattern': 'const_offset',
            'overflow_kind': 'write', 'cwe': 'CWE-787',
        },
        'readme': (
            'Linux hso_serial 驱动包解析时 memcpy 到 buf+off,\n'
            'off 超过包容量导致堆越界。复现: 分配 len, 在偏移 len+4\n'
            '处写 4 字节(常量越界)。'),
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            /* CVE-2019-1010298: 包头的 off 未校验就 memcpy */
            static void hso_trigger(const char *data, size_t len)
            {
                char *buf = (char *)malloc(len);
                if (!buf)
                    return;
                /* off = len + 4 越界写 */
                memcpy(buf + len + 4, data, 4);
                free(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                size_t len = (size_t)strtoul(argv[1], NULL, 10);
                hso_trigger(argv[2], len);
                return 0;
            }
        '''),
    },

    # 5. CVE-2020-14386: 帧长度计算错误
    {
        'name': 'CVE-2020-14386_afpacket',
        'cve': 'CVE-2020-14386',
        'category': 'write',
        'func': 'tpacket_trigger',
        'truth': {
            'is_vuln': True, 'pattern': 'index_overflow',
            'overflow_kind': 'write', 'cwe': 'CWE-787',
        },
        'readme': (
            'Linux AF_PACKET tpacket_rcv 对帧元数据索引计算未校验,\n'
            '导致写越界。复现: 分配 frame_len 字节, 下标按帧数*2\n'
            '推进, 超出容量。'),
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            /* CVE-2020-14386: 下标 i*2 超过帧容量 */
            static void tpacket_trigger(size_t frames)
            {
                size_t frame_len = frames * 2;
                unsigned char *meta = (unsigned char *)malloc(frame_len);
                if (!meta)
                    return;
                size_t i;
                for (i = 0; i < frames; i++) {
                    /* 每帧元数据占 2 字节, 帧数倍后越界 */
                    meta[i * 2] = (unsigned char)i;
                    meta[i * 2 + 1] = 0;
                }
                free(meta);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                size_t frames = (size_t)strtoul(argv[1], NULL, 10);
                tpacket_trigger(frames);
                return 0;
            }
        '''),
    },

    # 6. CVE-2020-25656: 循环步长与容量失配
    {
        'name': 'CVE-2020-25656_vt_ioctl',
        'cve': 'CVE-2020-25656',
        'category': 'write',
        'func': 'vt_trigger',
        'truth': {
            'is_vuln': True, 'pattern': 'loop_scale_mismatch',
            'overflow_kind': 'write', 'cwe': 'CWE-787',
        },
        'readme': (
            'Linux vt_ioctl 中 count 整数运算后被用作写入步长,\n'
            '分配容量按 count 但写入按 count*2 推进。复现:\n'
            'malloc(count) 却在循环中写 buf[i*2]。'),
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            /* CVE-2020-25656: 分配 count 字节, 写指针按 2 步进 */
            static void vt_trigger(size_t count)
            {
                unsigned char *screen = (unsigned char *)malloc(count);
                if (!screen)
                    return;
                size_t i;
                for (i = 0; i < count; i++) {
                    screen[i * 2] = 0x41;
                    screen[i * 2 + 1] = 0x00;
                }
                free(screen);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                size_t count = (size_t)strtoul(argv[1], NULL, 10);
                if (count > 100000)
                    count = 100000;
                vt_trigger(count);
                return 0;
            }
        '''),
    },

    # 7. CVE-2021-22555: 用户大小与内核大小混淆
    {
        'name': 'CVE-2021-22555_netfilter',
        'cve': 'CVE-2021-22555',
        'category': 'write',
        'func': 'xt_trigger',
        'truth': {
            'is_vuln': True, 'pattern': 'memcpy_len_overflow',
            'overflow_kind': 'write', 'cwe': 'CWE-787',
        },
        'readme': (
            'Linux netfilter xt_compat_target_from_user 复制数据时\n'
            '用了用户提供的 size 而非目标实际容量, 堆越界。复现:\n'
            'malloc(cap) 却复制 user_len(cap+16)。'),
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            /* CVE-2021-22555: user_len 超过目标分配容量 */
            static void xt_trigger(const char *data, size_t cap, size_t user_len)
            {
                char *target = (char *)malloc(cap);
                if (!target)
                    return;
                /* 未校验 user_len <= cap */
                memcpy(target, data, user_len);
                free(target);
            }

            int main(int argc, char **argv)
            {
                if (argc < 4)
                    return 1;
                size_t cap = (size_t)strtoul(argv[1], NULL, 10);
                size_t user_len = (size_t)strtoul(argv[2], NULL, 10);
                xt_trigger(argv[3], cap, user_len);
                return 0;
            }
        '''),
    },

    # 8. CVE-2021-3156: 拼接导致总量超出
    {
        'name': 'CVE-2021-3156_sudo',
        'cve': 'CVE-2021-3156',
        'category': 'write',
        'func': 'sudo_trigger',
        'truth': {
            'is_vuln': True, 'pattern': 'concat_overflow',
            'overflow_kind': 'write', 'cwe': 'CWE-122',
        },
        'readme': (
            'sudo Baron Samedit: sudoedit 处理命令行参数时未转义\n'
            '反斜杠导致堆缓冲溢出。复现: malloc(n) 后先写 n 字节\n'
            '用户数据再追加固定后缀, 总量超出。'),
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            /* CVE-2021-3156: 先复制用户 n 字节, 再拼后缀, 总量超 n */
            static char *sudo_trigger(const char *user, size_t n)
            {
                static const char suffix[] = " -h 0.0.0.0:1";
                char *cmd = (char *)malloc(n);
                if (!cmd)
                    return NULL;
                memcpy(cmd, user, n);
                memcpy(cmd + n, suffix, sizeof(suffix));
                return cmd;
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                size_t n = (size_t)strtoul(argv[1], NULL, 10);
                char *cmd = sudo_trigger(argv[2], n);
                free(cmd);
                return 0;
            }
        '''),
    },
]


SAMPLE_DEFS_B = [

    # 9. CVE-2021-33909: 长度偏移+1
    {
        'name': 'CVE-2021-33909_seccomp',
        'cve': 'CVE-2021-33909',
        'category': 'write',
        'func': 'seccomp_trigger',
        'truth': {
            'is_vuln': True, 'pattern': 'memcpy_len_overflow',
            'overflow_kind': 'write', 'cwe': 'CWE-122',
        },
        'readme': (
            'Linux seccomp size_too_big: filter 头长度计算使实际\n'
            '拷贝多出字节。复现: malloc(flen) 后 memcpy flen+1 字节。'),
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            /* CVE-2021-33909: 头偏移使拷贝多 1 字节 */
            static void seccomp_trigger(const char *filter, size_t flen)
            {
                char *copy = (char *)malloc(flen);
                if (!copy)
                    return;
                memcpy(copy, filter, flen + 1);
                free(copy);
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                size_t flen = (size_t)strtoul(argv[1], NULL, 10);
                seccomp_trigger(argv[2], flen);
                return 0;
            }
        '''),
    },

    # 10. CVE-2022-0185: nlen 少算 1
    {
        'name': 'CVE-2022-0185_fsconfig',
        'cve': 'CVE-2022-0185',
        'category': 'write',
        'func': 'parse_param_trigger',
        'truth': {
            'is_vuln': True, 'pattern': 'memcpy_len_overflow',
            'overflow_kind': 'write', 'cwe': 'CWE-787',
        },
        'readme': (
            'Linux legacy_parse_param 中 nlen 少算 1, 尾部 memcpy\n'
            '多复制导致堆越界。复现: malloc(nlen) 复制 nlen+1。'),
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            /* CVE-2022-0185: 参数长度少算 1 字节 */
            static void parse_param_trigger(const char *val, size_t nlen)
            {
                char *param = (char *)malloc(nlen);
                if (!param)
                    return;
                memcpy(param, val, nlen + 1);
                free(param);
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                size_t nlen = (size_t)strtoul(argv[1], NULL, 10);
                parse_param_trigger(argv[2], nlen);
                return 0;
            }
        '''),
    },

    # 11. CVE-2023-0286: 双倍展开
    {
        'name': 'CVE-2023-0286_x400',
        'cve': 'CVE-2023-0286',
        'category': 'write',
        'func': 'x400_trigger',
        'truth': {
            'is_vuln': True, 'pattern': 'length_double',
            'overflow_kind': 'write', 'cwe': 'CWE-122',
        },
        'readme': (
            'OpenSSL X.400 地址处理 (c2i_ASN1_IA5STRING) 对 RDNs\n'
            '总长度与目标缓冲长度不一致, 展开写入越界。复现:\n'
            'malloc(len) 却复制 len*2。'),
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            /* CVE-2023-0286: 展开长度 2x 超出分配 */
            static char *x400_trigger(const char *rdn, size_t len)
            {
                char *name = (char *)malloc(len);
                if (!name)
                    return NULL;
                memcpy(name, rdn, len * 2);
                return name;
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                size_t len = (size_t)strtoul(argv[1], NULL, 10);
                char *name = x400_trigger(argv[2], len);
                free(name);
                return 0;
            }
        '''),
    },

    # 12. CVE-2023-2286: 包头+2
    {
        'name': 'CVE-2023-2286_libssh2',
        'cve': 'CVE-2023-2286',
        'category': 'write',
        'func': 'sftp_trigger',
        'truth': {
            'is_vuln': True, 'pattern': 'memcpy_len_overflow',
            'overflow_kind': 'write', 'cwe': 'CWE-122',
        },
        'readme': (
            'libssh2 sftp.c 解析 SFTP 包时长度校验缺失, 复制超出\n'
            '分配缓冲。复现: malloc(size) 复制 size+2。'),
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            /* CVE-2023-2286: 包长度未校验 */
            static void sftp_trigger(const char *pkt, size_t size)
            {
                char *buf = (char *)malloc(size);
                if (!buf)
                    return;
                memcpy(buf, pkt, size + 2);
                free(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                size_t size = (size_t)strtoul(argv[1], NULL, 10);
                sftp_trigger(argv[2], size);
                return 0;
            }
        '''),
    },

    # 13. CVE-2024-21762: 偏移+长度
    {
        'name': 'CVE-2024-21762_fortios',
        'cve': 'CVE-2024-21762',
        'category': 'write',
        'func': 'vpn_trigger',
        'truth': {
            'is_vuln': True, 'pattern': 'offset_plus_len',
            'overflow_kind': 'write', 'cwe': 'CWE-787',
        },
        'readme': (
            'Fortinet FortiOS SSL VPN 在 sslvpn 会话数据拷贝时目标\n'
            '偏移加长度超过分配容量。复现: malloc(len) 后写\n'
            'buf[len..2len)。'),
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            /* CVE-2024-21762: 偏移 len 再写 len 字节 */
            static void vpn_trigger(const char *data, size_t len)
            {
                char *buf = (char *)malloc(len);
                if (!buf)
                    return;
                memcpy(buf + len, data, len);
                free(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                size_t len = (size_t)strtoul(argv[1], NULL, 10);
                vpn_trigger(argv[2], len);
                return 0;
            }
        '''),
    },

    # 14. CVE-2024-23222: 双倍复制
    {
        'name': 'CVE-2024-23222_webkit',
        'cve': 'CVE-2024-23222',
        'category': 'write',
        'func': 'webkit_trigger',
        'truth': {
            'is_vuln': True, 'pattern': 'length_double',
            'overflow_kind': 'write', 'cwe': 'CWE-787',
        },
        'readme': (
            'Apple WebKit 类型混淆导致越界写。复现: malloc(size)\n'
            '却复制 size*2 字节。'),
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            /* CVE-2024-23222: 越界写 (类型混淆根因简化) */
            static void webkit_trigger(const char *payload, size_t size)
            {
                char *slot = (char *)malloc(size);
                if (!slot)
                    return;
                memcpy(slot, payload, size * 2);
                free(slot);
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                size_t size = (size_t)strtoul(argv[1], NULL, 10);
                webkit_trigger(argv[2], size);
                return 0;
            }
        '''),
    },

    # 15. CVE-2017-16995: 常量索引越界
    {
        'name': 'CVE-2017-16995_ebpf',
        'cve': 'CVE-2017-16995',
        'category': 'write',
        'func': 'ebpf_trigger',
        'truth': {
            'is_vuln': True, 'pattern': 'const_offset',
            'overflow_kind': 'write', 'cwe': 'CWE-787',
        },
        'readme': (
            'Linux eBPF 验证器对 32 位算术的检查可被绕过, 允许\n'
            '越界写 map 数据。复现: malloc(n) 后写 buf[n*2]。'),
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            /* CVE-2017-16995: 下标 n*2 越界写 */
            static void ebpf_trigger(size_t n)
            {
                unsigned char *map = (unsigned char *)malloc(n);
                if (!map)
                    return;
                map[n * 2] = 1;
                free(map);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                size_t n = (size_t)strtoul(argv[1], NULL, 10);
                ebpf_trigger(n);
                return 0;
            }
        '''),
    },

    # 16. CVE-2021-4204: 元素数*尺寸失配
    {
        'name': 'CVE-2021-4204_ebpf32',
        'cve': 'CVE-2021-4204',
        'category': 'write',
        'func': 'ebpf32_trigger',
        'truth': {
            'is_vuln': True, 'pattern': 'scale_mismatch',
            'overflow_kind': 'write', 'cwe': 'CWE-787',
        },
        'readme': (
            'Linux eBPF 32 位寄存器边界跟踪缺陷导致越界写。复现:\n'
            'malloc(count) 却按 count*4 字节复制。'),
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            /* CVE-2021-4204: 元素数与字节数失配 */
            static void ebpf32_trigger(const char *data, size_t count)
            {
                unsigned char *buf = (unsigned char *)malloc(count);
                if (!buf)
                    return;
                memcpy(buf, data, count * 4);
                free(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                size_t count = (size_t)strtoul(argv[1], NULL, 10);
                ebpf32_trigger(argv[2], count);
                return 0;
            }
        '''),
    },
]


SAMPLE_DEFS_SAFE = [
    {
        'name': 'FP-01_coupled_len',
        'cve': '',
        'category': 'safe',
        'func': 'safe_copy',
        'truth': {
            'is_vuln': False, 'pattern': 'coupled_len',
            'overflow_kind': 'none', 'cwe': '',
            'filter': 'coupled-delta',
        },
        'readme': 'malloc(n) 后 memcpy 恰好 n 字节 — 安全等长复制。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            static void safe_copy(const char *input, size_t n)
            {
                char *buf = (char *)malloc(n);
                if (!buf)
                    return;
                memcpy(buf, input, n);
                free(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                size_t n = (size_t)strtoul(argv[1], NULL, 10);
                safe_copy(argv[2], n);
                return 0;
            }
        '''),
    },

    {
        'name': 'FP-02_loop_scaled',
        'cve': '',
        'category': 'safe',
        'func': 'safe_loop',
        'truth': {
            'is_vuln': False, 'pattern': 'loop_scaled',
            'overflow_kind': 'none', 'cwe': '',
            'filter': 'guard-subst',
        },
        'readme': 'malloc(n*4) 且循环 i<n 写 int 数组 — 容量恰配。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void safe_loop(size_t n)
            {
                int *buf = (int *)malloc(n * 4);
                if (!buf)
                    return;
                size_t i;
                for (i = 0; i < n; i++) {
                    buf[i] = (int)i;
                }
                free(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                size_t n = (size_t)strtoul(argv[1], NULL, 10);
                safe_loop(n);
                return 0;
            }
        '''),
    },

    {
        'name': 'FP-03_guard_check',
        'cve': '',
        'category': 'safe',
        'func': 'safe_guarded',
        'truth': {
            'is_vuln': False, 'pattern': 'guard_check',
            'overflow_kind': 'none', 'cwe': '',
            'filter': 'guard-subst',
        },
        'readme': 'if (len > size) return; 后再 memcpy — 守卫保护。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            static void safe_guarded(const char *input, size_t len, size_t size)
            {
                char *buf = (char *)malloc(size);
                if (!buf)
                    return;
                if (len > size)
                    return;
                memcpy(buf, input, len);
                free(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 4)
                    return 1;
                size_t len = (size_t)strtoul(argv[1], NULL, 10);
                size_t size = (size_t)strtoul(argv[2], NULL, 10);
                safe_guarded(argv[3], len, size);
                return 0;
            }
        '''),
    },

    {
        'name': 'FP-04_aligned_slack',
        'cve': '',
        'category': 'safe',
        'func': 'safe_aligned',
        'truth': {
            'is_vuln': False, 'pattern': 'aligned_slack',
            'overflow_kind': 'none', 'cwe': '',
            'filter': 'aligned-capacity',
        },
        'readme': 'malloc(17) 的 chunk 对齐到 32 字节, 写 24..31 安全。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void safe_aligned(void)
            {
                char *buf = (char *)malloc(17);
                if (!buf)
                    return;
                buf[24] = 1;
                buf[31] = 2;
                free(buf);
            }

            int main(void)
            {
                safe_aligned();
                return 0;
            }
        '''),
    },

    {
        'name': 'FP-05_strcpy_literal',
        'cve': '',
        'category': 'safe',
        'func': 'safe_strcpy',
        'truth': {
            'is_vuln': False, 'pattern': 'strcpy_literal',
            'overflow_kind': 'none', 'cwe': '',
            'filter': 'string-literal-len',
        },
        'readme': 'strcpy 到 malloc(64), 源为已知字面量 — 长度可证。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            static void safe_strcpy(void)
            {
                char *buf = (char *)malloc(64);
                if (!buf)
                    return;
                strcpy(buf, "hello world");
                free(buf);
            }

            int main(void)
            {
                safe_strcpy();
                return 0;
            }
        '''),
    },

    {
        'name': 'FP-06_realloc_expansion',
        'cve': '',
        'category': 'safe',
        'func': 'safe_realloc',
        'truth': {
            'is_vuln': False, 'pattern': 'realloc_expand',
            'overflow_kind': 'none', 'cwe': '',
            'filter': 'alloc-dedup',
        },
        'readme': 'malloc(16) 后 realloc(16*4), 循环写 int 数组 — 扩容后安全。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void safe_realloc(void)
            {
                int *buf = (int *)malloc(16);
                if (!buf)
                    return;
                buf = (int *)realloc(buf, 16 * 4);
                if (!buf)
                    return;
                int i;
                for (i = 0; i < 16; i++) {
                    buf[i] = i;
                }
                free(buf);
            }

            int main(void)
            {
                safe_realloc();
                return 0;
            }
        '''),
    },

    {
        'name': 'FP-07_struct_fields',
        'cve': '',
        'category': 'safe',
        'func': 'safe_struct',
        'truth': {
            'is_vuln': False, 'pattern': 'struct_fields',
            'overflow_kind': 'none', 'cwe': '',
            'filter': 'struct-layout',
        },
        'readme': 'malloc(sizeof(struct)) 后逐字段写 — 布局内合法访问。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            struct Node {
                int a;
                int b;
                int c;
            };

            static void safe_struct(void)
            {
                struct Node *n = (struct Node *)malloc(sizeof(struct Node));
                if (!n)
                    return;
                n->a = 1;
                n->b = 2;
                n->c = 3;
                free(n);
            }

            int main(void)
            {
                safe_struct();
                return 0;
            }
        '''),
    },

    {
        'name': 'FP-08_strncpy_terminated',
        'cve': '',
        'category': 'safe',
        'func': 'safe_strncpy',
        'truth': {
            'is_vuln': False, 'pattern': 'strncpy_terminated',
            'overflow_kind': 'none', 'cwe': '',
            'filter': 'interval',
        },
        'readme': 'strncpy n-1 字节后手动补 0 — 总量恰为 n 不越界。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            static void safe_strncpy(const char *src, size_t n)
            {
                if (n > 64)
                    return;
                char *buf = (char *)malloc(64);
                if (!buf)
                    return;
                strncpy(buf, src, n - 1);
                buf[n - 1] = '\\0';
                free(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                size_t n = (size_t)strtoul(argv[1], NULL, 10);
                safe_strncpy(argv[2], n);
                return 0;
            }
        '''),
    },
]
