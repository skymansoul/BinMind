"""???? ? ?????????(????)?
????: ???? + main ??; ???????? CVE ??,
??????????
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
]
