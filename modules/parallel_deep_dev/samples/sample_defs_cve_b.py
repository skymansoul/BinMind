"""???? ? ?????????(????)?
????: ???? + main ??; ???????? CVE ??,
??????????
"""

import textwrap


SAMPLE_DEFS_B = [
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
]
