"""???? ? ?????????(????)?
????: ???? + main ??; ???????? CVE ??,
??????????
"""

import textwrap


SAMPLE_DEFS_C = [
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
