"""格式化字符串样本定义 (漏洞 1-8) — 生成样本集的源数据。

每个样本: 触发函数(用户输入进入格式参数) + main 驱动。
漏洞模式复刻 CVE 的 CWE-134 根因: 攻击者可控字符串被直接
用作 printf 族格式参数, 导致 %n 写或信息泄露。
"""

import textwrap

SAMPLE_DEFS_A = [

    # 1. CVE-2012-0809: 直接传参格式串
    {
        'name': 'CVE-2012-0809_sudo',
        'cve': 'CVE-2012-0809',
        'category': 'fmt',
        'func': 'sudo_log_trigger',
        'truth': {'is_vuln': True, 'pattern': 'direct_format_arg',
                  'overflow_kind': 'fmt', 'cwe': 'CWE-134'},
        'readme': 'sudo 1.8.3p1 前版本日志路径把用户提供的用户名直接\n'
                  '作为格式参数传给 printf, 可 %n 任意写。\n'
                  '复现: printf(user)。',
        'source': textwrap.dedent('''\
            #include <stdio.h>

            static void sudo_log_trigger(const char *user)
            {
                printf(user);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                sudo_log_trigger(argv[1]);
                return 0;
            }
        '''),
    },

    # 2. CVE-2017-1000353: 日志内容进格式串
    {
        'name': 'CVE-2017-1000353_jenkins',
        'cve': 'CVE-2017-1000353',
        'category': 'fmt',
        'func': 'note_trigger',
        'truth': {'is_vuln': True, 'pattern': 'buffer_as_format',
                  'overflow_kind': 'fmt', 'cwe': 'CWE-134'},
        'readme': 'Jenkins ConsoleNote 解析日志文本时把内容直接格式化,\n'
                  '构造的日志可触发格式串攻击。\n'
                  '复现: strcpy 后 printf(buf)。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <string.h>

            static void note_trigger(const char *text)
            {
                char buf[256];
                strcpy(buf, text);
                printf(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                note_trigger(argv[1]);
                return 0;
            }
        '''),
    },

    # 3. CVE-2019-15642: SOAP 头进格式串
    {
        'name': 'CVE-2019-15642_miniupnpd',
        'cve': 'CVE-2019-15642',
        'category': 'fmt',
        'func': 'upnp_trigger',
        'truth': {'is_vuln': True, 'pattern': 'buffer_as_format',
                  'overflow_kind': 'fmt', 'cwe': 'CWE-134'},
        'readme': 'miniupnpd SOAP 处理把请求头字段拼进缓冲后作为\n'
                  '格式串输出。复现: sprintf 组装后 printf(buf)。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <string.h>

            static void upnp_trigger(const char *header)
            {
                char buf[128];
                sprintf(buf, "%s", header);
                printf(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                upnp_trigger(argv[1]);
                return 0;
            }
        '''),
    },

    # 4. fprintf 直接传参
    {
        'name': 'FMT-004_fprintf_arg',
        'cve': '',
        'category': 'fmt',
        'func': 'log_trigger',
        'truth': {'is_vuln': True, 'pattern': 'direct_format_arg',
                  'overflow_kind': 'fmt', 'cwe': 'CWE-134'},
        'readme': 'fprintf 的格式参数来自外部输入 — 格式串攻击。',
        'source': textwrap.dedent('''\
            #include <stdio.h>

            static void log_trigger(const char *msg)
            {
                fprintf(stderr, msg);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                log_trigger(argv[1]);
                return 0;
            }
        '''),
    },

    # 5. syslog 直接传参
    {
        'name': 'FMT-005_syslog_arg',
        'cve': '',
        'category': 'fmt',
        'func': 'syslog_trigger',
        'truth': {'is_vuln': True, 'pattern': 'direct_format_arg',
                  'overflow_kind': 'fmt', 'cwe': 'CWE-134'},
        'readme': 'syslog 的格式参数来自外部输入 — 格式串攻击。',
        'source': textwrap.dedent('''\
            #include <stdio.h>

            static void syslog_trigger(const char *detail)
            {
                printf("[err] ");
                printf(detail);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                syslog_trigger(argv[1]);
                return 0;
            }
        '''),
    },

    # 6. getenv 来源格式串
    {
        'name': 'FMT-006_env_format',
        'cve': '',
        'category': 'fmt',
        'func': 'env_trigger',
        'truth': {'is_vuln': True, 'pattern': 'tainted_env_format',
                  'overflow_kind': 'fmt', 'cwe': 'CWE-134'},
        'readme': '格式串来自环境变量(外部可控) — 格式串攻击。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void env_trigger(int n)
            {
                char *fmt = getenv("LOG_FORMAT");
                if (fmt)
                    printf(fmt, n);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                env_trigger(atoi(argv[1]));
                return 0;
            }
        '''),
    },

    # 7. recv 缓冲进格式串
    {
        'name': 'FMT-007_recv_buffer',
        'cve': '',
        'category': 'fmt',
        'func': 'recv_trigger',
        'truth': {'is_vuln': True, 'pattern': 'recv_buffer_format',
                  'overflow_kind': 'fmt', 'cwe': 'CWE-134'},
        'readme': '网络读取的缓冲直接作为格式串 — 格式串攻击。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <string.h>

            static void recv_trigger(const char *payload)
            {
                char buf[64];
                memcpy(buf, payload, strlen(payload) + 1);
                printf(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                recv_trigger(argv[1]);
                return 0;
            }
        '''),
    },

    # 8. scanf 缓冲进格式串
    {
        'name': 'FMT-008_scanf_buffer',
        'cve': '',
        'category': 'fmt',
        'func': 'scanf_trigger',
        'truth': {'is_vuln': True, 'pattern': 'scanf_buffer_format',
                  'overflow_kind': 'fmt', 'cwe': 'CWE-134'},
        'readme': 'scanf 读入的缓冲作为格式串 — 格式串攻击。',
        'source': textwrap.dedent('''\
            #include <stdio.h>

            static void scanf_trigger(const char *line)
            {
                char buf[80];
                sscanf(line, "%s", buf);
                printf(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                scanf_trigger(argv[1]);
                return 0;
            }
        '''),
    },
]
