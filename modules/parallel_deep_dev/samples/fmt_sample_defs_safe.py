"""格式化字符串安全(误报基准)样本定义 — 朴素基线报但实际安全。

每个陷阱对应一个 FSV 安全信号:
  S01/S02/S04/S06  字面量格式 → literal
  S03/S05          字面量来源变量 → literal_vars
  S07/S08          不可证字段/调用返回 → UNCERTAIN 抑制
"""

import textwrap

SAMPLE_DEFS_SAFE = [

    # S01 字面量直接
    {
        'name': 'FMT-S01_literal_direct',
        'cve': '',
        'category': 'fmt_safe',
        'func': 'safe_literal',
        'truth': {'is_vuln': False, 'pattern': 'literal_format',
                  'overflow_kind': 'none', 'cwe': '', 'filter': 'literal'},
        'readme': 'printf("%s", user) — 格式为字面量, 安全。',
        'source': textwrap.dedent('''\
            #include <stdio.h>

            static void safe_literal(const char *user)
            {
                printf("%s", user);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                safe_literal(argv[1]);
                return 0;
            }
        '''),
    },

    # S02 字面量 fprintf
    {
        'name': 'FMT-S02_literal_fprintf',
        'cve': '',
        'category': 'fmt_safe',
        'func': 'safe_fprintf',
        'truth': {'is_vuln': False, 'pattern': 'literal_format',
                  'overflow_kind': 'none', 'cwe': '', 'filter': 'literal'},
        'readme': 'fprintf(fp, "%s\\n", user) — 格式为字面量, 安全。',
        'source': textwrap.dedent('''\
            #include <stdio.h>

            static void safe_fprintf(FILE *fp, const char *user)
            {
                fprintf(fp, "%s\\n", user);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                safe_fprintf(stdout, argv[1]);
                return 0;
            }
        '''),
    },

    # S03 常量来源格式变量
    {
        'name': 'FMT-S03_const_format_var',
        'cve': '',
        'category': 'fmt_safe',
        'func': 'safe_const_var',
        'truth': {'is_vuln': False, 'pattern': 'const_origin_format',
                  'overflow_kind': 'none', 'cwe': '', 'filter': 'literal_vars'},
        'readme': '格式变量为 static const 字面量来源 — 安全。',
        'source': textwrap.dedent('''\
            #include <stdio.h>

            static const char *FMT = "user=%s";

            static void safe_const_var(const char *user)
            {
                printf(FMT, user);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                safe_const_var(argv[1]);
                return 0;
            }
        '''),
    },

    # S04 snprintf 字面量 + fputs
    {
        'name': 'FMT-S04_snprintf_fputs',
        'cve': '',
        'category': 'fmt_safe',
        'func': 'safe_snp_fputs',
        'truth': {'is_vuln': False, 'pattern': 'literal_format',
                  'overflow_kind': 'none', 'cwe': '', 'filter': 'literal'},
        'readme': 'snprintf 字面量格式组装, fputs 输出 — 非格式串使用。',
        'source': textwrap.dedent('''\
            #include <stdio.h>

            static void safe_snp_fputs(const char *user)
            {
                char buf[64];
                snprintf(buf, sizeof(buf), "%s", user);
                fputs(buf, stdout);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                safe_snp_fputs(argv[1]);
                return 0;
            }
        '''),
    },

    # S05 局部字面量变量
    {
        'name': 'FMT-S05_local_literal_var',
        'cve': '',
        'category': 'fmt_safe',
        'func': 'safe_local_lit',
        'truth': {'is_vuln': False, 'pattern': 'const_origin_format',
                  'overflow_kind': 'none', 'cwe': '', 'filter': 'literal_vars'},
        'readme': '局部变量持有字面量格式 — 安全。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void safe_local_lit(int n)
            {
                char *fmt = "%d";
                printf(fmt, n);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                safe_local_lit(atoi(argv[1]));
                return 0;
            }
        '''),
    },

    # S06 syslog 字面量
    {
        'name': 'FMT-S06_syslog_literal',
        'cve': '',
        'category': 'fmt_safe',
        'func': 'safe_syslog',
        'truth': {'is_vuln': False, 'pattern': 'literal_format',
                  'overflow_kind': 'none', 'cwe': '', 'filter': 'literal'},
        'readme': 'syslog 字面量格式 — 安全。',
        'source': textwrap.dedent('''\
            #include <stdio.h>

            static void safe_syslog(const char *user)
            {
                printf("login: %s\\n", user);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                safe_syslog(argv[1]);
                return 0;
            }
        '''),
    },

    # S07 结构体字面量字段
    {
        'name': 'FMT-S07_struct_literal_field',
        'cve': '',
        'category': 'fmt_safe',
        'func': 'safe_struct_fmt',
        'truth': {'is_vuln': False, 'pattern': 'field_format',
                  'overflow_kind': 'none', 'cwe': '', 'filter': 'uncertain'},
        'readme': '结构体字段持有内部格式(不可证来源) — 抑制不报。',
        'source': textwrap.dedent('''\
            #include <stdio.h>

            struct Logger {
                const char *fmt;
            };

            static void safe_struct_fmt(struct Logger *lg, const char *user)
            {
                printf(lg->fmt, user);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                struct Logger lg = {"user=%s"};
                safe_struct_fmt(&lg, argv[1]);
                return 0;
            }
        '''),
    },

    # S08 字面量返回函数
    {
        'name': 'FMT-S08_literal_return',
        'cve': '',
        'category': 'fmt_safe',
        'func': 'safe_ret_fmt',
        'truth': {'is_vuln': False, 'pattern': 'return_format',
                  'overflow_kind': 'none', 'cwe': '', 'filter': 'uncertain'},
        'readme': '格式串来自返回字面量的函数(不可证来源) — 抑制不报。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static const char *get_fmt(void)
            {
                return "value=%d";
            }

            static void safe_ret_fmt(int n)
            {
                printf(get_fmt(), n);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                safe_ret_fmt(atoi(argv[1]));
                return 0;
            }
        '''),
    },
]
