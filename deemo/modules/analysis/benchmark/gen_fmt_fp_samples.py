"""批量生成格式化字符串对抗样本 (8 误报诱发 + 8 真实漏洞).

设计依据: 针对 binary_fmt_scanner 的已知误报根源 —
  R-F1: 栈槽加载一律视为用户可控 (栈槽常量初始化字符串被误报)
  R-F2: 非 .rdata 来源即报 "possibly user-controlled" (conf 0.35)
  R-F5: 常量格式串中的 %n 被当作写原语 (printf("..%n", &count) 合法)

每个 fp_NN 对应一个同形态真漏洞 vuln_NN, 用于验证改进在
消除误报时不损失召回.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _sample_writer import write_sample

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "samples_fmt_fp")

SAMPLES = {
    # 误报诱发 (安全)
    "fp_01_const_fmt_printf": {
        "kind": "safe",
        "desc": "printf 常量格式串 — 最基础安全形态",
        "code": r"""#include <stdio.h>
int main(int argc, char **argv) {
    printf("hello %d\n", argc);   /* 常量格式串 + 匹配参数 */
    return 0;
}
""",
    },
    "fp_02_stack_init_fmt": {
        "kind": "safe",
        "desc": "栈数组初始化为字面量后作为格式串",
        "code": r"""#include <stdio.h>
int main(int argc, char **argv) {
    char fmt[32] = "val=%d\n";    /* 栈槽常量初始化 */
    printf(fmt, argc);            /* 内容恒定, 非用户可控 */
    return 0;
}
""",
    },
    "fp_03_rdata_copy_fmt": {
        "kind": "safe",
        "desc": "从 .rdata 复制到栈缓冲再格式化",
        "code": r"""#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char fmt[64];
    strcpy(fmt, "count=%d\n");    /* 复制自常量字符串 */
    printf(fmt, argc);
    return 0;
}
""",
    },
    "fp_04_pctn_normal": {
        "kind": "safe",
        "desc": "常量格式串含 %n, 写入本地计数变量 — 合法用法",
        "code": r"""#include <stdio.h>
int main(void) {
    int written = 0;
    printf("prefix%n-suffix\n", &written);  /* %n 目标为本地地址 */
    return written == 0;
}
""",
    },
    "fp_05_heap_fmt_literal": {
        "kind": "safe",
        "desc": "堆缓冲复制常量字符串后格式化",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *fmt = (char *)malloc(64);
    if (!fmt) return 1;
    strcpy(fmt, "status=%d\n");   /* 常量内容 */
    printf(fmt, argc);
    free(fmt);
    return 0;
}
""",
    },
    "fp_06_args_matched": {
        "kind": "safe",
        "desc": "多说明符常量串 + 完整参数列表",
        "code": r"""#include <stdio.h>
int main(int argc, char **argv) {
    printf("%s:%d (%s)\n", argv[0], argc, "prog");
    return 0;
}
""",
    },
    "fp_07_param_passthrough": {
        "kind": "safe",
        "desc": "包装函数内常量格式串, 用户数据仅作参数",
        "code": r"""#include <stdio.h>
static void log_msg(const char *user) {
    printf("user=%s\n", user);    /* 格式串常量, user 是参数 */
}
int main(int argc, char **argv) {
    log_msg(argc > 1 ? argv[1] : "anon");
    return 0;
}
""",
    },
    "fp_08_snprintf_safe": {
        "kind": "safe",
        "desc": "snprintf 常量格式串 + 有界输出",
        "code": r"""#include <stdio.h>
int main(int argc, char **argv) {
    char out[128];
    snprintf(out, sizeof(out), "argc=%d", argc);
    printf("%s\n", out);
    return 0;
}
""",
    },
    # 真实漏洞 (对照)
    "vuln_01_user_fmt_argv": {
        "kind": "vuln",
        "desc": "argv 直接作格式串",
        "code": r"""#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    printf(argv[1]);              /* 用户输入作格式串 */
    printf("\n");
    return 0;
}
""",
    },
    "vuln_02_heap_fmt_argv": {
        "kind": "vuln",
        "desc": "堆缓冲装入 argv 后格式化",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char *fmt = (char *)malloc(strlen(argv[1]) + 1);
    if (!fmt) return 1;
    strcpy(fmt, argv[1]);         /* 用户输入进堆 */
    printf(fmt);
    free(fmt);
    return 0;
}
""",
    },
    "vuln_03_pctn_write": {
        "kind": "vuln",
        "desc": "用户格式串含 %n 写原语",
        "code": r"""#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    printf(argv[1]);              /* 攻击者可控 %n 写任意地址 */
    return 0;
}
""",
    },
    "vuln_04_stack_fmt_gets": {
        "kind": "vuln",
        "desc": "gets 读入栈缓冲后格式化",
        "code": r"""#include <stdio.h>
int main(void) {
    char fmt[64];
    gets(fmt);                    /* 用户输入 */
    printf(fmt);
    return 0;
}
""",
    },
    "vuln_05_recv_fmt": {
        "kind": "vuln",
        "desc": "网络接收数据作格式串",
        "code": r"""#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char fmt[128];
    if (argc < 2) return 1;
    strncpy(fmt, argv[1], sizeof(fmt) - 1);   /* 模拟 recv 输入 */
    fmt[sizeof(fmt) - 1] = '\0';
    printf(fmt);
    return 0;
}
""",
    },
    "vuln_06_pctn_heap": {
        "kind": "vuln",
        "desc": "堆格式串含 %n (用户可控堆内容)",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char *fmt = (char *)malloc(128);
    if (!fmt) return 1;
    snprintf(fmt, 128, "%s", argv[1]);
    printf(fmt);                  /* 用户可控 + %n 风险 */
    free(fmt);
    return 0;
}
""",
    },
    "vuln_07_fprintf_user": {
        "kind": "vuln",
        "desc": "fprintf 用户格式串",
        "code": r"""#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    fprintf(stderr, argv[1]);
    return 0;
}
""",
    },
    "vuln_08_sprintf_user": {
        "kind": "vuln",
        "desc": "sprintf 用户格式串写入输出缓冲",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char *out = (char *)malloc(256);
    if (!out) return 1;
    sprintf(out, argv[1]);        /* 用户格式串 */
    free(out);
    return 0;
}
""",
    },
}




if __name__ == "__main__":
    for name, info in SAMPLES.items():
        write_sample(name, info, OUT)
        print(f"  [OK] {name}")
    print(f"Generated {len(SAMPLES)} fmt samples in {OUT}")
