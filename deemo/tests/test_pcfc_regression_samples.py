#!/usr/bin/env python3
"""
PCFC回归测试样本 — 24个C源码样本+期望结果.

样本分类:
  MUTEX_FP (1-6): 路径互斥 — taint与sink在不同分支
  EARLY_FP (7-10): early-return — sink前有无条件return
  COND_FP (11-14): 条件赋值 — 变量在安全分支赋值, sink也在安全分支
  TP_VULN (15-24): 真实漏洞 — 各类路径条件下仍可达
"""

# 每项: (name, source, expected_vuln)
PCFC_CASES = [
# MUTEX_FP: taint与sink在互斥路径 → PCFC过滤
    ("01.mutex: if/else taint-sink分支互斥", """
int main(int argc, char **argv) {
    char *fmt;
    int safe = 1;
    if (safe) {
        fmt = "constant";
        printf(fmt);
    } else {
        fmt = argv[1];
    }
    return 0;
}
""", False),

    ("02.mutex: flag条件互斥", """
int main(int argc, char **argv) {
    char *fmt;
    int flag = argc;
    if (flag) {
        fmt = argv[1];
    }
    if (!flag) {
        printf(fmt);
    }
    return 0;
}
""", False),

    ("03.mutex: mode比较互斥", """
int main(int argc, char **argv) {
    char *fmt;
    int mode = argc;
    if (mode == 1) {
        fmt = argv[1];
    }
    if (mode != 1) {
        printf(fmt);
    }
    return 0;
}
""", False),

    ("04.mutex: if/else-if分支互斥", """
int main(int argc, char **argv) {
    char *fmt;
    int level = argc;
    if (level > 0) {
        fmt = "safe_msg";
    } else {
        fmt = argv[1];
    }
    if (level > 0) {
        printf(fmt);
    }
    return 0;
}
""", False),

    ("05.mutex: 嵌套if互斥", """
int main(int argc, char **argv) {
    char *fmt;
    int trusted = 1;
    if (trusted) {
        if (argc > 1) {
            fmt = "constant";
        } else {
            fmt = "default";
        }
        printf(fmt);
    } else {
        fmt = argv[1];
    }
    return 0;
}
""", False),

    ("06.mutex: 条件取反互斥", """
int main(int argc, char **argv) {
    char *fmt;
    int validated = argc > 1;
    if (validated) {
        fmt = "ok";
    } else {
        fmt = argv[1];
    }
    if (validated) {
        printf(fmt);
    }
    return 0;
}
""", False),

# EARLY_FP: sink前有无条件return → PCFC过滤
    ("07.early: 无条件return阻断sink", """
int main(int argc, char **argv) {
    char *fmt = argv[1];
    return 0;
    printf(fmt);
}
""", False),

    ("08.early: 无条件exit阻断sink", """
int main(int argc, char **argv) {
    char *fmt = argv[1];
    exit(1);
    printf(fmt);
}
""", False),

    ("09.early: 无条件abort阻断sink", """
int main(int argc, char **argv) {
    char *fmt = argv[1];
    abort();
    printf(fmt);
}
""", False),

    ("10.early: return在分支中条件不满足时sink可达", """
int main(int argc, char **argv) {
    char *fmt = argv[1];
    if (argc > 99) {
        return 0;
    }
    printf(fmt);
    return 0;
}
""", True),

# COND_FP: 条件赋值/路径受限sink → PCFC过滤
    ("11.cond: safe分支赋常 unsafe分支赋taint, sink在safe分支", """
int main(int argc, char **argv) {
    char *fmt;
    int safe = argc > 1;
    if (safe) {
        fmt = "constant";
    } else {
        fmt = argv[1];
    }
    if (safe) {
        printf(fmt);
    }
    return 0;
}
""", False),

    ("12.cond: validated路径安全赋值", """
int main(int argc, char **argv) {
    char *fmt;
    int validated = 1;
    if (validated) {
        fmt = "safe_format";
    } else {
        fmt = argv[1];
    }
    if (validated) {
        printf(fmt);
    }
    return 0;
}
""", False),

    ("13.cond: if/else链安全赋值 受限sink(mode!=2过滤else分支)", """
int main(int argc, char **argv) {
    char *fmt;
    int mode = 2;
    if (mode == 0) {
        fmt = "zero";
    } else if (mode == 1) {
        fmt = "one";
    } else {
        fmt = argv[1];
    }
    if (mode == 0 || mode == 1) {
        printf(fmt);
    }
    return 0;
}
""", False),

    ("14.cond: 多变量条件赋值", """
int main(int argc, char **argv) {
    char *fmt;
    int level = 1;
    int debug = 0;
    if (level && debug) {
        fmt = argv[1];
    } else {
        fmt = "safe";
    }
    if (!debug) {
        printf(fmt);
    }
    return 0;
}
""", False),

]

# 从独立文件导入TP_VULN样本
from tests.test_pcfc_regression_samples_vuln import TP_VULN_CASES
PCFC_CASES.extend(TP_VULN_CASES)
