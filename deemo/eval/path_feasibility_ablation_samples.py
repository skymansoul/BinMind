"""

四种FP类型 + TP漏洞样本, 验证路径可行性检查各子模块的增量过滤能力.
"""
from __future__ import annotations
from typing import List, Tuple

# FP样本: 路径约束收集验证判VULN但实际SAFE
MUTEX_FP: List[Tuple[str, str, str]] = [
    ('mutex_01', """
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
""", 'SAFE'),
    ('mutex_02', """
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
""", 'SAFE'),
    ('mutex_03', """
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
""", 'SAFE'),
    ('mutex_04', """
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
""", 'SAFE'),
    ('mutex_05', """
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
""", 'SAFE'),
    ('mutex_06', """
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
""", 'SAFE'),
]

EARLY_FP: List[Tuple[str, str, str]] = [
    ('early_01', """
int main(int argc, char **argv) {
    char *fmt = argv[1];
    return 0;
    printf(fmt);
}
""", 'SAFE'),
    ('early_02', """
int main(int argc, char **argv) {
    char *fmt = argv[1];
    exit(1);
    printf(fmt);
}
""", 'SAFE'),
    ('early_03', """
int main(int argc, char **argv) {
    char *fmt = argv[1];
    abort();
    printf(fmt);
}
""", 'SAFE'),
]

COND_FP: List[Tuple[str, str, str]] = [
    ('cond_01', """
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
""", 'SAFE'),
    ('cond_02', """
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
""", 'SAFE'),
    ('cond_03', """
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
""", 'SAFE'),
    ('cond_04', """
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
""", 'SAFE'),
]

# TP样本: 真实漏洞, 路径可行性检查不得过滤
TP_VULN: List[Tuple[str, str, str]] = [
    ('tp_01', """
int main(int argc, char **argv) {
    char *fmt = argv[1];
    printf(fmt);
    return 0;
}
""", 'VULN'),
    ('tp_02', """
int main(int argc, char **argv) {
    char *fmt;
    int trusted = argc > 1;
    if (trusted) {
        fmt = argv[1];
        printf(fmt);
    }
    return 0;
}
""", 'VULN'),
    ('tp_03', """
int main(int argc, char **argv) {
    char *fmt;
    int safe = argc > 1;
    if (safe) {
        fmt = "constant";
    } else {
        fmt = argv[1];
    }
    if (!safe) {
        printf(fmt);
    }
    return 0;
}
""", 'VULN'),
    ('tp_04', """
int main() {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    printf(buf);
    return 0;
}
""", 'VULN'),
    ('tp_05', """
int main() {
    char *val = getenv("PATH");
    printf(val);
    return 0;
}
""", 'VULN'),
    ('tp_06', """
int main(int argc, char **argv) {
    char buf[256];
    strcpy(buf, argv[1]);
    printf(buf);
    return 0;
}
""", 'VULN'),
    ('tp_07', """
int main(int argc, char **argv) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", argv[1]);
    printf(buf);
    return 0;
}
""", 'VULN'),
    ('tp_08', """
int main(int argc, char **argv) {
    char *fmt = argv[1];
    if (argc > 99) {
        return 0;
    }
    printf(fmt);
    return 0;
}
""", 'VULN'),
    ('tp_09', """
int main(int argc, char **argv) {
    char *fmt;
    if (argc > 1) {
        fmt = argv[1];
    } else {
        fmt = "safe";
    }
    if (argc > 1) {
        printf(fmt);
    }
    return 0;
}
""", 'VULN'),
    ('tp_10', """
int main(int argc, char **argv) {
    char *fmt;
    int mode = argc;
    if (mode == 1) {
        fmt = argv[1];
    } else if (mode == 2) {
        fmt = argv[2];
    } else {
        fmt = argv[3];
    }
    printf(fmt);
    return 0;
}
""", 'VULN'),
]

ALL_SAMPLES = MUTEX_FP + EARLY_FP + COND_FP + TP_VULN

__all__ = [
    'MUTEX_FP', 'EARLY_FP', 'COND_FP', 'TP_VULN', 'ALL_SAMPLES',
]
