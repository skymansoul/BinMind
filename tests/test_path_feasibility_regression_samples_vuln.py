#!/usr/bin/env python3
"""路径可行性检查回归测试TP_VULN样本 — 真实漏洞样本(15-24), 路径可行性检查不得过滤."""

# 每项: (name, source, expected_vuln)
TP_VULN_CASES = [
    ("15.real: 无路径条件直接taint", """
int main(int argc, char **argv) {
    char *fmt = argv[1];
    printf(fmt);
    return 0;
}
""", True),

    ("16.real: taint和sink在同一路径", """
int main(int argc, char **argv) {
    char *fmt;
    int trusted = argc > 1;
    if (trusted) {
        fmt = argv[1];
        printf(fmt);
    }
    return 0;
}
""", True),

    ("17.real: 条件赋值但sink在tainted路径", """
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
""", True),

    ("18.real: fgets型taint无路径保护", """
int main() {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    printf(buf);
    return 0;
}
""", True),

    ("19.real: getenv型taint无路径保护", """
int main() {
    char *val = getenv("PATH");
    printf(val);
    return 0;
}
""", True),

    ("20.real: strcpy间接taint无路径保护", """
int main(int argc, char **argv) {
    char buf[256];
    strcpy(buf, argv[1]);
    printf(buf);
    return 0;
}
""", True),

    ("21.real: snprintf %s透传无路径保护", """
int main(int argc, char **argv) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", argv[1]);
    printf(buf);
    return 0;
}
""", True),

    ("22.real: 条件return但不阻断sink路径", """
int main(int argc, char **argv) {
    char *fmt = argv[1];
    if (argc > 99) {
        return 0;
    }
    printf(fmt);
    return 0;
}
""", True),

    ("23.real: mutex路径但sink在tainted分支", """
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
""", True),

    ("24.real: 多条路径均可达taint+sink", """
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
""", True),
]
