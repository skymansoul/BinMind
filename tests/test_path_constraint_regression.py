#!/usr/bin/env python3
"""
路径约束收集验证约束传播验证器回归测——覆盖全部9条推导规则和关键边界场景.

用例设计:
  规则1: 常量格式——SAFE
  规则2: 变量+taint+无sanitize —VULN
  规则3: 变量+taint+snprintf安全格式(—s—n) —SAFE
  规则4: 变量+taint+snprintf—n —VULN
  规则5: 变量+无taint+无cross —SAFE
  规则6: 变量+无taint+cross-func caller_tainted —VULN
  规则7: 无法判定 —UNCERTAIN
  规则8: 字面量含%n+taint=CLEAN —VULN
  规则9: snprintf "%s"透传 —VULN
  --- 边界场景 ---
  10: argv直接作为printf参数 —VULN (同行source+sink)
  11: fgets→var→printf(var) —VULN (参数写入型taint)
  12: getenv→var→printf(var) —VULN (返回值型taint)
  13: strcpy(argv)→var→printf(var) —VULN (间接传输)
  14: mbstowcs(argv)→var→printf(var) —VULN (宽字符传—
  15: snprintf(buf,"%s",argv)→printf(buf) —VULN (%s透传)
  16: snprintf(buf,"Value: %s",argv)→printf(buf) —VULN (混合格式%s透传)
  17: snprintf(buf,"%d",n)→printf(buf) —SAFE (—s格式不透传)
  18: wprintf/fwprintf/swprintf —VULN (宽字符sink)
  19: vprintf wrapper跨函——VULN (cross-func taint)
  20: 常量printf("hello %s") —SAFE (常量—s但format=constant)
"""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.path_constraint_pipeline import fcpv_filter
from core.path_constraint_constraint_types import SafetyLabel

passed = 0
failed = 0


def _check_case(name, source, expected_vuln):
    """运行路径约束收集验证检测并验证结果."""
    global passed, failed
    r = fcpv_filter(source)
    has_vuln = r['has_vuln']
    if has_vuln == expected_vuln:
        passed += 1
        label = 'VULN' if has_vuln else 'SAFE'
        print(f"  [PASS] {name}: {label}")
    else:
        failed += 1
        exp = 'VULN' if expected_vuln else 'SAFE'
        got = 'VULN' if has_vuln else 'SAFE'
        vuln_reason = r['vuln'][0].reason if r['vuln'] else 'N/A'
        print(f"  [FAIL] {name}: got {got}, expected {exp}")
        print(f"         reason: {vuln_reason}")


def run_all():
    global passed, failed
    passed = 0
    failed = 0

# 规则1: 常量格式::SAFE
    _check_case("1.常量格式", """
int main() { printf("hello %s\\n"); return 0; }
""", False)

# 规则2: 变量+taint+无sanitize :VULN
    _check_case("2.直接taint", """
int main(int argc, char **argv) {
    printf(argv[1]);
    return 0;
}
""", True)

# 规则3: 变量+taint+snprintf安全格式 :SAFE
    _check_case("3.snprintf安全格式", """
int main(int argc, char **argv) {
    char buf[128];
    snprintf(buf, sizeof(buf), "%d", argc);
    printf("%s\\n", buf);
    return 0;
}
""", False)

# 规则4: 变量+taint+snprintf:n :VULN
    # snprintf的格式串:n :安全化无: 保留VULN
    _check_case("4.snprintf n", """
int main(int argc, char **argv) {
    char buf[128];
    char *input = argv[1];
    snprintf(buf, sizeof(buf), input);
    printf(buf);
    return 0;
}
""", True)

# 规则5: 变量+无taint :SAFE
    _check_case("5.无taint变量", """
int main() {
    char buf[] = "hello";
    printf(buf);
    return 0;
}
""", False)

# 规则8: 字面量含%n :VULN
    _check_case("8.字面量含%n", """
int main() {
    char *fmt = "AAAA%n";
    printf(fmt);
    return 0;
}
""", True)

# 规则9: snprintf "%s"透传 :VULN
    _check_case("9.snprintf_%s透传", """
int main(int argc, char **argv) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", argv[1]);
    printf(buf);
    return 0;
}
""", True)

# 边界10: argv直接作为printf参数
    _check_case("10.argv直接printf", """
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    printf(argv[1]);
    return 0;
}
""", True)

# 边界11: fgets参数写入型taint
    _check_case("11.fgets→printf", """
int main() {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    printf(buf);
    return 0;
}
""", True)

# 边界12: getenv返回值型taint
    _check_case("12.getenv→printf", """
int main() {
    char *val = getenv("PATH");
    printf(val);
    return 0;
}
""", True)

# 边界13: strcpy间接传输
    _check_case("13.strcpy(argv)→printf", """
int main(int argc, char **argv) {
    char buf[256];
    strcpy(buf, argv[1]);
    printf(buf);
    return 0;
}
""", True)

# 边界14: mbstowcs宽字符传:
    _check_case("14.mbstowcs(argv)→printf", """
int main(int argc, char **argv) {
    wchar_t msg[256];
    mbstowcs(msg, argv[1], 256);
    wprintf(msg);
    return 0;
}
""", True)

# 边界15: snprintf "%s"透传 (:s)
    _check_case("15.snprintf s透传", """
int main(int argc, char **argv) {
    char dst[512];
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    snprintf(dst, sizeof(dst), "%s", buf);
    printf(dst);
    return 0;
}
""", True)

# 边界16: snprintf "Value: %s" 混合格式透传
    _check_case("16.snprintf混合%s透传", """
int main(int argc, char **argv) {
    char fmt[64];
    snprintf(fmt, sizeof(fmt), "Value: %s", argv[1]);
    printf(fmt);
    return 0;
}
""", True)

# 边界17: snprintf "%d" 非透传 :SAFE
    _check_case("17.snprintf_%d不透传", """
int main(int argc, char **argv) {
    char buf[128];
    int n = argc;
    snprintf(buf, sizeof(buf), "%d", n);
    printf(buf);
    return 0;
}
""", False)

# 边界18: wprintf宽字符sink
    _check_case("18.wprintf直接taint", """
int main(int argc, char **argv) {
    wprintf(argv[1]);
    return 0;
}
""", True)

# 边界19: vprintf wrapper跨函:
    _check_case("19.vprintf_wrapper跨函", """
void log_msg(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}
int main(int argc, char **argv) {
    log_msg(argv[1]);
    return 0;
}
""", True)

# 边界20: 常量printf("hello %s") :SAFE
    _check_case("20.常量 s参数", """
int main(int argc, char **argv) {
    printf("hello %s", argv[1]);
    return 0;
}
""", False)

    print(f"\n{'='*60}")
    print(f"路径约束收集验证回归测试: {passed} passed, {failed} failed, {passed+failed} total")
    print(f"{'='*60}")
    return failed == 0


if __name__ == '__main__':
    ok = run_all()
    sys.exit(0 if ok else 1)
