#!/usr/bin/env python3
"""
CJ增强回归测试case构建 — FM边界推理、跨函数约束传播、区间域抽象解释的测试数据.
"""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.cj_constraint_types import (
    ConstraintType, LinearConstraint, ConstraintSystem, SolverVerdict,
)


def build_fm_boundary_cases():
    """FM边界推理测试用例 → list of (name, sys_obj, expected_verdict)."""
    cases = []

    # Case 10: 单向guard安全 — malloc(n), guard n<=64, write: offset_var=n store_size=4
    sys10 = ConstraintSystem(
        alloc_size=0, alloc_var='n', store_size=4,
        offset_var='n', mnemonic='store',
    )
    sys10.add(LinearConstraint(
        coefficients={'n': 1.0}, constant=-64,
        operator="<=", source=ConstraintType.GUARD_CONDITION,
        confidence=0.90, description="if(n>64) return"))
    cases.append(("10.单向guard安全 n<=64+off=n+4", sys10, SolverVerdict.PROVEN_SAFE))

    # Case 11: 单向guard溢出 — malloc(64), guard n>=65, write: offset=n+8
    sys11 = ConstraintSystem(
        alloc_size=64, alloc_var='', store_size=8,
        offset_var='n', mnemonic='store',
    )
    sys11.add(LinearConstraint(
        coefficients={'n': 1.0}, constant=-65,
        operator=">=", source=ConstraintType.GUARD_CONDITION,
        confidence=0.90, description="if(n<65) return → continuation n>=65"))
    cases.append(("11.单向guard溢出 n>=65+off=n+8,alloc64", sys11, SolverVerdict.PROVEN_OVERFLOW))

    # Case 12: 循环guard安全 — malloc(64), loop_bound=8, store_size=4
    sys12 = ConstraintSystem(
        alloc_size=64, store_size=4, loop_bound=8,
        loop_var='i', mnemonic='store',
    )
    cases.append(("12.循环安全 malloc(64)+loop8*4B", sys12, SolverVerdict.PROVEN_SAFE))

    # Case 13: 双变量FM推导 — write_end = m + 4, m <= 50, alloc_size=64 usable=72
    sys13 = ConstraintSystem(
        alloc_size=64, alloc_var='', store_size=4,
        offset_var='m', mnemonic='store',
    )
    sys13.add(LinearConstraint(
        coefficients={'m': 1.0}, constant=-50,
        operator="<=", source=ConstraintType.GUARD_CONDITION,
        confidence=0.90, description="if(m>50) return → m<=50"))
    cases.append(("13.双变量FM安全 m<=50+off=m+4,alloc64", sys13, SolverVerdict.PROVEN_SAFE))

    return cases


def build_interproc_cases():
    """跨函数约束传播测试用例 → list of (name, sys_obj, code, alloc_func, write_func, expected_verdict)."""
    cases = []

    # Case 14: 跨函数guard安全
    sys14 = ConstraintSystem(
        alloc_size=0, alloc_var='n', store_size=4,
        offset_var='n', mnemonic='store',
    )
    code14 = """
int caller(int n) {
    char *buf = helper_alloc(n);
    write_data(buf, n);
    return 0;
}
char *helper_alloc(int n) {
    return (char*)malloc(n);
}
void write_data(char *buf, int n) {
    if (n > 64) return;
    buf[n] = 'x';
}
"""
    cases.append(("14.跨函数guard安全 n<=64+off=n+4", sys14, code14,
                   "helper_alloc", "write_data", SolverVerdict.PROVEN_SAFE))

    # Case 15: 跨函数无guard — INCONCLUSIVE
    sys15 = ConstraintSystem(
        alloc_size=0, alloc_var='n', store_size=4,
        offset_var='n', mnemonic='store',
    )
    code15 = """
int caller(int n) {
    char *buf = helper_alloc(n);
    write_data(buf, n);
    return 0;
}
char *helper_alloc(int n) {
    return (char*)malloc(n);
}
void write_data(char *buf, int n) {
    buf[n] = 'x';
}
"""
    cases.append(("15.跨函数无guard n+4", sys15, code15,
                   "helper_alloc", "write_data", SolverVerdict.INCONCLUSIVE))

    # Case 16: 共同调用者guard
    sys16 = ConstraintSystem(
        alloc_size=0, alloc_var='n', store_size=4,
        offset_var='n', mnemonic='store',
    )
    code16 = """
int caller(int n) {
    if (n > 64) return -1;
    char *buf = helper_alloc(n);
    write_data(buf, n);
    return 0;
}
char *helper_alloc(int n) {
    return (char*)malloc(n);
}
void write_data(char *buf, int n) {
    buf[n] = 'x';
}
"""
    cases.append(("16.共同调用者guard n<=64+off=n+4", sys16, code16,
                   "helper_alloc", "write_data", SolverVerdict.PROVEN_SAFE))

    return cases


def build_interval_domain_cases():
    """区间域抽象解释测试用例 → (name, sys_obj, ir_lines, code, expected_verdict) 或特殊标记."""
    cases = []

    # Case 17: 路径条件传播
    code17 = """int func(int n) {
    if (n <= 100) {
        char *buf = malloc(n);
        buf[n] = 'x';
    }
}"""
    sys17 = ConstraintSystem(
        alloc_size=0, alloc_var='n', store_size=1,
        offset_var='n', mnemonic='store',
    )
    cases.append(("17.路径条件传播", sys17, [], code17, SolverVerdict.PROVEN_SAFE))

    # Case 20: 不动点收敛
    sys20 = ConstraintSystem(
        alloc_size=64, store_size=4,
        offset_var='m', mnemonic='store',
    )
    sys20.add(LinearConstraint(
        coefficients={'m': 1.0}, constant=-50,
        operator="<=", source=ConstraintType.GUARD_CONDITION,
        confidence=0.90, description="m <= 50"))
    ir20 = ["m = getval();", "if (m <= 50) {", "  buf[m] = 'x';", "}"]
    cases.append(("20.不动点收敛", sys20, ir20, "", SolverVerdict.PROVEN_SAFE))

    return cases
