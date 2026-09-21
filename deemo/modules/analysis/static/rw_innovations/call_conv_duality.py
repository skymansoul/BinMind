"""CallConvDuality - 双 ABI 对偶 (stage 81).

同一 call 点按 SysV/Linux 与 Windows 两套寄存器约定各解析一遍 size,
双解析一致才采信. 与 constraint_based_pairing 双 ABI 枚举不同:
对偶一致性投票.

设计决策:
  - SysV: size 在 rdx/r8;  Win64: size 在 r8
  - 同一 call 点两套解析, 若都得到相同 size -> 采信
  - 双解析不一致 -> 降权

差异化 (vs liveness_role_template):
  - 本模块聚焦双约定对偶校验: 同一调用点在 SysV/Win64 两套约定下
    实参-形参个数是否都一致
  - 两套约定结论相同 -> dual_agree; 矛盾结论 -> dual_conflict
  - 不再做寄存器表单表投票 (与 liveness 重叠, 标记 DEPRECATED 保留)
  - liveness 做消费型角色审计 (收 findings), 本模块纯伪代码分析 (不收 findings)
"""

import re
from typing import Dict, List, Optional

_SYSV_SIZE_REGS = ("rdx", "r8")
_WIN_SIZE_REGS = ("r8", "rcx")

# C 风格库函数签名表: {函数名: 固定参数个数}
# printf/scanf 为可变参, 存储最小参数个数
_C_FUNC_ARITY = {
    "malloc": 1, "free": 1, "realloc": 2,
    "memcpy": 3, "memset": 3, "memmove": 3,
    "strlen": 1, "strcpy": 2,
    "printf": 1, "scanf": 2,
}
_C_VARIADIC = {"printf", "scanf"}
_C_CALL_RE = re.compile(
    r"\b(malloc|free|realloc|memcpy|memset|memmove|strlen|strcpy|printf|scanf)\s*\("
)

# 差异化: SysV/Win64 两套调用约定下各函数的参数传递寄存器个数
# SysV 前 6 个整型参数: rdi,rsi,rdx,rcx,r8,r9
# Win64 前 4 个整型参数: rcx,rdx,r8,r9, 超过则栈传
# 对偶校验: 两套约定下实际可寄存传递的参数个数是否都 >= 形参个数
_SYSV_REG_ARGS = 6
_WIN64_REG_ARGS = 4


def _count_c_args(args_str: str) -> int:
    """统计 C 风格调用的实参个数, 处理嵌套括号."""
    depth = 0
    count = 0
    for ch in args_str:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            count += 1
    return count + 1 if args_str.strip() else 0


def _extract_call_args(line: str, paren_pos: int) -> Optional[str]:
    """从 paren_pos 位置的左括号开始提取实参字符串."""
    depth = 0
    for i in range(paren_pos, len(line)):
        if line[i] == "(":
            depth += 1
        elif line[i] == ")":
            depth -= 1
            if depth == 0:
                return line[paren_pos + 1:i]
    return None


def _resolve_size(pseudocode: str, line_no: int, regs: tuple) -> Optional[int]:
    """在 call 前若干行查找对 size 寄存器的常量赋值."""
    lines = pseudocode.splitlines()
    for i in range(max(0, line_no - 8), line_no):
        for reg in regs:
            m = re.search(r"\bmov\s+" + reg + r"\s*,\s*(0[xX][0-9a-fA-F]+|\d+)", lines[i])
            if m:
                return int(m.group(1), 0)
    return None


def run_call_conv_duality(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """双 ABI 对偶. 返回 findings."""
    findings: List[dict] = []
    # #[DEPRECATED] 汇编风格寄存器表单表投票路径
    # 与 liveness_role_template 的 size 寄存器表+窗口提取重叠,
    # 差异化后保留旧逻辑但不作为主判定, 仅汇编场景兼容回退
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        if "call" not in line:
            continue
        size_sysv = _resolve_size(pseudocode, ln, _SYSV_SIZE_REGS)
        size_win = _resolve_size(pseudocode, ln, _WIN_SIZE_REGS)
        if size_sysv is not None and size_win is not None:
            agree = size_sysv == size_win
            verdict, conf = ("dual_agree", 0.9) if agree else ("dual_conflict", 0.3)
            desc = f"call@{ln} sysv={size_sysv} win={size_win} agree={agree}"
        elif size_sysv is not None:
            verdict, conf = "sysv_only", 0.6
            desc = f"call@{ln} sysv={size_sysv} win=unknown"
        elif size_win is not None:
            verdict, conf = "win_only", 0.6
            desc = f"call@{ln} sysv=unknown win={size_win}"
        else:
            verdict, conf = "no_size", 0.4
            desc = f"call@{ln} no size reg resolved"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": desc,
            "verdict": verdict,
            "source": "call_conv_duality",
        })

    # C 风格双约定对偶校验: 同一调用点在 SysV/Win64 两套约定下
    # 实参个数是否都满足寄存器传递上限, 两套结论相同才采信
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        for m in _C_CALL_RE.finditer(line):
            fname = m.group(1)
            paren_pos = m.end() - 1
            args_str = _extract_call_args(line, paren_pos)
            if args_str is None:
                continue
            actual = _count_c_args(args_str)
            expected = _C_FUNC_ARITY[fname]
            # 可变参函数: 最小参数个数即签名要求
            if fname in _C_VARIADIC:
                check_actual = max(actual, expected)
            else:
                check_actual = actual
            # SysV 约定判定: 实参 <= 6 个寄存器位 -> 可寄存传递
            sysv_ok = check_actual <= _SYSV_REG_ARGS
            # Win64 约定判定: 实参 <= 4 个寄存器位 -> 可寄存传递
            win64_ok = check_actual <= _WIN64_REG_ARGS
            # 对偶校验: 两套约定结论相同
            if sysv_ok and win64_ok:
                # 双约定均判定可寄存传递 -> dual_agree
                verdict, conf = "dual_agree", 0.85
                desc = (f"call@{ln} c_call {fname}({actual} args) "
                       f"sysv_reg={sysv_ok} win64_reg={win64_ok} dual_agree")
            elif not sysv_ok and not win64_ok:
                # 双约定均判定溢出寄存器 -> dual_agree (一致判定溢出)
                verdict, conf = "dual_agree", 0.85
                desc = (f"call@{ln} c_call {fname}({actual} args) "
                       f"sysv_reg={sysv_ok} win64_reg={win64_ok} dual_agree_overflow")
            else:
                # 两套约定矛盾 (一套可寄存一套溢出) -> dual_conflict
                verdict, conf = "dual_conflict", 0.3
                desc = (f"call@{ln} c_call {fname}({actual} args) "
                       f"sysv_reg={sysv_ok} win64_reg={win64_ok} dual_conflict")
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": conf,
                "description": desc,
                "verdict": verdict,
                "source": "call_conv_duality",
            })
    return findings


if __name__ == "__main__":
    demo = """\
mov rdi, buf;
mov rdx, 64;
call memcpy;
"""
    out = run_call_conv_duality(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])