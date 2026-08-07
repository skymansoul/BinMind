# analysis/fmt_fc_detector — FMT-FC 流相关格式串检测 (FC-VRA 方法论向格式串迁移)
# 核心创新扩展: 用"格式参数是否攻击者可达 + 格式内容是否可解析为常量"
# 把误报压下去。现有 format_string_v3 的误报来源:
#   (a) "来源不明→保守评估" 把一切非字面量格式参数都算告警 (conf 0.25),
#       而真实代码中大量 printf(local_buf) 的 local_buf 是内部拼装常量 → 安全;
#   (b) "UNINIT_STACK" 启发式 (conf 0.40) 把未初始化栈缓冲直接告警 → 纯推测。
#
# FMT-FC 管线:
#   C0 可达性: 格式参数是否被输入源污染 (污点图复用 format_string_v3)
#   C1 内容解析: 能否解析格式变量为常量字面量 → 非攻击者控制 → 安全
#   C2 写原语: 已解析内容含 %n → 仍为写原语 → 中置信告警
#   C3 分级: 污染→高置信; 未污染未解析→低置信; 已解析非%n→抑制
# 理论依据: 格式串污点传播须与常量折叠结合, 否则误报爆炸。

from __future__ import annotations
from typing import Dict, List, Set, Tuple, Optional
import re

from format_string_v3 import (
    build_taint_graph, _PRINTF_FNS, _SAFE_WRAPPERS,
    _is_format_arg_position, _parse_format_args, _FMT_SPEC_RE,
)

_FMT_FUNCS = {"printf", "fprintf", "sprintf", "snprintf", "dprintf",
              "syslog", "vsprintf", "vsnprintf", "vfprintf", "vprintf"}

def _resolve_format_literal(code: str, var: str) -> Optional[str]:
    """C1: 解析格式变量 → 常量字面量 (含经变量复制/strcpy/数组初始化)。"""
    # var = "literal" / char var[] = "literal"
    m = re.search(rf"{re.escape(var)}\s*(?:\[[^\]]*\])?\s*=\s*\"([^\"]*)\"",
                  code)
    if m:
        return m.group(1)
    # strcpy(var, "literal") / strncpy(var, "literal", n)
    m = re.search(rf"(?:strcpy|strncpy|strcat)\s*\(\s*{re.escape(var)}\s*,"
                  rf"\s*\"([^\"]*)\"", code)
    if m:
        return m.group(1)
    # 前向: 其它变量 = "literal", 且该变量赋给 var
    for other in re.findall(r"\b(\w+)\s*(?:\[[^\]]*\])?\s*=\s*\"([^\"]*)\"",
                            code):
        if re.search(rf"{re.escape(var)}\s*=\s*{re.escape(other[0])}\s*;", code):
            return other[1]
    return None

def _copy_taint(code: str, taint: Dict) -> Dict:
    """strcpy/strncpy 拷贝污染传播: 源被污染 → 目标被污染。"""
    t2 = dict(taint)
    changed = True
    while changed:
        changed = False
        for m in re.finditer(r"(?:strcpy|strncpy|strcat|memcpy)\s*\("
                             r"\s*(\w+)\s*,\s*(\w+)\s*[,)]", code):
            dst, src = m.group(1), m.group(2)
            if src in t2 and dst not in t2:
                t2[dst] = set(t2[src])
                changed = True
        for m in re.finditer(r"(?:strcpy|strncpy|strcat)\s*\("
                             r"\s*(\w+)\s*,\s*(argv\s*\[\s*\d+\s*\])", code):
            dst = m.group(1)
            if dst not in t2:
                t2[dst] = {"argv"}
                changed = True
    return t2

def _direct_buf_taint(code: str, taint: Dict) -> Dict:
    """fgets/gets/scanf 直接写入缓冲区的污染。"""
    t2 = dict(taint)
    for m in re.finditer(r"(?:fgets)\s*\(\s*(\w+)\s*,", code):
        if m.group(1) not in t2:
            t2[m.group(1)] = {"fgets"}
    for m in re.finditer(r"\bgets\s*\(\s*(\w+)\s*\)", code):
        if m.group(1) not in t2:
            t2[m.group(1)] = {"gets"}
    for m in re.finditer(r"\bscanf\s*\(\s*\"[^\"]*\"\s*,\s*&?\s*(\w+)", code):
        if m.group(1) not in t2:
            t2[m.group(1)] = {"scanf"}
    return t2

def _param_taint(code: str, taint: Dict) -> bool:
    """跨函数参数污染: 函数以 char* 参数为格式串, 且调用点传入污染值。"""
    fmt_funcs = "|".join(_FMT_FUNCS)
    for m in re.finditer(
        r"(?:static\s+)?(?:void|int|char|size_t|unsigned|long|bool)\s+"
        r"([a-zA-Z_]\w*)\s*\([^)]*?(?:const\s+)?char\s*\*\s*(\w+)"
        r"(?:\s*,\s*\.\.\.\s*)?\)", code):
        fn_name, param = m.group(1), m.group(2)
        body_start = m.end()
        # 该函数体内是否把 param 当格式串
        if not re.search(rf"\b(?:{fmt_funcs})\s*\(\s*{re.escape(param)}\b",
                         code[body_start:]):
            continue
        # 调用点: fn_name(ARG) 中 ARG 来自 argv/污染变量
        for call in re.finditer(rf"\b{re.escape(fn_name)}\s*\(\s*([^)]*?)\)",
                                code):
            arg = call.group(1).strip()
            if re.match(r"argv\s*\[", arg) or \
               re.search(r"argv\s*\[\s*\d+\s*\]", arg) or \
               any(v in taint for v in re.findall(r"\b(\w+)\b", arg)
                   if v not in ("char", "const")):
                return True
    return False

def detect_format_string_fcv3(code: str, func_name: str = "") -> List[Dict]:
    """FMT-FC 主入口。"""
    findings = []
    taint = build_taint_graph(code)
    taint = _copy_taint(code, taint)
    taint = _direct_buf_taint(code, taint)
    param_tainted = _param_taint(code, taint)
    has_safe_wrapper = any(w in code for w in _SAFE_WRAPPERS)

    for fn in _FMT_FUNCS:
        for m in re.finditer(rf"\b{re.escape(fn)}\s*\(", code):
            start = m.start()
            depth = 0
            end = start
            for i in range(start, len(code)):
                if code[i] == "(":
                    depth += 1
                elif code[i] == ")":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            args = _parse_format_args(code[start:end], fn)
            for arg_text, idx in args:
                if not _is_format_arg_position(fn, idx):
                    continue
                fmt_var = arg_text.strip()
                if fmt_var.startswith('"') or fmt_var in ("NULL", "stderr",
                                                          "stdout", "stdin"):
                    continue  # 字面量/无意义参数
                if fmt_var in ("format", "fmt", "__fmt", "__format") and \
                   fmt_var not in taint and not param_tainted:
                    continue

                # C0: 可达性
                is_tainted = bool(taint.get(fmt_var)) or \
                    bool(re.match(r"argv\s*\[", fmt_var)) or \
                    re.search(rf"argv\s*\[\s*\d+\s*\]", fmt_var) or \
                    param_tainted

                # C1: 内容解析
                resolved = _resolve_format_literal(code, fmt_var)

                # C2: 写原语检测 (仅对已解析内容)
                has_n = False
                if resolved is not None:
                    specs = _FMT_SPEC_RE.findall(resolved)
                    has_n = any("%n" in s for s in specs)

                if is_tainted:
                    conf = 0.88
                    reason = f"格式串可达输入源→攻击者可控"
                    if fmt_var.startswith("argv") or \
                       re.match(r"argv\s*\[", fmt_var):
                        conf = 0.95
                        reason += " (argv 直接)"
                elif resolved is not None:
                    if has_n:
                        conf = 0.55
                        reason = f"已解析常量含%n→写原语风险"
                    else:
                        # 常量格式串, 无 %n → 非攻击者控制 → 安全
                        continue
                else:
                    # 未污染且不可解析 → 大概率内部格式 → 抑制 (低于阈值)
                    conf = 0.15
                    reason = "来源不明且不可解析→非攻击者可控"

                if has_safe_wrapper:
                    conf = max(0.10, conf - 0.25)
                    reason += "; 编译器安全包装存在"

                findings.append({
                    "type": "format-string", "cwe": "CWE-134",
                    "function": func_name, "format_func": fn,
                    "format_arg": fmt_var,
                    "tainted": is_tainted,
                    "resolved_constant": resolved is not None,
                    "format_content": (resolved or "")[:80],
                    "has_n_writer": has_n,
                    "severity": "Critical" if conf > 0.70 else "High",
                    "confidence": round(conf, 2),
                    "description": reason,
                })

    findings.sort(key=lambda f: f["confidence"], reverse=True)
    return findings

if __name__ == "__main__":
    cases = [
        ("printf(argv[1]);", True),
        ("printf(user_buf);", True),     # 需 user_buf 被污染
        ("char f[16]; strcpy(f, \"hello %s\"); printf(f);", False),
        ("char *f = \"%s %d\"; printf(f);", False),
        ("printf(\"%n\", &n);", False),  # 常量但 %n
    ]
    for code, expect in cases:
        fs = detect_format_string_fcv3(code)
        print("=", repr(code[:40]))
        for f in fs:
            print("  ", f["confidence"], f["description"])
