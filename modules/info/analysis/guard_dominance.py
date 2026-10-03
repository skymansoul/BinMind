# analysis/guard_dominance — FC-VRA 阶段C3: 支配守卫检测
# 守卫必须"支配"sink 且约束写入量变量才算数。
# 现有 path_feasibility_check 只要代码中任意位置存在守卫模式便累加
# guard_strength, 忽略了两个事实:
#   (a) 守卫可能位于与写入点完全无关的分支中 (非支配)
#   (b) 守卫约束的变量可能不是写入量变量 (无关守卫)
# 这两类"幽灵守卫"是误报的又一来源 — 本模块按括号作用域做结构支配近似,
# 只承认"写入点词法上位于守卫块内/守卫之后"且"守卫约束写入量变量"的守卫。
#
# 支持的守卫形态:
#   直接守卫:   if (len <= N) { ...memcpy(...,len)... }   → 块内
#   早退守卫:   if (len > N) return;  ...memcpy(...,len)... → 逆约束
#   钳制守卫:   if (n > N) n = N;  ...memcpy(...,n)...      → 变量被截断
#   三目/下限:  len = min(len, N); / len = n < N ? n : N;
#
# 理论依据: 结构化程序的作用域支配; 与验证器对守卫的支配性要求一致。

from __future__ import annotations
from typing import Dict, List, Tuple, Optional
import re

def _extract_size_vars(size_expr: str) -> List[str]:
    """从写入量表达式提取参与变量。"""
    if not size_expr:
        return []
    expr = size_expr.replace(" ", "")
    parts = re.split(r"[*+()]", expr)
    vars_ = []
    for p in parts:
        p = p.strip()
        if p and not p.isdigit() and re.match(r"^\w+$", p):
            if p not in vars_:
                vars_.append(p)
    return vars_

def _brace_chain(code: str, pos: int) -> List[int]:
    """返回从内到外包裹 pos 的 '{' 位置列表 (结构支配链)。"""
    chain = []
    depth = 0
    for i in range(pos - 1, -1, -1):
        ch = code[i]
        if ch == "}":
            depth += 1
        elif ch == "{":
            if depth > 0:
                depth -= 1
            else:
                chain.append(i)
    return chain

def _construct_before(code: str, brace_pos: int) -> Optional[Tuple[str, str]]:
    """取 '{' 前最近的 if/while/for 及其条件 (忽略中间语句)。"""
    seg = code[max(0, brace_pos - 600):brace_pos]
    # 找到最后一个 ";","}","{" 分隔的构造
    last_stop = max(seg.rfind(";"), seg.rfind("}"), seg.rfind("{"))
    cand = seg[last_stop + 1:] if last_stop >= 0 else seg
    m = re.search(r"(if|while|for)\s*\(([^()]*)\)\s*$", cand)
    if not m:
        return None
    kw, cond = m.group(1), m.group(2).strip()
    if kw == "for":
        return None  # for 循环条件不视为守卫
    return (kw, cond)

def _block_body(code: str, brace_pos: int) -> str:
    """取 brace_pos '{' 到匹配 '}' 的块体文本。"""
    depth = 0
    i = brace_pos
    n = len(code)
    while i < n:
        ch = code[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return code[brace_pos + 1:i]
        i += 1
    return code[brace_pos + 1:]

def _is_trivial_body(body: str) -> bool:
    """块体是否只含 return/goto/break/continue (早退)。"""
    t = body.strip()
    if not t:
        return False
    if re.search(r"\b(return|goto|break|continue)\b", t):
        # 排除含写入的复杂块: 早退守卫体不应包含其他语句
        return len(t.split(";")) <= 2
    return False

def _parse_bound(cond: str, var: str) -> Optional[Tuple[str, int]]:
    """从条件中提取对 var 的上界约束。返回 (op, limit) 或 None。

    支持: var <= N / var < N / var <= min(N,...) / N >= var 等。
    """
    patterns = [
        rf"{var}\s*<=\s*(\d+)",
        rf"{var}\s*<\s*(\d+)",
        rf"(\d+)\s*>=\s*{var}",
        rf"(\d+)\s*>\s*{var}",
        rf"{var}\s*<=\s*min\s*\(\s*(\d+)",
    ]
    for pat in patterns:
        m = re.search(pat, cond)
        if m:
            limit = int(m.group(1))
            return ("le", limit) if pat.startswith(rf"{var}\s*<") or pat.startswith(rf"(\d+)\s*>") else ("le", limit)
    return None

def _find_guard_candidates(
    code: str, write_pos: int, size_vars: List[str],
) -> List[Dict]:
    """扫描支配链, 提取对写入量变量的上界守卫。"""
    guards = []
    for brace_pos in _brace_chain(code, write_pos):
        ctor = _construct_before(code, brace_pos)
        if not ctor:
            continue
        kw, cond = ctor
        body = _block_body(code, brace_pos)
        if kw == "while":
            # while 循环守卫: 循环体内的写入被条件约束 (len < N 循环)
            for var in size_vars:
                b = _parse_bound(cond, var)
                if b:
                    guards.append({"var": var, "op": b[0], "value": b[1],
                                   "kind": "while_guard",
                                   "strength": 0.40,
                                   "brace_pos": brace_pos})
            continue
        # if 守卫
        is_early = _is_trivial_body(body)
        write_inside = write_pos > brace_pos and code.find("}", write_pos) > 0
        # 粗略判断写入点是否在此块体内: 块体的匹配 '}' 位置
        body_end = brace_pos + len(body) + 1
        inside = write_pos < body_end
        for var in size_vars:
            b = _parse_bound(cond, var)
            if not b:
                continue
            if is_early and not inside:
                # 早退守卫: if (var > N) return; → 到达写入 ⇒ var <= N
                # 需要逆判定: 条件为 var > N 或 var >= N 才构成早退上界
                if re.search(rf"{var}\s*[>]=\s*(\d+)|{var}\s*[>]\s*(\d+)", cond):
                    m = re.search(rf"{var}\s*[>]=\s*(\d+)|{var}\s*[>]\s*(\d+)", cond)
                    limit = int(m.group(1) or m.group(2))
                    guards.append({"var": var, "op": "le", "value": limit,
                                   "kind": "early_return",
                                   "strength": 0.45,
                                   "brace_pos": brace_pos})
            elif inside:
                # 直接守卫: 写入在 if 块内且条件约束 var
                guards.append({"var": var, "op": b[0], "value": b[1],
                               "kind": "direct_guard",
                               "strength": 0.55,
                               "brace_pos": brace_pos})
        # 钳制守卫: if (var > N) var = N;
        for var in size_vars:
            if re.search(rf"if\s*\(\s*{var}\s*>\s*(\d+)\s*\)\s*{var}\s*=\s*(\d+)", cond + body[:80]):
                m = re.search(rf"if\s*\(\s*{var}\s*>\s*(\d+)\s*\)\s*{var}\s*=\s*(\d+)",
                              cond + body[:80])
                guards.append({"var": var, "op": "le", "value": int(m.group(2)),
                               "kind": "clamp_guard",
                               "strength": 0.50,
                               "brace_pos": brace_pos})
    return guards

def _find_early_return_guards(code: str, write_pos: int,
                              size_vars: List[str]) -> List[Dict]:
    """线性扫描: if (var > N) return; 形式的早退守卫 (无花括号)。

    构造需 (a) 完整结束于写入点之前 (b) 逆约束写入量变量。
    作用域近似: 假定与写入点同级 (结构化程序的典型形态)。
    """
    guards = []
    pat = re.compile(
        r"if\s*\(([^()]*)\)\s*\{?\s*(return\s*;|return\s+[-]?\w*\s*;|"
        r"goto\s+\w+\s*;|break\s*;|continue\s*;)\s*\}?")
    for m in pat.finditer(code):
        if m.end() > write_pos:
            continue
        cond = m.group(1)
        for var in size_vars:
            rm = re.search(rf"{var}\s*[>]=\s*(\d+)|{var}\s*[>]\s*(\d+)", cond)
            if rm:
                limit = int(rm.group(1) or rm.group(2))
                guards.append({"var": var, "op": "le", "value": limit,
                               "kind": "early_return", "strength": 0.45})
    return guards

def _resolve_const(name: str, code: str) -> int:
    """解析钳制常量: 数字字面量直接返回, 否则查 #define 宏。"""
    if name.isdigit():
        return int(name)
    m = re.search(rf"#define\s+{re.escape(name)}\s+(\d+)", code)
    return int(m.group(1)) if m else 0

def _find_ternary_clamps(code: str, write_pos: int,
                         size_vars: List[str]) -> List[Dict]:
    """三目钳制: var = (var > N) ? N : var; / var = var > N ? N : var;
    跨变量钳制: X = (Y > N) ? N : Y;  → X 被截断到 N (N 可为宏名)
    出现在写入点之前且作用于写入量变量 → 上界 N。"""
    guards = []
    prefix = code[:write_pos]
    for var in size_vars:
        # 同变量钳制
        for m in re.finditer(
            rf"{var}\s*=\s*\(?\s*{var}\s*[>]=?\s*(\w+)\s*\)?\s*\?\s*"
            rf"(\w+)\s*:\s*{var}\s*;", prefix):
            limit = _resolve_const(m.group(2), code)
            if limit > 0:
                guards.append({"var": var, "op": "le", "value": limit,
                               "kind": "ternary_clamp", "strength": 0.50})
        # 跨变量钳制: X = (Y > N) ? N : Y
        for m in re.finditer(
            rf"{var}\s*=\s*\(?\s*(\w+)\s*[>]=?\s*(\w+)\s*\)?\s*\?\s*"
            rf"(\w+)\s*:\s*\1\s*;", prefix):
            limit = _resolve_const(m.group(3), code)
            if limit > 0:
                guards.append({"var": var, "op": "le", "value": limit,
                               "kind": "ternary_clamp_cross",
                               "strength": 0.50})
    return guards

def find_dominating_guards(code: str, write_pos: int,
                           size_expr: str) -> Dict:
    """C3 主入口。

    返回 {
      "has_guard": bool,
      "guards": [...],
      "effective_strength": 0..1,
      "bounded_write_max": int 或 None  (推导出的写入量上界)
    }
    """
    size_vars = _extract_size_vars(size_expr)
    guards = _find_guard_candidates(code, write_pos, size_vars)
    guards += _find_early_return_guards(code, write_pos, size_vars)
    guards += _find_ternary_clamps(code, write_pos, size_vars)

    strength = 0.0
    bounded_max = None
    for g in guards:
        strength = max(strength, g["strength"])
        if g["kind"] == "early_return":
            candidate = g["value"]  # var <= limit
        else:
            candidate = g["value"]
        if bounded_max is None or candidate < bounded_max:
            bounded_max = candidate

    # 钳制守卫/三目下限的补充: min(len, N) 出现在表达式本身
    m = re.search(r"min\s*\(\s*(\w+)\s*,\s*(\d+)", size_expr)
    if m:
        limit = int(m.group(2))
        strength = max(strength, 0.50)
        bounded_max = min(bounded_max, limit) if bounded_max else limit

    return {
        "has_guard": len(guards) > 0 or bool(re.search(r"min\s*\(", size_expr)),
        "guards": guards,
        "effective_strength": round(min(strength, 1.0), 2),
        "bounded_write_max": bounded_max,
    }

if __name__ == "__main__":
    s1 = ("int len = atoi(argv[1]);\n"
          "char *buf = malloc(64);\n"
          "if (len <= 64) { memcpy(buf, src, len); }\n")
    s2 = ("int len = atoi(argv[1]);\n"
          "char *buf = malloc(64);\n"
          "if (len > 64) return;\n"
          "memcpy(buf, src, len);\n")
    s3 = ("int len = atoi(argv[1]);\n"
          "char *buf = malloc(64);\n"
          "if (x > 100) { memcpy(buf, src, len); }\n")
    for name, s in [("direct", s1), ("early_return", s2), ("ghost", s3)]:
        pos = s.find("memcpy")
        print(name, find_dominating_guards(s, pos, "len"))
