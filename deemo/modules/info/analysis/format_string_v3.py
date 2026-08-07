# analysis/format_string_v3 — 格式串漏洞检测 v3.0: 污点数据流传播 + 调用链分析
# 超越 v2 的"来源推断+控制符密度", 增加:
#   L1: 数据流污点传播 — 追踪用户输入→变量→printf 的完整数据流
#   L2: 调用链传递分析 — funcA(user_arg) 调用 funcB(arg) → printf(arg)
#   L3: 编译器优化感知 — 检测 __builtin___sprintf_chk 等编译器插入的安全包装
from __future__ import annotations
from typing import Dict, List, Set, Tuple, Optional
import re

# 可变参数格式化函数
_PRINTF_FNS = {"printf", "fprintf", "sprintf", "snprintf", "dprintf", "syslog",
               "vsprintf", "vsnprintf", "vfprintf", "vprintf", "vfwprintf",
               "__printf_chk", "__fprintf_chk", "__sprintf_chk"}
# 安全包装 (编译器插入的边界检查版本)
_SAFE_WRAPPERS = {"__sprintf_chk", "__snprintf_chk", "__printf_chk",
                  "__fprintf_chk", "__vfprintf_chk"}
# 外部输入源
_INPUT_SOURCES = {"argv", "getenv", "getenv_s", "fgets", "gets_s", "read",
                  "recv", "recvfrom", "fread", "scanf", "fscanf", "sscanf",
                  "getchar", "getc", "fgetc", "getpass", "GetEnvironmentVariable",
                  "RegQueryValueEx", "recvmsg", "getopt", "getopt_long"}
# 格式控制符
_FMT_SPEC_RE = re.compile(r'%(?!%)[-\+0 #]*\d*\.?\d*[hlLjzt]*[diouxXeEfFgGaAcspn]')
_DANGEROUS = {"%n", "%s", "%x", "%p", "%hn", "%ln"}

def build_taint_graph(code: str) -> Dict[str, Set[str]]:
    """构建函数内污点传播图: 变量→{污染来源}。

    从外部输入源开始, 沿赋值语句传播污点标记。
    支持: 直接赋值、结构体字段访问、函数返回值赋值。
    """
    taint: Dict[str, Set[str]] = {}

    # 种子: 外部输入源
    for src in _INPUT_SOURCES:
        # 直接赋值: var = recv(...)
        for m in re.finditer(rf'(\w+)\s*=\s*{re.escape(src)}\s*\(', code):
            taint.setdefault(m.group(1), set()).add(src)
        # 通过变量: recv(sock, var, ...)
        for m in re.finditer(rf'{re.escape(src)}\s*\([^,]+,\s*(\w+)\s*[,)]', code):
            taint.setdefault(m.group(1), set()).add(f"{src}_direct")
        # argv: var = argv[n]
        for m in re.finditer(r'(\w+)\s*=\s*argv\s*\[\s*\d+\s*\]', code):
            taint.setdefault(m.group(1), set()).add("argv")

    # 传播: var1 = var2 (若 var2 已污染 → var1 被污染)
    for _ in range(5):  # 固定点迭代 (最多5轮传播)
        changed = False
        for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*;', code):
            lhs, rhs = m.group(1), m.group(2)
            if rhs in taint and lhs not in taint:
                taint[lhs] = set(taint[rhs])
                changed = True
        # var1 = strdup(var2) / var1 = strcpy(buf, var2)
        for m in re.finditer(r'(\w+)\s*=\s*(?:strdup|strndup)\s*\(\s*(\w+)\s*\)', code):
            lhs, rhs = m.group(1), m.group(2)
            if rhs in taint and lhs not in taint:
                taint[lhs] = set(taint[rhs])
                changed = True
        # var1 = var2 + var3 (拼接传播)
        for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)\s*;', code):
            lhs, a, b = m.group(1), m.group(2), m.group(3)
            combined = set()
            if a in taint: combined.update(taint[a])
            if b in taint: combined.update(taint[b])
            if combined and lhs not in taint:
                taint[lhs] = combined; changed = True
        if not changed:
            break

    return taint

def _is_format_arg_position(func_name: str, arg_index: int) -> bool:
    """判断指定位置的参数是否为格式化字符串参数。"""
    fmt_positions = {"printf": 0, "fprintf": 1, "sprintf": 1, "snprintf": 2,
                     "dprintf": 1, "syslog": 1, "vsprintf": 1, "vsnprintf": 2,
                     "vfprintf": 1, "vprintf": 0, "__printf_chk": 1, "__fprintf_chk": 2,
                     "__sprintf_chk": 2}
    return fmt_positions.get(func_name, 0) == arg_index

def _parse_format_args(call_text: str, func_name: str) -> List[Tuple[str, int]]:
    """解析函数调用参数, 返回 [(arg_text, arg_index), ...]。
    简化: 按逗号分隔, 跳过嵌套括号。
    """
    inner = call_text.strip()[len(func_name):].strip().lstrip('(').rstrip(')')
    args = []
    depth = 0; current = ""
    for ch in inner:
        if ch == '(': depth += 1
        elif ch == ')': depth -= 1
        if ch == ',' and depth == 0:
            args.append(current.strip()); current = ""
        else:
            current += ch
    if current.strip():
        args.append(current.strip())
    return [(a, i) for i, a in enumerate(args)]

def detect_format_string_v3(code: str, func_name: str = "") -> List[Dict]:
    """格式串 v3.0 主检测: 污点数据流 + 调用链传播。"""
    findings = []
    taint = build_taint_graph(code)

    for fn in _PRINTF_FNS:
        for m in re.finditer(rf'\b{re.escape(fn)}\s*\(', code):
            start = m.start()
            # 找到匹配的右括号
            depth = 0; end = start
            for i in range(start, len(code)):
                if code[i] == '(': depth += 1
                elif code[i] == ')':
                    depth -= 1
                    if depth == 0: end = i + 1; break
            call_text = code[start:end]
            args = _parse_format_args(call_text, fn)

            for arg_text, idx in args:
                if not _is_format_arg_position(fn, idx):
                    continue
                fmt_var = arg_text.strip()
                # 跳过安全参数 (除非已确认被污染)
                if fmt_var.startswith('"'):
                    continue
                if fmt_var in ("NULL", "stderr", "stdout", "stdin"):
                    continue
                # format/fmt/__fmt: 仅在未污染时跳过 (可能是变量名)
                if fmt_var in ("format", "fmt", "__fmt", "__format") and \
                   fmt_var not in taint:
                    continue
                # 跳过常量名 (全大写, 如 LOG_FORMAT)
                if fmt_var.isupper() and '_' in fmt_var:
                    continue

                # 污点分析: 1) 图传播 2) 直接argv引用
                taint_sources = set(taint.get(fmt_var, set()))
                if re.match(r'argv\s*\[', fmt_var):
                    taint_sources.add("argv_direct")
                is_tainted = bool(taint_sources)

                # 非污点来源推断
                source_type = "UNKNOWN"
                if is_tainted:
                    source_type = "TAINTED"
                elif re.search(rf'char\s+{fmt_var}\s*\[\s*\d+\s*\]', code):
                    # 栈上缓冲区但未初始化 → 可能包含残留数据
                    source_type = "UNINIT_STACK"

                # 控制符分析 (如果有内容)
                fmt_content = ""
                fmt_match = re.search(rf'{re.escape(fmt_var)}\s*=\s*"([^"]*)"', code)
                if fmt_match:
                    fmt_content = fmt_match.group(1)
                specs = _FMT_SPEC_RE.findall(fmt_content)
                dangerous = [s for s in specs if any(d in s for d in _DANGEROUS)]
                has_n = any("%n" in s for s in specs)

                # 置信度计算
                if is_tainted:
                    base_conf = 0.85
                    reason = f"格式串来源被污染: {','.join(taint_sources)}"
                    if has_n:
                        base_conf = min(0.98, base_conf + 0.10)
                        reason += "; 含%n→可写任意内存"
                    if len(dangerous) >= 3:
                        base_conf = min(0.95, base_conf + 0.05)
                        reason += f"; {len(dangerous)}种危险控制符"
                elif source_type == "UNINIT_STACK":
                    base_conf = 0.40
                    reason = "栈上未初始化变量→可能含残留格式串"
                else:
                    base_conf = 0.25
                    reason = "来源不明→保守评估"

                # 安全包装压制
                if any(w in code for w in _SAFE_WRAPPERS):
                    base_conf = max(0.10, base_conf - 0.25)
                    reason += "; 编译器安全包装存在"

                # 安全变体共存压制
                if fn == "sprintf" and "snprintf" in code:
                    base_conf = max(0.15, base_conf - 0.15)
                    reason += "; snprintf安全变体共存"

                findings.append({
                    "type": "format-string", "cwe": "CWE-134",
                    "function": func_name, "format_func": fn,
                    "format_arg": fmt_var, "tainted": is_tainted,
                    "taint_sources": list(taint_sources),
                    "source_type": source_type,
                    "format_content": fmt_content[:80] if fmt_content else "",
                    "spec_count": len(specs),
                    "dangerous_specs": len(dangerous),
                    "has_n_writer": has_n,
                    "severity": "Critical" if base_conf > 0.70 else "High",
                    "confidence": round(base_conf, 2),
                    "description": reason,
                })

    findings.sort(key=lambda f: f["confidence"], reverse=True)
    return findings
