"""RetAddrChainStitch - 返回地址链缝合 (stage 64).

对跨函数告警, 沿 call 返回点把 caller 的 alloc 证据与 callee 的
write 证据缝合, 缝合成功 (callee 写大小 <= caller alloc 大小) 则过滤.
与 AWSC-ICF 摘要不同: 返回点证据缝合而非参数摘要.

设计决策:
  - 识别 call 指令及其调用目标函数名
  - 在伪代码中搜索目标函数的函数体定义, 提取 callee 内写操作证据 (写大小/写偏移)
  - 在 caller 上下文中提取 alloc 证据 (malloc 大小)
  - 缝合判定: callee 写大小 <= caller alloc 大小 -> stitched_safe; 否则 stitched_overflow
  - 若目标函数不在当前伪代码中 (外部函数), fallback 到 call 下一行写值比较
"""

import re
from typing import Dict, List, Optional, Tuple


def _call_sites(pseudocode: str) -> List[Tuple[int, str]]:
    """返回 [(行号1基, callee)]."""
    out = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\bcall\s+(\w+)", line)
        if m:
            out.append((ln, m.group(1)))
    return out


def _const_of(s: str) -> Optional[int]:
    """尝试将字符串解析为整数常量."""
    try:
        return int(s, 0)
    except ValueError:
        return None


def _find_func_body(pseudocode: str, func_name: str) -> Optional[str]:
    """在伪代码中搜索目标函数的函数体.
    支持 'func_name(...)' 定义头 + 大括号/缩进体两种风格.
    返回函数体文本 (到下一个顶层函数定义或文件尾).
    """
    lines = pseudocode.splitlines()
    start = None
    # 匹配函数定义头: func_name( 后跟 { 或直接缩进
    for i, line in enumerate(lines):
        # 形如 "int func_name(" 或 "void func_name(" 或 "func_name("
        m = re.search(r"\b" + re.escape(func_name) + r"\s*\(", line)
        if m:
            # 排除 call 语句 (函数定义行不应以 call 开头)
            if re.search(r"\bcall\s+", line):
                continue
            start = i
            break
    if start is None:
        return None
    # 从定义头之后收集函数体
    body_lines = []
    # 确定函数体起始: 同行有 { 或下一行开始
    header = lines[start]
    if "{" in header:
        body_start = start
    else:
        body_start = start + 1
    base_indent = -1
    for j in range(body_start, len(lines)):
        ln = lines[j]
        if not ln.strip():
            continue
        indent = len(ln) - len(ln.lstrip())
        if base_indent == -1:
            base_indent = indent
        # 遇到缩进更浅或等深的顶层定义头 -> 函数体结束
        if j > body_start and indent <= base_indent and (
            re.search(r"\b\w+\s+\w+\s*\(", ln) or  # 形如 type name(
            re.search(r"^\w+\s*\(", ln)               # 形如 name(
        ):
            # 但不含 call 语句
            if not re.search(r"\bcall\s+", ln):
                break
        body_lines.append(ln)
    return "\n".join(body_lines) if body_lines else None


def _extract_callee_write_evidence(
    func_body: str,
) -> List[Dict]:
    """从 callee 函数体中提取写操作证据.
    返回 [{'write_size': int|None, 'write_offset': int|None, 'line': str}].
    """
    evidence = []
    for ln, line in enumerate(func_body.splitlines(), 1):
        # 匹配 [addr] = val 或 mov [addr], val
        m = re.search(r"\[([^\]]+)\]\s*[,=]\s*(\w+)", line)
        if m:
            addr_expr = m.group(1)
            val = m.group(2)
            # 写大小: 若 RHS 是常量则直接取; 否则 None (大小未知)
            write_size = _const_of(val)
            # 写偏移: 从地址表达式中提取常量偏移
            write_offset = _extract_offset(addr_expr)
            evidence.append({
                "write_size": write_size,
                "write_offset": write_offset,
                "line": line.strip(),
            })
    return evidence


def _extract_offset(addr_expr: str) -> Optional[int]:
    """从地址表达式 [base+off] 中提取常量偏移 off."""
    # [p+8] -> 8; [p] -> 0; [p+idx*4+8] -> 8
    m = re.search(r"\+\s*(\d+)\s*$", addr_expr)
    if m:
        return int(m.group(1))
    # 无偏移部分: [p] 或 [p+idx]
    if "+" not in addr_expr and "*" not in addr_expr:
        return 0
    # 多项表达式中取最后一个常量项
    parts = re.split(r"\s*\+\s*", addr_expr)
    for part in reversed(parts):
        if re.fullmatch(r"\d+", part):
            return int(part)
    return None


def run_ret_addr_chain_stitch(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """返回地址链缝合. 返回 findings.
    优先: 搜索 callee 函数体提取写证据, 与 caller alloc 证据缝合.
    Fallback: 外部函数无函数体时, 用 call 下一行写值比较保守近似.
    """
    findings: List[dict] = []
    lines = pseudocode.splitlines()
    # caller 上下文: 提取 alloc 证据 (malloc 大小)
    alloc_size: Optional[int] = None
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    if m_alloc:
        alloc_size = int(m_alloc.group(1))
    for ln, callee in _call_sites(pseudocode):
        # 尝试在当前伪代码中搜索 callee 函数体
        func_body = _find_func_body(pseudocode, callee)
        if func_body is not None:
            # 跨函数证据缝合: 提取 callee 写操作证据
            write_evidence = _extract_callee_write_evidence(func_body)
            if write_evidence:
                for ev in write_evidence:
                    write_size = ev["write_size"]
                    write_offset = ev["write_offset"]
                    # 缝合判定: callee 写大小 <= caller alloc 大小
                    if alloc_size is not None and write_size is not None:
                        closed = write_size <= alloc_size
                        verdict = "stitched_safe" if closed else "stitched_overflow"
                        confidence = 0.9 if closed else 0.8
                    elif alloc_size is not None and write_offset is not None:
                        # 无写大小时用写偏移近似: 偏移 < alloc 大小
                        closed = write_offset < alloc_size
                        verdict = "stitched_safe" if closed else "stitched_overflow"
                        confidence = 0.7 if closed else 0.6
                    else:
                        closed = False
                        verdict = "unstitched"
                        confidence = 0.4
                    findings.append({
                        "type": "heap_overflow",
                        "function": func_name or "unknown",
                        "severity": "medium",
                        "cwe": "CWE-122",
                        "confidence": confidence,
                        "description": (
                            f"call@{ln}->{callee} (cross-func stitch) "
                            f"alloc={alloc_size} write_size={write_size} "
                            f"write_offset={write_offset} closed={closed}"
                        ),
                        "verdict": verdict,
                        "source": "ret_addr_chain_stitch",
                    })
                continue  # 跨函数缝合完成, 不走 fallback
            # 函数体存在但无写证据 -> 跳过
            # 继续走 fallback
        # Fallback: 外部函数无函数体, 用 call 下一行写值比较保守近似
        if ln >= len(lines):
            continue
        ret_line = lines[ln]  # 0 基: lines[ln] 是 call 的下一行
        write_size = None
        m_write = re.search(r"\[[^\]]+\]\s*[,=]\s*(\w+)", ret_line)
        if m_write:
            write_size = _const_of(m_write.group(1))
        if alloc_size is not None and write_size is not None:
            closed = write_size <= alloc_size
        else:
            closed = False
        verdict = "stitched_safe" if closed else "unstitched"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.9 if closed else 0.5,
            "description": (
                f"call@{ln}->{callee} (fallback) alloc={alloc_size} "
                f"write={write_size} closed={closed}"
            ),
            "verdict": verdict,
            "source": "ret_addr_chain_stitch",
        })
    return findings


def _scan_sites(pseudocode: str) -> List[Tuple[int, str]]:
    """兼容旧接口, 保留 _scan_sites 不删除."""
    return _call_sites(pseudocode)


if __name__ == "__main__":
    demo = """\
p = malloc(64);
call helper;
mov [p+8], rax;
"""
    out = run_ret_addr_chain_stitch(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"])
