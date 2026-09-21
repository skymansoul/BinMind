"""FreedAliasEpoch - 释放别名纪元 (stage 63).

free 事件把对象划入"纪元", 写点查询纪元状态, 同纪元后重分配
(realloc) 开启新纪元消解误报. 与 double_free 的 FreeHistory
不同: 纪元划分而非序号链.

设计决策:
  - 每遇到 free(p) 将 p 划入新纪元 (epoch + 1)
  - realloc(p, ...) 视为开新纪元 (对象重生)
  - 写点: 若查询到对象处于"已释放且未重生"纪元 -> UAF
  - 处于重生纪元 -> 安全 (误报消解)
"""

import re
from typing import Dict, List, Optional


def run_freed_alias_epoch(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """释放别名纪元判定. 返回 findings."""
    findings: List[dict] = []
    # per-object free 次数计数: 奇数=已释放未重生(UAF), 偶数=reborn
    _obj_freed_count: Dict[str, int] = {}
    # 按分号拆分子语句, 保留行号, 使单行多语句可正确处理时间序
    stmts = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        for stmt in line.split(";"):
            stmt = stmt.strip()
            if stmt:
                stmts.append((ln, stmt))
    for ln, stmt in stmts:
        m_free = re.search(r"\bfree\s*\(\s*(\w+)\s*\)", stmt)
        if m_free:
            obj = m_free.group(1)
            _obj_freed_count[obj] = _obj_freed_count.get(obj, 0) + 1
            continue
        m_realloc = re.search(r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?realloc\s*\(\s*(\w+)\s*,", stmt)
        if m_realloc:
            obj = m_realloc.group(2)
            # realloc 视为释放旧块+重生新块, 强制偶数计数的 reborn 状态
            _obj_freed_count[obj] = (_obj_freed_count.get(obj, 0) // 2 + 1) * 2
            continue
        # use 点识别: 覆盖汇编风格与 C 风格
        obj = None
        # 汇编风格: [obj+off] =
        m_write = re.search(r"\[\s*(\w+)\s*\+\s*\d+\s*\]\s*=", stmt)
        if m_write:
            obj = m_write.group(1)
        # C 风格: func(obj, ...) 函数调用实参
        if obj is None:
            m_call = re.search(r"\b(\w+)\s*\(\s*(\w+)", stmt)
            if m_call:
                obj = m_call.group(2)
        # C 风格: obj->field 或 obj.field 成员访问
        if obj is None:
            m_member = re.search(r"\b(\w+)\s*(?:->|\.)\s*\w+", stmt)
            if m_member:
                obj = m_member.group(1)
        # C 风格: *obj 解引用
        if obj is None:
            m_deref = re.search(r"\*(\w+)", stmt)
            if m_deref:
                obj = m_deref.group(1)
        # C 风格: obj[idx] 下标写
        if obj is None:
            m_idx = re.search(r"\b(\w+)\s*\[", stmt)
            if m_idx:
                obj = m_idx.group(1)
        if obj and obj in _obj_freed_count:
            cnt = _obj_freed_count[obj]
            findings.append({
                "type": "use_after_free",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-416",
                "confidence": 0.9 if cnt % 2 == 1 else 0.2,
                "description": f"line{ln} write to {obj} freed_count={cnt}",
                "verdict": "use_after_free" if cnt % 2 == 1 else "reborn",
                "source": "freed_alias_epoch",
            })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(32);
free(p);
mov [p+8], 0;
q = realloc(p, 64);
mov [q+16], 0;
"""
    out = run_freed_alias_epoch(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"])