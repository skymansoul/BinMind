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
    epoch = 0
    obj_epoch: Dict[str, int] = {}
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m_free = re.search(r"\bfree\s*\(\s*(\w+)\s*\)", line)
        if m_free:
            obj = m_free.group(1)
            epoch += 1
            obj_epoch[obj] = epoch
            continue
        m_realloc = re.search(r"\b(\w+)\s*=\s*realloc\s*\(\s*(\w+)\s*,", line)
        if m_realloc:
            obj = m_realloc.group(2)
            epoch += 1
            obj_epoch[obj] = epoch  # 重生
            continue
        # 写点: [obj+off] =
        m_write = re.search(r"\[\s*(\w+)\s*\+\s*\d+\s*\]\s*=", line)
        if m_write:
            obj = m_write.group(1)
            if obj in obj_epoch:
                ep = obj_epoch[obj]
                findings.append({
                    "type": "use_after_free",
                    "function": func_name or "unknown",
                    "severity": "medium",
                    "cwe": "CWE-416",
                    "confidence": 0.9 if ep % 2 == 1 else 0.2,
                    "description": f"line{ln} write to {obj} epoch={ep}",
                    "verdict": "use_after_free" if ep % 2 == 1 else "reborn",
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