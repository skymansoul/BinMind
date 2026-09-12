"""MinChunkGeometry - 最小块几何 (stage 74).

request2size 下任何 malloc 可用 >= 32 字节 (MINSIZE), 写入 <= 32 时
无论分配多大必安全. 与 CACBV slack 不同: MINSIZE 下界定理直接应用.

设计决策:
  - 采用 glibc request2size 语义: MINSIZE = 32
  - 写大小 <= 32 且写偏移在 [0, alloc) 内 -> 恒安全
  - 即使 alloc 未知, 写 <= 32 也按最小块几何判安全
"""

import re
from typing import List, Optional

_MINSIZE = 32


def run_min_chunk_geometry(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """最小块几何判定. 返回 findings."""
    findings: List[dict] = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 写点 [ptr+off] = 值 或 [ptr] = 值
        m = re.search(r"\[\s*(\w+)\s*\+\s*(\d+)\s*\]\s*(?:,|=)\s*(\d+)", line)
        if not m:
            m = re.search(r"\[\s*(\w+)\s*\]\s*(?:,|=)\s*(\d+)", line)
        if not m:
            continue
        if len(m.groups()) == 3:
            off = int(m.group(2))
            write_size = int(m.group(3)) if m.group(3) else 0
        else:
            off = 0
            write_size = int(m.group(2))
        # 最小块几何: 任何 malloc 请求可用 >= 32B
        if write_size <= _MINSIZE and off + write_size <= _MINSIZE:
            verdict, conf = "safe_minsize", 0.95
        else:
            verdict, conf = "beyond_minsize", 0.4
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "low" if verdict == "safe_minsize" else "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"line{ln} off={off} write={write_size} "
                           f"minsize={_MINSIZE}",
            "verdict": verdict,
            "source": "min_chunk_geometry",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(1);
mov [p+8], 0x41;
"""
    out = run_min_chunk_geometry(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"], f["confidence"])