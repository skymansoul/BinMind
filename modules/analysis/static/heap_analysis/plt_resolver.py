"""PLT/导入表解析 - 剥离二进制上的函数名恢复.

剥离 (--strip-all) 后反汇编中的 call 目标为裸地址, malloc/memcpy
等符号不可见. 方案: 从带符号反汇编提取 `call addr <name@plt>`
映射 (thunk 地址 → 函数名); 剥离只删除符号表, 不改变代码布局,
同一构建的 stripped/plain 二进制 thunk 地址一致 - 映射可跨版本
复用. 该映射用于 InstructionParser.extract_callee 的兜底查询.

设计决策:
  - 依赖同构建 plain 二进制作为符号源 (由调用方提供 fallback)
  - IAT 双块倒序问题在符号级映射下不存在 — 不依赖顺序关联
  - 映射缺失 → 回退为无符号行为 (保守, 与旧版一致)
"""

import re
import subprocess
from typing import Dict, List, Optional

_CALL_SYM_RE = re.compile(
    r'\bcall\s+([0-9a-f]+)\s+<([^>]+)>')
_JMP_SYM_RE = re.compile(
    r'\bjmp\s+([0-9a-f]+)\s+<([^>]+)>')


def _run_objdump(args: List[str], binary_path: str) -> str:
    try:
        r = subprocess.run(["objdump"] + args + [binary_path],
                           capture_output=True, text=True, timeout=30)
        return r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def _clean_name(name: str) -> str:
    """去掉 @plt/@PLT 后缀."""
    return name.split("@")[0].split("@")[0]


def _collect_sym_targets(disasm: str) -> Dict[int, str]:
    """提取 call/jmp 目标地址 → 函数名 (带符号反汇编)."""
    mapping = {}
    for line in disasm.split("\n"):
        for regex in (_CALL_SYM_RE, _JMP_SYM_RE):
            m = regex.search(line)
            if m:
                try:
                    addr = int(m.group(1), 16)
                except ValueError:
                    continue
                mapping[addr] = _clean_name(m.group(2))
                break
    return mapping


def build_import_map(binary_path: str) -> Dict[int, str]:
    """从二进制自身提取 call 目标 → 函数名 映射.

    无符号 (stripped) → 返回空映射, 由调用方提供同构建
    plain 二进制的映射.
    """
    disasm = _run_objdump(["-d", "-M", "intel"], binary_path)
    if not disasm:
        return {}
    return _collect_sym_targets(disasm)


# smoke test
def _check():
    import os
    plain = os.path.join("modules", "testing", "heap_samples",
                         "cve_unbounded_strcpy_003", "vuln.exe")
    stripped = os.path.join("modules", "testing", "heap_samples_stripped",
                            "cve_unbounded_strcpy_003", "vuln.exe")
    m = build_import_map(plain)
    assert any("malloc" in v for v in m.values()), "malloc missing"
    assert any("memcpy" in v for v in m.values()), "memcpy missing"
    assert build_import_map(stripped) == {}, \
        "stripped binary must yield no symbols"
    print(f"[OK] plt_resolver: {len(m)} symbol targets "
          f"(malloc/memcpy resolved), stripped yields empty")


if __name__ == "__main__":
    _check()
