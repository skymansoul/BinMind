# 跨函数 UAF 检测 — 指针别名追踪 + 调用返回污染 + 全局变量传播。
# 相比纯函数内检测, 增加两个维度: (1) 函数调用返回值可携带已释放指针,
# (2) 全局变量在 free 后未置 NULL 导致跨调用点 UAF。
import re
from dataclasses import dataclass
from typing import List, Set

_FREE_RE = re.compile(r'(?:free|kfree|delete)\s*\(\s*([a-zA-Z_]\w*)\s*\)')
_DEREF_RE = re.compile(r'([a-zA-Z_]\w*)\s*->')
_ASSIGN_RE = re.compile(r'([a-zA-Z_]\w*)\s*=\s*([a-zA-Z_]\w*)\s*;')
_RETURN_PTR_RE = re.compile(r'return\s+([a-zA-Z_]\w*)\s*;')
_GLOBAL_ASSIGN_RE = re.compile(r'(g_\w+|[A-Z_]+\w*)\s*=\s*([a-zA-Z_]\w*)\s*;')


@dataclass
class UAFSite:
    ptr_name: str
    free_line: int
    deref_line: int
    deref_text: str
    confidence: float = 0.85
    cross_function: bool = False


class UAFCrossFunctionDetector:
    def detect(self, pseudocode: str, caller_pseudocode: str = '') -> list:
        lines = pseudocode.splitlines()
        aliases: dict[str, str] = {}
        globals_seen: set[str] = set()
        free_sites: list[tuple[int, str]] = []

        for i, raw in enumerate(lines):
            line = raw.strip()
            am = _ASSIGN_RE.search(line)
            if am:
                aliases[am.group(1)] = am.group(2)
            gm = _GLOBAL_ASSIGN_RE.search(line)
            if gm:
                globals_seen.add(gm.group(1))
            fm = _FREE_RE.search(line)
            if fm:
                free_sites.append((i, fm.group(1)))

        sites = []
        for fline, fptr in free_sites:
            tainted = self._expand_tainted(fptr, aliases, globals_seen)

            # 同行检查: free(p); p->field 模式
            line = lines[fline].strip()
            free_pos = line.find(f'free({fptr}')
            if free_pos < 0:
                free_pos = line.find(f'free ({fptr}')
            if free_pos >= 0:
                rest = line[free_pos + len(f'free({fptr})'):]
                dm = _DEREF_RE.search(rest)
                if dm and dm.group(1) in tainted:
                    sites.append(UAFSite(ptr_name=fptr, free_line=fline + 1,
                        deref_line=fline + 1, deref_text=rest[:80]))

            # 后续行检查
            for i in range(fline + 1, len(lines)):
                dm = _DEREF_RE.search(lines[i].strip())
                if dm and dm.group(1) in tainted:
                    sites.append(UAFSite(ptr_name=fptr, free_line=fline + 1,
                        deref_line=i + 1, deref_text=lines[i].strip()[:80]))

        # 跨函数: 检查调用者伪代码中是否使用了返回的已释放指针
        if caller_pseudocode:
            caller_lines = caller_pseudocode.splitlines()
            returned = self._find_returned_ptrs(pseudocode, free_sites, aliases)
            for rptr in returned:
                for i, cl in enumerate(caller_lines):
                    if rptr in cl and _DEREF_RE.search(cl):
                        sites.append(UAFSite(ptr_name=rptr, free_line=-1,
                            deref_line=i + 1, deref_text=cl.strip()[:80],
                            confidence=0.70, cross_function=True))
        return sites

    def _expand_tainted(self, fptr: str, aliases: dict, globals_seen: set) -> set:
        tainted = {fptr}
        for a, b in aliases.items():
            if b == fptr or b in tainted:
                tainted.add(a)
        for g in globals_seen:
            if g in aliases and aliases[g] == fptr:
                tainted.add(g)
        return tainted

    def _find_returned_ptrs(self, pseudocode: str, free_sites: list,
                            aliases: dict) -> set:
        returned = set()
        for fline, fptr in free_sites:
            for i in range(fline + 1, len(pseudocode.splitlines())):
                line = pseudocode.splitlines()[i].strip()
                rm = _RETURN_PTR_RE.search(line)
                if rm:
                    ret_var = rm.group(1)
                    if ret_var == fptr or ret_var in aliases and aliases[ret_var] == fptr:
                        returned.add(ret_var)
        return returned


__all__ = ['UAFSite', 'UAFCrossFunctionDetector']
