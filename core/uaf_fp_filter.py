# UAF误报过滤器 v2 — 四模式检测: NULL置零/立即复用/条件保护/栈指针
# 决策: 每种模式对应一类常见的UAF误报, 独立检测
import re
from typing import List

class UAFFalsePositiveFilter:
    # 安全模式1: free后立即置NULL
    _NULL_PAT = re.compile(r'free\s*\([^)]+\)\s*;\s*\n?\s*(\w+)\s*=\s*NULL')
    # 安全模式2: free后立即重新分配(复用)
    _REUSE_PAT = re.compile(r'free\s*\((\w+)\)\s*;\s*\n?\s*\1\s*=\s*malloc')
    # 安全模式3: 在free的同一条件分支内(简化检测: free前有if检查)
    _GUARD_PAT = re.compile(r'if\s*\((\w+)\s*!=\s*NULL\)\s*\{[^}]*free\s*\(\s*\1\s*\)')
    # 安全模式4: 指针是栈变量(非堆), free不可达 — 此模式不适用于反编译代码

    def __init__(self):
        self._safe_count = 0; self._passed_count = 0
        self._reasons = {'nullified':0, 'reused':0, 'guarded':0}

    def filter(self, pseudocode: str, findings: List[dict]) -> List[dict]:
        code_flat = pseudocode.replace('\n', ' ')
        nullified = set()
        reused = set()
        guarded = set()

        # 检测NULL置零
        for m in re.finditer(r'free\s*\(\s*(?:&?\*?)(\w+)\s*\)', pseudocode):
            v = m.group(1)
            end_pos = m.end()
            after = pseudocode[end_pos:end_pos+200]
            if re.search(rf'\b{v}\s*=\s*NULL', after) or re.search(rf'\b{v}\s*=\s*0\s*;', after):
                nullified.add(v)

        # 检测复用
        for m in re.finditer(r'free\s*\(\s*(?:&?\*?)(\w+)\s*\)', pseudocode):
            v = m.group(1)
            end_pos = m.end()
            after = pseudocode[end_pos:end_pos+200]
            if re.search(rf'\b{v}\s*=\s*malloc\s*\(', after) or re.search(rf'\b{v}\s*=\s*realloc\s*\(', after):
                reused.add(v)

        # 检测条件保护
        for m in re.finditer(r'if\s*\(\s*(\w+)\s*\)', pseudocode):
            v = m.group(1)
            end_pos = m.end()
            after = pseudocode[end_pos:end_pos+200]
            if re.search(rf'free\s*\(\s*(?:&?\*?){v}\s*\)', after):
                guarded.add(v)

        filtered = []
        for f in findings:
            ptr = f.get('pointer_name', f.get('alloc_var', ''))
            if ptr in nullified:
                f['severity'] = 'LOW'; f['confidence'] = 0.15
                f['fp_filter_note'] = 'nullified_after_free'
                self._safe_count += 1; self._reasons['nullified'] += 1
            elif ptr in reused:
                f['severity'] = 'INFO'; f['confidence'] = 0.10
                f['fp_filter_note'] = 'reused_after_free'
                self._safe_count += 1; self._reasons['reused'] += 1
            elif ptr in guarded:
                f['severity'] = 'MEDIUM'; f['confidence'] = 0.40
                f['fp_filter_note'] = 'guarded_free_path'
                self._safe_count += 1; self._reasons['guarded'] += 1
            else:
                self._passed_count += 1
            filtered.append(f)
        return filtered

    def stats(self) -> dict:
        total = self._safe_count + self._passed_count
        return {'safe_filtered': self._safe_count, 'passed': self._passed_count,
                'fp_reduction_pct': round(self._safe_count*100/max(1,total), 1),
                'reasons': self._reasons}
