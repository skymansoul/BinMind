# Race condition lockset analysis: shared variable → lock protection modeling.
# TOCTOU pattern matching alone cannot detect unprotected shared-variable
# access. Lockset analysis tracks the set of locks held during each access;
# inconsistent locksets across accesses to the same variable → potential race.
# Adapted from Eraser lockset algorithm
# for static analysis — inferred from code structure rather than dynamic traces.
import re
from collections import defaultdict
from dataclasses import dataclass, field

_LOCK_FUNCS = {'pthread_mutex_lock','pthread_mutex_unlock','pthread_spin_lock',
    'pthread_spin_unlock','spin_lock','spin_unlock','mutex_lock','mutex_unlock',
    'EnterCriticalSection','LeaveCriticalSection','acquire','release','lock','unlock'}
_SHARED_PATTERNS = [
    (r'static\s+\w+\s+\*?(\w+)\s*;', 'static_var'),
    (r'extern\s+\w+\s+\*?(\w+)\s*;', 'extern_var'),
    (r'(\w+)\s*=\s*getenv\s*\(', 'env_var'),
]

@dataclass
class SharedVar:
    name: str; var_type: str = ""
    access_lines: list = field(default_factory=list)
    held_locks: dict = field(default_factory=dict)  # line -> set of locks held

@dataclass  
class RaceWarning:
    finding_id: str = ""; var_name: str = ""; line_a: int = 0; line_b: int = 0
    locks_a: set = field(default_factory=set); locks_b: set = field(default_factory=set)
    confidence: float = 0.5; description: str = ""

def analyze_lockset(ir_lines, func_name=""):
    """锁集分析: 追踪共享变量访问时的锁保护状态."""
    shared = {}; current_locks = set(); warnings = []
    code = '\n'.join(ir_lines)
    for pattern, vtype in _SHARED_PATTERNS:
        for m in re.finditer(pattern, code, re.MULTILINE):
            vname = m.group(1)
            if vname not in shared:
                shared[vname] = SharedVar(vname, vtype)
    for lineno, line in enumerate(ir_lines):
        line_l = line.strip().lower()
        # 锁获取
        for lf in _LOCK_FUNCS:
            if lf in line_l and 'unlock' not in lf:
                # 提取锁变量名
                lm = re.search(rf'{lf}\s*\(\s*&?(\w+)', line)
                if lm: current_locks.add(lm.group(1))
                else: current_locks.add('_anon_lock_')
        # 锁释放
        for lf in _LOCK_FUNCS:
            if 'unlock' in lf and lf in line_l:
                lm = re.search(rf'{lf}\s*\(\s*&?(\w+)', line)
                if lm: current_locks.discard(lm.group(1))
                else: current_locks.discard('_anon_lock_')
        # 变量访问检测
        for vname, var in shared.items():
            if vname in line:
                var.access_lines.append(lineno)
                var.held_locks[lineno] = set(current_locks)
    for vname, var in shared.items():
        if len(var.access_lines) < 2: continue
        lock_sets = list(var.held_locks.values())
        for i in range(len(lock_sets)):
            for j in range(i+1, len(lock_sets)):
                li, lj = lock_sets[i], lock_sets[j]
                # 两次访问中至少一次无锁保护 -> 竞态
                if not li or not lj:
                    conf = 0.80 if (not li and not lj) else 0.55
                    warnings.append(RaceWarning(
                        f'RACE_{vname}_{var.access_lines[i]}_{var.access_lines[j]}',
                        vname, var.access_lines[i], var.access_lines[j], li, lj, conf,
                        f'{vname}: L{var.access_lines[i]}(locks={li}) vs L{var.access_lines[j]}(locks={lj})'))
                # 两次访问持有不同锁 -> 可能竞态
                elif li != lj:
                    if not (li & lj):  # 无公共锁
                        warnings.append(RaceWarning(
                            f'RACE_{vname}_{var.access_lines[i]}_{var.access_lines[j]}',
                            vname, var.access_lines[i], var.access_lines[j], li, lj, 0.45,
                            f'{vname}: diff locks L{var.access_lines[i]}={li} vs L{var.access_lines[j]}={lj}'))
    return warnings
