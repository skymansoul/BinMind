# Use-After-Free 检测 — 静态启发式匹配 + 动态类型状态追踪
# 参考: FreeSentry (NDSS 2015) 悬垂指针保护 &
#   UAFSan (ISSTA 2021) 对象标识符动态检测 &
#   Undangle (ISSTA 2012) 早期悬垂指针识别 &
#   UFO (ICSE 2018) 预测性并发 UAF &
#   Typestate-guided fuzzer for UAF (ICSE 2020) 类型状态引导模糊测试
import re as _re
from collections import defaultdict as _defdict

# UAF 特征模式 — FreeSentry 定义的悬垂指针生命周期模式
_UAF_INDICATOR_PATTERNS = [
    # free(p) ... p->field  或  free(p) ... *p
    _re.compile(r'free\s*\(\s*(\w+)\s*\).*?\1\s*->', _re.DOTALL),
    _re.compile(r'delete\s+(\w+).*?\1\s*->', _re.DOTALL),
    _re.compile(r'kfree\s*\(\s*(\w+)\s*\).*?\1', _re.DOTALL),  # Linux 内核
]

def scan_uaf_patterns(source_or_asm: str) -> list[dict]:
    """扫描源码/汇编中的 UAF 模式。
    返回 [{'var': str, 'line': int, 'confidence': float}]。
    Undangle 启发式: free→use 在 CFG 上的路径越短越可疑。"""
    findings = []
    lines = source_or_asm.split('\n')
    for i, line in enumerate(lines):
        for pattern in _UAF_INDICATOR_PATTERNS:
            for match in pattern.finditer(line):
                var_name = match.group(1)
                # 置信度初值 — CFG 距离衰减需图分析，此处保守估计
                conf = 0.65 if '!' not in line else 0.4  # NULL 检查降低可疑度
                findings.append({'var': var_name, 'line': i + 1, 'confidence': conf})
    return findings


# 类型状态模型 — 来自 Typestate-guided fuzzer (ICSE 2020)
# 对象状态机: ALLOC → INIT → USE → FREE → [USE_AFTER_FREE | SAFE]
_OBJ_STATES = {'allocated', 'initialized', 'in_use', 'freed'}
_TRANSITIONS = {
    ('allocated', 'init'): 'initialized',
    ('initialized', 'use'): 'in_use',
    ('in_use', 'use'): 'in_use',
    ('in_use', 'free'): 'freed',
    ('freed', 'use'): 'UAF',          # 非法状态迁移: use-after-free
    ('freed', 'free'): 'DOUBLE_FREE',  # 非法状态迁移: double-free
}

def track_typestate(events: list[tuple[str, str]]) -> list[dict]:
    """追踪对象类型状态序列，检测 UAF 和 double-free 违规。
    events: [(obj_id, event_type), ...], event_type ∈ {alloc, init, use, free}
    返回类型状态冲突事件列表。"""
    state = {}
    violations = []
    for step, (obj_id, evt) in enumerate(events):
        cur = state.get(obj_id, 'allocated' if evt == 'alloc' else None)
        if cur is None and evt != 'alloc':
            violations.append({'step': step, 'obj': obj_id, 'event': evt,
                               'reason': 'use_before_alloc'})
            continue
        next_state = _TRANSITIONS.get((cur, evt))
        if next_state == 'UAF':
            violations.append({'step': step, 'obj': obj_id, 'event': evt,
                               'reason': 'use_after_free'})
        elif next_state == 'DOUBLE_FREE':
            violations.append({'step': step, 'obj': obj_id, 'event': evt,
                               'reason': 'double_free'})
        if next_state:
            state[obj_id] = next_state
    return violations
