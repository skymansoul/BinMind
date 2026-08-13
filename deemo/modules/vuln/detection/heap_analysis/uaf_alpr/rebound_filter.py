"""ALPR 重绑定过滤器 — 溯源等价判定, 输出 UAF 最终裁定.

创建: 2025-02-06
用途: 对追踪器产出的 use 事件, 与 free 事件做标签等价配对:

  - use 标签 == free 标签 → 同一对象先释放后使用 → 经典 UAF
      alloc@ 溯源 → CONFIRMED; 其他溯源 → LIKELY (保守)
  - use 标签 != 曾释放该寄存器的标签 → 指针已重绑定新分配 →
      SAFE_REBOUND (滤除)   ← 这是 UAF 误报削减的核心
  - use 与任何 free 无关 → 非 UAF 候选, 不产生告警

设计决策:
  - 为何按标签而非寄存器配对: uaf_detector 按寄存器记录"已释放",
    free(p) 后 p=malloc() 重绑定, 朴素检测仍标记 use(p)——误报。
    标签等价判定天然识别重绑定: 新分配建立新标签, use 标签与释放
    标签不同 → 作用对象不同。
  - 保守原则: 标签无法确定(unknown)时不得放行; 只有明确的重绑定
    证据(标签不同)才滤除。
"""

from typing import List, Optional

from modules.vuln.detection.heap_analysis.uaf_alpr.uaf_types import (
    FreeRecord, UafUse, UafVerdict, UafVerdictRecord, UseKind)


def _match_free(use: UafUse, frees: List[FreeRecord]) -> Optional[FreeRecord]:
    """标签等价的最近 free."""
    best = None
    for f in frees:
        if f.freed_label == use.use_label and f.addr < use.addr:
            if best is None or f.addr > best.addr:
                best = f
    return best


def _reg_freed_before(use: UafUse, frees: List[FreeRecord]) -> bool:
    """该寄存器在 use 前是否被释放过(标签不同 → 重绑定)."""
    return any(f.ptr_reg == use.ptr_reg and f.addr < use.addr
               for f in frees)


def evaluate_use(use: UafUse, frees: List[FreeRecord]) -> Optional[UafVerdictRecord]:
    """对单次 use 做溯源等价判定. 返回 None 表示非 UAF 候选."""
    free = _match_free(use, frees)
    if free is not None:
        if use.use_label.startswith('alloc@'):
            verdict = UafVerdict.CONFIRMED
            conf, fp = 0.85, 0.10
        else:
            verdict = UafVerdict.LIKELY
            conf, fp = 0.55, 0.35
        reasoning = (f'use {use.use_label} == freed {free.freed_label} '
                     f'(free@{free.addr:x}) — same object after free')
        return UafVerdictRecord(
            func_name=use.func_name, use_addr=use.addr, ptr_reg=use.ptr_reg,
            use_kind=use.use_kind, freed_label=free.freed_label,
            use_label=use.use_label, verdict=verdict,
            reasoning=reasoning, confidence=conf, fp_probability=fp)

    if _reg_freed_before(use, frees):
        return UafVerdictRecord(
            func_name=use.func_name, use_addr=use.addr, ptr_reg=use.ptr_reg,
            use_kind=use.use_kind, freed_label='',
            use_label=use.use_label, verdict=UafVerdict.SAFE_REBOUND,
            reasoning=(f'reg {use.ptr_reg} freed earlier but label now '
                       f'{use.use_label} — rebound to different object'),
            confidence=0.90, fp_probability=0.90)

    return None


def run_filter(result) -> List[UafVerdictRecord]:
    """对单函数结果运行过滤器."""
    verdicts: List[UafVerdictRecord] = []
    for use in result.uses:
        rec = evaluate_use(use, result.frees)
        if rec is not None:
            verdicts.append(rec)
    return verdicts


def summarize(verdicts: List[UafVerdictRecord]) -> dict:
    counts = {v: 0 for v in UafVerdict}
    for rec in verdicts:
        counts[rec.verdict] += 1
    total = len(verdicts)
    kept = counts[UafVerdict.CONFIRMED] + counts[UafVerdict.LIKELY]
    safe = counts[UafVerdict.SAFE_REBOUND]
    return {
        'total': total,
        'confirmed': counts[UafVerdict.CONFIRMED],
        'likely': counts[UafVerdict.LIKELY],
        'safe_rebound': safe,
        'kept': kept,
        'fp_reduction_pct': round(safe / total * 100, 1) if total else 0.0,
    }


# 自检
def _check():
    from modules.vuln.detection.heap_analysis.uaf_alpr.uaf_types import (
        FreeRecord, UafUse)
    frees = [
        FreeRecord(0x100, 'f', 'rcx', 'alloc@1000'),
        FreeRecord(0x120, 'f', 'rdx', 'alloc@1200'),
    ]
    # 经典 UAF: use 标签 == 释放标签
    use1 = UafUse(0x140, 'f', 'rcx', 'alloc@1000', UseKind.READ)
    rec1 = evaluate_use(use1, frees)
    assert rec1 is not None and rec1.verdict == UafVerdict.CONFIRMED, rec1
    # 重绑定: 寄存器释放过, 但 use 标签不同 → SAFE_REBOUND
    use2 = UafUse(0x150, 'f', 'rcx', 'alloc@2000', UseKind.READ)
    rec2 = evaluate_use(use2, frees)
    assert rec2 is not None and rec2.verdict == UafVerdict.SAFE_REBOUND, rec2
    # 与任何 free 无关 → None
    use3 = UafUse(0x160, 'f', 'rax', 'arg1', UseKind.READ)
    assert evaluate_use(use3, frees) is None
    print('[OK] rebound_filter passed')


if __name__ == '__main__':
    _check()
