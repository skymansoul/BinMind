# coding: utf-8
"""UAF 指针逃逸分析 — 判定释放后的悬垂指针是否逃逸到可被攻击者控制的存储位置.

UAF 从缺陷升级为可利用漏洞的关键条件: 释放后的悬垂指针被存储到
全局变量/堆对象/vtable 等攻击者可间接控制的位置, 使得后续解引用
能够被定向利用. 若指针释放后仅保留在栈上且函数返回前未再解引用,
则虽为缺陷但几乎不可利用.

与 uaf_detector.py 的关系: uaf_detector 做状态机检测(UAF 存在性),
本模块做可利用性分级(UAF 严重度). 二者组合给出完整的 UAF 风险评估.

参考: Undangle 的指针别名分析 + UAF 生命周期验证 的
typestate 引导 fuzzing. 本模块的差异: 不依赖别名分析或 fuzzing,
而是做静态的指针存储目标分类(栈/堆/全局/vtable)来判定逃逸.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# 指针存储目标分类 — 按利用难度递增
class EscapeLevel:
    NONE = 0        # 无存储, 仅寄存器传递
    STACK = 1       # 存到栈上局部变量 — 低风险 (函数返回即失效)
    HEAP = 2        # 存到堆对象字段 — 中风险 (可通过堆风水操控)
    GLOBAL = 3      # 存到全局/静态变量 — 高风险 (持久化可控)
    VTABLE = 4      # 存到虚表/函数指针表 — 极高风险 (直接劫持控制流)
    INDIRECT = 5    # 通过间接调用传递 — 极高风险 (调用者可控)


@dataclass
class UafEscapeResult:
    """单个 UAF 候选的逃逸分析结果."""
    uaf_site: int                # use-after-free 发生地址
    alloc_site: int              # 分配地址
    free_site: int               # 释放地址
    escape_level: int = EscapeLevel.NONE
    escape_target: str = ''      # 逃逸目标的描述
    exploitable: bool = False
    confidence: float = 0.0
    detail: str = ''


def analyze_pointer_escape(
    uaf_candidates: List[Dict],
    pointer_stores: Dict[int, Dict],  # addr → {target_type, target_name, storing_instruction}
    global_vars: Optional[Set[str]] = None,
    heap_field_writes: Optional[Dict[int, str]] = None,  # addr → field_name
) -> List[UafEscapeResult]:
    """对 UAF 候选列表做指针逃逸分析.

    uaf_candidates: uaf_detector 的输出 [{'use_site': addr, 'alloc_site': addr, 'free_site': addr, ...}]
    pointer_stores: 指针如何被存储的映射, 从 IR 分析中提取
      {addr: {'target_type': 'stack'|'heap'|'global'|'vtable'|'register',
              'target_name': 'var_name'|'field_name', ...}}
    global_vars: 全局变量名集合
    heap_field_writes: {addr: field_name} — 堆对象字段写入点
    """
    global_vars = global_vars or set()
    heap_field_writes = heap_field_writes or {}
    results = []

    for c in uaf_candidates:
        use_site = _addr(c.get('use_site', 0))
        free_site = _addr(c.get('free_site', 0))
        alloc_site = _addr(c.get('alloc_site', 0))

        # 查找 free_site 和 use_site 之间指针的存储目标
        escape_level = EscapeLevel.NONE
        escape_target = 'register'
        exploitable = False
        conf = 0.15  # 基线置信度 (仅检测到 UAF)

        # 检查 free→use 窗口内的所有指针操作
        for addr, store in pointer_stores.items():
            if not (free_site <= addr <= use_site):
                continue
            target = store.get('target_type', 'register')
            tname = store.get('target_name', '')

            if target == 'global' or tname in global_vars:
                # 悬垂指针存入了全局变量 — 持久化可控
                new_level = EscapeLevel.GLOBAL
                if new_level > escape_level:
                    escape_level = new_level
                    escape_target = f'global:{tname}'
                    exploitable = True
                    conf = 0.85

            elif target == 'heap' or addr in heap_field_writes:
                # 悬垂指针存入了堆对象字段 — 可通过堆布局操控
                new_level = EscapeLevel.HEAP
                if new_level > escape_level:
                    escape_level = new_level
                    field = heap_field_writes.get(addr, tname or 'heap_field')
                    escape_target = f'heap:{field}'
                    exploitable = True
                    conf = 0.70

            elif target == 'vtable' or 'vtable' in tname.lower():
                # 悬垂指针存入了虚表 — 控制流劫持
                new_level = EscapeLevel.VTABLE
                if new_level > escape_level:
                    escape_level = new_level
                    escape_target = f'vtable:{tname}'
                    exploitable = True
                    conf = 0.95

            elif target == 'stack' and escape_level < EscapeLevel.STACK:
                escape_level = EscapeLevel.STACK
                escape_target = f'stack:{tname or "local"}'
                # 栈存储: 低风险但若函数返回前再解引用仍可利用
                if addr < use_site:
                    exploitable = True
                    conf = 0.40

        # 降权: 若 free 和 use 在同一函数内 (非跨函数逃逸)
        if escape_level <= EscapeLevel.STACK:
            conf *= 0.6
            detail = '悬垂指针未逃逸到堆/全局/虚表, 利用难度高'
        elif escape_level == EscapeLevel.HEAP:
            detail = f'悬垂指针逃逸到堆对象字段 ({escape_target}), 可利用'
        elif escape_level >= EscapeLevel.GLOBAL:
            detail = f'悬垂指针逃逸到{escape_target}, 高可利用性'

        results.append(UafEscapeResult(
            uaf_site=use_site, alloc_site=alloc_site, free_site=free_site,
            escape_level=escape_level, escape_target=escape_target,
            exploitable=exploitable, confidence=min(1.0, conf),
            detail=detail,
        ))

    # 按置信度降序
    results.sort(key=lambda r: -r.confidence)
    return results


def uaf_severity_summary(results: List[UafEscapeResult]) -> Dict[str, Any]:
    """UAF 逃逸分析的统计摘要."""
    total = len(results)
    exploitable = [r for r in results if r.exploitable]
    by_level: Dict[int, int] = {}
    for r in results:
        by_level[r.escape_level] = by_level.get(r.escape_level, 0) + 1
    level_names = {0: 'none', 1: 'stack', 2: 'heap', 3: 'global', 4: 'vtable', 5: 'indirect'}
    return {
        'total_candidates': total,
        'exploitable': len(exploitable),
        'avg_confidence': round(sum(r.confidence for r in results) / max(1, total), 2),
        'by_escape_level': {level_names.get(k, str(k)): v for k, v in sorted(by_level.items())},
        'high_confidence': len([r for r in results if r.confidence >= 0.70]),
    }


def _addr(v: Any) -> int:
    if isinstance(v, int): return v
    if isinstance(v, str):
        try: return int(v, 16) if v.startswith('0x') else int(v)
        except ValueError: return 0
    return 0
