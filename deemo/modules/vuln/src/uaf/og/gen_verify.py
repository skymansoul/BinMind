"""代际判决 — free→use 对象代际比较.

三态判决: SAME_GEN 同代际确认 (同一对象), DIFF_GEN 指针已指向新对象
压制, UNKNOWN 保守保留. 全局指针族无代际语义, 一律 UNKNOWN 避免误压.
use 代际支持调用方位置敏感提供 (重放到 use 点), 优先于最终态查询.
"""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

from .gen_state import GenState, SlotGen, GEN_NULL, GEN_UNKNOWN, GEN_GLOBAL
from .gen_flow import GenEvent, slot_name
class GenVerdict(Enum):
    SAME_GEN = auto()
    DIFF_GEN = auto()
    UNKNOWN = auto()



@dataclass
class GenProof:
    verdict: GenVerdict
    free_gen: int = 0
    use_gen: int = 0
    free_source: str = ''
    use_source: str = ''
    reason: str = ''


class GenVerifier:
    """代际判决器: 输入 free 事件与 use 定位, 输出三态."""

    def __init__(self, state: GenState):
        self._state = state

    def verify_free_event(self, ev: GenEvent,
                          use_reg: str,
                          use_slot: Optional[str] = None,
                          use_def_idx: int = -1,
                          use_gen: int = GEN_UNKNOWN) -> GenProof:
        """按 free 事件与 use 载体判决.

        use_gen 由调用方位置敏感提供 (重放到 use 点), 优先于
        最终态查询 (最终态可能被 use 之后的指令覆盖)."""
        free_reg = ev.args.get('free_reg', '')
        free_params = ev.args.get('params', {})
        if free_reg and free_reg in free_params:
            fg = free_params[free_reg][0]
        else:
            fg = GEN_UNKNOWN

        ug, us = use_gen, 'positional'
        if ug == GEN_UNKNOWN:
            if use_slot:
                sg = self._state.slot(use_slot)
                ug, us = sg.gen, sg.source
            if ug == GEN_UNKNOWN and use_reg:
                sg = self._state.reg(use_reg)
                ug, us = sg.gen, sg.source

        if fg == GEN_UNKNOWN or ug == GEN_UNKNOWN:
            return GenProof(GenVerdict.UNKNOWN, fg, ug,
                            str(free_reg), us,
                            '任一端代际未知')
        if fg == GEN_GLOBAL or ug == GEN_GLOBAL:
            # 全局指针族无代际语义, 保守保留
            return GenProof(GenVerdict.UNKNOWN, fg, ug,
                            str(free_reg), us,
                            '全局指针族, 代际不可判定')
        if fg == ug and fg > 0:
            return GenProof(GenVerdict.SAME_GEN, fg, ug,
                            str(free_reg), us,
                            f'free/use 同代际 {fg}, 同一对象')
        if ug == GEN_NULL:
            return GenProof(GenVerdict.DIFF_GEN, fg, ug,
                            str(free_reg), us,
                            'use 侧指针已置空, 非 UAF 语义')
        return GenProof(GenVerdict.DIFF_GEN, fg, ug,
                        str(free_reg), us,
                        f'代际变化 {fg} → {ug}, 指针已重新赋值')

    def verify_slot_pair(self, free_slot: str, free_gen: int,
                         use_slot: str,
                         use_gen: int = GEN_UNKNOWN) -> GenProof:
        """槽级代际比较: 显式给定 free 代际, use 代际位置敏感优先."""
        sg = self._state.slot(use_slot)
        if use_gen == GEN_UNKNOWN:
            use_gen = sg.gen
        if free_gen == GEN_UNKNOWN or use_gen == GEN_UNKNOWN:
            return GenProof(GenVerdict.UNKNOWN, free_gen, use_gen,
                            '', sg.source, '槽代际未知')
        if free_gen == GEN_GLOBAL or use_gen == GEN_GLOBAL:
            return GenProof(GenVerdict.UNKNOWN, free_gen, use_gen,
                            '', sg.source, '全局指针族, 代际不可判定')
        if free_gen == use_gen and free_gen > 0:
            return GenProof(GenVerdict.SAME_GEN, free_gen, use_gen,
                            '', sg.source, f'槽同代际 {free_gen}')
        return GenProof(GenVerdict.DIFF_GEN, free_gen, use_gen,
                        '', sg.source, f'槽代际 {free_gen} → {use_gen}')
