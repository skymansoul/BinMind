# 误报抑制混合层 (FpReductionMixin): 三层递进安全证明
# 职责: 在 HeapOverflowDetector 主管道产出 finding 之后追加
#   三条独立的证据链, 每条都能独立证明写入安全而撤销 finding:
#   L4 值流耦合: malloc(n) 与 memcpy(p,s,n) 共享同一 size 符号
#      → 写入量符号化 ≤ 分配量 (消除"同源 idiom"误报)
#   L5 路径守卫: 写入点前的分支守卫 (cmp+jcc 前向出口) 收敛
#      size 值域上界 → 重新约束验证
#   L6 循环耦合: 循环计数器边界与分配大小同源, 严格上界循环
#      逐字节写入 → 总写入量 ≤ 分配量
# 启用开关: 实例属性 _fp_reduction_enabled (默认 True),
#   置 False 即恢复原检测器行为 (消融实验的 baseline).
# 设计约束: 本层只撤销可证明安全的 finding, 绝不改变
#   DEFINITE_OVERFLOW 的判定路径, 保证召回率不损失.
from __future__ import annotations
from typing import Dict, List, Optional

from .path_constraint_applier import PathConstraintApplier
from .loop_bound_analyzer import LoopBoundAnalyzer
from .value_range import ValueRange

# TODO: 耦合距离阈值按函数规模自适应, 固定 256 对长函数偏保守
# 同函数耦合的最大指令距离 (超过则放弃耦合, 保守)
_MAX_COUPLING_DISTANCE = 256

# 严格上界循环的出口跳转: 迭代次数恰为边界值 (i < n 语义)
_STRICT_EXITS = {'jge', 'jae', 'jl', 'jb'}


class FpReductionMixin:
    """误报抑制混合层.

    通过 Python MRO 注入 HeapOverflowDetector:
      class HeapOverflowDetector(FpReductionMixin, CallHandlerMixin,
                                 LoopDetectorMixin, InlineTrackerMixin)
    本层方法名仅新增 _fp_* 前缀接口, 不与现有模块冲突.
    """

# 统计

    def _fp_stats_dict(self, instructions) -> Dict[str, int]:
        """按 analyze 调用周期重置统计 (以指令列表身份作周期键)."""
        if (getattr(self, '_fp_stats_key', None) is not instructions
                or not hasattr(self, '_fp_stats')):
            self._fp_stats_key = instructions
            self._fp_stats = {
                'l4_coupling_filtered': 0,
                'l5_path_guard_filtered': 0,
                'l6_loop_coupling_filtered': 0,
                'loop_trip_refined': 0,
            }
        return self._fp_stats

    def _fp_enabled(self) -> bool:
        return getattr(self, '_fp_reduction_enabled', True)

    def fp_reduction_stats(self) -> Dict[str, int]:
        return dict(getattr(self, '_fp_stats', {}))

# L4 + L5: 主写入路径的后置验证

    def _fp_reduction_post(self, chk, finding):
        """在 _verify 产出 finding 后追加两层安全证明.

        任一层证明安全 → 撤销 finding (返回 None).
        否则原样返回 (严重性等字段不变).
        """
        if not self._fp_enabled():
            return finding
        if chk is None or finding is None or chk.alloc_site is None:
            return finding
        stats = self._fp_stats_dict(getattr(self, '_fp_ctx', (None,))[0])

        # L4: 值流耦合
        sid = self._coord.size_identity
        alloc_id = sid.get_alloc_size_id(chk.alloc_site.site_id)
        sink_id = sid.get_sink_size_id(chk.access_id)
        if (alloc_id is not None and sink_id is not None
                and not alloc_id.is_unknown and not sink_id.is_unknown
                and self._coupling_in_distance(chk)):
            ptr_off = (chk.pointer_origin.offset_in_alloc
                       if chk.pointer_origin else 0)
            # write_le_alloc 内部处理 同链/常数 两种比较,
            # 无需在此前置 same_chain 门控
            if sink_id.write_le_alloc(alloc_id, ptr_off):
                stats['l4_coupling_filtered'] += 1
                return None

        # L5: 路径守卫重新约束验证 (仅对值域为 TOP 的写入有效)
        if chk.size_range.is_top:
            ctx = getattr(self, '_fp_ctx', ([], {}, None))
            clamped, used = PathConstraintApplier.clamp_size_range(
                ctx[0], ctx[1],
                chk.instruction_address, chk.size_reg,
                ValueRange.unsigned_range(0, 0x100000),
                ctx[2] if len(ctx) > 2 else None)
            if used:
                a_min = chk.alloc_site.min_allocation()
                usable = self._heap_model.get_usable_size(a_min)
                ptr_off = (chk.pointer_origin.offset_in_alloc
                           if chk.pointer_origin else 0)
                if clamped.umax <= usable - ptr_off:
                    stats['l5_path_guard_filtered'] += 1
                    return None

        return finding

    def _coupling_in_distance(self, chk) -> bool:
        """分配点与写入点的指令距离限制.

        同函数内距离过远的耦合不可信 (中间可能混入未建模的
        别名改写), 超过阈值放弃耦合判定.
        """
        site = chk.alloc_site
        if site.call_address < 0 or chk.instruction_address < 0:
            return False
        if site.call_address > chk.instruction_address:
            return False
        return (chk.instruction_address - site.call_address
                <= _MAX_COUPLING_DISTANCE)

# L6: 循环路径的后置验证

    def _loop_iteration_range(self, body_indices: List[int],
                              instructions: List[str],
                              loop_start: int):
        """循环迭代次数: 精确分析优先, 失败回退原估计器.

        同时记录最近一次 LoopInfo 供 _loop_write_extent 使用.
        边界寄存器的值域从 cmp 时刻快照读取 (Pass 2.5 的 _vd
        已是线性扫描结束状态, 直接使用会导致错误迭代数).
        """
        if not self._fp_enabled():
            self._fp_loop_info = None
            return self._estimate_loop_iterations(
                body_indices, instructions, loop_start)
        ctx = getattr(self, '_fp_ctx', ([], {}, None))
        info = LoopBoundAnalyzer.analyze(
            body_indices, instructions, loop_start,
            instr_addrs=ctx[2] if len(ctx) > 2 else None)
        if info.bound_reg and info.bound_range is None:
            info2 = LoopBoundAnalyzer.analyze(
                body_indices, instructions, loop_start,
                vd_getter=lambda reg: self._loop_bound_vd_at(
                    info, instructions, ctx, reg),
                instr_addrs=ctx[2] if len(ctx) > 2 else None)
            if info2.bound_range is not None:
                info = info2
        self._fp_loop_info = info
        if info.bound_range is not None:
            self._fp_stats_dict(instructions)['loop_trip_refined'] += 1
            return info.bound_range
        return self._estimate_loop_iterations(
            body_indices, instructions, loop_start)

    def _loop_bound_vd_at(self, info, instructions, ctx, reg: str):
        """读取循环边界寄存器在 cmp 时刻的值域, 并经路径守卫钳位.

        Pass 2.5 的 _vd 是线性扫描结束状态, 直接使用会产生错误
        迭代数 (heap13 release 回归). cmp 快照值域若为 TOP,
        尝试用分支守卫 (A/B/C 型) 收敛上界.
        """
        vr = self._vd_snap_at(info.cmp_idx, reg)
        if vr.is_top and info.cmp_idx >= 0:
            clamped, used = PathConstraintApplier.clamp_size_range(
                ctx[0], ctx[1], info.cmp_idx, reg,
                ValueRange.unsigned_range(0, 0x100000),
                ctx[2] if len(ctx) > 2 else None)
            if used:
                return clamped
        return vr

    def _vd_snap_at(self, cmp_idx: int, reg: str):
        """读取 cmp 时刻的寄存器值域快照 (无快照返回 TOP)."""
        snap = getattr(self._coord, 'vd_cmp_snapshots', {})
        return snap.get(cmp_idx, {}).get(reg, ValueRange.top())

    def _loop_write_extent(self, iter_range, write_size: int):
        """字节写入的跨步扩展模型.

        步进循环 (i += s, s>1) 的字节写入地址为 {0, s, 2s, ...},
        最大触达地址 = (trips-1)*s + 1. 旧模型按 迭代数×写入字节 计算,
        对步进循环低估偏移扩展 (cve22 回归根因).
        仅对逐字节写入生效; 多字节写入保持原总写入模型 (更保守).
        """
        info = getattr(self, '_fp_loop_info', None)
        if info is None or write_size != 1 or iter_range.is_top:
            return None
        step = info.step if info.step > 1 else 1
        if step == 1:
            return None
        trips_hi = iter_range.umax
        extent = max(0, trips_hi - 1) * step + write_size
        return ValueRange.unsigned_range(write_size, extent)

    def _loop_coupling_safe(self, loop_start: int, site,
                            body_indices: List[int],
                            instructions: List[str],
                            per_iter_write: int) -> bool:
        """循环耦合判定: 边界与分配同源且写入不超过分配倍率.

        成立条件 (全部满足才撤销循环写入 finding):
          1. 循环为严格上界形式 (counter < bound 语义)
          2. 边界 (寄存器或栈槽) 的 cmp 快照与分配 size identity 同链
          3. 每轮写入 ≤ 分配 scale, 且分配 offset ≥ 0
        非严格上界 (counter ≤ bound) 拒绝耦合 — 多写一次即溢出.
        """
        if not self._fp_enabled():
            return False
        ctx = getattr(self, '_fp_ctx', ([], {}, None))
        info = LoopBoundAnalyzer.analyze(
            body_indices, instructions, loop_start,
            instr_addrs=ctx[2] if len(ctx) > 2 else None)
        if info.is_equality_loop or info.cmp_idx < 0:
            return False
        if info.strictness != 'strict':
            return False
        sid = self._coord.size_identity
        if info.bound_reg:
            bound_loc = ('reg', info.bound_reg)
        elif info.bound_slot is not None:
            bound_loc = ('mem', info.bound_slot)
        else:
            return False
        bound_id = sid.get_cmp_snapshot(info.cmp_idx, bound_loc)
        if bound_id is None or bound_id.is_unknown:
            bound_id = sid.get_cmp_snapshot(info.cmp_idx)
        if bound_id is None or bound_id.is_unknown:
            return False
        alloc_id = sid.get_alloc_size_id(site.site_id)
        if alloc_id is None or alloc_id.is_unknown:
            return False
        if not bound_id.same_chain(alloc_id):
            return False
        if alloc_id.scale < 1 or alloc_id.offset < 0:
            return False
        # 总写入 = trips × per_iter = bound × per_iter,
        # 分配 = scale×bound + offset.
        # 对任意 bound ≥ 0: per_iter×bound ≤ scale×bound + offset
        #   ⟺ per_iter ≤ scale 且 offset ≥ 0.
        if per_iter_write > alloc_id.scale:
            return False
        self._fp_stats_dict(instructions)['l6_loop_coupling_filtered'] += 1
        return True
