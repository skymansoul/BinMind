"""
SGAV 溢出验证器 — Guard-Bounded Write Proof (GBWP) 核心.
结合守卫约束、值范围、有界API分析做路径敏感溢出判定.
"""
import re
from typing import List, Dict, Set, Optional, Tuple
from analysis.sgav_types import (
    SoVerdict, BufferDesc, WriteDesc, GuardConstraint,
    ValueRange, SoResult)
from analysis.sgav_overflow_helpers import (
    build_func_map as _build_func_map,
    is_recursive as _is_recursive,
    frame_size as _frame_size,
    _RECURSE_FRAME_THRESHOLD, _EXCESSIVE_FRAME,
)

# 无界写入API: 不接受长度参数 → 必然溢出
_UNBOUNDED_APIS = {'gets', 'strcpy', 'strcat', 'sprintf', 'scanf', 'sscanf'}
# 有界写入API: 接受长度参数 → 需检查长度
_BOUNDED_APIS = {
    'strncpy', 'strncat', 'snprintf', 'fgets', 'read', 'recv',
    'memcpy', 'memmove', 'memset'}
# 安全替代API: 长度参数 <= sizeof(buf) 时安全
_SAFE_BOUNDED = {'strncpy', 'snprintf', 'fgets'}


class OverflowVerifier:
    """Guard-Bounded Write Proof 验证器."""

    def verify(self, bufs: List[BufferDesc],
               writes: List[WriteDesc],
               guards: Dict[int, List[GuardConstraint]],
               ranges: Dict[int, Dict[str, ValueRange]],
               lines: List[str]) -> List[SoResult]:
        results: List[SoResult] = []
        buf_map = {b.name: b for b in bufs}
        # 每个写入做 GBWP 判定
        for w in writes:
            r = self._check_write(w, buf_map, guards, ranges, lines)
            if r:
                results.append(r)
        # strcat 累积检测
        results.extend(self._check_strcat_chain(writes, buf_map))
        # 递归栈耗尽检测
        results.extend(self._check_recursion(lines, buf_map))
        # 过大栈帧检测
        results.extend(self._check_excessive_frame(bufs))
        # 去重
        seen = set()
        unique = []
        for r in results:
            key = (r.buffer_line, r.write_line, r.buf_name)
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique

    def _check_write(self, w: WriteDesc,
                     buf_map: Dict[str, BufferDesc],
                     guards: Dict[int, List[GuardConstraint]],
                     ranges: Dict[int, Dict[str, ValueRange]],
                     lines: List[str]) -> Optional[SoResult]:
        b = buf_map.get(w.resolved_buf)
        if not b:
            return None
        bsz = b.size
        # VLA + 无界API → VULN
        if b.kind == 'vla' and w.kind in _UNBOUNDED_APIS:
            return SoResult(
                verdict=SoVerdict.VULN, buffer_line=b.line,
                write_line=w.line, buf_name=b.name, buf_size=-1,
                confidence=0.85, write_size=-1,
                reason=f"VLA '{b.name}[n]': unbounded {w.kind}@L{w.line}",
                guard_info="no guard")
        # alloca + memset oversized
        if b.kind == 'alloca' and w.kind == 'memset' and w.write_size == -2:
            return SoResult(
                verdict=SoVerdict.VULN, buffer_line=b.line,
                write_line=w.line, buf_name=b.name, buf_size=-2,
                confidence=0.80, write_size=-2,
                reason=f"alloca '{b.name}': variable memset@L{w.line}",
                guard_info="no guard")
        # 无界API + fixed/vla → VULN (除非有守卫证明源有界)
        # strcat 交给累积检测, 跳过单次报告避免重复
        if w.kind in _UNBOUNDED_APIS and w.kind != 'strcat':
            guard_info = self._check_guard_safety(
                w, guards, ranges, b)
            if guard_info['safe']:
                return SoResult(
                    verdict=SoVerdict.SAFE,
                    buffer_line=b.line, write_line=w.line,
                    buf_name=b.name, buf_size=bsz, confidence=0.90,
                    reason=f"'{b.name}[{bsz}]': {w.kind}@L{w.line} "
                           f"guard-proven safe: {guard_info['reason']}",
                    guard_info=guard_info['reason'])
            return SoResult(
                verdict=SoVerdict.VULN, buffer_line=b.line,
                write_line=w.line, buf_name=b.name, buf_size=bsz,
                confidence=0.90, write_size=-1,
                reason=f"'{b.name}[{bsz}]': unbounded {w.kind}@L{w.line}",
                guard_info=guard_info['reason'])
        # 有界API: write_size vs buf_size
        if w.kind in _BOUNDED_APIS:
            ws = w.write_size
            # sizeof(buf) → 恰好等于buf_size → SAFE
            if ws == -3:
                return None  # sizeof 保护，安全
            # 常量
            if ws >= 0 and bsz >= 0:
                if ws > bsz:
                    return SoResult(
                        verdict=SoVerdict.VULN,
                        buffer_line=b.line, write_line=w.line,
                        buf_name=b.name, buf_size=bsz,
                        write_size=ws, confidence=0.95,
                        reason=f"'{b.name}[{bsz}]': {w.kind} writes "
                               f"{ws}B@L{w.line}",
                        guard_info="no guard")
                return None  # 有界且 ≤ buf_size → 安全
            # 变量大小: 用守卫+值范围判断
            if ws == -2:
                guard_info = self._check_guard_safety(
                    w, guards, ranges, b)
                if guard_info['safe']:
                    return None
                # 检查是否在snprintf等安全API中且size参数有守卫
                if w.kind in _SAFE_BOUNDED:
                    safe = self._check_bounded_api_guard(
                        w, guards, ranges, b)
                    if safe:
                        return None
                return SoResult(
                    verdict=SoVerdict.VULN,
                    buffer_line=b.line, write_line=w.line,
                    buf_name=b.name, buf_size=bsz,
                    confidence=0.75, write_size=-2,
                    reason=f"'{b.name}[{bsz}]': {w.kind} variable "
                           f"size@L{w.line} no guard",
                    guard_info=guard_info['reason'])
        # OOB: arr[i] where i unbounded
        if w.kind == 'oob':
            guard_info = self._check_index_guard(
                w, guards, ranges, b)
            if guard_info['safe']:
                return None
            return SoResult(
                verdict=SoVerdict.VULN, buffer_line=b.line,
                write_line=w.line, buf_name=b.name, buf_size=bsz,
                confidence=0.80, write_size=-1,
                reason=f"'{b.name}[{bsz}]': OOB write "
                       f"arr[{w.src_var}]@L{w.line}",
                guard_info=guard_info['reason'])
        return None

    def _check_guard_safety(self, w: WriteDesc,
                            guards: Dict[int, List[GuardConstraint]],
                            ranges: Dict[int, Dict[str, ValueRange]],
                            b: BufferDesc) -> Dict:
        """检查写入操作是否有守卫保证安全."""
        line_guards = guards.get(w.line, [])
        # 检查源变量是否被守卫约束 ≤ buf_size
        src = w.src_var or ''
        if src:
            for g in line_guards:
                if g.var == src:
                    if g.bound == -3 and g.op in ('<', '<='):
                        return {'safe': True,
                                'reason': f'guard: {src} {g.op} sizeof(buf)'}
                    if g.bound >= 0 and g.op in ('<', '<=') and g.bound <= b.size:
                        return {'safe': True,
                                'reason': f'guard: {src}{g.op}{g.bound}<=buf({b.size})'}
            # 值范围检查
            line_ranges = ranges.get(w.line, {})
            if src in line_ranges:
                vr = line_ranges[src]
                if vr.hi < b.size:
                    return {'safe': True,
                            'reason': f'range: {src} hi={vr.hi} <buf({b.size})'}
        # 没有特定源变量时检查缓冲区自身的守卫
        # 例如: if (len < 32) { memcpy(buf, src, len) }
        # len 没有出现在 write 的 src_var 中但受守卫约束
        for g in line_guards:
            if g.bound == -3 and g.op in ('<', '<='):
                return {'safe': True,
                        'reason': f'guard: sizeof-bound on {g.var}'}
            if g.bound >= 0 and g.op in ('<', '<=') and g.bound <= b.size:
                # 检查这个变量是否可能是写入大小的约束
                line_ranges = ranges.get(w.line, {})
                if g.var in line_ranges:
                    vr = line_ranges[g.var]
                    if vr.hi < b.size:
                        return {'safe': True,
                                'reason': f'guard: {g.var}{g.op}{g.bound}<=buf({b.size})'}
        return {'safe': False, 'reason': 'no guard on source'}

    def _check_bounded_api_guard(self, w: WriteDesc,
                                 guards: Dict[int, List[GuardConstraint]],
                                 ranges: Dict[int, Dict[str, ValueRange]],
                                 b: BufferDesc) -> bool:
        """检查有界API的size参数是否有守卫约束 ≤ buf_size."""
        line_guards = guards.get(w.line, [])
        for g in line_guards:
            if g.bound == -3 and g.op in ('<', '<='):
                return True  # sizeof 守卫
            if g.bound >= 0 and g.op in ('<', '<=') and g.bound <= b.size:
                return True
        return False

    def _check_index_guard(self, w: WriteDesc,
                           guards: Dict[int, List[GuardConstraint]],
                           ranges: Dict[int, Dict[str, ValueRange]],
                           b: BufferDesc) -> Dict:
        """检查数组索引是否有上下界守卫."""
        idx = w.src_var
        if not idx:
            return {'safe': False, 'reason': 'no index var'}
        line_guards = guards.get(w.line, [])
        has_upper = False
        has_lower = False
        for g in line_guards:
            if g.var == idx:
                if g.op in ('<', '<=') and 0 <= g.bound <= b.size:
                    has_upper = True
                if g.op in ('>', '>=') and g.bound >= 0:
                    has_lower = True
        line_ranges = ranges.get(w.line, {})
        if idx in line_ranges:
            vr = line_ranges[idx]
            if 0 <= vr.lo and vr.hi < b.size // max(b.elem_size, 1):
                return {'safe': True,
                        'reason': f"range: {idx}[{vr.lo},{vr.hi}] within bounds"}
        if has_upper and has_lower:
            return {'safe': True,
                    'reason': f"guard: {idx} bounded [0, {b.size}]"}
        if has_upper:
            return {'safe': True,
                    'reason': f"guard: {idx} < {b.size}"}
        return {'safe': False, 'reason': f"no guard on index {idx}"}

    def _check_strcat_chain(self, writes: List[WriteDesc],
                            buf_map: Dict[str, BufferDesc]) -> List[SoResult]:
        """strcat 累积写入检测."""
        results = []
        targets: Dict[str, List[int]] = {}
        for w in writes:
            if w.kind == 'strcat':
                targets.setdefault(w.resolved_buf, []).append(w.line)
        for tgt, wlines in targets.items():
            b = buf_map.get(tgt)
            if not b or b.size < 0: continue
            if len(wlines) >= 2 and b.size < 256:
                # 2+ strcat 到小缓冲区 → 累积风险
                est_write = len(wlines) * 8  # 每次至少8字节
                if est_write >= b.size:
                    results.append(SoResult(
                        verdict=SoVerdict.VULN,
                        buffer_line=b.line, write_line=wlines[-1],
                        buf_name=b.name, buf_size=b.size,
                        confidence=0.85,
                        reason=f"'{b.name}[{b.size}]': {len(wlines)} "
                               f"strcat calls → cumulative overflow",
                        guard_info="no guard"))
            elif len(wlines) >= 3 and b.size < 512:
                results.append(SoResult(
                    verdict=SoVerdict.VULN,
                    buffer_line=b.line, write_line=wlines[-1],
                    buf_name=b.name, buf_size=b.size,
                    confidence=0.80,
                    reason=f"'{b.name}[{b.size}]': {len(wlines)} "
                           f"strcat calls → cumulative overflow",
                    guard_info="no guard"))
        return results

    def _check_recursion(self, lines: List[str],
                         buf_map: Dict[str, BufferDesc]) -> List[SoResult]:
        """递归栈耗尽检测."""
        results = []
        fmap = _build_func_map(lines)
        for name, start, end in fmap:
            frame = _frame_size(name, start, end, lines)
            is_rec = _is_recursive(name, start, end, lines)
            if is_rec and frame >= _RECURSE_FRAME_THRESHOLD:
                results.append(SoResult(
                    verdict=SoVerdict.VULN,
                    buffer_line=start, buf_name=name, buf_size=frame,
                    confidence=0.85,
                    reason=f"'{name}': recursive with {frame}B frame "
                           f"→ stack exhaustion",
                    guard_info="recursion"))
        return results

    def _check_excessive_frame(self,
                               bufs: List[BufferDesc]) -> List[SoResult]:
        """过大栈帧检测."""
        results = []
        for b in bufs:
            if b.size >= _EXCESSIVE_FRAME and b.kind == 'fixed':
                results.append(SoResult(
                    verdict=SoVerdict.VULN,
                    buffer_line=b.line, buf_name=b.name, buf_size=b.size,
                    confidence=0.75,
                    reason=f"'{b.name}[{b.size}]': excessive "
                           f"stack allocation",
                    guard_info="frame size"))
        return results


__all__ = ['OverflowVerifier']
