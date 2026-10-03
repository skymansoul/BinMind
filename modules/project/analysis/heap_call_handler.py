# 堆溢出检测 — 调用处理与指令传播
# 铁律
# 职责: _process_call (分配/释放/写入sink识别), _dispatch_propagation,
#   _conservative_scan (Pass 3保守回退)
import re
from typing import Dict, List, Optional, Tuple

from .value_range import ValueRange
from .allocation_tracker import (AllocationSite,
                                  _ALLOC_FUNCTIONS, _REALLOC_FUNCTIONS,
                                  _FREE_FUNCTIONS)
from .pointer_provenance import PointerOrigin
from .constraint_simplifier import OverflowVerdict
from .taint_propagation import TaintTag
from .instruction_parser import InstructionParser


# 按平台选择的参数寄存器已在 heap_overflow_detector 定义,
# 此处引用调用模块的 _ARG_REGS
def _get_arg_regs():
    import platform as _platform
    if _platform.system() == 'Windows':
        return ["rcx", "rdx", "r8", "r9"]
    return ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]


_WRITE_SINKS = {"memcpy", "memmove", "memset", "__memcpy_chk", "__memmove_chk",
    "strcpy", "strncpy", "strcat", "strncat", "stpcpy",
    "sprintf", "snprintf", "bcopy", "memccpy", "wmemcpy", "wmemmove"}


class CallHandlerMixin:
    """堆溢出检测 — 调用处理层 (Pass 1的调用识别 + Pass 3保守回退).

    以mixin形式注入 HeapOverflowDetector, 保持self._xxx访问.
    """

    def _process_call(self, idx: int, ops: List[str],
                      instrs: List[str],
                      func_map: Dict[str, Tuple[int, int]]
                      ) -> Optional['HeapAccessCheck']:
        """处理函数调用: 分配/释放/写入sink/污点源."""
        if not ops:
            return None
        target = ops[0].strip().split('@')[0]
        ctx = f"0x{idx:x}"
        _ARG_REGS = _get_arg_regs()
        _sid = self._coord.size_identity

        # 分配调用
        if target in _ALLOC_FUNCTIONS:
            size_reg = _ARG_REGS[0]
            size_vr = self._vd.get(size_reg)
            site_id = f"alloc_{self._call_ctr}_{target}@{idx}"
            self._call_ctr += 1
            # calloc: 分配量 = count × elem_size, 元素大小需乘入值域
            elem = 1
            if target == "calloc":
                elem_vr = self._vd.get(_ARG_REGS[1])
                if not elem_vr.is_top and elem_vr.is_constant:
                    elem = elem_vr.constant_value
                if not size_vr.is_top and elem > 1:
                    size_vr = size_vr.mul(ValueRange.constant(elem))
            is_fb = size_vr.is_top
            site = AllocationSite(site_id=site_id, alloc_func=target,
                alloc_size_range=size_vr if not is_fb
                else ValueRange.unsigned_range(1, 0x100000),
                return_reg="rax", call_address=idx,
                is_fallback=is_fb)
            self._alloc.register_alloc(site)
            self._prov.record_alloc_return("rax", site, idx, ctx)
            tag = self._taint.check_malloc_input_controlled(size_reg)
            if tag:
                site.alloc_size_range = ValueRange.top()
            _sid.bind_alloc(site_id, size_reg, scale=elem if elem > 1 else 1)
            _sid.on_call()
            return None

        # realloc调用: 更新分配大小, 重建指针溯源
        if target in _REALLOC_FUNCTIONS:
            size_reg = _ARG_REGS[1]  # realloc(ptr, size) — size是第2参数
            size_vr = self._vd.get(size_reg)
            site_id = f"realloc_{self._call_ctr}_{target}@{idx}"
            self._call_ctr += 1
            rfb = size_vr.is_top
            new_site = AllocationSite(site_id=site_id, alloc_func=target,
                alloc_size_range=size_vr if not rfb
                else ValueRange.unsigned_range(1, 0x100000),
                return_reg="rax", call_address=idx,
                is_fallback=rfb)
            self._alloc.register_alloc(new_site)
            self._prov.record_alloc_return("rax", new_site, idx, ctx)
            self._prov.mark_dead(_ARG_REGS[0])
            _sid.bind_alloc(site_id, size_reg)
            _sid.on_call()
            return None

        # 释放调用
        if target in _FREE_FUNCTIONS:
            self._prov.mark_dead(_ARG_REGS[0])
            _sid.on_call()
            return None

        # 写入调用 — 创建检查点
        if target in _WRITE_SINKS:
            # 延迟导入避免循环依赖
            from .heap_overflow_detector import HeapAccessCheck
            chk = HeapAccessCheck(
                access_id=f"wr_{self._call_ctr}_{target}@{idx}",
                sink_func=target, dst_reg=_ARG_REGS[0],
                src_reg=_ARG_REGS[1], size_reg=_ARG_REGS[2],
                instruction_address=idx, function_name=self._current_func)
            self._call_ctr += 1
            size_vr = self._vd.get(_ARG_REGS[2])
            guard_bound = self._find_early_return_guard(
                idx, instrs, _ARG_REGS[2])
            if guard_bound is not None and not size_vr.is_top:
                # 守卫降低写入大小的实际上界
                if size_vr.umax > guard_bound:
                    if size_vr.umin <= guard_bound:
                        # 常规夹紧: umin ≤ guard < umax → [umin, guard]
                        size_vr = ValueRange.unsigned_range(
                            size_vr.umin, guard_bound)
                    else:
                        # 守卫<umin: 初始值大于守卫 (如write_size=256,
                        # guard=128). 守卫保证fallthrough路径上≤guard,
                        # 原始umin来自被排除的路径 → 保守设[0, guard]
                        size_vr = ValueRange.unsigned_range(0, guard_bound)
            chk.size_range = size_vr
            origin = self._prov.get_origin(_ARG_REGS[0])
            chk.pointer_origin = origin
            if origin and origin.alloc_site_id != "unknown":
                site = self._alloc._alloc_sites.get(origin.alloc_site_id)
                if site and self._in_same_function(
                    site.call_address, idx, func_map):
                    chk.alloc_site = site
            chk.taint_tag = self._taint.check_write_input_controlled(
                _ARG_REGS[2])
            # 输入可控的写入大小: 即使值域分析看到常数,
            # 攻击者可能通过另一路径提供任意值 → 设TOP
            if chk.taint_tag is not None:
                chk.size_range = ValueRange.top()
            _sid.bind_sink(chk.access_id, _ARG_REGS[2])
            _sid.on_call()
            return chk

        # 污点源
        if self._taint.is_input_source(target):
            self._taint.mark_input_source(target, ctx, "rax")
            if self._vd:
                self._vd.set("rax", ValueRange.top())
                self._vd.set("eax", ValueRange.top())

        # 净化检测
        self._taint.detect_sanitization(target, ops[1:])

        # 记录调用边: 若rcx持有堆指针溯源, 保存用于 callee 内联写入修正
        if not InstructionParser.is_reg(target):
            rcx_origin = self._prov.get_origin('rcx')
            has_provenance = (rcx_origin
                              and rcx_origin.alloc_site_id != 'unknown')
            edx_vr = self._vd.get('rdx') if self._vd else None
            edx_has_value = (edx_vr and not edx_vr.is_top) if edx_vr else False

            if has_provenance or edx_has_value:
                is_crt_target = (target.startswith('__')
                                 or target.startswith('_.')
                                 or target.startswith('<'))
                if not is_crt_target:
                    self._call_provenance_edges.append({
                        'call_idx': idx,
                        'target': target,
                        'alloc_site_id': (rcx_origin.alloc_site_id
                                          if has_provenance else ''),
                        'edx_value_range': edx_vr if edx_has_value else None,
                    })

        _sid.on_call()
        return None

    def _dispatch_propagation(self, op: str, ops: List[str], idx: int,
                              raw_line: str = ""):
        """将指令分发给传播协调器."""
        ctx = f"0x{idx:x}"
        if not ops:
            if op == "cdqe" and self._vd:
                eax_vr = self._vd.get("eax")
                if eax_vr.is_top:
                    eax_vr = self._vd.get("rax")
                if not eax_vr.is_top:
                    self._vd.set("rax", eax_vr)
                self._prov.propagate_reg_to_reg("rax", "eax", ctx)
            return
        if op in ("mov", "movzx", "movsx", "movsxd") and len(ops) >= 2:
            self._coord.handle_mov(ops[0], ops[1], ctx)
            if op == "mov":
                self._track_inline_write(ops[0], ops[1], idx, ctx,
                                         raw_line)
        elif op in ("movups", "movupd", "movdqu", "movdqa", "movaps",
                    "movapd", "movntdq", "movntps", "movntpd") \
                and len(ops) >= 2:
            # SIMD 向量化存储 (gcc -O2 将字节循环向量化为 16B XMM 写)
            self._track_inline_write(ops[0], ops[1], idx, ctx,
                                     raw_line, simd=True)
        elif op in ("lea",) and len(ops) >= 2:
            self._coord.handle_lea(ops[0], ops[1], ctx)
        elif op in ("add", "sub") and len(ops) >= 2:
            self._coord.handle_arith(op, ops[0], ops[1], ctx)
        elif op in ("imul", "mul", "shl", "shr", "sar") and len(ops) >= 2:
            self._coord.handle_mul_div_shift(op, ops[0], ops[1], ctx)
        elif op in ("xor",) and len(ops) >= 2:
            self._coord.handle_xor_zero(ops[0], ops[1])
        elif op in ("push",) and ops:
            self._coord.handle_push(ops[0], ctx)
        elif op in ("pop",) and ops:
            self._coord.handle_pop(ops[0], ctx)
        elif op in ("cmp", "test") and len(ops) >= 2:
            imm = self._parser.parse_immediate(ops[1])
            if imm is not None:
                self._coord.handle_bound_check(ops[0], imm)
            # 循环耦合: 对 cmp 的左右操作数分别快照 identity.
            # 计数器可能在左 (cmp i, n) 也可能在右 (cmp n, i),
            # 快照按 ('reg', reg64) / ('mem', slot) 位置键存储.
            # 同时快照寄存器值域: 循环界分析在 Pass 2.5 执行,
            # 彼时 _vd 已非 cmp 时刻状态 (heap13 release 回归根因).
            vd_snap = getattr(self._coord, 'vd_cmp_snapshots', None)
            if vd_snap is None:
                vd_snap = self._coord.vd_cmp_snapshots = {}
            vd_snap.setdefault(idx, {})
            for cand in (ops[0], ops[1]):
                cand_clean = cand.strip()
                if InstructionParser.is_reg(cand_clean):
                    r64 = InstructionParser.normalize_reg64(
                        InstructionParser.clean_reg(cand_clean))
                    self._coord.size_identity.snapshot_cmp(
                        idx, ('reg', r64),
                        self._coord.size_identity.get_identity(r64))
                    vd_snap[idx][r64] = self._vd.get(r64)
                else:
                    slot = InstructionParser.parse_mem_slot(cand_clean)
                    if slot is not None:
                        self._coord.size_identity.snapshot_cmp(
                            idx, ('mem', slot),
                            self._coord.size_identity.get_mem_identity(
                                'rbp', slot))

    def _conservative_scan(self, instrs: List[str],
                           func_map: Dict[str, Tuple[int, int]]
                           ) -> List['OverflowFinding']:
        """Pass 3: 无溯源时的保守模式匹配 (仅低置信度报告)."""
        from .heap_overflow_detector import OverflowFinding, OverflowSeverity
        findings = []
        for i, line in enumerate(instrs):
            if 'call' not in line.lower():
                continue
            m = re.search(r'(memcpy|strcpy|strcat|sprintf).*?,\s*(\d+)',
                          line, re.I)
            if not m:
                continue
            size = int(m.group(2))
            if size > 0x200:
                findings.append(OverflowFinding(
                    finding_id=f"HEAP-CONS-{i}",
                    function_name=self._current_func,
                    sink_func=m.group(1),
                    severity=OverflowSeverity.LOW, confidence=0.15,
                    alloc_site_info="conservative",
                    overflow_detail=f"模式匹配: {m.group(1)}写入{size}B",
                    write_size_max=size, input_controlled=False,
                    recommendation="自动保守检出, 建议手动验证"))
        return findings
