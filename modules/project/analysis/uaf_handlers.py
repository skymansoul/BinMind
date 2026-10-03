# UAF检测 — 调用处理与使用点检测 (Mixin)
# 职责: 调用处理与使用点检测 — _process_call, _handle_alloc,
#   _handle_free, _check_deref_write/read, _check_call_args
from __future__ import annotations
import re
from typing import Dict, List, Optional, Tuple

# 懒加载: 与 uaf_detector 互相引用, 延迟到属性访问 (PEP 562)
def __getattr__(name):
    if name in ("UafSeverity", "FreeSiteInfo", "UafFinding"):
        from .uaf_detector import UafSeverity, FreeSiteInfo, UafFinding
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
from .allocation_tracker import (_ALLOC_FUNCTIONS, _REALLOC_FUNCTIONS,
                                  _FREE_FUNCTIONS)
from .instruction_parser import InstructionParser

import platform as _platform
if _platform.system() == 'Windows':
    _ARG_REGS = ["rcx", "rdx", "r8", "r9"]
else:
    _ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

# 写入目标缓冲区 — arg0是目标
_WRITE_SINKS = {"memcpy", "memmove", "memset", "__memcpy_chk", "__memmove_chk",
    "strcpy", "strncpy", "strcat", "strncat", "stpcpy", "read", "recv",
    "fread", "fgets", "gets", "scanf", "fscanf", "sprintf", "snprintf"}

# 读取/解引用 — 读取指针指向的内容
_DEREF_SINKS = {"strlen", "strcmp", "strncmp", "strcasecmp", "puts", "printf",
    "fprintf", "fputs", "fwrite", "write", "send", "perror", "free"}


class UafHandlerMixin:
    """UAF检测 — 调用处理与使用点检测层.

    以mixin形式注入 UafDetector, 保持self._xxx访问.
    """

    def _process_call(self, idx: int, parts: List[str],
                      instructions: List[str], in_loop: bool = False):
        """in_loop: 调用点位于循环体内 (回跳检测结果)."""
        if len(parts) < 2:
            return
        target = _extract_call_target(parts[-1])
        if not target:
            return

        # 分配函数
        if target in _ALLOC_FUNCTIONS:
            self._handle_alloc(idx, target)
            return
        if target in _REALLOC_FUNCTIONS:
            self._handle_alloc(idx, target)
            return

        # 释放函数
        if target in _FREE_FUNCTIONS:
            self._handle_free(idx, target, instructions,
                              in_loop=in_loop)
            return

        # 其他调用: 检查参数中是否有悬挂指针
        self._check_call_args(idx, target)

    def _handle_alloc(self, idx: int, target: str):
        """记录分配: 模型化malloc调用."""
        site_id = f"{self._current_func}:{idx}"
        size_reg = _ARG_REGS[0] if target != 'calloc' else _ARG_REGS[1]

        # 创建分配点
        # 保守使用默认值域 (ValueRange.top) — 无值域分析时假设大小未知
        from .value_range import ValueRange
        default_vr = ValueRange()
        site = self._alloc.model_malloc_call(
            site_id, size_reg, 'rax', idx, default_vr)
        if site:
            self._alloc.register_alloc(site)

        # 记录rax的溯源 (分配函数返回值)
        self._prov.record_alloc_return('rax', site, idx)

        # malloc覆写rax → 清除rax的悬挂状态
        self._dangling.clear_reg('rax')

    def _handle_free(self, idx: int, target: str,
                     instructions: List[str], in_loop: bool = False):
        """处理释放: 检查双重释放, 标记悬挂.

        in_loop: 循环体内的 free 在迭代次数 ≥2 时构成重复释放,
        指针来自循环前分配 (provenance 存在) 即报告.
        """
        arg0 = _ARG_REGS[0]
        origin = self._prov.get_origin(arg0)

        # 循环内重复释放识别: 循环体每次迭代执行一次 free,
        # 循环 ≥2 次迭代 → 第二次释放时指针已释放
        if in_loop and origin is not None and origin.alloc_site_id \
                and origin.alloc_site_id != 'unknown':
            finding = UafFinding(
                finding_id=f"uaf_{self._call_ctr}_df@{idx}",
                severity=UafSeverity.MEDIUM, confidence=0.60,
                free_site=FreeSiteInfo(
                    free_idx=idx, free_func=target, freed_reg=arg0,
                    ptr_origin=origin,
                    alloc_site_id=origin.alloc_site_id,
                    in_function=self._current_func,
                    is_double_free_candidate=True),
                use_type="DOUBLE_FREE",
                use_idx=idx,
                use_instruction=instructions[idx].strip(),
                use_reg=arg0, function_name=self._current_func,
                distance_from_free=0,
                detail=f"{target}({arg0}) — 循环体内释放, "
                       f"迭代≥2次即双重释放")
            self._findings.append(finding)
            self._call_ctr += 1

        # 释放参数的堆溯源门控: 仅当被释放指针可证实为堆分配时才
        # 标记悬挂. free(栈/全局指针) 后对同一寄存器的读写是合法操作,
        # 无条件标记悬挂将产生 DEREF_* 误报 (非堆释放 FP 类).
        # 门控可经实例属性 _heap_provenance_gate 关闭 (消融基线).
        alloc_site_id = origin.alloc_site_id if origin else ""
        if getattr(self, '_heap_provenance_gate', True) \
                and (not alloc_site_id or alloc_site_id == 'unknown'):
            return

        # 双重释放检测
        if self._dangling.is_dangling(arg0):
            prev = self._dangling.get_info(arg0)
            finding = UafFinding(
                finding_id=f"uaf_{self._call_ctr}_df@{idx}",
                severity=UafSeverity.MEDIUM, confidence=0.85,
                free_site=FreeSiteInfo(
                    free_idx=idx, free_func=target, freed_reg=arg0,
                    ptr_origin=origin,
                    alloc_site_id=prev.alloc_site_id if prev else "",
                    in_function=self._current_func,
                    is_double_free_candidate=True),
                use_type="DOUBLE_FREE",
                use_idx=idx, use_instruction=instructions[idx].strip(),
                use_reg=arg0, function_name=self._current_func,
                distance_from_free=(idx - prev.freed_at_idx if prev else 0),
                detail=f"{target}({arg0}) — 指针已释放, 双重释放")
            self._findings.append(finding)
            self._call_ctr += 1

        # 标记为悬挂
        self._dangling.mark_freed(arg0, origin, idx, target, alloc_site_id)

        # 传播到栈槽: 若free的指针来自栈加载, 标记该栈槽为悬挂
        if origin and origin.propagation_path:
            for step in reversed(origin.propagation_path):
                if 'load' in step and '←[' in step:
                    m = re.search(r'←\[(\w+)[+\-]([+\-]?0x[0-9a-fA-F]+)\]', step)
                    if m:
                        base = m.group(1)
                        off_str = m.group(2)
                        try:
                            off = int(off_str, 16)
                            self._dangling.mark_stack_dangling(
                                base, off,
                                self._dangling.get_info(arg0), idx)
                        except ValueError:
                            pass
                    break

        # 别名传播: 标记所有持有相同alloc_site_id的栈槽为悬挂
        if alloc_site_id:
            freed_info = self._dangling.get_info(arg0)
            for loc, loc_origin in self._prov.all_provenances().items():
                if loc.kind == 'stack' and loc_origin.alloc_site_id == alloc_site_id:
                    self._dangling.mark_stack_dangling(
                        loc.identifier, loc.offset, freed_info, idx)

    def _check_deref_write(self, idx: int, parts: List[str]):
        """检测通过悬挂指针的内存写入: mov [dangling_ptr+off], reg."""
        mem_part = parts[1]
        base = _extract_mem_base(mem_part)
        if not base:
            return
        base64 = InstructionParser.normalize_reg64(base)
        if not self._dangling.is_dangling(base64):
            return

        info = self._dangling.get_info(base64)
        finding = UafFinding(
            finding_id=f"uaf_{self._call_ctr}_dw@{idx}",
            severity=UafSeverity.CRITICAL, confidence=0.90,
            free_site=FreeSiteInfo(
                free_idx=info.freed_at_idx, free_func=info.freed_by,
                freed_reg=info.ptr_reg,
                alloc_site_id=info.alloc_site_id,
                in_function=self._current_func),
            use_type="DEREF_WRITE",
            use_idx=idx, use_instruction=' '.join(parts),
            use_reg=base64, function_name=self._current_func,
            distance_from_free=idx - info.freed_at_idx if info else 0,
            detail=f"通过悬挂指针{base64}写入内存 (free在idx={info.freed_at_idx})")
        self._findings.append(finding)
        self._call_ctr += 1

    def _check_deref_read(self, idx: int, parts: List[str]):
        """检测通过悬挂指针的内存读取: movzx/mov reg, [dangling_ptr+off]."""
        mem_part = parts[2]
        base = _extract_mem_base(mem_part)
        if not base:
            return
        base64 = InstructionParser.normalize_reg64(base)
        if not self._dangling.is_dangling(base64):
            return

        info = self._dangling.get_info(base64)
        finding = UafFinding(
            finding_id=f"uaf_{self._call_ctr}_dr@{idx}",
            severity=UafSeverity.HIGH, confidence=0.85,
            free_site=FreeSiteInfo(
                free_idx=info.freed_at_idx, free_func=info.freed_by,
                freed_reg=info.ptr_reg,
                alloc_site_id=info.alloc_site_id,
                in_function=self._current_func),
            use_type="DEREF_READ",
            use_idx=idx, use_instruction=' '.join(parts),
            use_reg=base64, function_name=self._current_func,
            distance_from_free=idx - info.freed_at_idx if info else 0,
            detail=f"通过悬挂指针{base64}读取内存 (free在idx={info.freed_at_idx})")
        self._findings.append(finding)
        self._call_ctr += 1

    def _check_call_args(self, idx: int, target: str):
        """检测函数调用中的悬挂指针参数."""
        for i, arg_reg in enumerate(_ARG_REGS):
            if not self._dangling.is_dangling(arg_reg):
                continue
            info = self._dangling.get_info(arg_reg)

            if i == 0 and target in _WRITE_SINKS:
                use_type = "CALL_ARG_DST"
                severity = UafSeverity.CRITICAL
            elif target in _DEREF_SINKS:
                use_type = "CALL_ARG_PTR"
                severity = UafSeverity.HIGH
            else:
                use_type = "CALL_ARG_PTR"
                severity = UafSeverity.MEDIUM
                # 值传递抑制: 未知函数无法证实对指针的解引用,
                # 悬挂指针仅作值传递 (如 printf("%p", p)) 不构成 UAF.
                # finding 保留但标记为可抑制误报 (INFO + 证据说明),
                # 与堆检测的 L4/L5/L6 证据分层设计一致.
                if getattr(self, '_uaf_value_pass_suppression', True):
                    severity = UafSeverity.INFO

            finding = UafFinding(
                finding_id=f"uaf_{self._call_ctr}_ca@{idx}",
                severity=severity, confidence=0.75,
                free_site=FreeSiteInfo(
                    free_idx=info.freed_at_idx, free_func=info.freed_by,
                    freed_reg=info.ptr_reg,
                    alloc_site_id=info.alloc_site_id,
                    in_function=self._current_func),
                use_type=use_type,
                use_idx=idx, use_instruction=f"call {target}",
                use_reg=arg_reg, function_name=self._current_func,
                distance_from_free=idx - info.freed_at_idx if info else 0,
                detail=f"call {target}(..., {arg_reg}, ...) — "
                       f"{arg_reg}是悬挂指针 (arg{i})",
                is_false_positive=(severity == UafSeverity.INFO),
                false_positive_reason=(
                    "值传递抑制: 未知函数未能证实解引用, "
                    "悬挂指针仅作值传递" if severity == UafSeverity.INFO
                    else ""))
            self._findings.append(finding)
            self._call_ctr += 1


# 辅助函数

def _extract_call_target(part: str) -> str:
    """从call指令操作数提取目标名."""
    part = part.strip()
    if '<' in part and '>' in part:
        return part.split('<')[1].rstrip('>')
    if part.startswith('*'):
        return ''
    if part.startswith('0x'):
        return ''
    return part


def _extract_mem_base(s: str) -> str:
    """从 [base+offset] 中提取基址寄存器."""
    s = s.strip()
    if s.startswith('[') and s.endswith(']'):
        inner = s[1:-1]
        m = re.match(r'(\w+)', inner)
        if m:
            reg = m.group(1)
            # 排除rip相对寻址 (全局变量)
            if reg.lower() == 'rip':
                return ''
            return reg
    return ''
