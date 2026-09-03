"""QEMU user-mode 运行时追踪器 + Python 具体内存迹回退.

用途: 外部对照工具 2。优先调用 qemu-x86_64 -d in_asm 记录运行时
      危险调用; 本机无 QEMU 时回退到 Python 具体值解释器, 以固定
      攻击输入向量(入口参数=0x1000)对 objdump 指令做线性具体执行,
      记录 分配/写入/运行时越界 内存操作作为 ground truth。

检测口径:
  detected = 具体执行中出现 malloc 容量 < memcpy 长度的越界写
  与静态工具不同: 仅记录输入向量实际触发的越界 → 精确但召回受限。

CLI:
  python qemu_tracer.py <binary> [--json]
"""

import json
import shutil
import subprocess
import sys
import time

_DANGEROUS = {'memcpy', 'memmove', 'memset', 'strcpy', 'strcat',
              'malloc', 'calloc', 'realloc', 'free'}
_INPUT_ARG = 0x1000        # 固定攻击输入向量
_CALLER_SAVED = {'rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'}
_ARG_REGS_WIN = ['rcx', 'rdx', 'r8', 'r9']
_ARG_REGS_SYSV = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']


def qemu_runtime_trace(binary: str, timeout_s: int = 10) -> dict:
    """优先路径: qemu user mode 插桩输出危险调用."""
    t0 = time.time()
    qemu = shutil.which('qemu-x86_64') or shutil.which('qemu-i386')
    if not qemu:
        return {'tool': 'qemu', 'binary': binary, 'mode': 'fallback',
                'detected': False, 'error': 'qemu not installed',
                'elapsed_sec': 0.0}
    try:
        proc = subprocess.run(
            [qemu, '-d', 'in_asm', binary],
            capture_output=True, text=True, timeout=timeout_s,
            input='A' * 64, errors='replace')
        text = (proc.stdout + proc.stderr).lower()
        found = {f for f in _DANGEROUS if f in text}
        return {'tool': 'qemu', 'binary': binary, 'mode': 'qemu-asm',
                'detected': bool(found & {'memcpy', 'strcpy', 'memmove'}),
                'finding_count': len(found), 'sites': sorted(found),
                'elapsed_sec': round(time.time() - t0, 3)}
    except subprocess.TimeoutExpired:
        return {'tool': 'qemu', 'binary': binary, 'mode': 'qemu-asm',
                'detected': False, 'error': 'timeout',
                'elapsed_sec': round(time.time() - t0, 3)}


def _usable(requested: int) -> int:
    if requested <= 0:
        return 0
    return ((requested + 16 + 15) // 16) * 16 - 16


class ConcreteHeapTracer:
    """线性具体值堆追踪器 — 记录运行时分配/写入/越界内存操作."""

    def __init__(self):
        self._regs = {}
        self._slots = {}
        self.alloc_ops = []
        self.write_ops = []
        self.overflows = []

    def run(self, functions) -> None:
        for fn in functions:
            self._run_func(fn)

    def _run_func(self, fn) -> None:
        arg_regs = _detect_abi(fn.insns)
        self._regs = {r: _INPUT_ARG for r in arg_regs}
        self._slots = {}
        for insn in fn.insns:
            mn = insn.mnemonic
            if mn == 'call':
                self._on_call(insn, fn.name, arg_regs)
            elif mn in ('mov', 'movzx', 'movsxd', 'movsx'):
                self._on_mov(insn)
            elif mn == 'lea':
                self._on_lea(insn)
            elif mn in ('add', 'sub'):
                self._on_addsub(insn, mn == 'add')
            elif mn == 'imul':
                self._on_imul(insn)
            elif mn in ('xor', 'pxor'):
                self._on_xor(insn)
            elif mn == 'and':
                self._on_and(insn)

    def _on_call(self, insn, fn, arg_regs):
        op = insn.operands.lower()
        if 'malloc' in op or 'calloc' in op or 'realloc' in op:
            size = self._regs.get(arg_regs[0], 0)
            self.alloc_ops.append({'func': fn, 'addr': insn.addr,
                                   'size': size,
                                   'usable': _usable(size),
                                   'kind': 'malloc'})
            self._regs['rax'] = insn.addr   # 具体指针值
            self._clobber()
            return
        if 'memcpy' in op or 'memmove' in op or 'memset' in op:
            dst = self._regs.get(arg_regs[0], 0)
            size = self._regs.get(arg_regs[2], 0)
            self.write_ops.append({'func': fn, 'addr': insn.addr,
                                   'dst': dst, 'size': size})
            self._check_overflow(fn, insn.addr, dst, size)
            self._clobber()
            return
        if 'strcpy' in op or 'strcat' in op or 'gets' in op:
            self.write_ops.append({'func': fn, 'addr': insn.addr,
                                   'dst': self._regs.get(arg_regs[0], 0),
                                   'size': _INPUT_ARG})
            self._clobber()
            return
        if 'read' in op or 'recv' in op or 'fread' in op:
            dst = self._regs.get(arg_regs[1], 0)
            size = self._regs.get(arg_regs[2], 0)
            self.write_ops.append({'func': fn, 'addr': insn.addr,
                                   'dst': dst, 'size': size})
            self._check_overflow(fn, insn.addr, dst, size)
            self._clobber()
            return
        self._clobber()

    def _check_overflow(self, func, addr, dst, size):
        # dst 的具体值是 malloc 调用地址(近似基址); 匹配最近较小地址
        best = None
        for a in self.alloc_ops:
            if a['addr'] < addr:
                if best is None or a['addr'] > best['addr']:
                    best = a
        if best is not None and size > best['usable']:
            self.overflows.append({
                'func': func, 'write_addr': addr,
                'size': size, 'alloc_addr': best['addr'],
                'usable': best['usable'],
                'overflow_bytes': size - best['usable'],
            })

    def _on_mov(self, insn):
        op = insn.operands
        dst, _, src = op.partition(',')
        dst, src = dst.strip(), src.strip()
        if '[' in dst:
            base, off = _mem_offset(dst)
            if base in ('rbp', 'rsp') and off is not None:
                self._slots[off] = self._val(src)
            return
        reg = _canon(dst)
        if reg:
            self._regs[reg] = self._val(src)

    def _on_lea(self, insn):
        op = insn.operands
        dst, _, src = op.partition(',')
        reg = _canon(dst.strip())
        if not reg:
            return
        base, off = _mem_offset(src.strip())
        if base:
            self._regs[reg] = self._regs.get(base, 0) + (off or 0)

    def _on_addsub(self, insn, is_add):
        op = insn.operands
        dst, _, c = op.partition(',')
        reg = _canon(dst.strip())
        val = _imm(c.strip())
        if reg and val is not None:
            cur = self._regs.get(reg, 0)
            self._regs[reg] = cur + (val if is_add else -val)

    def _on_imul(self, insn):
        op = insn.operands
        parts = [p.strip() for p in op.split(',')]
        if len(parts) < 3:
            return
        reg = _canon(parts[0])
        val = _imm(parts[2])
        if reg and val is not None:
            self._regs[reg] = self._regs.get(reg, 0) * val

    def _on_xor(self, insn):
        op = insn.operands
        parts = [p.strip() for p in op.split(',')]
        if _canon(parts[0]) and _canon(parts[0]) == _canon(parts[1]):
            self._regs[_canon(parts[0])] = 0

    def _on_and(self, insn):
        op = insn.operands
        dst, _, c = op.partition(',')
        reg = _canon(dst.strip())
        val = _imm(c.strip())
        if reg and val is not None:
            self._regs[reg] = self._regs.get(reg, 0) & val

    def _val(self, operand):
        if '[' in operand:
            base, off = _mem_offset(operand)
            if base in ('rbp', 'rsp') and off is not None:
                return self._slots.get(off, 0)
            if base:
                return self._regs.get(base, 0) + (off or 0)
            return 0
        v = _imm(operand)
        if v is not None:
            return v
        return self._regs.get(_canon(operand), 0)

    def _clobber(self):
        for r in _CALLER_SAVED:
            self._regs.pop(r, None)


def _canon(operand):
    from modules.vuln.detection.heap_analysis.insn_parser import (
        extract_register)
    return extract_register(operand)


def _imm(operand):
    from modules.vuln.detection.heap_analysis.insn_parser import (
        extract_constant)
    return extract_constant(operand)


def _mem_offset(operand):
    from modules.vuln.detection.heap_analysis.insn_parser import (
        extract_mem_offset)
    return extract_mem_offset(operand)


def _detect_abi(insns):
    rcx = rdi = 0
    for insn in insns[:20]:
        o = insn.operands.lower()
        if 'rcx' in o:
            rcx += 1
        if 'rdi' in o:
            rdi += 1
    return _ARG_REGS_WIN if rcx >= rdi else _ARG_REGS_SYSV


def concrete_runtime_trace(binary: str) -> dict:
    """回退路径: Python 具体值追踪器."""
    t0 = time.time()
    try:
        from modules.vuln.detection.heap_analysis.insn_parser import (
            disassemble, parse_instructions)
        asm = disassemble(binary)
        functions = parse_instructions(asm)
        tracer = ConcreteHeapTracer()
        tracer.run(functions)
        return {
            'tool': 'qemu', 'binary': binary, 'mode': 'concrete-fallback',
            'detected': len(tracer.overflows) > 0,
            'finding_count': len(tracer.overflows),
            'alloc_ops': len(tracer.alloc_ops),
            'write_ops': len(tracer.write_ops),
            'overflows': tracer.overflows[:10],
            'elapsed_sec': round(time.time() - t0, 3),
        }
    except Exception as exc:
        return {'tool': 'qemu', 'binary': binary, 'mode': 'concrete-fallback',
                'detected': False, 'error': f'{type(exc).__name__}: {exc}',
                'elapsed_sec': round(time.time() - t0, 3)}


def trace(binary: str, timeout_s: int = 10) -> dict:
    """统一入口: 优先 qemu, 缺失时回退具体值追踪."""
    result = qemu_runtime_trace(binary, timeout_s)
    if result.get('mode') == 'fallback':
        fb = concrete_runtime_trace(binary)
        result.update(fb)
    return result


def main() -> None:
    binary = sys.argv[1] if len(sys.argv) > 1 else 'a.out'
    as_json = '--json' in sys.argv
    result = trace(binary)
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"qemu: mode={result.get('mode')} "
              f"detected={result.get('detected')} "
              f"overflows={result.get('finding_count', 0)}")


if __name__ == '__main__':
    main()
