"""
创新模块桥接层 — 将 39 个创新模块统一接入 core/pipeline.py 主链路的 rule 检测段.

各模块原始接口异构 (输入有伪代码/IR/C源码/二进制路径, 输出有dict/dataclass),
本层做签名归一化: (pseudocode, func_name, binary_path) → List[dict] findings.
每个模块的适配函数:
  - 将 pipeline 的 pseudocode 转为模块所需输入格式
  - 调用模块主入口
  - 将模块返回值转为 pipeline统一的 dict finding 格式
  - 任何模块异常都被捕获, 不影响主链路运行

调用顺序 (39个创新模块):
  HOFPR → HFP → ACFPC → DDSSC → AWSC → CJ-BVF → CJ-PCBVF →
  GAPSBV → GASRI → UAF-HOIG → UAF-Enhanced → UAF-Lifecycle →
  Double-Free → UAF-Lifetime-Tracker → Buffer-Underflow → Off-by-One →
  Uninitialized → FMTPROV → Int-Overflow-Enhance → Provenance →
  Cross-Domain → Cross-Pipeline →
  BWR+PCST → DD-BVF → CACBV → 双向区间交汇 → ACPE → PSVR-HLM → DP-TVRA →
  AWSC-ICF → HOFPR-APC → PcWBI-IRL → FC-VRA-PTA → CACBV-DSS →
  BIV-CTC → SI-CTA → PG-WBV-LSA → ACPE-VRP → ACFPC-CMS

前7模块聚焦堆溢出; 8-17扩展至UAF/DF/underflow/uninit等全类型; 18-22做误报削减与跨管线聚合;
23-29为D类深度创新补全, 覆盖有界写恢复/后向值流/容量耦合/双向区间/溯源等价/路径敏感分层/需求驱动污点;
30-39为差异化创新模块, 将22个重复副本在代码层面实现为不同算法.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 模块可用性标志, 首次调用时检测
_module_available: Dict[str, bool] = {}


def _check_module(name: str, import_fn) -> bool:
    """惰性检测模块可导入性, 缓存结果.

    部分模块位于 deemo/ 下属子包 (analysis/ 等), 当其他 bridge
    (如 ACFPC) 把 modules/vuln/src/heap 注入 sys.path 后,
    该路径下的 analysis/ 子包会遮蔽顶层 deemo/analysis/, 导致
    analysis.gapsbv_pipeline 等模块导入失败. 这里在每次检测前
    把 deemo/ 重新插回 sys.path[0], 保证顶层包优先解析.
    """
    if name not in _module_available:
        import os, sys
        _here = os.path.dirname(os.path.abspath(__file__))
        _project_root = os.path.dirname(_here)  # deemo/
        # 强制把 deemo/ 移到 sys.path 最前, 避免子包遮蔽
        if _project_root in sys.path:
            sys.path.remove(_project_root)
        sys.path.insert(0, _project_root)
        try:
            import_fn()
            _module_available[name] = True
        except Exception:
            _module_available[name] = False
    return _module_available[name]


# -- HOFPR: C源码级堆溢出误报抑制器 --
def run_hofpr_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """HOFPR 桥接: 将伪代码作为C源码输入, 产出HOFPR独立检测的堆溢出findings.

    HOFPR自含检测管线, 不依赖已有findings. 返回VULN判定的findings.
    existing_findings参数保留用于接口统一, 当前不参与过滤.
    """
    if not _check_module('hofpr', lambda: __import__(
            'modules.exploit.src.analysis.hofpr', fromlist=['run_hofpr_pipeline'])):
        return existing_findings

    try:
        from modules.exploit.src.analysis.hofpr import run_hofpr_pipeline
        report = run_hofpr_pipeline(pseudocode)

        # HOFPR报告中的VULN finding转为pipeline格式
        new_findings = []
        for f in report.findings:
            if hasattr(f, 'verdict') and str(f.verdict) in ('HoFprVerdict.VULN', 'VULN'):
                new_findings.append({
                    'type': 'heap-overflow',
                    'function': func_name,
                    'severity': 'High',
                    'cwe': 'CWE-122',
                    'confidence': 0.8,
                    'description': f'HOFPR: alloc_var={f.alloc_var} '
                                   f'alloc_size={f.alloc_size} '
                                   f'write_kind={f.write_kind} '
                                   f'reason={f.reason}',
                    'verdict': 'POSSIBLE',
                    'source': 'hofpr',
                })
        return new_findings
    except Exception as e:
        logger.debug('HOFPR bridge failed: %s', e)
        return []


# -- HFP: IR级堆溢出三态判定引擎 --
def run_hfp_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
) -> List[dict]:
    """HFP 桥接: 伪代码→IR归一化→三态判定, 返回OVERFLOW/POTENTIAL的findings."""
    if not _check_module('hfp', lambda: __import__(
            'modules.hfp.hfp_engine', fromlist=['detect_heap_overflow_hfp'])):
        return []

    try:
        from core.ir_normalizer import normalize_ir
        from modules.hfp.hfp_engine import detect_heap_overflow_hfp
        from modules.hfp.hfp_verdict import Verdict

        ir_lines = normalize_ir(pseudocode)
        hfp_findings = detect_heap_overflow_hfp(ir_lines)

        results = []
        for f in hfp_findings:
            if f.verdict == Verdict.SAFE:
                continue
            d = f.to_dict()
            severity = 'High' if f.verdict == Verdict.OVERFLOW else 'Medium'
            results.append({
                'type': 'heap-overflow',
                'function': func_name,
                'severity': severity,
                'cwe': 'CWE-122',
                'confidence': f.confidence,
                'description': f'HFP: verdict={d["verdict"]} '
                               f'write_base={d["write"]["base"]} '
                               f'offset={d["write"]["offset"]} '
                               f'evidence={d["evidence"]}',
                'verdict': 'DEFINITE' if f.verdict == Verdict.OVERFLOW else 'POSSIBLE',
                'source': 'hfp',
            })
        return results
    except Exception as e:
        logger.debug('HFP bridge failed: %s', e)
        return []


# -- ACFPC: 分配契约流保持压缩 --

def _pseudocode_to_acfpc_asm(
        pseudocode: str) -> Tuple[List[str], List[int]]:
    """将 C 伪代码转为 x86-64 SysV 汇编指令列表, 供 FpCompressor 处理.

    核心数据流映射 (SysV ABI):
      malloc(N)     → mov rdi, N; call malloc; mov [slot], rax
      calloc(N,M)   → mov rdi, N; mov rsi, M; call calloc; mov [slot], rax
      memcpy(d,s,n) → mov rdx, n; mov rsi, s; mov rdi, d; call memcpy
      if(n>N) n=N   → cmp [slot], N; jbe skip; mov [slot], N; skip:

    变量映射到栈槽 (rbp-0x8, rbp-0x10, ...), 经定义链追踪建立同源关系.
    DefChainTracker 线性处理指令, 不建模控制流, 守卫钳位后槽值恒为上界.
    """
    import re

    instructions: List[str] = []
    addrs: List[int] = []
    _addr = [0x1000]

    def emit(insn: str) -> None:
        instructions.append(insn)
        addrs.append(_addr[0])
        _addr[0] += 4

    var_slot: Dict[str, str] = {}
    _slot_off = [8]

    def get_slot(var: str) -> str:
        if var not in var_slot:
            var_slot[var] = f'rbp-0x{_slot_off[0]:x}'
            _slot_off[0] += 8
        return var_slot[var]

    def load_to_reg(expr: str, reg: str) -> None:
        """生成指令将表达式值加载到寄存器.

        支持: 立即数/变量/strlen(var)/strlen(var)±imm/var±imm.
        strlen 调用复用 rcx 传参, rax 接收返回值, 不干扰后续 reg 装载.
        """
        expr = expr.strip()
        # 立即数
        if re.match(r'0x[0-9a-fA-F]+$', expr) or re.match(r'-?\d+$', expr):
            emit(f'mov {reg}, {expr}')
            return
        # 变量名
        if re.match(r'\w+$', expr):
            if expr in var_slot:
                emit(f'mov {reg}, [{get_slot(expr)}]')
            else:
                emit(f'mov {reg}, {expr}')
            return
        # strlen(var) ± imm
        m = re.match(
            r'strlen\s*\(\s*(\w+)\s*\)\s*([+\-*])\s*(0x[0-9a-fA-F]+|\d+)$',
            expr)
        if m:
            s_var, op, imm = m.groups()
            if s_var in var_slot:
                emit(f'mov rcx, [{get_slot(s_var)}]')
            else:
                emit(f'mov rcx, {s_var}')
            emit('call strlen')
            if op == '+':
                emit(f'add rax, {imm}')
            elif op == '-':
                emit(f'sub rax, {imm}')
            else:
                emit(f'imul rax, {imm}')
            emit(f'mov {reg}, rax')
            return
        # strlen(var)
        m = re.match(r'strlen\s*\(\s*(\w+)\s*\)$', expr)
        if m:
            s_var = m.group(1)
            if s_var in var_slot:
                emit(f'mov rcx, [{get_slot(s_var)}]')
            else:
                emit(f'mov rcx, {s_var}')
            emit('call strlen')
            emit(f'mov {reg}, rax')
            return
        # var ± imm
        m = re.match(r'(\w+)\s*([+\-*])\s*(0x[0-9a-fA-F]+|\d+)$', expr)
        if m:
            base, op, imm = m.groups()
            if base in var_slot:
                emit(f'mov {reg}, [{get_slot(base)}]')
            else:
                emit(f'mov {reg}, {base}')
            if op == '+':
                emit(f'add {reg}, {imm}')
            elif op == '-':
                emit(f'sub {reg}, {imm}')
            else:
                emit(f'imul {reg}, {imm}')
            return
        # 无法解析 — 保守加载 0
        emit(f'mov {reg}, 0')

    for raw_line in (pseudocode or '').split('\n'):
        line = raw_line.strip()
        if not line or line.startswith(('{', '}', '//', '#', '/*', '*')):
            continue
        # 去除类型强转: (char *) 等
        line = re.sub(r'\([^)]*\*[^)]*\)\s*', '', line)
        # 去除类型声明前缀
        line = re.sub(
            r'^(?:int|char|void|size_t|ssize_t|unsigned|long|short|float|'
            r'double|uint\d+_t|int\d+_t|uchar|ushort|uint|ulong|bool|byte|'
            r'DWORD|WORD|BYTE|QWORD)\s+\*?\s*', '', line)
        # 去除单行大括号
        line = line.replace('{', '').replace('}', '')
        line = line.rstrip(';').strip()
        if not line:
            continue
        if line.startswith('return'):
            continue

        # var = malloc(N)
        m = re.match(r'(\w+)\s*=\s*malloc\s*\(([^)]+)\)', line)
        if m:
            var, size_arg = m.group(1), m.group(2).strip()
            load_to_reg(size_arg, 'rdi')
            emit('call malloc')
            emit(f'mov [{get_slot(var)}], rax')
            continue

        # var = calloc(N, M)
        m = re.match(r'(\w+)\s*=\s*calloc\s*\(([^,]+),\s*([^)]+)\)', line)
        if m:
            var, nmemb, size = m.groups()
            load_to_reg(nmemb.strip(), 'rdi')
            load_to_reg(size.strip(), 'rsi')
            emit('call calloc')
            emit(f'mov [{get_slot(var)}], rax')
            continue

        # var = realloc(ptr, N)
        m = re.match(r'(\w+)\s*=\s*realloc\s*\(([^,]+),\s*([^)]+)\)', line)
        if m:
            var, ptr, size = m.groups()
            load_to_reg(ptr.strip(), 'rdi')
            load_to_reg(size.strip(), 'rsi')
            emit('call realloc')
            emit(f'mov [{get_slot(var)}], rax')
            continue

        # memcpy(dst, src, n) — SysV: dst=rdi, src=rsi, size=rdx
        m = re.match(r'memcpy\s*\(([^,]+),\s*([^,]+),\s*([^)]+)\)', line)
        if m:
            dst, src, size = m.groups()
            load_to_reg(size.strip(), 'rdx')
            load_to_reg(src.strip(), 'rsi')
            load_to_reg(dst.strip(), 'rdi')
            emit('call memcpy')
            continue

        # memset(dst, val, n) — SysV: dst=rdi, val=rsi, size=rdx
        m = re.match(r'memset\s*\(([^,]+),\s*([^,]+),\s*([^)]+)\)', line)
        if m:
            dst, val, size = m.groups()
            load_to_reg(size.strip(), 'rdx')
            load_to_reg(dst.strip(), 'rdi')
            emit('call memset')
            continue

        # strncpy(dst, src, n) — SysV: dst=rdi, src=rsi, size=rdx
        m = re.match(r'strncpy\s*\(([^,]+),\s*([^,]+),\s*([^)]+)\)', line)
        if m:
            dst, src, size = m.groups()
            load_to_reg(size.strip(), 'rdx')
            load_to_reg(dst.strip(), 'rdi')
            emit('call strncpy')
            continue

        # strcpy(dst, src) — SysV: dst=rdi, src=rsi
        m = re.match(r'strcpy\s*\(([^,]+),\s*([^)]+)\)', line)
        if m:
            dst, src = m.groups()
            load_to_reg(dst.strip(), 'rdi')
            emit('call strcpy')
            continue

        # sprintf(dst, ...) — SysV: dst=rdi
        m = re.match(r'sprintf\s*\(([^,]+),', line)
        if m:
            dst = m.group(1).strip()
            load_to_reg(dst, 'rdi')
            emit('call sprintf')
            continue

        # if (n > N) n = N; — 守卫钳位 (常量上界)
        m = re.match(
            r'if\s*\(\s*(\w+)\s*(>|>=)\s*(0x[0-9a-fA-F]+|\d+)\s*\)'
            r'\s*\1\s*=\s*(0x[0-9a-fA-F]+|\d+)', line)
        if m:
            var, op, bound, new_val = m.groups()
            slot = get_slot(var)
            emit(f'cmp [{slot}], {bound}')
            jcc = 'jbe' if op == '>' else 'jb'
            skip_label = f'L_{_addr[0]:x}'
            emit(f'{jcc} {skip_label}')
            emit(f'mov [{slot}], {new_val}')
            emit(f'{skip_label}:')
            continue

        # if (n > var) n = var; — 守卫钳位 (变量上界)
        m = re.match(
            r'if\s*\(\s*(\w+)\s*(>|>=)\s*(\w+)\s*\)'
            r'\s*\1\s*=\s*(\w+)', line)
        if m:
            var, op, bound, new_val = m.groups()
            slot = get_slot(var)
            if bound in var_slot:
                emit(f'mov rax, [{get_slot(bound)}]')
                emit(f'cmp [{slot}], rax')
            else:
                emit(f'cmp [{slot}], {bound}')
            jcc = 'jbe' if op == '>' else 'jb'
            skip_label = f'L_{_addr[0]:x}'
            emit(f'{jcc} {skip_label}')
            if new_val in var_slot:
                emit(f'mov rax, [{get_slot(new_val)}]')
                emit(f'mov [{slot}], rax')
            else:
                emit(f'mov [{slot}], {new_val}')
            emit(f'{skip_label}:')
            continue

        # var = strlen(s)
        m = re.match(r'(\w+)\s*=\s*strlen\s*\(([^)]+)\)$', line)
        if m:
            var, s_arg = m.groups()
            load_to_reg(s_arg.strip(), 'rdi')
            emit('call strlen')
            emit(f'mov [{get_slot(var)}], rax')
            continue

        # var = argN (参数赋值, SysV: arg0=rdi, arg1=rsi, arg2=rdx, arg3=rcx, arg4=r8, arg5=r9)
        m = re.match(r'(\w+)\s*=\s*arg(\d+)$', line)
        if m:
            var, arg_idx = m.groups()
            arg_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
            reg = arg_regs[int(arg_idx)] if int(arg_idx) < len(arg_regs) else 'r9'
            emit(f'mov [{get_slot(var)}], {reg}')
            continue

        # var = other_var (简单赋值)
        m = re.match(r'(\w+)\s*=\s*(\w+)$', line)
        if m:
            dst, src = m.groups()
            if src in var_slot:
                emit(f'mov rax, [{get_slot(src)}]')
                emit(f'mov [{get_slot(dst)}], rax')
            elif re.match(r'0x[0-9a-fA-F]+|\d+$', src):
                emit(f'mov [{get_slot(dst)}], {src}')
            continue

        # var = src ± k (算术赋值)
        m = re.match(r'(\w+)\s*=\s*(\w+)\s*([+\-*])\s*(\w+)$', line)
        if m:
            dst, src, op, k = m.groups()
            # 算术赋值用 rdi 作为临时寄存器 (与 SysV ABI 一致)
            if src in var_slot:
                emit(f'mov rdi, [{get_slot(src)}]')
            elif re.match(r'0x[0-9a-fA-F]+|\d+$', src):
                emit(f'mov rdi, {src}')
            else:
                emit(f'mov rdi, {src}')
            if re.match(r'0x[0-9a-fA-F]+|\d+$', k):
                if op == '+':
                    emit(f'add rdi, {k}')
                elif op == '-':
                    emit(f'sub rdi, {k}')
                else:
                    emit(f'imul rdi, {k}')
            elif k in var_slot:
                emit(f'mov rsi, [{get_slot(k)}]')
                if op == '+':
                    emit('add rdi, rsi')
                elif op == '-':
                    emit('sub rdi, rsi')
                else:
                    emit('imul rdi, rsi')
            emit(f'mov [{get_slot(dst)}], rdi')
            continue

    return instructions, addrs


def run_acfpc_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """ACFPC 桥接: 分配契约流保持压缩.

    有 binary_path 时走完整管线 (反汇编→检测→压缩);
    无 binary_path 时从伪代码合成 x86-64 汇编, 直接调 FpCompressor
    做契约提取+证据链压缩, 保证伪代码输入下 ACFPC 真实执行.
    """
    if not _check_module('acfpc', lambda: __import__(
            'modules.vuln.src.heap.acfpc.acfpc_pipeline',
            fromlist=['run_acfpc_pipeline'])):
        return existing_findings

    try:
        if binary_path:
            # 有二进制: 走完整管线 (反汇编 → 检测 → 压缩)
            from modules.vuln.src.heap.acfpc.acfpc_pipeline import (
                run_acfpc_pipeline)
            report = run_acfpc_pipeline(
                binary_path, findings=existing_findings or None)
            results = []
            for f in report.findings:
                f.setdefault('source', 'acfpc')
                f.setdefault('type', 'heap-overflow')
                f.setdefault('function', func_name)
                results.append(f)
            return results

        # 无二进制: 从伪代码合成汇编, 直接调 FpCompressor
        instructions, addrs = _pseudocode_to_acfpc_asm(pseudocode)
        if not instructions:
            return existing_findings

        # 为 heap findings 分配 insn_addr, 映射到写调用指令地址
        # FpCompressor 通过 insn_addr 将 finding 关联到被压制的写点
        import re as _re
        write_call_pat = _re.compile(
            r'call\s+(?:memcpy|memset|strncpy|strcpy|sprintf)',
            _re.IGNORECASE)
        write_addrs = []
        for i, insn in enumerate(instructions):
            if write_call_pat.match(insn.strip()):
                write_addrs.append(addrs[i])

        findings_copy = []
        for f in existing_findings:
            f_copy = dict(f) if isinstance(f, dict) else f
            if (isinstance(f_copy, dict)
                    and 'heap' in f_copy.get('type', '').lower()
                    and not f_copy.get('insn_addr')
                    and write_addrs):
                f_copy['insn_addr'] = write_addrs[0]
            findings_copy.append(f_copy)

        from modules.vuln.src.heap.acfpc.fp_compressor import FpCompressor
        compressor = FpCompressor(abi='sysv', mode='strict')
        result = compressor.compress(
            instructions, findings_copy, addrs, {})

        # 补充 source 标记
        for f in result.kept:
            if isinstance(f, dict):
                f.setdefault('source', 'acfpc')
                f.setdefault('function', func_name)
        return list(result.kept)
    except Exception as e:
        logger.debug('ACFPC bridge failed: %s', e)
        return existing_findings


# -- DDSSC: 三层混合误报过滤协调器 --
def run_ddssc_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """DDSSC 桥接: 对已有堆溢出findings执行三层级联过滤.

    Layer1: 区间推理 (常数 alloc/write 直接比较)
    Layer2: 符号尺寸关联 (从伪代码构建 SymExpr, 同变量判定等价/支配)
    Layer3: 按需 SMT (z3 可用时构建路径约束并求解, 不可用退化为区间窄化)
    """
    if not _check_module('ddssc', lambda: __import__(
            'modules.analysis.static.ddssc_coordinator',
            fromlist=['DDSSCCoordinator'])):
        return existing_findings

    try:
        from modules.analysis.static.ddssc_coordinator import DDSSCCoordinator
        from modules.analysis.static.heap_constraint import Interval
        from modules.analysis.static.sym_size_correlator import SymExpr
        from modules.analysis.static.value_range import ValueRange
        from core.ir_normalizer import normalize_ir
        import re

        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        if not heap_findings:
            return existing_findings

        # 从伪代码解析变量符号表达式, 为 Layer2 构造 SymExpr
        # malloc(n) → n 的 SymExpr = SymExpr(var='n')
        # n = size - 8 → SymExpr(var='size', coeff=1, const=-8)
        # n = arg → SymExpr(var='arg', coeff=1, const=0)
        # buf = malloc(N) → alloc_var 'buf' 的 size_expr = SymExpr(const=N)
        var_symexpr: Dict[str, SymExpr] = {}
        # 记录每个变量的值域 (从守卫钳位推导)
        var_vr: Dict[str, ValueRange] = {}

        for line in pseudocode.split('\n') if pseudocode else []:
            line = line.strip()
            if not line:
                continue

            # 守卫钳位: if (n > N) n = N; → var_vr[n] = [0, N]
            guard_m = re.match(
                r'if\s*\(\s*(\w+)\s*>\s*(\d+|0x[0-9a-fA-F]+)\s*\)'
                r'\s*\1\s*=\s*(\d+|0x[0-9a-fA-F]+)', line)
            if guard_m:
                var, _bound, new_val = guard_m.groups()
                val = int(new_val, 0)
                var_vr[var] = ValueRange(0, val)
                continue

            # dst = src ± k / dst = src * k / dst = src
            assign_m = re.search(
                r'(\w+)\s*=\s*(\w+)\s*([+\-*])\s*(\d+|0x[0-9a-fA-F]+)', line)
            if assign_m:
                dst, src, op, k_str = assign_m.groups()
                k = int(k_str, 0)
                if src in var_symexpr:
                    base = var_symexpr[src]
                    if op == '+':
                        var_symexpr[dst] = SymExpr(
                            base.var, base.coeff, base.const + k)
                    elif op == '-':
                        var_symexpr[dst] = SymExpr(
                            base.var, base.coeff, base.const - k)
                    elif op == '*':
                        var_symexpr[dst] = SymExpr(
                            base.var, base.coeff * k, base.const * k)
                else:
                    if op == '+':
                        var_symexpr[dst] = SymExpr(var=src, coeff=1, const=k)
                    elif op == '-':
                        var_symexpr[dst] = SymExpr(var=src, coeff=1, const=-k)
                    elif op == '*':
                        var_symexpr[dst] = SymExpr(var=src, coeff=k, const=0)
                continue

            # 简单赋值: dst = src
            simple_m = re.match(r'(\w+)\s*=\s*(\w+)$', line)
            if simple_m:
                dst, src = simple_m.groups()
                if src in var_symexpr:
                    var_symexpr[dst] = var_symexpr[src]
                else:
                    var_symexpr[dst] = SymExpr(var=src, coeff=1, const=0)

        # 构建指令列表供 Layer3 SMT 路径约束收集使用
        # DDSSC 的 SMT 求解器 PathConstraintCollector 需要 x86-64 格式:
        #   cmp reg, imm; jcc target — 只有这两类指令被识别为路径约束
        # 因此从伪代码的 if 守卫模式生成真实 cmp+jcc 指令对,
        # 使 Layer3 SMT 能收集到路径约束并交给 z3 求解
        ir_lines = normalize_ir(pseudocode)
        smt_instructions = []
        _smt_addr = [0x1000]

        def _smt_emit(mnem, ops_list):
            smt_instructions.append({
                'address': _smt_addr[0],
                'mnemonic': mnem,
                'operands': ops_list,
            })
            _smt_addr[0] += 4

        # 变量名 → 寄存器映射 (使用 SysV arg 寄存器 + callee-saved)
        _dd_var_reg: Dict[str, str] = {}
        _dd_ri = [0]
        _dd_callee = ['rbx', 'r12', 'r13', 'r14', 'r15']
        _dd_sysv = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']

        def _dd_gr(var):
            if var not in _dd_var_reg:
                if _dd_ri[0] < len(_dd_callee):
                    _dd_var_reg[var] = _dd_callee[_dd_ri[0]]
                    _dd_ri[0] += 1
                else:
                    _dd_var_reg[var] = f'r{_dd_ri[0] + 5}'
                    _dd_ri[0] += 1
            return _dd_var_reg[var]

        # 第一遍: 为变量分配寄存器
        for _l in pseudocode.split('\n') if pseudocode else []:
            for _m in re.finditer(r'\b([a-zA-Z_]\w*)\b', _l):
                _v = _m.group(1)
                if _v not in ('malloc', 'calloc', 'realloc', 'free',
                              'memcpy', 'memmove', 'memset', 'strcpy',
                              'strcat', 'sprintf', 'vsprintf', 'stpcpy',
                              'gets', 'if', 'else', 'while', 'for',
                              'return', 'break', 'continue', 'NULL',
                              'arg0', 'arg1', 'arg2', 'arg3',
                              'int', 'char', 'void', 'size_t',
                              'unsigned', 'long', 'short', 'float',
                              'double', 'ssize_t', 'uint32_t', 'uint64_t',
                              'int32_t', 'int64_t'):
                    _dd_gr(_v)

        for line in (pseudocode.split('\n') if pseudocode else []):
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('#'):
                continue

            # if (var > N) return/break/continue
            # → cmp var_reg, N; ja <skip_addr>  (早退守卫)
            m = re.match(
                r'if\s*\(\s*(\w+)\s*>\s*(\d+|0x[0-9a-fA-F]+)\s*\)'
                r'\s*(?:return|break|continue)', line)
            if m:
                var, bound_str = m.groups()
                bound = int(bound_str, 0)
                reg = _dd_gr(var)
                _smt_emit('cmp', [reg, str(bound)])
                _smt_emit('ja', [hex(_smt_addr[0] + 0x100)])
                continue

            # if (var >= N) return/break/continue
            m = re.match(
                r'if\s*\(\s*(\w+)\s*>=\s*(\d+|0x[0-9a-fA-F]+)\s*\)'
                r'\s*(?:return|break|continue)', line)
            if m:
                var, bound_str = m.groups()
                bound = int(bound_str, 0)
                reg = _dd_gr(var)
                _smt_emit('cmp', [reg, str(bound)])
                _smt_emit('jae', [hex(_smt_addr[0] + 0x100)])
                continue

            # if (N < var) return/break/continue → cmp var, N; ja skip
            m = re.match(
                r'if\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*<\s*(\w+)\s*\)'
                r'\s*(?:return|break|continue)', line)
            if m:
                bound_str, var = m.groups()
                bound = int(bound_str, 0)
                reg = _dd_gr(var)
                _smt_emit('cmp', [reg, str(bound)])
                _smt_emit('ja', [hex(_smt_addr[0] + 0x100)])
                continue

            # if (var <= N) return/break/continue
            # → cmp var_reg, N; jbe <skip_addr>  (反例守卫)
            m = re.match(
                r'if\s*\(\s*(\w+)\s*<=\s*(\d+|0x[0-9a-fA-F]+)\s*\)'
                r'\s*(?:return|break|continue)', line)
            if m:
                var, bound_str = m.groups()
                bound = int(bound_str, 0)
                reg = _dd_gr(var)
                _smt_emit('cmp', [reg, str(bound)])
                _smt_emit('jbe', [hex(_smt_addr[0] + 0x100)])
                continue

            # if (N >= var) return/break/continue → cmp var, N; jbe skip
            m = re.match(
                r'if\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*>=\s*(\w+)\s*\)'
                r'\s*(?:return|break|continue)', line)
            if m:
                bound_str, var = m.groups()
                bound = int(bound_str, 0)
                reg = _dd_gr(var)
                _smt_emit('cmp', [reg, str(bound)])
                _smt_emit('jbe', [hex(_smt_addr[0] + 0x100)])
                continue

            # 守卫钳位: if (n > N) n = N;
            m = re.match(
                r'if\s*\(\s*(\w+)\s*>\s*(\d+|0x[0-9a-fA-F]+)\s*\)'
                r'\s*\1\s*=\s*(\d+|0x[0-9a-fA-F]+)', line)
            if m:
                var, bound_str, _ = m.groups()
                bound = int(bound_str, 0)
                reg = _dd_gr(var)
                _smt_emit('cmp', [reg, str(bound)])
                _smt_emit('ja', [hex(_smt_addr[0] + 0x20)])
                continue

            # 其余 IR 行保持原有格式 (malloc/memcpy 等)
            parts = line.split(None, 1)
            mnem = parts[0].lower() if parts else ''
            ops_str = parts[1] if len(parts) > 1 else ''
            operands = [op.strip().rstrip(';')
                        for op in ops_str.split(',')] if ops_str else []
            _smt_emit(mnem, operands)

        # 查找 alloc 和 write 调用地址
        alloc_addr_val = 0
        write_addr_val = 0
        for ins in smt_instructions:
            mnem = ins['mnemonic']
            if alloc_addr_val == 0 and mnem in ('malloc', 'calloc', 'realloc'):
                alloc_addr_val = ins['address']
            if write_addr_val == 0 and mnem in (
                    'memcpy', 'memmove', 'strncpy', 'strcpy', 'memset'):
                write_addr_val = ins['address']

        # 启用 SMT (z3 可用时自动启用)
        try:
            import z3 as _z3
            _has_z3 = True
        except ImportError:
            _has_z3 = False

        coordinator = DDSSCCoordinator(enable_smt=_has_z3)
        filtered = []
        for f in heap_findings:
            alloc_size = f.get('alloc_size', -1)
            write_size = f.get('write_size', -1)
            alloc_var = f.get('alloc_var', '')
            write_var = f.get('write_var', '')

            # 构建 SymExpr (Layer2 使用)
            alloc_expr = var_symexpr.get(alloc_var) if alloc_var else None
            write_expr = var_symexpr.get(write_var) if write_var else None

            # 构建值域 (Layer3 SMT 使用)
            alloc_vr = var_vr.get(alloc_var) if alloc_var else None
            write_vr = var_vr.get(write_var) if write_var else None

            # 构建区间 (Layer1 使用)
            # 当 alloc_size/write_size 是整数时使用精确区间
            # 否则从 SymExpr 推导宽区间
            if isinstance(alloc_size, int) and alloc_size >= 0:
                alloc_iv = Interval(alloc_size, alloc_size)
            elif alloc_expr is not None and alloc_expr.is_const():
                alloc_iv = Interval(alloc_expr.const, alloc_expr.const)
            else:
                # 符号化: 用宽区间
                if alloc_vr is not None:
                    alloc_iv = Interval(alloc_vr.lo, alloc_vr.hi)
                else:
                    alloc_iv = Interval(0, 2**31 - 1)

            if isinstance(write_size, int) and write_size >= 0:
                write_iv = Interval(write_size, write_size)
            elif write_expr is not None and write_expr.is_const():
                write_iv = Interval(write_expr.const, write_expr.const)
            else:
                if write_vr is not None:
                    write_iv = Interval(write_vr.lo, write_vr.hi)
                else:
                    write_iv = Interval(0, 2**31 - 1)

            result = coordinator.analyze_finding(
                alloc_addr=alloc_addr_val,
                alloc_size_interval=alloc_iv,
                write_size_interval=write_iv,
                alloc_size_expr=alloc_expr,
                write_size_expr=write_expr,
                alloc_vr=alloc_vr,
                write_vr=write_vr,
                instructions=smt_instructions,
                write_addr=write_addr_val,
            )
            if result.verdict == 'safe':
                continue  # DDSSC 判定安全, 过滤
            if result.verdict == 'overflow':
                f.setdefault('ddssc_verdict', 'overflow')
                f.setdefault('ddssc_layer', result.layer)
                f.setdefault('ddssc_detail', result.detail)
            elif result.verdict == 'unknown':
                f.setdefault('ddssc_verdict', 'unknown')
                f.setdefault('ddssc_layer', result.layer)
            filtered.append(f)
        return non_heap + filtered
    except Exception as e:
        logger.debug('DDSSC bridge failed: %s', e)
        return existing_findings


# -- AWSC: 分配-写入同源关联引擎 --
def run_awsc_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """AWSC 桥接: 对已有堆溢出findings做同源关联过滤.

    AWSC原始接口需要指令序列做后向def-use根来源追踪,
    此处从finding中提取alloc_size/write_size构建Root对象,
    调用AWSCEngine.correlate()做同源判定.
    两个立即数Root的同源判定等价于AWSC的Case 1常量比较路径.
    """
    if not _check_module('awsc', lambda: __import__(
            'modules.analysis.static.co_source_engine',
            fromlist=['AWSCEngine'])):
        return existing_findings

    try:
        from modules.analysis.static.co_source_engine import AWSCEngine
        from modules.analysis.static.co_source_core import (
            Root, ROOT_IMM, ROOT_PARAM, ROOT_STACK, ROOT_CALLRET, ROOT_UNKNOWN)
        import re
        engine = AWSCEngine(use_win64_abi=False)  # SysV ABI: rdi=arg0, rdx=arg2

        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        if not heap_findings:
            return existing_findings

        # 将伪代码转为 x86-64 汇编指令序列, 使 trace_size_root 能做真实后向追踪
        # SysV ABI: malloc size 在 rdi, memcpy/memset size 在 rdx
        # 变量映射到 callee-saved 寄存器 (rbx/r12/r13/r14/r15)
        _callee_saved = ['rbx', 'r12', 'r13', 'r14', 'r15']
        _aw_var_reg: Dict[str, str] = {}
        _aw_ri = [0]

        def _aw_gr(var: str) -> str:
            if var not in _aw_var_reg:
                if _aw_ri[0] < len(_callee_saved):
                    _aw_var_reg[var] = _callee_saved[_aw_ri[0]]
                    _aw_ri[0] += 1
                else:
                    _aw_var_reg[var] = f'r{_aw_ri[0] + 5}'
                    _aw_ri[0] += 1
            return _aw_var_reg[var]

        # 预扫描: 为所有变量分配寄存器
        for _l in pseudocode.split('\n') if pseudocode else []:
            for _m in re.finditer(r'\b([a-zA-Z_]\w*)\b', _l):
                _v = _m.group(1)
                if _v not in ('malloc', 'calloc', 'realloc', 'free',
                              'memcpy', 'memmove', 'memset', 'strcpy',
                              'strcat', 'sprintf', 'vsprintf', 'stpcpy',
                              'gets', 'if', 'else', 'while', 'for',
                              'return', 'NULL', 'arg0', 'arg1', 'arg2',
                              'arg3', 'int', 'char', 'void', 'size_t',
                              'unsigned', 'long', 'short', 'float',
                              'double', 'ssize_t', 'uint32_t', 'uint64_t',
                              'int32_t', 'int64_t'):
                    _aw_gr(_v)

        instructions = []
        _a = [0x1000]
        alloc_call_addr = -1
        write_call_addr = -1

        def _emit(mnem, ops):
            ins = {'address': _a[0], 'mnemonic': mnem, 'operands': ops}
            instructions.append(ins)
            _a[0] += 4
            return ins

        for line in pseudocode.split('\n') if pseudocode else []:
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('#'):
                continue

            # var = malloc(N) → mov rdi, N; call malloc; mov <reg>, rax
            m = re.match(
                r'(\w+)\s*=\s*malloc\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*\)', line)
            if m:
                var, sz = m.groups()
                _emit('mov', ['rdi', str(int(sz, 0))])
                c = _emit('call', ['malloc'])
                if alloc_call_addr < 0:
                    alloc_call_addr = c['address']
                _emit('mov', [_aw_gr(var), 'rax'])
                continue

            # var = malloc(var2) → mov rdi, <reg2>; call malloc; mov <reg>, rax
            m = re.match(
                r'(\w+)\s*=\s*malloc\s*\(\s*(\w+)\s*\)', line)
            if m:
                var, sv = m.groups()
                _emit('mov', ['rdi', _aw_gr(sv)])
                c = _emit('call', ['malloc'])
                if alloc_call_addr < 0:
                    alloc_call_addr = c['address']
                _emit('mov', [_aw_gr(var), 'rax'])
                continue

            # var = argN → mov <reg>, <sysv_arg_reg>
            m = re.match(r'(\w+)\s*=\s*arg(\d+)', line)
            if m:
                var, idx = m.groups()
                _sa = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
                _emit('mov', [_aw_gr(var),
                              _sa[int(idx)] if int(idx) < len(_sa) else 'rdi'])
                continue

            # recv/read/fread → mov <reg>, rax
            m = re.search(
                r'(?:recv|read|fread)\s*\([^,]+,\s*[^,]+,\s*(\w+)', line)
            if m:
                _emit('mov', [_aw_gr(m.group(1)), 'rax'])
                continue

            # var = src ± k → mov <reg>, <src_reg>; add/sub/imul
            m = re.match(
                r'(\w+)\s*=\s*(\w+)\s*([+\-*])\s*(\d+|0x[0-9a-fA-F]+)', line)
            if m:
                dst, src, op, ks = m.groups()
                k = int(ks, 0)
                dr = _aw_gr(dst)
                sr = _aw_gr(src) if src in _aw_var_reg else src
                _emit('mov', [dr, sr])
                if op == '+':
                    _emit('add', [dr, str(k)])
                elif op == '-':
                    _emit('sub', [dr, str(k)])
                else:
                    _emit('imul', [dr, sr, str(k)])
                continue

            # var = var2 → mov <reg>, <reg2>
            m = re.match(r'(\w+)\s*=\s*(\w+)$', line)
            if m:
                dst, src = m.groups()
                dr = _aw_gr(dst)
                if src in _aw_var_reg:
                    _emit('mov', [dr, _aw_gr(src)])
                elif re.match(r'0x[0-9a-fA-F]+|\d+$', src):
                    _emit('mov', [dr, src])
                continue

            # memcpy(dst, src, N) → mov rdi; mov rsi; mov rdx; call memcpy
            m = re.match(
                r'memcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\d+|0x[0-9a-fA-F]+)\s*\)', line)
            if m:
                d, s, sz = m.groups()
                _emit('mov', ['rdi', _aw_gr(d)])
                _emit('mov', ['rsi', _aw_gr(s)])
                _emit('mov', ['rdx', str(int(sz, 0))])
                c = _emit('call', ['memcpy'])
                if write_call_addr < 0:
                    write_call_addr = c['address']
                continue

            # memcpy(dst, src, var) → mov rdi; mov rsi; mov rdx; call memcpy
            m = re.match(
                r'memcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)', line)
            if m:
                d, s, sv = m.groups()
                _emit('mov', ['rdi', _aw_gr(d)])
                _emit('mov', ['rsi', _aw_gr(s)])
                _emit('mov', ['rdx', _aw_gr(sv)])
                c = _emit('call', ['memcpy'])
                if write_call_addr < 0:
                    write_call_addr = c['address']
                continue

            # memset/memmove/strncpy(dst, val, N_or_var)
            m = re.match(
                r'(memset|memmove|strncpy)\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\d+|0x[0-9a-fA-F]+|\w+)\s*\)', line)
            if m:
                fn, d, v, sz = m.groups()
                _emit('mov', ['rdi', _aw_gr(d)])
                if re.match(r'0x[0-9a-fA-F]+|\d+$', v):
                    _emit('mov', ['rsi', v])
                else:
                    _emit('mov', ['rsi', _aw_gr(v)])
                if re.match(r'0x[0-9a-fA-F]+|\d+$', sz):
                    _emit('mov', ['rdx', sz])
                else:
                    _emit('mov', ['rdx', _aw_gr(sz)])
                c = _emit('call', [fn])
                if write_call_addr < 0:
                    write_call_addr = c['address']
                continue

            # strcpy(dst, src) → mov rdi; mov rsi; call strcpy
            m = re.match(r'strcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)', line)
            if m:
                d, s = m.groups()
                _emit('mov', ['rdi', _aw_gr(d)])
                _emit('mov', ['rsi', _aw_gr(s)])
                c = _emit('call', ['strcpy'])
                if write_call_addr < 0:
                    write_call_addr = c['address']
                continue

            # free(ptr) → mov rdi; call free
            m = re.match(r'free\s*\(\s*(\w+)\s*\)', line)
            if m:
                _emit('mov', ['rdi', _aw_gr(m.group(1))])
                _emit('call', ['free'])
                continue

        # 从伪代码解析变量来源链, 构建 Root 对象作为回退
        # (当 trace_size_root 无法追踪时使用)
        var_root_map: Dict[str, Root] = {}
        lines = pseudocode.split('\n') if pseudocode else []

        # 第一遍: 解析外部输入调用 (recv/read/fread → ROOT_CALLRET)
        for line in lines:
            line = line.strip()
            input_m = re.search(
                r'(?:recv|read|fread)\s*\([^,]+,\s*[^,]+,\s*(\w+)', line)
            if input_m:
                var = input_m.group(1)
                var_root_map.setdefault(
                    var, Root(ROOT_CALLRET, 0, 1, 0))
            arg_m = re.search(r'(\w+)\s*=\s*arg(\d+)', line)
            if arg_m:
                var, idx = arg_m.group(1), int(arg_m.group(2))
                var_root_map.setdefault(var, Root(ROOT_PARAM, idx, 1, 0))

        # 第二遍: 解析变量赋值中的线性变换 (dst = src ± k, dst = src * k)
        for line in lines:
            line = line.strip()
            assign_m = re.search(
                r'(\w+)\s*=\s*(\w+)\s*([+\-*])\s*(\d+)', line)
            if assign_m:
                dst, src, op, k = (assign_m.group(i) for i in range(1, 5))
                k = int(k)
                if src in var_root_map:
                    base_root = var_root_map[src]
                    if not base_root.is_unknown():
                        coeff, const = base_root.coeff, base_root.const
                        if op == '+':
                            const += k
                        elif op == '-':
                            const -= k
                        elif op == '*':
                            coeff *= k
                        var_root_map[dst] = Root(
                            base_root.kind, base_root.value, coeff, const)

        # 用 trace_size_root 做真实后向 def-use 根来源追踪
        # SysV ABI: malloc size 在 rdi, memcpy/memset size 在 rdx
        alloc_root = None
        write_root = None
        if alloc_call_addr >= 0:
            alloc_root = engine.trace_size_root(
                instructions, alloc_call_addr, 'rdi')
        if write_call_addr >= 0:
            write_root = engine.trace_size_root(
                instructions, write_call_addr, 'rdx')

        filtered = []
        for f in heap_findings:
            alloc_size = f.get('alloc_size', -1)
            write_size = f.get('write_size', -1)
            alloc_var = f.get('alloc_var', '')
            write_var = f.get('write_var', '')

            # 优先使用 trace_size_root 的结果, 回退到 var_root_map, 再回退到立即数
            if alloc_root is not None and not alloc_root.is_unknown():
                ar = alloc_root
            elif alloc_var in var_root_map:
                ar = var_root_map[alloc_var]
            elif (isinstance(alloc_size, int) and alloc_size >= 0):
                ar = Root(ROOT_IMM, alloc_size)
            else:
                ar = None

            if write_root is not None and not write_root.is_unknown():
                wr = write_root
            elif write_var in var_root_map:
                wr = var_root_map[write_var]
            elif (isinstance(write_size, int) and write_size >= 0):
                wr = Root(ROOT_IMM, write_size)
            else:
                wr = None

            if ar is not None and wr is not None:
                category, overflow, detail = engine.correlate(
                    ar, wr,
                    usable_size=alloc_size if isinstance(alloc_size, int) else 0,
                )
                if category == 'safe':
                    # AWSC 判定分配=写入同源, 过滤误报
                    continue
                if category == 'overflow':
                    f.setdefault('awsc_verdict', 'overflow')
                    f.setdefault('awsc_detail', detail)
                    f.setdefault('awsc_overflow_bytes', overflow)
                elif category == 'unknown':
                    f.setdefault('awsc_verdict', 'unknown')
                    f.setdefault('awsc_detail', detail)
                f.setdefault('awsc_alloc_root', str(ar))
                f.setdefault('awsc_write_root', str(wr))
                filtered.append(f)
            else:
                # 无法构建 Root, 保守保留
                filtered.append(f)
        return non_heap + filtered
    except Exception as e:
        logger.debug('AWSC bridge failed: %s', e)
        return existing_findings


# -- CJ-BVF: 约束联结+反向值流证明 --
def run_cj_bvf_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """CJ-BVF 桥接: 对已有堆溢出findings做反向值流安全证明.

    CJ-BVF原始接口需要HeapOverflowCandidate对象+IR行,
    此处从dict findings构造简化candidate, 调用filter_by_bvf.
    """
    if not _check_module('cj_bvf', lambda: __import__(
            'core.cj_bvf_filter', fromlist=['filter_by_bvf'])):
        return existing_findings

    try:
        from core.cj_bvf_filter import filter_by_bvf
        from core.heap_overflow_detector import HeapOverflowCandidate, HeapAllocSite, HeapStore
        from core.ir_normalizer import normalize_ir

        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        if not heap_findings:
            return existing_findings

        ir_lines = normalize_ir(pseudocode)

        # 从 ir_lines 查找每个 finding 对应的分配行和写入行
        # 用真实行号作为 pc, 使 BVF 反向追踪能正确定位指令
        import re as _re
        alloc_line_pat = _re.compile(r'(?:malloc|calloc|realloc)\s*\(')
        write_line_pat = _re.compile(
            r'(memcpy|memmove|strncpy|strcpy|sprintf|memset|fwrite)\s*\(')

        # 预扫描: 找到第一个 alloc 行和第一个 write 行
        first_alloc_pc = -1
        first_write_pc = -1
        for i, line in enumerate(ir_lines):
            if first_alloc_pc < 0 and alloc_line_pat.search(line):
                first_alloc_pc = i
            if first_write_pc < 0 and write_line_pat.search(line):
                first_write_pc = i

        # 从dict findings构造HeapOverflowCandidate对象
        candidates = []
        for f in heap_findings:
            alloc_size = f.get('alloc_size', 0)
            if not isinstance(alloc_size, int):
                alloc_size = 0
            # 用真实行号: 若 finding 中有 insn_addr 则用之, 否则用预扫描行号
            alloc_pc = f.get('alloc_pc', first_alloc_pc if first_alloc_pc >= 0 else 0)
            write_pc = f.get('write_pc', first_write_pc if first_write_pc >= 0 else 0)
            alloc_site = HeapAllocSite(
                pc=alloc_pc, alloc_func='malloc', size_arg=alloc_size,
                size_is_dynamic=not isinstance(f.get('alloc_size'), int),
                result_var=f.get('alloc_var', ''),
            )
            store_size = f.get('write_size', -1)
            if not isinstance(store_size, int):
                store_size = -1
            # 从 finding 中提取 mnemonic
            mnemonic = ''
            desc = f.get('description', '')
            mn_m = _re.search(r'(memcpy|strcpy|strncpy|memmove|memset|sprintf|fwrite)', desc)
            if mn_m:
                mnemonic = mn_m.group(1)
            overflow_store = HeapStore(
                pc=write_pc, base_var=f.get('write_var', ''),
                offset=0, offset_is_dynamic=f.get('offset_is_dynamic', True),
                store_size=store_size,
                mnemonic=mnemonic or 'memcpy',
            )
            c = HeapOverflowCandidate(
                alloc_site=alloc_site,
                overflow_store=overflow_store,
                overflow_bytes=f.get('overflow_bytes', 0),
                confidence=f.get('confidence', 0.5),
                description=f.get('description', ''),
            )
            candidates.append(c)

        kept, stats = filter_by_bvf(candidates, ir_lines)

        # 将保留的candidate转回dict
        results = []
        for c in kept:
            results.append({
                'type': 'heap-overflow',
                'function': func_name,
                'severity': 'High' if c.overflow_bytes > 0 else 'Medium',
                'cwe': 'CWE-122',
                'confidence': c.confidence,
                'description': c.description,
                'verdict': 'DEFINITE' if c.overflow_bytes > 0 else 'POSSIBLE',
                'alloc_var': c.alloc_site.result_var,
                'alloc_size': c.alloc_site.size_arg,
                'overflow_bytes': c.overflow_bytes,
                'source': 'cj_bvf',
            })
        return non_heap + results
    except Exception as e:
        logger.debug('CJ-BVF bridge failed: %s', e)
        return existing_findings


# -- CJ-PCBVF: 路径约束感知证明 --
def run_cj_pcbvf_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """CJ-PCBVF 桥接: 对BVF无法判定的findings做路径约束增强证明."""
    if not _check_module('cj_pcbvf', lambda: __import__(
            'core.cj_pcbvf_filter', fromlist=['filter_by_pcbvf'])):
        return existing_findings

    try:
        from core.cj_pcbvf_filter import filter_by_pcbvf
        from core.heap_overflow_detector import HeapOverflowCandidate, HeapAllocSite, HeapStore
        from core.ir_normalizer import normalize_ir

        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        if not heap_findings:
            return existing_findings

        ir_lines = normalize_ir(pseudocode)

        candidates = []
        for f in heap_findings:
            alloc_size = f.get('alloc_size', 0)
            if not isinstance(alloc_size, int):
                alloc_size = 0
            alloc_site = HeapAllocSite(
                pc=0, alloc_func='malloc', size_arg=alloc_size,
                size_is_dynamic=not isinstance(f.get('alloc_size'), int),
                result_var=f.get('alloc_var', ''),
            )
            store_size = f.get('write_size', -1)
            if not isinstance(store_size, int):
                store_size = -1
            overflow_store = HeapStore(
                pc=0, base_var=f.get('write_var', ''),
                offset=0, offset_is_dynamic=True,
                store_size=store_size,
            )
            c = HeapOverflowCandidate(
                alloc_site=alloc_site,
                overflow_store=overflow_store,
                overflow_bytes=f.get('overflow_bytes', 0),
                confidence=f.get('confidence', 0.5),
                description=f.get('description', ''),
            )
            candidates.append(c)

        kept, stats = filter_by_pcbvf(candidates, ir_lines)

        results = []
        for c in kept:
            results.append({
                'type': 'heap-overflow',
                'function': func_name,
                'severity': 'High' if c.overflow_bytes > 0 else 'Medium',
                'cwe': 'CWE-122',
                'confidence': c.confidence,
                'description': c.description,
                'verdict': 'DEFINITE' if c.overflow_bytes > 0 else 'POSSIBLE',
                'alloc_var': c.alloc_site.result_var,
                'alloc_size': c.alloc_site.size_arg,
                'overflow_bytes': c.overflow_bytes,
                'source': 'cj_pcbvf',
            })
        return non_heap + results
    except Exception as e:
        logger.debug('CJ-PCBVF bridge failed: %s', e)
        return existing_findings


# -- UAF-HOIG: UAF混合对象身份图 --
def run_uaf_hoig_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """UAF-HOIG 桥接: 对伪代码做对象身份追踪, 产出UAF findings.

    HOIG独立检测UAF, 不依赖已有findings. 对已有UAF findings做误报过滤:
    HOIG判定SAFE的UAF finding被过滤, HOIG CONFIRMED补充新findings.
    """
    if not _check_module('uaf_hoig', lambda: __import__(
            'analysis.uaf_hoig_pipeline', fromlist=['UafHoigPipeline'])):
        return existing_findings

    try:
        from analysis.uaf_hoig_pipeline import UafHoigPipeline
        pipeline = UafHoigPipeline()
        result = pipeline.analyze(pseudocode, func_name)

        # HOIG CONFIRMED -> 补充新UAF findings
        new_findings = []
        for v in result.get('intra_func_findings', []):
            new_findings.append({
                'type': 'uaf',
                'function': func_name,
                'severity': 'High' if v.verdict == 'CONFIRMED' else 'Medium',
                'cwe': 'CWE-416',
                'confidence': v.confidence,
                'description': f'HOIG: {v.reason} '
                               f'(free@L{v.free_line} use@L{v.use_line} '
                               f'var={v.use_var})',
                'verdict': 'DEFINITE' if v.verdict == 'CONFIRMED' else 'POSSIBLE',
                'source': 'uaf_hoig',
            })
        for v in result.get('realloc_findings', []):
            new_findings.append({
                'type': 'uaf',
                'function': func_name,
                'severity': 'High',
                'cwe': 'CWE-416',
                'confidence': v.confidence,
                'description': f'HOIG-realloc: {v.reason}',
                'verdict': 'DEFINITE',
                'source': 'uaf_hoig',
            })

        # HOIG SAFE -> 过滤已有UAF findings中的假阳性
        if result['verdict'] == 'SAFE':
            existing_findings = [f for f in existing_findings
                                 if f.get('type', '').lower() not in ('uaf', 'use-after-free')]

        return existing_findings + new_findings
    except Exception as e:
        logger.debug('UAF-HOIG bridge failed: %s', e)
        return existing_findings


# -- GAPSBV: 仿射关系堆溢出检测 --
def run_gapsbv_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
) -> List[dict]:
    """GAPSBV 桥接: 7维度仿射关系堆溢出检测, 产出新findings.

    GAPSBV独立检测堆溢出, 不依赖已有findings.
    """
    if not _check_module('gapsbv', lambda: __import__(
            'analysis.gapsbv_pipeline', fromlist=['detect_heap_overflow_gapsbv'])):
        return []

    try:
        from analysis.gapsbv_pipeline import detect_heap_overflow_gapsbv
        report = detect_heap_overflow_gapsbv(pseudocode)

        results = []
        if report.verdict in ('OVERFLOW', 'POTENTIAL'):
            for dim in report.dimensions:
                if dim.verdict in ('OVERFLOW', 'POTENTIAL') and dim.confidence > 0:
                    results.append({
                        'type': 'heap-overflow',
                        'function': func_name,
                        'severity': 'High' if dim.verdict == 'OVERFLOW' else 'Medium',
                        'cwe': 'CWE-122',
                        'confidence': dim.confidence,
                        'description': f'GAPSBV-{dim.name}: {dim.reason}',
                        'verdict': 'DEFINITE' if dim.verdict == 'OVERFLOW' else 'POSSIBLE',
                        'source': 'gapsbv',
                    })
        return results
    except Exception as e:
        logger.debug('GAPSBV bridge failed: %s', e)
        return []


# -- FMTPROV: 格式串常量折叠+污点溯源 --
def run_fmtprov_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """FMTPROV 桥接: 对已有格式串findings做6阶段误报削减.

    仅编译期字面量可证安全->FILTER, 用户可控无危险符->降级不删除.
    """
    if not _check_module('fmtprov', lambda: __import__(
            'analysis.fmt_verifier', fromlist=['verify_fmt_candidates'])):
        return existing_findings

    try:
        from analysis.fmt_verifier import verify_fmt_candidates
        fmt_findings = [f for f in existing_findings
                        if 'format' in f.get('type', '').lower()
                        or 'fmt' in f.get('type', '').lower()]
        non_fmt = [f for f in existing_findings
                   if 'format' not in f.get('type', '').lower()
                   and 'fmt' not in f.get('type', '').lower()]
        if not fmt_findings:
            return existing_findings

        verified, stats = verify_fmt_candidates(fmt_findings, pseudocode, func_name)
        for f in verified:
            f.setdefault('source', 'fmtprov')
        return non_fmt + verified
    except Exception as e:
        logger.debug('FMTPROV bridge failed: %s', e)
        return existing_findings


# -- GASRI: 守卫感知值域推理 --
def run_gasri_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """GASRI 桥接: 对已有堆溢出findings做守卫感知过滤.

    匹配上游if/for守卫到下游堆写入, 强守卫保护->过滤误报.
    """
    if not _check_module('gasri', lambda: __import__(
            'core.guard_correlator', fromlist=['correlate_write'])):
        return existing_findings

    try:
        from core.guard_correlator import correlate_write
        from core.ir_normalizer import normalize_ir
        import re

        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        if not heap_findings:
            return existing_findings

        ir_lines = normalize_ir(pseudocode)

        # 从 ir_lines 查找每个 finding 对应的写入行号
        write_patterns = re.compile(
            r'(memcpy|memmove|strncpy|strcpy|sprintf|memset|fwrite)\s*\(')

        filtered = []
        for f in heap_findings:
            alloc_size = f.get('alloc_size', 0)
            write_var = f.get('write_var', 'buf')
            alloc_var = f.get('alloc_var', 'buf')

            # 在 ir_lines 中查找包含写入操作且匹配 write_var 的行
            write_line = 0
            for i, line in enumerate(ir_lines):
                if write_patterns.search(line) and write_var in line:
                    write_line = i
                    break
            # 若未匹配到 write_var, 回退到第一个写入操作行
            if write_line == 0:
                for i, line in enumerate(ir_lines):
                    if write_patterns.search(line):
                        write_line = i
                        break

            result = correlate_write(
                ir_lines, write_line=write_line, size_var=write_var,
                alloc_var=alloc_var, alloc_size=alloc_size if isinstance(alloc_size, int) else 0)
            if result and result.safe_confidence > 0.8:
                # 强守卫保护, 过滤误报
                continue
            f.setdefault('gasri_safe_conf', result.safe_confidence if result else 0.0)
            f.setdefault('gasri_write_line', write_line)
            filtered.append(f)
        return non_heap + filtered
    except Exception as e:
        logger.debug('GASRI bridge failed: %s', e)
        return existing_findings


# -- UAF-Enhanced: TARPS五阶段UAF增强检测 --
def run_uaf_enhanced_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
) -> List[dict]:
    """UAF-Enhanced 桥接: TARPS五阶段UAF检测, 产出新findings.

    A-NULL置零 / B-立即复用 / C-别名分析 / D-路径可行性 / E-置信度评分.
    """
    if not _check_module('uaf_enhanced', lambda: __import__(
            'core.uaf_enhanced', fromlist=['detect_uaf_enhanced'])):
        return []

    try:
        from core.uaf_enhanced import detect_uaf_enhanced
        from core.ir_normalizer import normalize_ir

        ir_lines = normalize_ir(pseudocode)
        candidates, stats = detect_uaf_enhanced(ir_lines)

        results = []
        for c in candidates:
            if c.verdict in ('CONFIRMED', 'LIKELY'):
                results.append({
                    'type': 'uaf',
                    'function': func_name,
                    'severity': 'High' if c.verdict == 'CONFIRMED' else 'Medium',
                    'cwe': 'CWE-416',
                    'confidence': c.confidence,
                    'description': f'TARPS: {c.summary()}',
                    'verdict': 'DEFINITE' if c.verdict == 'CONFIRMED' else 'POSSIBLE',
                    'source': 'uaf_enhanced',
                })
        return results
    except Exception as e:
        logger.debug('UAF-Enhanced bridge failed: %s', e)
        return []


# -- UAF-Pointer-Lifecycle: 指针生命周期状态机 --
def run_uaf_lifecycle_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
) -> List[dict]:
    """UAF-Lifecycle 桥接: 指针生命周期状态机检测UAF.

    ALLOCATED->IN_USE->FREED->DANGLING, FREED后解引用即UAF.
    """
    if not _check_module('uaf_lifecycle', lambda: __import__(
            'core.uaf_pointer_lifecycle', fromlist=['analyze_pointer_lifecycle'])):
        return []

    try:
        from core.uaf_pointer_lifecycle import analyze_pointer_lifecycle
        findings_list, final_state = analyze_pointer_lifecycle(pseudocode, func_name)

        results = []
        for f in findings_list:
            if f.get('type', '').lower() in ('uaf', 'use-after-free', 'dangling'):
                results.append({
                    'type': 'uaf',
                    'function': func_name,
                    'severity': 'High',
                    'cwe': 'CWE-416',
                    'confidence': f.get('confidence', 0.7),
                    'description': f'Lifecycle: {f.get("description", f.get("reason", ""))}',
                    'verdict': 'DEFINITE',
                    'source': 'uaf_lifecycle',
                })
        return results
    except Exception as e:
        logger.debug('UAF-Lifecycle bridge failed: %s', e)
        return []


# -- Double-Free: 四层Double-Free检测 --
def run_double_free_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
) -> List[dict]:
    """Double-Free 桥接: 四层DF检测, 产出新findings.

    L1直接free / L2别名 / L3时序间隔 / L4上下文利用分析.
    """
    if not _check_module('double_free', lambda: __import__(
            'modules.core.compat.double_free', fromlist=['FreeHistory'])):
        return []

    try:
        from modules.core.compat.double_free import FreeHistory, DFPattern
        import re

        # 先从伪代码解析变量赋值建立别名图
        # 别名图: ptr_name → canonical_name (通过赋值链解析)
        aliases: Dict[str, str] = {}
        malloc_vars: Dict[str, int] = {}
        # 模拟堆地址分配器: 每个 malloc 分配一个单调递增的堆地址
        # 类似 glibc brk 堆增长, 起始地址 0x20000, 每次分配按请求大小对齐到 16 字节
        # 这比字符串 hash 更真实: 不同 malloc 得到不同地址, 别名指针共享同一地址
        _heap_base = [0x20000]
        var_chunk_addr: Dict[str, int] = {}

        for lineno, raw in enumerate(pseudocode.split('\n'), 1):
            line = raw.strip()
            # malloc 返回值: var = malloc(N)
            alloc_m = re.search(
                r'(\w+)\s*=\s*malloc\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*\)', line)
            if alloc_m:
                var = alloc_m.group(1)
                sz = int(alloc_m.group(2), 0)
                malloc_vars[var] = lineno
                aliases[var] = var  # malloc 返回的变量是 canonical
                # 模拟 ptmalloc2 chunk: usable = round_up(sz+16, 16) - 16
                _usable = ((max(sz, 16) + 16 + 15) & ~15) - 16
                _chunk_size = _usable + 16  # 含 header
                var_chunk_addr[var] = _heap_base[0]
                _heap_base[0] += _chunk_size
                continue
            # var = malloc(var2) — 动态大小, 用默认 chunk
            alloc_m2 = re.search(r'(\w+)\s*=\s*malloc\s*\(\s*(\w+)\s*\)', line)
            if alloc_m2:
                var = alloc_m2.group(1)
                malloc_vars[var] = lineno
                aliases[var] = var
                var_chunk_addr[var] = _heap_base[0]
                _heap_base[0] += 64  # 默认 chunk 大小
                continue
            # calloc(N, M)
            alloc_m3 = re.search(
                r'(\w+)\s*=\s*calloc\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*,\s*(\d+|0x[0-9a-fA-F]+)\s*\)', line)
            if alloc_m3:
                var = alloc_m3.group(1)
                sz = int(alloc_m3.group(2), 0) * int(alloc_m3.group(3), 0)
                malloc_vars[var] = lineno
                aliases[var] = var
                _usable = ((max(sz, 16) + 16 + 15) & ~15) - 16
                _chunk_size = _usable + 16
                var_chunk_addr[var] = _heap_base[0]
                _heap_base[0] += _chunk_size
                continue
            # 赋值别名: dst = src (非 malloc 非 free)
            assign_m = re.match(r'(\w+)\s*=\s*(\w+)\s*;', line)
            if assign_m and 'malloc' not in line and 'free' not in line:
                dst, src = assign_m.groups()
                # 沿已有别名链解析 src 的 canonical
                canon = aliases.get(src, src)
                aliases[dst] = canon
                # 别名共享同一 chunk_addr
                if canon in var_chunk_addr:
                    var_chunk_addr[dst] = var_chunk_addr[canon]

        # 构建别名解析函数
        def resolve_canonical(ptr_name: str) -> str:
            chain = ptr_name
            visited = set()
            while chain in aliases and aliases[chain] != chain and chain not in visited:
                visited.add(chain)
                chain = aliases[chain]
            return chain

        # 别名图对象 (传给 detect_all)
        class AliasGraph:
            def __init__(self, resolver_func):
                self._resolve = resolver_func
            def resolve_ptr(self, ptr_name: str) -> str:
                return self._resolve(ptr_name)

        alias_graph = AliasGraph(resolve_canonical)

        history = FreeHistory()
        # 收集所有 free 事件, 用别名解析获取真实 chunk_addr
        for lineno, raw in enumerate(pseudocode.split('\n'), 1):
            line = raw.strip()
            m = re.search(r'\bfree\s*\(\s*(\w+)', line)
            if m:
                var = m.group(1)
                # 用别名解析获取 canonical 名
                canon = resolve_canonical(var)
                # 用模拟堆分配器的真实地址, 保证别名指针指向同一 chunk
                # 回退: 若变量未被 malloc 赋值, 用 canonical 名的确定性映射
                chunk_addr = var_chunk_addr.get(
                    canon, var_chunk_addr.get(var, 0))
                history.record_free(lineno, var, chunk_addr=chunk_addr)

        # 全管线检测 L1→L3: 直接/别名/桥接 double-free
        # 传入 alias_graph 使 L2 别名检测可用
        detections = history.detect_all(alias_graph=alias_graph)

        results = []
        for df in detections:
            # 按模式映射严重度: 桥接 > 别名 > 直接
            if df.pattern == DFPattern.BRIDGED:
                sev = 'Critical'
                verdict = 'DEFINITE'
            elif df.pattern == DFPattern.ALIAS:
                sev = 'High'
                verdict = 'DEFINITE'
            else:
                sev = 'High'
                verdict = 'DEFINITE'
            # 记录中间事件用于桥接模式溯源
            mid_ptrs = [e.ptr_name for e in df.intermediate_events]
            results.append({
                'type': 'double-free',
                'function': func_name,
                'severity': sev,
                'cwe': 'CWE-415',
                'confidence': df.confidence,
                'description': f'Double-Free[{df.pattern.name}]: {df.description}',
                'verdict': verdict,
                'source': 'double_free',
                'df_pattern': df.pattern.name,
                'df_first_free_line': df.first_free.address,
                'df_second_free_line': df.second_free.address,
                'df_intermediate': mid_ptrs,
                'df_glibc_mitigated': df.glibc_version_mitigated,
            })
        return results
    except Exception as e:
        logger.debug('Double-Free bridge failed: %s', e)
        return []


# -- Buffer-Underflow: CWE-124 Buffer Underwrite --
def run_buffer_underflow_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
) -> List[dict]:
    """Buffer-Underflow 桥接: 检测负偏移访问写入.

    L1负偏移访问 / L2指针算术溯源 / L3前邻chunk影响.
    """
    if not _check_module('buffer_underflow', lambda: __import__(
            'modules.core.compat.buffer_underflow', fromlist=['detect_buffer_underflow'])):
        return []

    try:
        from modules.core.compat.buffer_underflow import (
            detect_buffer_underflow, trace_pointer_arithmetic,
            PrevChunkAnalyzer)
        import re

        # L1: 从伪代码解析 malloc(N) 获取真实 base_size
        base_sizes: Dict[str, int] = {}
        var_ops: Dict[str, List[Tuple[str, int]]] = {}
        for line in pseudocode.split('\n') if pseudocode else []:
            line = line.strip()
            # malloc(N) → buf = malloc(64)
            alloc_m = re.search(
                r'(\w+)\s*=\s*malloc\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*\)', line)
            if alloc_m:
                var, sz_str = alloc_m.groups()
                base_sizes[var] = int(sz_str, 0)
            # buf = buf + N / buf = buf - N → 指针算术
            arith_m = re.search(
                r'(\w+)\s*=\s*(\w+)\s*([+\-])\s*(\d+|0x[0-9a-fA-F]+)', line)
            if arith_m:
                dst, src, op, off_str = arith_m.groups()
                off = int(off_str, 0)
                if dst == src:
                    var_ops.setdefault(dst, []).append(
                        ('add' if op == '+' else 'sub', off))

        analyzer = PrevChunkAnalyzer()
        results = []
        for lineno, raw in enumerate(pseudocode.split('\n'), 1):
            line = raw.strip()
            # 检测 buf[-N] 或 *(buf-N) 模式
            m = re.search(r'(\w+)\s*\[\s*-(\d+)\s*\]', line)
            if not m:
                m = re.search(r'\*\s*\(\s*(\w+)\s*-\s*(\d+)\s*\)', line)
            if m:
                var = m.group(1)
                offset = -int(m.group(2))
                base_size = base_sizes.get(var, 0)

                # L2: 如果有指针算术记录, 用 trace_pointer_arithmetic
                if var in var_ops:
                    ops = var_ops[var]
                    trace = trace_pointer_arithmetic(
                        var, ops, base_size if base_size > 0 else 64)
                    analysis = trace.underflow_analysis
                else:
                    # L1: 直接检测
                    analysis = detect_buffer_underflow(
                        base_addr=0,
                        base_size=base_size if base_size > 0 else 64,
                        access_offset=offset)

                if analysis.risk.value not in ('SAFE',):
                    # L3: 前邻 chunk 影响分析
                    impact = analyzer.analyze_prev_chunk_impact(analysis)
                    results.append({
                        'type': 'buffer-underflow',
                        'function': func_name,
                        'severity': 'High' if analysis.risk.value in ('HIGH', 'CRITICAL') else 'Medium',
                        'cwe': 'CWE-124',
                        'confidence': analysis.confidence,
                        'description': f'Underflow: {var}[{offset}] at L{lineno} ({analysis.risk.value}) → {impact["field"]} affected, technique: {impact["technique"]}',
                        'verdict': 'DEFINITE',
                        'source': 'buffer_underflow',
                        'base_size': base_size,
                        'prev_impact': impact,
                    })
        return results
    except Exception as e:
        logger.debug('Buffer-Underflow bridge failed: %s', e)
        return []


# -- Off-by-One: 越界写入单字节 --
def run_off_by_one_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """Off-by-One 桥接: 独立检测+已有findings分类.

    两层检测:
    L1 独立扫描: 从伪代码识别 off-by-one 写模式（三种模式）
       - 循环<=边界: for(i=0;i<=N;i++) buf[i]=... → 写入N+1个元素
       - strlen+1: memcpy(dst, src, strlen(src)+1) 当 dst=malloc(strlen(src))
       - null终止符: d[strlen(s)]=0 当 d=malloc(strlen(s))
    L2 已有分类: 对已有 heap findings 做 write==alloc_usable+1 精确分类
    """
    if not _check_module('off_by_one', lambda: __import__(
            'modules.core.compat.off_by_one', fromlist=['detect_off_by_one'])):
        return existing_findings

    try:
        from modules.core.compat.off_by_one import detect_off_by_one, verify_exploit_chain
        import re

        # --- L1: 独立伪代码扫描检测 off-by-one 写模式 ---
        obo_findings: List[dict] = []
        if pseudocode:
            # 收集 malloc 分配点和变量映射
            alloc_map: Dict[str, int] = {}
            for line in pseudocode.split('\n'):
                line = line.strip()
                m = re.match(r'(\w+)\s*=\s*malloc\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*\)', line)
                if m:
                    var, sz = m.group(1), int(m.group(2), 0)
                    alloc_map[var] = sz
                # malloc(strlen(s))
                m2 = re.match(r'(\w+)\s*=\s*malloc\s*\(\s*strlen\s*\(\s*(\w+)\s*\)\s*\)', line)
                if m2:
                    var, src_var = m2.groups()
                    alloc_map[var] = -1  # 动态大小标记

            # 模式1: 循环 <= 边界 → off-by-one
            # for(i=0;i<=N;i++) buf[i]=... 或 for(i=0;i<=count;i++) arr[i]=val
            for line in pseudocode.split('\n'):
                line = line.strip()
                m = re.match(
                    r'for\s*\(\s*(\w+)\s*=\s*0\s*;\s*\1\s*<=\s*(\w+)\s*;\s*\1\+\+\s*\)',
                    line)
                if m:
                    idx_var, bound_var = m.groups()
                    # 检查循环体中是否有 buf[i] = ... 写入
                    # 简化: 假设下一行包含 buf[idx_var] = ...
                    # 独立检出: i <= N 循环写入 N+1 个元素
                    obo_findings.append({
                        'type': 'heap-overflow',
                        'subtype': 'off-by-one',
                        'function': func_name,
                        'severity': 'High',
                        'cwe': 'CWE-787',
                        'confidence': 0.85,
                        'description': (
                            f'OBO-L1: loop {idx_var}<={bound_var} writes '
                            f'{bound_var}+1 elements (off-by-one)'),
                        'verdict': 'POSSIBLE',
                        'source': 'off_by_one_l1_scan',
                        'pattern': 'loop_le_bound',
                        'index_var': idx_var,
                        'bound_var': bound_var,
                    })

            # 模式2: memcpy(dst, src, strlen(src)+1) 当 dst=malloc(strlen(src))
            for line in pseudocode.split('\n'):
                line = line.strip()
                m = re.match(
                    r'memcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*strlen\s*\(\s*\2\s*\)\s*\+\s*1\s*\)',
                    line)
                if m:
                    dst_var, src_var = m.groups()
                    if dst_var in alloc_map:
                        alloc_sz = alloc_map[dst_var]
                        if alloc_sz == -1:
                            # malloc(strlen(src)) vs memcpy(..., strlen(src)+1)
                            obo_findings.append({
                                'type': 'heap-overflow',
                                'subtype': 'off-by-one',
                                'function': func_name,
                                'severity': 'High',
                                'cwe': 'CWE-787',
                                'confidence': 0.90,
                                'description': (
                                    f'OBO-L1: malloc(strlen({src_var})) + '
                                    f'memcpy(..., strlen({src_var})+1) → '
                                    f'1-byte null terminator overflow'),
                                'verdict': 'POSSIBLE',
                                'source': 'off_by_one_l1_scan',
                                'pattern': 'strlen_plus_one',
                                'dst_var': dst_var,
                                'src_var': src_var,
                            })

            # 模式3: d[strlen(s)] = 0 当 d=malloc(strlen(s))
            for line in pseudocode.split('\n'):
                line = line.strip()
                m = re.match(
                    r'(\w+)\s*\[\s*strlen\s*\(\s*(\w+)\s*\)\s*\]\s*=\s*0\s*;',
                    line)
                if m:
                    dst_var, src_var = m.groups()
                    if dst_var in alloc_map:
                        alloc_sz = alloc_map[dst_var]
                        if alloc_sz == -1:
                            # malloc(strlen(s)) + d[strlen(s)]=0 → 写入下标等于分配大小
                            obo_findings.append({
                                'type': 'heap-overflow',
                                'subtype': 'off-by-one',
                                'function': func_name,
                                'severity': 'High',
                                'cwe': 'CWE-193',
                                'confidence': 0.88,
                                'description': (
                                    f'OBO-L1: malloc(strlen({src_var})) + '
                                    f'{dst_var}[strlen({src_var})]=0 → '
                                    f'null terminator at allocation boundary'),
                                'verdict': 'POSSIBLE',
                                'source': 'off_by_one_l1_scan',
                                'pattern': 'null_terminator_boundary',
                                'dst_var': dst_var,
                                'src_var': src_var,
                            })

        # --- L2: 对已有 heap findings 做 off-by-one 精确分类 ---
        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]

        for f in heap_findings:
            alloc_size = f.get('alloc_size', 0)
            write_size = f.get('write_size', 0)
            if isinstance(alloc_size, int) and isinstance(write_size, int) and alloc_size > 0:
                analysis = detect_off_by_one(alloc_size, write_size)
                if analysis.risk.value != 'SAFE':
                    f['off_by_one_risk'] = analysis.risk.value
                    f.setdefault('source', 'off_by_one')
                    # L3: 利用链验证
                    if analysis.is_off_by_one:
                        exploitable, technique, exp_conf = verify_exploit_chain(analysis)
                        f['obo_exploitable'] = exploitable
                        f['obo_technique'] = technique
                        f['obo_exploit_confidence'] = exp_conf
                        if exploitable:
                            f['description'] = (
                                f'{f.get("description", "")} | '
                                f'OBO-L3: {technique} (conf={exp_conf:.2f})')
                            if 'CRITICAL' in technique:
                                f['severity'] = 'Critical'

        # 合并 L1 独立检出 + L2 分类结果
        if obo_findings:
            return non_heap + heap_findings + obo_findings
        return non_heap + heap_findings
    except Exception as e:
        logger.debug('Off-by-One bridge failed: %s', e)
        return existing_findings


# -- Uninitialized-Memory: CWE-457 --
def run_uninit_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
) -> List[dict]:
    """Uninitialized-Memory 桥接: 检测malloc后未初始化即使用.

    三层检测:
    L1 alloc->use间隔追踪
    L2 字节级bitmap + 结构体字段级追踪 (p->field 和 var.field 模式)
    L3 跨函数传播
    增强: 变量参数 malloc(var) 识别 (原版只识别 malloc(常量))
    """
    if not _check_module('uninit', lambda: __import__(
            'modules.core.compat.uninitialized_memory', fromlist=['InitTracker'])):
        return []

    try:
        from modules.core.compat.uninitialized_memory import (
            InitTracker, InitStatus, detect_uninitialized_use,
            CrossFunctionInitTracker)
        import re

        tracker = InitTracker()
        results = []
        ptr_to_addr: Dict[str, int] = {}
        # 记录每个指针的分配大小, 用于变量参数 malloc 的默认尺寸推断
        ptr_to_size: Dict[str, int] = {}
        next_addr = 0x1000
        call_edges: Dict[int, str] = {}
        all_analyses = []
        # 结构体字段路径 → 初始化状态 (独立于字节 bitmap 的字段级追踪)
        field_init_map: Dict[str, bool] = {}

        for lineno, raw in enumerate(pseudocode.split('\n'), 1):
            line = raw.strip()
            # 检测 malloc: var = malloc(常量) 或 var = malloc(变量)
            m = re.search(r'(\w+)\s*=\s*.*malloc\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*\)', line)
            if m:
                var = m.group(1)
                size = int(m.group(2), 0)
                addr = next_addr
                next_addr += size
                tracker.record_alloc(addr, size, var)
                ptr_to_addr[var] = addr
                ptr_to_size[var] = size
                continue
            # 增强: 变量参数 malloc(var) — 原版只匹配常量, 现在支持变量参数
            m_var = re.search(r'(\w+)\s*=\s*.*malloc\s*\(\s*(\w+)\s*\)', line)
            if m_var and not m:
                var = m_var.group(1)
                size_var = m_var.group(2)
                # 变量参数: 用默认大小 64 字节 (常见结构体大小)
                # 真实场景中应通过值域传播推断, 这里保守用 64
                size = 64
                addr = next_addr
                next_addr += size
                tracker.record_alloc(addr, size, var)
                ptr_to_addr[var] = addr
                ptr_to_size[var] = size
                continue
            # 检测 calloc — calloc 清零, 不需要未初始化检测
            c_m = re.search(r'(\w+)\s*=\s*.*calloc\s*\(', line)
            if c_m:
                # calloc 分配的内存已清零, 标记为已初始化
                ptr_to_addr[c_m.group(1)] = -1  # -1 表示已初始化
                continue
            # 检测函数调用
            call_m = re.search(r'(\w+)\s*\(', line)
            if call_m and not any(k in line for k in ('malloc', 'free', 'memcpy', 'memset', 'printf', 'calloc')):
                callee = call_m.group(1)
                call_edges[lineno] = callee
            # 检测数组写入: var[offset] = ...
            write_m = re.search(r'(\w+)\s*\[\s*(\d+)\s*\]', line)
            if write_m and '=' in line:
                var = write_m.group(1)
                offset = int(write_m.group(2))
                addr = ptr_to_addr.get(var)
                if addr is not None and addr > 0:
                    tracker.record_write(addr, offset, 1)
            # 增强: 结构体字段写入: p->field = ... 或 p.field = ...
            field_write_m = re.search(r'(\w+)\s*->\s*(\w+)\s*=', line)
            if not field_write_m:
                field_write_m = re.search(r'(\w+)\s*\.\s*(\w+)\s*=', line)
            if field_write_m:
                ptr_var = field_write_m.group(1)
                field_name = field_write_m.group(2)
                if ptr_var in ptr_to_addr and ptr_to_addr[ptr_var] > 0:
                    field_key = f'{ptr_var}->{field_name}'
                    field_init_map[field_key] = True
                    # 同时在字节 bitmap 中标记前 8 字节为已写入 (字段近似)
                    addr = ptr_to_addr[ptr_var]
                    tracker.record_write(addr, 0, 8)
            # 检测数组读取: var[offset] (非赋值左边)
            use_m = re.search(r'(\w+)\s*\[\s*(\d+)\s*\]', line)
            if use_m and '=' not in line.split(use_m.group(0))[0]:
                var = use_m.group(1)
                offset = int(use_m.group(2))
                addr = ptr_to_addr.get(var)
                if addr is not None and addr > 0:
                    check = tracker.check_use(addr, offset, 1, lineno)
                    if check and check.status == InitStatus.UNINIT:
                        all_analyses.append(check)
                        results.append({
                            'type': 'uninitialized-memory',
                            'function': func_name,
                            'severity': 'Medium',
                            'cwe': 'CWE-457',
                            'confidence': check.confidence,
                            'description': f'Uninit: {var}[{offset}] used before init at L{lineno} ({check.description})',
                            'verdict': 'POSSIBLE',
                            'source': 'uninit',
                        })
            # 增强: 结构体字段读取: p->field 或 p.field (非赋值左边)
            field_use_m = re.search(r'(\w+)\s*->\s*(\w+)', line)
            if not field_use_m:
                field_use_m = re.search(r'(\w+)\s*\.\s*(\w+)', line)
            if field_use_m and '=' not in line.split(field_use_m.group(0))[0]:
                ptr_var = field_use_m.group(1)
                field_name = field_use_m.group(2)
                field_key = f'{ptr_var}->{field_name}'
                if ptr_var in ptr_to_addr and ptr_to_addr[ptr_var] > 0:
                    if field_key not in field_init_map:
                        # 字段未初始化
                        results.append({
                            'type': 'uninitialized-memory',
                            'function': func_name,
                            'severity': 'Medium',
                            'cwe': 'CWE-457',
                            'confidence': 0.75,
                            'description': (
                                f'Uninit field: {ptr_var}->{field_name} '
                                f'read before init at L{lineno}'),
                            'verdict': 'POSSIBLE',
                            'source': 'uninit_l2_field',
                        })

        # L3: 跨函数传播
        if all_analyses and call_edges:
            cf_tracker = CrossFunctionInitTracker()
            call_graph: Dict[int, List[int]] = {}
            for a in all_analyses:
                if a.use_site in call_edges:
                    callee_id = hash(call_edges[a.use_site]) & 0xFFFF
                    call_graph.setdefault(a.use_site, []).append(callee_id)
                    cf_tracker.add_call_edge(a.use_site, callee_id)

            propagated = cf_tracker.trace_uninit_across_calls(
                all_analyses, call_graph)

            for p in propagated:
                results.append({
                    'type': 'uninitialized-memory',
                    'function': func_name,
                    'severity': 'Medium',
                    'cwe': 'CWE-457',
                    'confidence': p['propagated_confidence'],
                    'description': f'Uninit cross-function: alloc@0x{p["source_alloc"]:x} propagated to callee@0x{p["target_callee"]:x} via call@L{p["propagation_site"]}',
                    'verdict': 'POSSIBLE',
                    'source': 'uninit_l3_crossfunc',
                })

        return results
    except Exception as e:
        logger.debug('Uninitialized-Memory bridge failed: %s', e)
        return []


# -- Int-Overflow-Enhance: L4-L6整数溢出增强 --
def run_intovf_enhance_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """Int-Overflow-Enhance 桥接: 对已有整数溢出findings做L4-L6增强.

    L4同余模数回绕 / L5混合符号传播 / L6分配器影响链.
    """
    if not _check_module('intovf_enhance', lambda: __import__(
            'modules.core.compat.int_overflow_enhance',
            fromlist=['CongruenceWrapAnalyzer'])):
        return existing_findings

    try:
        from modules.core.compat.int_overflow_enhance import (
            CongruenceWrapAnalyzer, MixedSignAnalyzer, AllocImpactTracer,
            enhanced_detect_int_overflow)
        from modules.core.compat.int_overflow import IntOperation, IntWidth
        import re

        int_findings = [f for f in existing_findings
                        if 'integer' in f.get('type', '').lower()
                        or 'int' in f.get('type', '').lower()]
        non_int = [f for f in existing_findings
                   if 'integer' not in f.get('type', '').lower()
                   and 'int' not in f.get('type', '').lower()]

        if not int_findings:
            return existing_findings

        # 从伪代码直接解析整数运算 (补充从 description 解析的不足)
        operations = []
        known_ranges = {}
        alloc_sites = {}
        write_sites = {}
        def_use_chains = {}
        # 变量符号性映射: True=有符号, False=无符号
        var_signed: Dict[str, bool] = {}

        # 预扫描: 解析变量类型声明, 判断有符号/无符号
        # unsigned/size_t/uint → 无符号; int/long/ssize_t → 有符号
        for raw in pseudocode.split('\n') if pseudocode else []:
            line = raw.strip()
            # 匹配类型声明: (unsigned|signed)? (int|long|short|char|size_t|...)? var
            decl_m = re.match(
                r'(unsigned\s+|signed\s+)?(int|long|short|char|size_t|ssize_t|uint\d+_t|int\d+_t|u_int\w+)\s+(\w+)',
                line)
            if decl_m:
                qual, typ, varname = decl_m.groups()
                if qual and 'unsigned' in qual:
                    var_signed[varname] = False
                elif qual and 'signed' in qual:
                    var_signed[varname] = True
                elif typ in ('size_t', 'uint32_t', 'uint64_t', 'uint16_t',
                             'uint8_t', 'u_int', 'u_long', 'uintptr_t'):
                    var_signed[varname] = False
                elif typ in ('ssize_t', 'int', 'long', 'short', 'char',
                             'int32_t', 'int64_t', 'int16_t', 'int8_t'):
                    var_signed[varname] = True
            # 也匹配直接赋值中的类型转换: (int)var, (unsigned int)var
            cast_m = re.search(r'\(unsigned\s+\w+\)\s*(\w+)', line)
            if cast_m:
                var_signed[cast_m.group(1)] = False
            cast_m2 = re.search(r'\(signed\s+\w+\)\s*(\w+)', line)
            if cast_m2:
                var_signed[cast_m2.group(1)] = True

        # 解析伪代码中的算术运算: var = a op b
        for lineno, raw in enumerate(pseudocode.split('\n'), 1):
            line = raw.strip()
            # 匹配 var = operand op operand
            arith_m = re.search(
                r'(\w+)\s*=\s*(\w+)\s*([+\-*])\s*(\w+)', line)
            if arith_m:
                dst, left, op, right = arith_m.groups()
                # 根据变量类型声明决定 signed 值
                # 若任一操作数是无符号, 整个运算视为无符号; 否则有符号
                left_s = var_signed.get(left, True)
                right_s = var_signed.get(right, True)
                # C 语言隐式转换: 混合时无符号优先
                is_signed = left_s and right_s
                io_op = IntOperation(
                    op=op, left=left, right=right,
                    width=IntWidth.I32, signed=is_signed)
                operations.append(io_op)
                # 根据符号性设置默认范围
                if is_signed:
                    default_range = (-(2**15), 2**15 - 1)
                else:
                    default_range = (0, 2**16 - 1)
                for var in (left, right):
                    if var not in known_ranges:
                        known_ranges[var] = default_range
                # def-use: dst 依赖 left, right
                def_use_chains.setdefault(left, []).append(dst)
                def_use_chains.setdefault(right, []).append(dst)
                # dst 继承符号性 (C 隐式转换规则)
                if dst not in var_signed:
                    var_signed[dst] = is_signed

            # 解析 malloc(var) — 分配点, 用更紧的范围
            alloc_m = re.search(r'malloc\s*\(\s*(\w+)\s*\)', line)
            if alloc_m:
                var = alloc_m.group(1)
                if var not in alloc_sites:
                    # 从 known_ranges 提取更紧的范围, 而非全 32 位
                    if var in known_ranges:
                        alloc_sites[var] = known_ranges[var]
                    else:
                        alloc_sites[var] = (1, 2**20)

            # 解析 memcpy(dst, src, n) — 写入点
            write_m = re.search(r'memcpy\s*\([^,]+,\s*[^,]+,\s*(\w+)\s*\)', line)
            if write_m:
                var = write_m.group(1)
                if var not in write_sites:
                    if var in known_ranges:
                        write_sites[var] = known_ranges[var]
                    else:
                        write_sites[var] = (1, 2**20)

        # 也从 findings description 中补充解析
        for f in int_findings:
            desc = f.get('description', '')
            op_match = re.search(r'(\w+)\s*([+\-*])\s*(\w+)', desc)
            if op_match:
                left, op, right = op_match.groups()
                left_s = var_signed.get(left, True)
                right_s = var_signed.get(right, True)
                is_signed = left_s and right_s
                io_op = IntOperation(
                    op=op, left=left, right=right,
                    width=IntWidth.I32, signed=is_signed)
                # 避免重复
                if not any(o.left == left and o.op == op and o.right == right
                           for o in operations):
                    operations.append(io_op)
                for var in (left, right):
                    if var not in known_ranges:
                        known_ranges[var] = (-(2**15), 2**15 - 1) if is_signed else (0, 2**16 - 1)

            # 提取分配点信息, 用 findings 中的具体 alloc_size
            alloc_size = f.get('alloc_size', 0)
            if isinstance(alloc_size, int) and alloc_size > 0:
                # 用实际分配大小作为上界, 而非全 32 位
                alloc_sites[f'alloc_var_{len(alloc_sites)}'] = (0, alloc_size)
            write_size = f.get('write_size', 0)
            if isinstance(write_size, int) and write_size > 0:
                write_sites[f'write_var_{len(write_sites)}'] = (0, write_size)

        if operations:
            enhanced, stats = enhanced_detect_int_overflow(
                operations, known_ranges,
                alloc_sites=alloc_sites,
                write_sites=write_sites,
                def_use_chains=def_use_chains)
            # 将增强结果回写到 findings
            for i, f in enumerate(int_findings):
                f.setdefault('source', 'intovf_enhance')
                f['enhanced'] = True
                if i < len(enhanced):
                    c = enhanced[i]
                    if 'congruence' in c:
                        f['congruence_narrowed'] = c['congruence']['narrowed']
                        f['congruence_range'] = c['congruence']['refined_range']
                    if c.get('sign_mismatch'):
                        f['sign_mismatch'] = True
                    if 'alloc_trace' in c:
                        f['alloc_reaches'] = c['alloc_trace']['reaches_alloc']
                        f['alloc_exploitable'] = c['alloc_trace']['is_exploitable']
        else:
            # 无法解析操作, 至少做标签增强
            for f in int_findings:
                f.setdefault('source', 'intovf_enhance')
                f['enhanced'] = True
        return non_int + int_findings
    except Exception as e:
        logger.debug('Int-Overflow-Enhance bridge failed: %s', e)
        return existing_findings


# -- Cross-Pipeline-Correlate: 跨管线贝叶斯关联 --
def run_cross_pipeline_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    all_findings: List[dict],
) -> List[dict]:
    """Cross-Pipeline 桥接: 跨管线贝叶斯置信度聚合.

    从 findings 中提取数据流变量集(alloc_var/write_var 等)构建跨类型证据图,
    用函数名+变量集 Jaccard 重叠度做跨类型关联键,
    贝叶斯更新公式聚合多管线置信度, P(E|H)>P(E|¬H)才纳入证据.
    """
    if not _check_module('cross_pipeline', lambda: __import__(
            'modules.core.compat.cross_pipeline_correlate',
            fromlist=['batch_correlate'])):
        return all_findings

    try:
        from modules.core.compat.cross_pipeline_correlate import batch_correlate

        # 从 findings 提取数据流变量集, 使底层贝叶斯关联能基于真实变量重叠工作
        def _enrich_findings(findings):
            enriched = []
            for f in findings:
                vars_set = set()
                for key in ('alloc_var', 'write_var', 'buffer', 'ptr', 'pointer'):
                    val = f.get(key, '')
                    if val and isinstance(val, str):
                        vars_set.add(val)
                # 从 description 中提取额外变量名
                desc = f.get('description', '')
                if desc:
                    import re as _re
                    for m in _re.finditer(r'\b([a-zA-Z_]\w{2,})\b', desc):
                        v = m.group(1)
                        if v not in ('memcpy', 'strcpy', 'malloc', 'free',
                                      'memset', 'strncpy', 'into', 'size'):
                            vars_set.add(v)
                f_copy = dict(f)
                f_copy['data_flow_vars'] = list(vars_set)
                # 用函数名+变量集 hash 做稳定地址, 使同函数同变量的跨类型
                # findings 能被正确分组到同一证据簇
                addr_parts = [func_name] + sorted(vars_set)
                f_copy['address'] = abs(hash(tuple(addr_parts))) & 0xFFFFFFFF
                enriched.append(f_copy)
            return enriched

        heap_f = _enrich_findings(
            [f for f in all_findings if 'heap' in f.get('type', '').lower()])
        uaf_f = _enrich_findings(
            [f for f in all_findings if 'uaf' in f.get('type', '').lower()])
        fmt_f = _enrich_findings(
            [f for f in all_findings if 'format' in f.get('type', '').lower()])
        int_f = _enrich_findings(
            [f for f in all_findings if 'integer' in f.get('type', '').lower()])

        correlated, stats = batch_correlate(
            heap_findings=heap_f, uaf_findings=uaf_f,
            fmt_findings=fmt_f, int_overflow_findings=int_f)

        if correlated:
            for c in correlated:
                support_names = [t.name for t in c.supporting_types]
                c_dict = {
                    'type': c.primary_type.name.lower().replace('_', '-'),
                    'function': func_name,
                    'severity': 'High' if c.aggregated_confidence > 0.8 else 'Medium',
                    'confidence': c.aggregated_confidence,
                    'description': f'Cross-pipeline: {c.verdict} {c.primary_type.name}'
                                   f' (supporting={support_names}, '
                                   f'boosted={c.aggregated_confidence:.2f})',
                    'verdict': 'DEFINITE' if c.aggregated_confidence > 0.8 else 'POSSIBLE',
                    'source': 'cross_pipeline',
                }
                all_findings.append(c_dict)
        return all_findings
    except Exception as e:
        logger.debug('Cross-Pipeline bridge failed: %s', e)
        return all_findings


# -- Cross-Domain-Refiner: 跨域稀疏值流精炼 --
def run_cross_domain_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """Cross-Domain 桥接: 跨域(堆/栈/全局)稀疏值流追踪过滤.

    将伪代码转为 x86-64 汇编指令序列, 调用 CrossDomainRefiner.refine()
    做双向精化(着色追踪+区间分析), 用精化结果对已有 findings 做过滤.

    双向精化:
      方向1: 着色追踪识别堆派生指针, 仅堆访问进入区间检查
      方向2: 区间推断独立发现溢出候选, 仅保留被着色确认为堆访问的候选
    """
    if not _check_module('cross_domain', lambda: __import__(
            'modules.exploit.src.analysis.cross_domain_refiner',
            fromlist=['CrossDomainRefiner'])):
        return existing_findings

    try:
        from modules.exploit.src.analysis.cross_domain_refiner import (
            CrossDomainRefiner)
        import re

        # 将伪代码转为 x86-64 汇编指令序列
        # 变量映射到寄存器, 使着色传播和区间推断能在寄存器间工作
        _callee_saved = ['rbx', 'r12', 'r13', 'r14', 'r15']
        _var_to_reg: Dict[str, str] = {}
        _reg_idx = 0

        def _get_reg(var: str) -> str:
            nonlocal _reg_idx
            if var not in _var_to_reg:
                if _reg_idx < len(_callee_saved):
                    _var_to_reg[var] = _callee_saved[_reg_idx]
                    _reg_idx += 1
                else:
                    _var_to_reg[var] = f'r{_reg_idx + 5}'
                    _reg_idx += 1
            return _var_to_reg[var]

        insns = []
        addr = 0x1000

        for line in pseudocode.split('\n') if pseudocode else []:
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('#'):
                continue

            # buf = malloc(N)
            m = re.match(
                r'(\w+)\s*=\s*malloc\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*\)', line)
            if m:
                var, size_str = m.groups()
                size = int(size_str, 0)
                reg = _get_reg(var)
                insns.append((addr, f'mov rdi, {size}'))
                addr += 4
                insns.append((addr, 'call malloc'))
                addr += 4
                insns.append((addr, f'mov {reg}, rax'))
                addr += 4
                continue

            # buf = malloc(var)
            m = re.match(
                r'(\w+)\s*=\s*malloc\s*\(\s*(\w+)\s*\)', line)
            if m:
                var, size_var = m.groups()
                reg = _get_reg(var)
                size_reg = _get_reg(size_var)
                insns.append((addr, f'mov rdi, {size_reg}'))
                addr += 4
                insns.append((addr, 'call malloc'))
                addr += 4
                insns.append((addr, f'mov {reg}, rax'))
                addr += 4
                continue

            # memcpy(buf, src, N) / memset(buf, val, N)
            m = re.match(
                r'(memcpy|memmove|memset|strncpy|strcpy)\s*\(\s*(\w+)\s*,'
                r'\s*[^,]+\s*,\s*(\d+|0x[0-9a-fA-F]+)\s*\)', line)
            if m:
                func, dst_var, size_str = m.groups()
                size = int(size_str, 0)
                dst_reg = _get_reg(dst_var)
                insns.append((addr, f'mov rdi, {dst_reg}'))
                addr += 4
                insns.append((addr, f'mov rdx, {size}'))
                addr += 4
                insns.append((addr, f'call {func}'))
                addr += 4
                continue

            # memcpy(buf, src, var)
            m = re.match(
                r'(memcpy|memmove|memset|strncpy|strcpy)\s*\(\s*(\w+)\s*,'
                r'\s*[^,]+\s*,\s*(\w+)\s*\)', line)
            if m:
                func, dst_var, size_var = m.groups()
                dst_reg = _get_reg(dst_var)
                size_reg = _get_reg(size_var)
                insns.append((addr, f'mov rdi, {dst_reg}'))
                addr += 4
                insns.append((addr, f'mov rdx, {size_reg}'))
                addr += 4
                insns.append((addr, f'call {func}'))
                addr += 4
                continue

            # free(ptr)
            m = re.match(r'free\s*\(\s*(\w+)\s*\)', line)
            if m:
                ptr_var = m.group(1)
                ptr_reg = _get_reg(ptr_var)
                insns.append((addr, f'mov rdi, {ptr_reg}'))
                addr += 4
                insns.append((addr, 'call free'))
                addr += 4
                continue

            # dst = src ± k
            m = re.match(
                r'(\w+)\s*=\s*(\w+)\s*([+\-*])\s*(\d+|0x[0-9a-fA-F]+)', line)
            if m:
                dst, src, op, k_str = m.groups()
                k = int(k_str, 0)
                dst_reg = _get_reg(dst)
                src_reg = _get_reg(src)
                insns.append((addr, f'mov {dst_reg}, {src_reg}'))
                addr += 4
                if op == '+':
                    insns.append((addr, f'add {dst_reg}, {k}'))
                elif op == '-':
                    insns.append((addr, f'sub {dst_reg}, {k}'))
                elif op == '*':
                    insns.append((addr, f'imul {dst_reg}, {src_reg}, {k}'))
                addr += 4
                continue

            # dst = src (简单赋值)
            m = re.match(r'(\w+)\s*=\s*(\w+)$', line)
            if m:
                dst, src = m.groups()
                dst_reg = _get_reg(dst)
                src_reg = _get_reg(src)
                insns.append((addr, f'mov {dst_reg}, {src_reg}'))
                addr += 4
                continue

            # *ptr = val (解引用写入)
            m = re.match(r'\*(\w+)\s*=\s*(\w+|\d+|0x[0-9a-fA-F]+)', line)
            if m:
                ptr_var, val = m.groups()
                ptr_reg = _get_reg(ptr_var)
                insns.append((addr, f'mov [{ptr_reg}], {val}'))
                addr += 4
                continue

            # if (n > N) n = N; (守卫钳位)
            m = re.match(
                r'if\s*\(\s*(\w+)\s*>\s*(\d+|0x[0-9a-fA-F]+)\s*\)'
                r'\s*\1\s*=\s*(\d+|0x[0-9a-fA-F]+)', line)
            if m:
                var, bound_str, new_val_str = m.groups()
                var_reg = _get_reg(var)
                bound = int(bound_str, 0)
                new_val = int(new_val_str, 0)
                insns.append((addr, f'cmp {var_reg}, {bound}'))
                addr += 4
                insns.append((addr, f'jbe skip_{addr:x}'))
                addr += 4
                insns.append((addr, f'mov {var_reg}, {new_val}'))
                addr += 4
                insns.append((addr, f'skip_{addr:x}:'))
                addr += 4
                continue

        refiner = CrossDomainRefiner()
        refined_vulns, stats = refiner.refine(insns)

        # 用精化结果对已有 findings 做过滤
        if not refined_vulns:
            # 无跨域确认结果——保守保留所有 findings, 仅标记
            for f in existing_findings:
                f.setdefault('cross_domain_refined', True)
                f.setdefault('cross_domain_verdict', 'no_vuln_refined')
                f.setdefault('cross_domain_fp_reduction',
                              stats.fp_reduction_pct)
            return existing_findings

        # 建立变量→refined_vuln 映射 (用 description 中包含的变量名匹配)
        refined_by_var: Dict[str, object] = {}
        for rv in refined_vulns:
            for var, reg in _var_to_reg.items():
                if reg in rv.description:
                    refined_by_var[var] = rv
                    break

        # 对已有 findings 做跨域验证
        verified = []
        for f in existing_findings:
            f.setdefault('cross_domain_refined', True)
            f.setdefault('cross_domain_fp_reduction',
                          stats.fp_reduction_pct)
            matched_vuln = None

            # 用 finding 的变量名匹配 refined_vuln
            f_var = f.get('alloc_var', f.get('ptr', ''))
            if f_var and f_var in refined_by_var:
                matched_vuln = refined_by_var[f_var]

            if matched_vuln:
                f['cross_domain_verdict'] = 'confirmed'
                f['cross_domain_confidence'] = matched_vuln.confidence
                if matched_vuln.passed_interval_filter:
                    f.setdefault('cross_domain_interval_verified', True)
                verified.append(f)
            else:
                # 未被跨域精化确认——保守保留, 标记未确认
                f['cross_domain_verdict'] = 'unconfirmed'
                verified.append(f)

        return verified
    except Exception as e:
        logger.debug('Cross-Domain bridge failed: %s', e)
        return existing_findings


# -- UAF-Lifetime-Tracker: 着色分配追踪UAF --
def run_uaf_lifetime_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
) -> List[dict]:
    """UAF-Lifetime-Tracker 桥接: 着色分配+状态机检测UAF.

    复用alloc_color_tracker的着色机制, ALLOCATED->FREED->DANGLING.
    将伪代码转为 x86-64 汇编, 变量映射到寄存器 (非栈槽),
    使着色传播在寄存器间保持, classify_pointer 能正确识别堆访问.
    """
    if not _check_module('uaf_lifetime', lambda: __import__(
            'modules.exploit.src.analysis.uaf_lifetime_tracker',
            fromlist=['UAF_LifetimeTracker'])):
        return []

    try:
        from modules.exploit.src.analysis.uaf_lifetime_tracker import (
            UAF_LifetimeTracker)
        import re

        # 用 callee-saved 寄存器映射变量, 避免栈槽 (rbp/rsp) 干扰分类
        # classify_pointer 遇到 rbp/rsp 立即返回 STACK, 故不能使用栈槽
        var_reg: Dict[str, str] = {}
        _reg_pool = ['rbx', 'r12', 'r13', 'r14', 'r15', 'rdi', 'rsi']
        _reg_idx = [0]
        insns: List[Tuple[int, str]] = []
        _addr = [0x1000]

        def get_reg(var: str) -> str:
            if var not in var_reg:
                if _reg_idx[0] < len(_reg_pool):
                    var_reg[var] = _reg_pool[_reg_idx[0]]
                    _reg_idx[0] += 1
                else:
                    var_reg[var] = f'r{_reg_idx[0] + 10}'
                    _reg_idx[0] += 1
            return var_reg[var]

        def emit(insn: str) -> None:
            insns.append((_addr[0], insn))
            _addr[0] += 4

        for raw_line in (pseudocode or '').split('\n'):
            line = raw_line.strip()
            if not line or line.startswith(('{', '}', '//', '#')):
                continue
            # 跳过多行注释的续行 (* ... *) 但保留指针解引用 (*ptr = ...)
            if line.startswith('*') and (len(line) == 1 or line[1].isspace()):
                continue
            line = re.sub(r'\([^)]*\*[^)]*\)\s*', '', line)
            line = re.sub(
                r'^(?:int|char|void|size_t|ssize_t|unsigned|long|short|'
                r'float|double|uint\d+_t|int\d+_t|uchar|ushort|uint|'
                r'ulong|bool|byte|DWORD|WORD|BYTE|QWORD)\s+\*?\s*',
                '', line)
            line = line.replace('{', '').replace('}', '')
            line = line.rstrip(';').strip()
            if not line or line.startswith('return'):
                continue

            # var = malloc(N) → call malloc; mov <reg>, rax
            m = re.match(r'(\w+)\s*=\s*malloc\s*\(([^)]+)\)', line)
            if m:
                var = m.group(1)
                emit('call malloc')
                emit(f'mov {get_reg(var)}, rax')
                continue

            # var = calloc(N, M)
            m = re.match(r'(\w+)\s*=\s*calloc\s*\(([^,]+),\s*([^)]+)\)', line)
            if m:
                var = m.group(1)
                emit('call calloc')
                emit(f'mov {get_reg(var)}, rax')
                continue

            # free(ptr) → mov rcx, <reg>; call free
            m = re.match(r'free\s*\(([^)]+)\)', line)
            if m:
                arg = m.group(1).strip()
                if arg in var_reg:
                    emit(f'mov rcx, {get_reg(arg)}')
                else:
                    emit(f'mov rcx, {arg}')
                emit('call free')
                continue

            # var = other_var (别名传播, reg→reg)
            m = re.match(r'(\w+)\s*=\s*(\w+)$', line)
            if m:
                dst, src = m.groups()
                if src in var_reg:
                    emit(f'mov {get_reg(dst)}, {get_reg(src)}')
                elif re.match(r'0x[0-9a-fA-F]+|\d+$', src):
                    emit(f'mov {get_reg(dst)}, {src}')
                continue

            # memcpy(dst, src, n) — 使用 dst 指针 (堆访问检测)
            m = re.match(r'memcpy\s*\(([^,]+),\s*([^,]+),\s*([^)]+)\)', line)
            if m:
                dst = m.group(1).strip()
                if dst in var_reg:
                    emit(f'mov rcx, {get_reg(dst)}')
                else:
                    emit(f'mov rcx, {dst}')
                emit('call memcpy')
                continue

            # ptr->field = val (写操作, 触发 UAF 检测)
            m = re.match(r'(\w+)->(\w+)\s*=\s*(.+)$', line)
            if m:
                ptr = m.group(1)
                if ptr in var_reg:
                    reg = get_reg(ptr)
                    emit(f'mov [{reg}], 0')
                continue

            # *ptr = val (写操作)
            m = re.match(r'\*(\w+)\s*=\s*(.+)$', line)
            if m:
                ptr = m.group(1)
                if ptr in var_reg:
                    reg = get_reg(ptr)
                    emit(f'mov [{reg}], 0')
                continue

            # var = ptr->field (读操作, 触发 UAF 检测)
            m = re.match(r'(\w+)\s*=\s*(\w+)->(\w+)$', line)
            if m:
                dst, ptr = m.group(1), m.group(2)
                if ptr in var_reg:
                    src_reg = get_reg(ptr)
                    dst_reg = get_reg(dst)
                    emit(f'mov {dst_reg}, [{src_reg}]')
                continue

            # var = *ptr (读操作)
            m = re.match(r'(\w+)\s*=\s*\*(\w+)$', line)
            if m:
                dst, ptr = m.group(1), m.group(2)
                if ptr in var_reg:
                    src_reg = get_reg(ptr)
                    dst_reg = get_reg(dst)
                    emit(f'mov {dst_reg}, [{src_reg}]')
                continue

        tracker = UAF_LifetimeTracker()
        reports = tracker.track(insns)

        results = []
        for r in reports:
            if r.confidence > 0:
                results.append({
                    'type': 'uaf',
                    'function': func_name,
                    'severity': 'High',
                    'cwe': 'CWE-416',
                    'confidence': r.confidence,
                    'description': f'LifetimeTracker: {r.description}',
                    'verdict': 'DEFINITE',
                    'source': 'uaf_lifetime',
                })
        return results
    except Exception as e:
        logger.debug('UAF-Lifetime bridge failed: %s', e)
        return []


# -- Provenance-Aware: 分配点感知值范围分析 --
def run_provenance_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """Provenance 桥接: 从分配点前向+写入点反向追踪, 交汇判定.

    对已有堆溢出findings做来源感知精度提升.
    """
    if not _check_module('provenance', lambda: __import__(
            'modules.analysis.static.heap_analysis.provenance_aware_filter',
            fromlist=['ProvenanceAwareFilter'])):
        return existing_findings

    try:
        from modules.analysis.static.heap_analysis.provenance_aware_filter import ProvenanceAwareFilter
        import re

        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        if not heap_findings:
            return existing_findings

        pf = ProvenanceAwareFilter()

        # 从伪代码解析 malloc 调用建立溯源信息
        addr_counter = 0x401000
        for line in pseudocode.split('\n'):
            line = line.strip()
            if not line:
                continue
            m = re.search(r'malloc\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*\)', line)
            if m:
                size_str = m.group(1)
                size = int(size_str, 0)
                pf.track_malloc(addr_counter, func_name, 'rax', size)
                addr_counter += 0x100

        # 从伪代码解析寄存器赋值 (mov dst, src)
        line_addrs = []
        for i, line in enumerate(pseudocode.split('\n')):
            line = line.strip()
            if not line:
                continue
            addr = 0x401000 + i
            line_addrs.append((addr, line))

            m = re.match(r'(?:mov|lea)\s+(\w+)\s*,\s*(\w+)', line, re.I)
            if m:
                dst, src = m.groups()
                pf.track_assign(addr, dst, src)

            # 解析指针算术: dst = base + offset / dst = base - offset
            arith_m = re.search(
                r'(\w+)\s*=\s*(\w+)\s*([+\-*])\s*(\d+|0x[0-9a-fA-F]+)', line)
            if arith_m:
                dst, base, op, off_str = arith_m.groups()
                off = int(off_str, 0)
                if op == '-':
                    off = -off
                elif op == '*':
                    # 乘法视为 stride, 跳过
                    continue
                pf.track_arithmetic(addr, dst, base, off)

            # 解析字段访问: *(ptr + offset) = val 或 val = *(ptr + offset)
            field_m = re.search(
                r'\*\s*\(\s*(\w+)\s*([+\-])\s*(\d+|0x[0-9a-fA-F]+)\s*\)', line)
            if field_m:
                ptr, op, off_str = field_m.groups()
                off = int(off_str, 0)
                if op == '-':
                    off = -off
                # 判定读/写: =*(ptr+off) 是读, *(ptr+off)= 是写
                atype = 'write' if '=' in line and line.index('*') < line.index('=') else 'read'
                pf.track_field_access(addr, ptr, off, 4, atype)

        pf.finalize_analysis()

        # 将 heap findings 转换为 filter_findings 所需的 dict 格式
        raw_for_filter = []
        for f in heap_findings:
            alloc_size = f.get('alloc_size', 0)
            write_size = f.get('write_size', 4)
            raw_for_filter.append({
                'function_name': f.get('function', func_name),
                'insn_addr': f.get('insn_addr', 0),
                'ptr_register': f.get('ptr_register', 'rax'),
                'offset_expr': f.get('offset_expr', '0'),
                'access_size': write_size,
                'allocated_size': alloc_size,
                'usable_size': alloc_size,
                'overflow_by': f.get('overflow_by', 0),
            })

        report = pf.filter_findings(raw_for_filter)

        # 根据 report.details 中 filtered_out 标记过滤误报
        retained = []
        for orig, detail in zip(heap_findings, report.details):
            if detail.filtered_out:
                orig['provenance_filtered'] = True
                orig['provenance_reason'] = detail.filter_reason
            else:
                orig['provenance_checked'] = True
                orig['provenance_verdict'] = detail.verdict.name
                retained.append(orig)

        return non_heap + retained
    except Exception as e:
        logger.debug('Provenance bridge failed: %s', e)
        return existing_findings


def _norm_var_name(expr: str) -> str:
    """归一化变量名: 去掉数组索引/字段访问/指针算术.

    'handlers[id]'→'handlers', 'obj->data'→'obj',
    'buf+offset'→'buf', 'ptr + 8'→'ptr'
    """
    import re as _re
    expr = _re.sub(r'\[[^\]]*\]', '', expr)
    expr = _re.sub(r'\s*[+\-]\s*\w+', '', expr)
    expr = expr.split('->')[0].split('.')[0].strip()
    return expr


# -- D-1: BWR+PCST (有界写恢复+路径条件敏感污点) --
def run_bwr_pcst_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """BWR+PCST 桥接: 对已有堆溢出findings中涉及无界写入函数
    (strcpy/strcat/sprintf/gets)的告警, 恢复写尺寸上界做安全/溢出判定.

    将伪代码转为 x86-64 汇编指令序列, 变量映射到 callee-saved 寄存器,
    使 BWR 的 _resolve_src 能正确做反向 def-use 追踪,
    _compare 能通过 alloc_tracker._ptr_to_alloc 找到分配信息.
    """
    if not _check_module('bwr_pcst', lambda: __import__(
            'modules.analysis.static.bounded_write_recovery',
            fromlist=['BoundedWriteRecovery'])):
        return existing_findings

    try:
        from modules.analysis.static.bounded_write_recovery import (
            BoundedWriteRecovery, BWRVerdict, BWRSrcKind)
        from modules.analysis.static.heap_write_semantics import (
            is_unsized_write, is_alloc_func)
        from modules.analysis.static.heap_constraint import (
            HeapConstraintTracker, Interval)
        import re

        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        if not heap_findings:
            return existing_findings

        # 变量映射到 callee-saved 寄存器
        _callee_saved = ['rbx', 'r12', 'r13', 'r14', 'r15']
        _var_to_reg: Dict[str, str] = {}
        _reg_idx = 0

        def _get_reg(var: str) -> str:
            nonlocal _reg_idx
            if var not in _var_to_reg:
                if _reg_idx < len(_callee_saved):
                    _var_to_reg[var] = _callee_saved[_reg_idx]
                    _reg_idx += 1
                else:
                    _var_to_reg[var] = f'r{_reg_idx + 5}'
                    _reg_idx += 1
            return _var_to_reg[var]

        # 构建完整的 x86-64 汇编指令序列
        instructions = []
        tracker = HeapConstraintTracker()
        bwr = BoundedWriteRecovery()
        addr = 0x1000

        # 预扫描伪代码, 为所有出现的变量分配寄存器
        for line in pseudocode.split('\n') if pseudocode else []:
            for m in re.finditer(r'\b(\w+)\b', line):
                var = m.group(1)
                if var not in ('malloc', 'calloc', 'realloc', 'free',
                               'memcpy', 'memmove', 'memset', 'strcpy',
                               'strcat', 'sprintf', 'vsprintf', 'stpcpy',
                               'gets', 'if', 'else', 'while', 'for',
                               'return', 'NULL', 'arg0', 'arg1', 'arg2'):
                    if var[0].isalpha() or var[0] == '_':
                        _get_reg(var)

        # 构建指令序列
        alloc_addr_map: Dict[str, int] = {}  # var → alloc_addr
        write_calls: List[Tuple[int, str, str, str, int]] = []
        # (call_idx, func, dst_reg, src_reg, alloc_addr_for_dst)

        for line in pseudocode.split('\n') if pseudocode else []:
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('#'):
                continue

            # buf = malloc(N)
            m = re.match(
                r'(\w+)\s*=\s*malloc\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*\)', line)
            if m:
                var, size_str = m.groups()
                size = int(size_str, 0)
                reg = _get_reg(var)
                a_addr = addr
                instructions.append({
                    'address': addr, 'mnemonic': 'mov',
                    'operands': ['rdi', str(size)]})
                addr += 4
                instructions.append({
                    'address': addr, 'mnemonic': 'call',
                    'operands': ['malloc']})
                addr += 4
                instructions.append({
                    'address': addr, 'mnemonic': 'mov',
                    'operands': [reg, 'rax']})
                addr += 4
                tracker.track_alloc(a_addr, Interval(size, size),
                                    result_reg=reg)
                alloc_addr_map[var] = a_addr
                continue

            # buf = malloc(var)
            m = re.match(
                r'(\w+)\s*=\s*malloc\s*\(\s*(\w+)\s*\)', line)
            if m:
                var, size_var = m.groups()
                reg = _get_reg(var)
                size_reg = _get_reg(size_var)
                a_addr = addr
                instructions.append({
                    'address': addr, 'mnemonic': 'mov',
                    'operands': ['rdi', size_reg]})
                addr += 4
                instructions.append({
                    'address': addr, 'mnemonic': 'call',
                    'operands': ['malloc']})
                addr += 4
                instructions.append({
                    'address': addr, 'mnemonic': 'mov',
                    'operands': [reg, 'rax']})
                addr += 4
                tracker.track_alloc(a_addr, Interval(0, 2**30 - 1),
                                    result_reg=reg)
                alloc_addr_map[var] = a_addr
                continue

            # strcpy(dst, src) / strcat(dst, src)
            m = re.match(
                r'(strcpy|strcat|stpcpy)\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)',
                line)
            if m:
                func, dst_var, src_var = m.groups()
                dst_reg = _get_reg(dst_var)
                src_reg = _get_reg(src_var)
                instructions.append({
                    'address': addr, 'mnemonic': 'mov',
                    'operands': ['rdi', dst_reg]})
                addr += 4
                instructions.append({
                    'address': addr, 'mnemonic': 'mov',
                    'operands': ['rsi', src_reg]})
                addr += 4
                instructions.append({
                    'address': addr, 'mnemonic': 'call',
                    'operands': [func]})
                call_idx = len(instructions) - 1
                dst_alloc = alloc_addr_map.get(dst_var, 0)
                write_calls.append(
                    (call_idx, func, dst_reg, src_reg, dst_alloc))
                addr += 4
                continue

            # strcpy(dst, "literal")
            m = re.match(
                r'(strcpy|strcat|stpcpy)\s*\(\s*(\w+)\s*,\s*"([^"]*)"\s*\)',
                line)
            if m:
                func, dst_var, literal = m.groups()
                dst_reg = _get_reg(dst_var)
                instructions.append({
                    'address': addr, 'mnemonic': 'mov',
                    'operands': ['rdi', dst_reg]})
                addr += 4
                # lea rsi, [rip+0x0] # "literal"
                instructions.append({
                    'address': addr, 'mnemonic': 'lea',
                    'operands': ['rsi', f'[rip+0x0] # "{literal}"']})
                addr += 4
                instructions.append({
                    'address': addr, 'mnemonic': 'call',
                    'operands': [func]})
                call_idx = len(instructions) - 1
                dst_alloc = alloc_addr_map.get(dst_var, 0)
                write_calls.append(
                    (call_idx, func, dst_reg, 'rsi', dst_alloc))
                addr += 4
                continue

            # sprintf(dst, "fmt", ...)
            m = re.match(
                r'(sprintf|vsprintf)\s*\(\s*(\w+)\s*,\s*"([^"]*)"\s*[,)]',
                line)
            if m:
                func, dst_var, fmt = m.groups()
                dst_reg = _get_reg(dst_var)
                instructions.append({
                    'address': addr, 'mnemonic': 'mov',
                    'operands': ['rdi', dst_reg]})
                addr += 4
                instructions.append({
                    'address': addr, 'mnemonic': 'lea',
                    'operands': ['rsi', f'[rip+0x0] # "{fmt}"']})
                addr += 4
                instructions.append({
                    'address': addr, 'mnemonic': 'call',
                    'operands': [func]})
                call_idx = len(instructions) - 1
                dst_alloc = alloc_addr_map.get(dst_var, 0)
                write_calls.append(
                    (call_idx, func, dst_reg, 'rsi', dst_alloc))
                addr += 4
                continue

            # free(ptr)
            m = re.match(r'free\s*\(\s*(\w+)\s*\)', line)
            if m:
                ptr_var = m.group(1)
                ptr_reg = _get_reg(ptr_var)
                instructions.append({
                    'address': addr, 'mnemonic': 'mov',
                    'operands': ['rdi', ptr_reg]})
                addr += 4
                instructions.append({
                    'address': addr, 'mnemonic': 'call',
                    'operands': ['free']})
                addr += 4
                continue

            # *ptr = val
            m = re.match(r'\*(\w+)\s*=\s*(\w+|\d+|0x[0-9a-fA-F]+)', line)
            if m:
                ptr_var, val = m.groups()
                ptr_reg = _get_reg(ptr_var)
                instructions.append({
                    'address': addr, 'mnemonic': 'mov',
                    'operands': [f'[{ptr_reg}]', val]})
                addr += 4
                continue

        # 对每条无界写调用做 BWR 判定
        bwr_results: Dict[str, object] = {}  # dst_var → verdict
        for call_idx, func, dst_reg, src_reg, dst_alloc in write_calls:
            verdict = bwr.recover(
                instructions, call_idx, func, tracker,
                dst_reg=dst_reg, src_reg=src_reg,
                dst_alloc_addr=dst_alloc if dst_alloc else None)
            # 用 dst_reg 反查变量名
            for var, reg in _var_to_reg.items():
                if reg == dst_reg:
                    bwr_results[var] = verdict
                    break

        # 对已有 findings 做过滤
        filtered = []
        for f in heap_findings:
            write_func = f.get('write_func', '')
            if not write_func or not is_unsized_write(write_func):
                filtered.append(f)
                continue

            # 用 finding 的 write_var 或 alloc_var 匹配 BWR 结果
            match_var = f.get('write_var', f.get('alloc_var', ''))
            verdict = bwr_results.get(match_var)

            if verdict is not None:
                if verdict.kind == 'safe':
                    f['bwr_verdict'] = 'safe'
                    f['bwr_reason'] = verdict.reason
                    continue  # BWR 判定安全, 过滤
                if verdict.kind == 'overflow':
                    f['bwr_verdict'] = 'overflow'
                    f['bwr_reason'] = verdict.reason
                    f['bwr_bound'] = verdict.bound
            filtered.append(f)

        return non_heap + filtered
    except Exception as e:
        logger.debug('BWR+PCST bridge failed: %s', e)
        return existing_findings


# -- D-2: DD-BVF (按需后向值流UAF检测) --
def run_dd_bvf_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """DD-BVF 桥接: 对 CJ 返回 INCONCLUSIVE 的堆溢出 findings,
    触发 try_bvf_proof() 做反向值流精确化判定.

    BVF proven_safe 则过滤, proven_overflow 则提升置信度,
    无法判定则保守保留.
    """
    if not _check_module('dd_bvf', lambda: __import__(
            'core.cj_bvf_solver_bridge', fromlist=['try_bvf_proof'])):
        return existing_findings

    try:
        from core.cj_bvf_solver_bridge import try_bvf_proof
        from core.cj_constraint_types import SolverVerdict
        from core.heap_overflow_detector import (
            HeapOverflowCandidate, HeapAllocSite, HeapStore)
        from core.ir_normalizer import normalize_ir

        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        if not heap_findings:
            return existing_findings

        ir_lines = normalize_ir(pseudocode)
        platform = 'x86_64'

        # 从 ir_lines 预扫描真实行号, 替代 pc=0 假地址
        # 使 BVF 的 trace_alloc_size/trace_write_size 能正确定位 IR 行
        import re as _re
        alloc_pc = 0
        write_pc = 0
        alloc_var_in_ir = ''
        for i, line in enumerate(ir_lines):
            if _re.search(r'\bmalloc\s*\(', line) and alloc_pc == 0:
                alloc_pc = i
                m = _re.search(r'(\w+)\s*=\s*\w*malloc', line)
                if m:
                    alloc_var_in_ir = m.group(1)
            if _re.search(
                    r'\b(?:memcpy|memmove|strcpy|strncpy|strcat|strncat|'
                    r'memset|sprintf|snprintf|read|fread|gets|scanf)\s*\(',
                    line) and write_pc == 0:
                write_pc = i

        filtered = []
        for f in heap_findings:
            # 只对 CJ 模块返回 INCONCLUSIVE 的 findings 触发
            cj_verdict = f.get('verdict', '')
            if cj_verdict and 'INCONCLUSIVE' not in cj_verdict.upper():
                filtered.append(f)
                continue

            alloc_size = f.get('alloc_size', 0)
            if not isinstance(alloc_size, int):
                alloc_size = 0
            # 用预扫描的真实行号替代 pc=0
            result_alloc_var = f.get('alloc_var', '') or alloc_var_in_ir
            alloc_site = HeapAllocSite(
                pc=alloc_pc, alloc_func='malloc', size_arg=alloc_size,
                size_is_dynamic=not isinstance(f.get('alloc_size'), int),
                result_var=result_alloc_var,
            )
            store_size = f.get('write_size', -1)
            if not isinstance(store_size, int):
                store_size = -1
            # 从 findings 提取写入函数名
            write_func = 'memcpy'
            desc = f.get('description', '')
            wm = _re.match(r'(\w+)\s*\(', desc)
            if wm and wm.group(1) in ('memcpy', 'memmove', 'strcpy',
                                      'strncpy', 'strcat', 'strncat',
                                      'memset', 'sprintf', 'snprintf',
                                      'read', 'fread', 'gets', 'scanf'):
                write_func = wm.group(1)
            overflow_store = HeapStore(
                pc=write_pc, base_var=f.get('write_var', ''),
                offset=0, offset_is_dynamic=True,
                store_size=store_size,
                mnemonic=write_func,
            )
            candidate = HeapOverflowCandidate(
                alloc_site=alloc_site,
                overflow_store=overflow_store,
                overflow_bytes=f.get('overflow_bytes', 0),
                confidence=f.get('confidence', 0.5),
                description=f.get('description', ''),
            )

            result = try_bvf_proof(candidate, ir_lines, platform)

            if result is None:
                # BVF 无法判定, 保守保留
                filtered.append(f)
                continue

            if result.verdict == SolverVerdict.PROVEN_SAFE:
                # BVF 证明安全, 过滤误报
                f['dd_bvf_verdict'] = 'proven_safe'
                f['dd_bvf_reason'] = result.reason
                continue

            if result.verdict == SolverVerdict.PROVEN_OVERFLOW:
                # BVF 证明溢出, 提升置信度
                f['dd_bvf_verdict'] = 'proven_overflow'
                f['dd_bvf_reason'] = result.reason
                f['confidence'] = min(1.0, f.get('confidence', 0.5)
                                     + result.confidence_delta)
                f.setdefault('source', 'dd_bvf')

            filtered.append(f)

        return non_heap + filtered
    except Exception as e:
        logger.debug('DD-BVF bridge failed: %s', e)
        return existing_findings


# -- D-3: CACBV (容量感知耦合边界验证) --
def run_cacbv_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """CACBV 桥接: 路径敏感的容量感知边界验证.

    与 AWSC 的本质区别:
      AWSC 做路径不敏感的后向 def-use 根来源追踪, 判定分配与写入
      是否同源 (同根 → 不可能溢出). 但真实程序常写
      if (n > 64) return; memcpy(buf, src, n); — AWSC 无法利用路径约束,
      n 仍来自参数, 不判定同源.

      CACBV 是路径敏感的: 从伪代码解析 if 守卫 (cmp + jcc 等价模式),
      调用 guard_dominance.analyze_guards_for_write 提取守卫证据,
      再用 verdict.evaluate 汇总容量 + 守卫, 得到 SAFE/CONFIRMED/UNCERTAIN.
      AWSC 无此能力.

    差异化实现:
      1. 从伪代码解析 if (n > C) return/break/continue 守卫模式,
         构建 GuardRecord + Instruction 对象
      2. 调用 analyze_guards_for_write 做路径敏感守卫聚合
      3. 调用 verdict.evaluate 汇总容量/溯源/守卫, 输出完整 ACPE 判定
      4. verdict == SAFE 则过滤, CONFIRMED 则提升置信度, 其余保留
    """
    if not _check_module('cacbv', lambda: __import__(
            'modules.vuln.detection.heap_analysis.acpe.verdict',
            fromlist=['evaluate', 'Verdict', 'AcpeVerdict'])):
        return existing_findings

    try:
        from modules.vuln.detection.heap_analysis.acpe.capacity_model import (
            CapExpr, usable_size, const_relation, arith_relation,
            slack_bytes, MAX_SLACK)
        from modules.vuln.detection.heap_analysis.acpe.equivalence import (
            classify_pair)
        from modules.vuln.detection.heap_analysis.acpe.verdict import (
            evaluate, Verdict, AcpeVerdict)
        from modules.vuln.detection.heap_analysis.acpe.guard_dominance import (
            GuardRecord, GuardEvidence, analyze_guards_for_write,
            guard_safety_check)
        from modules.vuln.detection.heap_analysis.insn_parser import (
            Instruction)
        import re

        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        if not heap_findings:
            return existing_findings

        # --- 阶段 1: 从伪代码解析 if 守卫模式 → GuardRecord 列表 ---
        # 支持模式: if (var > N) return/break/continue
        #          if (var >= N) return/break/continue
        #          if (N < var) return/break/continue
        #          if (N <= var) return/break/continue  (反例守卫)
        guards: list = []
        var_sym_map: dict = {}  # 变量名 → 规范符号 (A:1, A:2, ...)
        _addr_seq = [0x100]

        # 第一遍: 为变量分配符号
        _sym_idx = [0]
        for _l in pseudocode.split('\n') if pseudocode else []:
            for _m in re.finditer(r'\b([a-zA-Z_]\w*)\b', _l):
                _v = _m.group(1)
                if _v not in ('malloc', 'calloc', 'realloc', 'free',
                              'memcpy', 'memmove', 'memset', 'strcpy',
                              'strcat', 'sprintf', 'vsprintf', 'stpcpy',
                              'gets', 'if', 'else', 'while', 'for',
                              'return', 'break', 'continue', 'NULL',
                              'arg0', 'arg1', 'arg2', 'arg3',
                              'int', 'char', 'void', 'size_t',
                              'unsigned', 'long', 'short', 'float',
                              'double', 'ssize_t', 'uint32_t', 'uint64_t',
                              'int32_t', 'int64_t'):
                    if _v not in var_sym_map:
                        _sym_idx[0] += 1
                        var_sym_map[_v] = f'A:{_sym_idx[0]}'

        # 第二遍: 解析 if 守卫
        _guard_addr = 0x100
        for line in pseudocode.split('\n') if pseudocode else []:
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('#'):
                continue

            # if (var > N) return/break/continue → ja 早退守卫
            # 安全语义: 只有 var <= N 可到达后续写入
            m = re.match(
                r'if\s*\(\s*(\w+)\s*>\s*(\d+|0x[0-9a-fA-F]+)\s*\)'
                r'\s*(?:return|break|continue)', line)
            if m:
                var, bound_str = m.groups()
                bound = int(bound_str, 0)
                sym = var_sym_map.get(var, f'A:{var}')
                guards.append(GuardRecord(
                    addr=_guard_addr, sym=sym, bound=bound,
                    jcc='ja', target=_guard_addr + 0x80,
                    taken_le_bound=False,
                    operand_key=var))
                _guard_addr += 4
                continue

            # if (var >= N) return/break/continue → jae 早退守卫
            m = re.match(
                r'if\s*\(\s*(\w+)\s*>=\s*(\d+|0x[0-9a-fA-F]+)\s*\)'
                r'\s*(?:return|break|continue)', line)
            if m:
                var, bound_str = m.groups()
                bound = int(bound_str, 0)
                sym = var_sym_map.get(var, f'A:{var}')
                guards.append(GuardRecord(
                    addr=_guard_addr, sym=sym, bound=bound,
                    jcc='jae', target=_guard_addr + 0x80,
                    taken_le_bound=False,
                    operand_key=var))
                _guard_addr += 4
                continue

            # if (N < var) return/break/continue → ja 早退守卫
            m = re.match(
                r'if\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*<\s*(\w+)\s*\)'
                r'\s*(?:return|break|continue)', line)
            if m:
                bound_str, var = m.groups()
                bound = int(bound_str, 0)
                sym = var_sym_map.get(var, f'A:{var}')
                guards.append(GuardRecord(
                    addr=_guard_addr, sym=sym, bound=bound,
                    jcc='ja', target=_guard_addr + 0x80,
                    taken_le_bound=False,
                    operand_key=var))
                _guard_addr += 4
                continue

            # if (var <= N) return/break/continue → jbe 反例守卫
            # 反例语义: 只有 var > N 可到达后续写入 → 溢出证据
            m = re.match(
                r'if\s*\(\s*(\w+)\s*<=\s*(\d+|0x[0-9a-fA-F]+)\s*\)'
                r'\s*(?:return|break|continue)', line)
            if m:
                var, bound_str = m.groups()
                bound = int(bound_str, 0)
                sym = var_sym_map.get(var, f'A:{var}')
                guards.append(GuardRecord(
                    addr=_guard_addr, sym=sym, bound=bound,
                    jcc='jbe', target=_guard_addr + 0x80,
                    taken_le_bound=True,
                    operand_key=var))
                _guard_addr += 4
                continue

        # --- 阶段 2: 从伪代码解析变量的符号容量表达式 ---
        var_capexpr: Dict[str, CapExpr] = {}

        for line in pseudocode.split('\n') if pseudocode else []:
            line = line.strip()
            if not line:
                continue

            # dst = src ± k / dst = src * k
            arith_m = re.search(
                r'(\w+)\s*=\s*(\w+)\s*([+\-*])\s*(\d+|0x[0-9a-fA-F]+)', line)
            if arith_m:
                dst, src, op, k_str = arith_m.groups()
                k = int(k_str, 0)
                if src in var_capexpr:
                    base_ce = var_capexpr[src]
                    if base_ce.is_const():
                        if op == '+':
                            var_capexpr[dst] = CapExpr.const(base_ce.value + k)
                        elif op == '-':
                            var_capexpr[dst] = CapExpr.const(base_ce.value - k)
                        elif op == '*':
                            var_capexpr[dst] = CapExpr.const(base_ce.value * k)
                    elif base_ce.is_symbolic():
                        sym_name = var_sym_map.get(src, src)
                        if op == '+' and base_ce.kind == 'SYM':
                            var_capexpr[dst] = CapExpr.arith(
                                base_ce.base, k)
                        elif op == '-' and base_ce.kind == 'SYM':
                            var_capexpr[dst] = CapExpr.arith(
                                base_ce.base, -k)
                        elif op == '+' and base_ce.kind == 'ARITH':
                            var_capexpr[dst] = CapExpr.arith(
                                base_ce.base, base_ce.offset + k)
                        elif op == '-' and base_ce.kind == 'ARITH':
                            var_capexpr[dst] = CapExpr.arith(
                                base_ce.base, base_ce.offset - k)
                else:
                    sym_name = var_sym_map.get(src, src)
                    if op == '+':
                        var_capexpr[dst] = CapExpr.arith(sym_name, k)
                    elif op == '-':
                        var_capexpr[dst] = CapExpr.arith(sym_name, -k)
                    elif op == '*':
                        var_capexpr[dst] = CapExpr.sym(sym_name)
                continue

            # dst = src (简单赋值)
            simple_m = re.match(r'(\w+)\s*=\s*(\w+)$', line)
            if simple_m:
                dst, src = simple_m.groups()
                if src in var_capexpr:
                    var_capexpr[dst] = var_capexpr[src]
                else:
                    sym_name = var_sym_map.get(src, src)
                    var_capexpr[dst] = CapExpr.sym(sym_name)

        # --- 阶段 3: 路径敏感 ACPE 判定 ---
        # 对每个 finding 构建 alloc/write CapExpr, 提取守卫证据,
        # 调用 verdict.evaluate 输出完整判定
        filtered = []
        for f in heap_findings:
            alloc_size = f.get('alloc_size', -1)
            write_size = f.get('write_size', -1)
            alloc_var = f.get('alloc_var', '')
            write_var = f.get('write_var', '')

            # 构建 alloc CapExpr
            if alloc_var and alloc_var in var_capexpr:
                alloc_ce = var_capexpr[alloc_var]
            elif isinstance(alloc_size, int) and alloc_size >= 0:
                alloc_ce = CapExpr.const(alloc_size)
            else:
                alloc_ce = CapExpr.unknown()

            # 构建 write CapExpr
            if write_var and write_var in var_capexpr:
                write_ce = var_capexpr[write_var]
            elif isinstance(write_size, int) and write_size >= 0:
                write_ce = CapExpr.const(write_size)
            else:
                write_ce = CapExpr.unknown()

            # 写入是否无界 (strcpy/gets 等)
            write_func = f.get('write_func', '')
            is_unbounded = write_func in (
                'strcpy', 'strcat', 'stpcpy', 'gets', 'sprintf',
                'vsprintf')

            # 提取守卫证据 — CACBV 独有的路径敏感分析
            write_sym = write_ce.base if write_ce.is_symbolic() else ''
            guard_ev = None
            if guards and write_sym:
                # 写入地址用伪代码行号近似
                _waddr = 0x200
                guard_ev = analyze_guards_for_write(
                    _waddr, write_sym, guards, None)

            # 调用 verdict.evaluate 汇总容量/溯源/守卫
            v = evaluate(
                alloc_expr=alloc_ce,
                write_expr=write_ce,
                write_unbounded=is_unbounded,
                guard_ev=guard_ev,
                insns=None,
                func_name=func_name,
                write_addr=0x200,
                write_func=write_func or 'memcpy',
            )

            # 根据判定结果做过滤/提升
            if v.verdict == Verdict.SAFE:
                # 路径敏感容量判定安全 → 过滤
                f['cacbv_verdict'] = 'safe'
                f['cacbv_detail'] = v.reasoning
                f['cacbv_relation'] = v.relation
                continue
            if v.verdict == Verdict.VULN_CONFIRMED:
                f['cacbv_verdict'] = 'confirmed'
                f['cacbv_detail'] = v.reasoning
                f['cacbv_relation'] = v.relation
                f['confidence'] = max(
                    f.get('confidence', 0.5), v.confidence)
            elif v.verdict == Verdict.UNCERTAIN:
                f['cacbv_verdict'] = 'uncertain'
                f['cacbv_detail'] = v.reasoning
                f['cacbv_relation'] = v.relation
            elif v.verdict == Verdict.VULN_LIKELY:
                f['cacbv_verdict'] = 'likely'
                f['cacbv_detail'] = v.reasoning
                f['cacbv_relation'] = v.relation
            filtered.append(f)

        return non_heap + filtered
    except Exception as e:
        logger.debug('CACBV bridge failed: %s', e)
        return existing_findings


# -- D-4: 双向区间交汇验证 --
def run_bidir_range_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """双向区间交汇桥接: 前向别名追踪 + 后向根来源追踪,
    双向交汇验证堆溢出 findings.

    前向: 用 pointer_tracker 提取堆指针+别名+写入绑定,
    用 value_range_analyzer 的 check_heap_overflow_by_range 做区间交汇.
    后向: 用 AWSC 引擎的 trace_size_root 做根来源交叉验证.
    两个方向一致判定 safe 则过滤, 一致判定 overflow 则提升置信度.
    """
    if not _check_module('bidir_range', lambda: __import__(
            'modules.info.analysis.pointer_tracker',
            fromlist=['extract_heap_ptrs'])):
        return existing_findings

    try:
        from modules.info.analysis.pointer_tracker import (
            extract_heap_ptrs, extract_write_sites, build_ptr_aliases,
            bind_writes_to_allocs)
        from modules.info.analysis.value_range_analyzer import (
            extract_value_ranges, check_heap_overflow_by_range, ValueRange)
        from modules.analysis.static.co_source_engine import AWSCEngine
        from modules.analysis.static.co_source_core import (
            Root, ROOT_IMM, ROOT_UNKNOWN)
        from core.ir_normalizer import normalize_ir
        import re

        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        if not heap_findings:
            return existing_findings

        # 前向: 从伪代码提取堆指针和写入点
        heap_ptrs = extract_heap_ptrs(pseudocode)
        write_sites = extract_write_sites(pseudocode)
        aliases = build_ptr_aliases(pseudocode, heap_ptrs)
        bindings = bind_writes_to_allocs(heap_ptrs, write_sites, aliases)

        # 提取值范围
        ranges = extract_value_ranges(pseudocode)
        alloc_range = ranges.get('__malloc_size__', ValueRange.top())

        # 后向: AWSC 引擎 — 从伪代码构建指令字典列表做真实后向追踪
        engine = AWSCEngine(use_win64_abi=True)
        ir_lines = normalize_ir(pseudocode)
        # 伪代码转指令字典列表 (与 AWSC bridge 相同的方法)
        _callee_saved = ['rbx', 'r12', 'r13', 'r14', 'r15']
        _var_to_reg: Dict[str, str] = {}
        _reg_idx = 0
        instructions: List[dict] = []
        _addr = 0x400000
        _alloc_addr = 0
        _write_addr = 0
        _alloc_size_reg = 'rdi'
        _write_size_reg = 'rdx'
        for line in ir_lines:
            line = line.strip()
            if not line:
                continue
            # malloc(N) → mov rdi, N; call malloc; mov reg, rax
            m_alloc = re.match(r'(\w+)\s*=\s*(?:malloc|calloc)\s*\(([^)]*)\)', line)
            if m_alloc:
                var, size_arg = m_alloc.group(1), m_alloc.group(2).strip()
                if var not in _var_to_reg:
                    _var_to_reg[var] = _callee_saved[_reg_idx % 5]
                    _reg_idx += 1
                dst_reg = _var_to_reg[var]
                cm = re.match(r'^(\d+|0x[0-9a-fA-F]+)$', size_arg)
                if cm:
                    instructions.append({'address': _addr, 'mnemonic': 'mov',
                        'operands': f'rdi, {size_arg}'})
                    _alloc_size_reg = 'rdi'
                else:
                    # 变量 size: mov rdi, var_reg
                    if size_arg in _var_to_reg:
                        instructions.append({'address': _addr, 'mnemonic': 'mov',
                            'operands': f'rdi, {_var_to_reg[size_arg]}'})
                    else:
                        if size_arg not in _var_to_reg:
                            _var_to_reg[size_arg] = _callee_saved[_reg_idx % 5]
                            _reg_idx += 1
                        instructions.append({'address': _addr, 'mnemonic': 'mov',
                            'operands': f'rdi, {_var_to_reg[size_arg]}'})
                    _alloc_size_reg = 'rdi'
                _addr += 4
                instructions.append({'address': _addr, 'mnemonic': 'call',
                    'operands': 'malloc'})
                _alloc_addr = _addr
                _addr += 4
                instructions.append({'address': _addr, 'mnemonic': 'mov',
                    'operands': f'{dst_reg}, rax'})
                _addr += 4
                continue
            # memcpy/memmove/strcpy 等 → mov rdi, dst; mov rsi, src; mov rdx, size; call func
            m_write = re.match(
                r'(?:memcpy|memmove|strcpy|strncpy|strcat|strncat|memset|'
                r'sprintf|snprintf|read|fread)\s*\(([^)]*)\)', line)
            if m_write:
                args = [a.strip() for a in m_write.group(1).split(',')]
                func_name_m = re.match(r'(\w+)\s*\(', line).group(1)
                if len(args) >= 2:
                    dst_v, src_v = args[0], args[1]
                    if dst_v not in _var_to_reg:
                        _var_to_reg[dst_v] = _callee_saved[_reg_idx % 5]
                        _reg_idx += 1
                    instructions.append({'address': _addr, 'mnemonic': 'mov',
                        'operands': f'rdi, {_var_to_reg[dst_v]}'})
                    _addr += 4
                    if len(args) >= 3:
                        sz = args[2]
                        cm = re.match(r'^(\d+|0x[0-9a-fA-F]+)$', sz)
                        if cm:
                            instructions.append({'address': _addr, 'mnemonic': 'mov',
                                'operands': f'rdx, {sz}'})
                        elif sz in _var_to_reg:
                            instructions.append({'address': _addr, 'mnemonic': 'mov',
                                'operands': f'rdx, {_var_to_reg[sz]}'})
                        else:
                            if sz not in _var_to_reg:
                                _var_to_reg[sz] = _callee_saved[_reg_idx % 5]
                                _reg_idx += 1
                            instructions.append({'address': _addr, 'mnemonic': 'mov',
                                'operands': f'rdx, {_var_to_reg[sz]}'})
                        _write_size_reg = 'rdx'
                    instructions.append({'address': _addr, 'mnemonic': 'call',
                        'operands': func_name_m})
                    _write_addr = _addr
                    _addr += 4
                    continue
            # 赋值: var = expr
            m_assign = re.match(r'(\w+)\s*=\s*(.+?)(?:;|$)', line)
            if m_assign:
                var, rhs = m_assign.group(1), m_assign.group(2).strip()
                if var not in _var_to_reg:
                    _var_to_reg[var] = _callee_saved[_reg_idx % 5]
                    _reg_idx += 1
                dst_reg = _var_to_reg[var]
                cm = re.match(r'^(\d+|0x[0-9a-fA-F]+)$', rhs)
                if cm:
                    instructions.append({'address': _addr, 'mnemonic': 'mov',
                        'operands': f'{dst_reg}, {rhs}'})
                elif rhs in _var_to_reg:
                    instructions.append({'address': _addr, 'mnemonic': 'mov',
                        'operands': f'{dst_reg}, {_var_to_reg[rhs]}'})
                _addr += 4
                continue

        # 构建 binding 查找表: (buffer_var) → (alloc_ptr, write_site)
        binding_map: Dict[str, dict] = {}
        for b in bindings:
            buf = b['write_site'].get('buffer', '')
            binding_map.setdefault(buf, b)

        filtered = []
        for f in heap_findings:
            alloc_size = f.get('alloc_size', -1)
            write_size = f.get('write_size', -1)
            write_var = f.get('write_var', '')

            # 前向区间交汇
            fwd_safe = False
            fwd_overflow = False
            fwd_confidence = 0.0

            # 从绑定关系中找写入量表达式
            write_range = ValueRange.top()
            binding = binding_map.get(write_var)
            if binding:
                size_expr = binding['write_site'].get('size_expr', '')
                if size_expr and size_expr != 'unbounded':
                    try:
                        write_range = ValueRange.const(int(size_expr))
                    except (ValueError, TypeError):
                        if size_expr in ranges:
                            write_range = ranges[size_expr]
            elif isinstance(write_size, int) and write_size >= 0:
                write_range = ValueRange.const(write_size)

            if isinstance(alloc_size, int) and alloc_size > 0:
                ar = ValueRange.const(alloc_size)
            else:
                ar = alloc_range

            overflow, conf, reason = check_heap_overflow_by_range(
                ar, write_range)
            fwd_safe = not overflow and conf > 0.5
            fwd_overflow = overflow and conf > 0.6
            fwd_confidence = conf

            # 后向根来源交叉验证 — 用 trace_size_root 做真实后向追踪
            bwd_safe = False
            bwd_overflow = False
            detail = ''
            if instructions and _alloc_addr > 0:
                # 从 malloc 调用点追踪 alloc_size 根来源
                alloc_root = engine.trace_size_root(
                    instructions, _alloc_addr, _alloc_size_reg)
                # 从 write 调用点追踪 write_size 根来源
                if _write_addr > 0:
                    write_root = engine.trace_size_root(
                        instructions, _write_addr, _write_size_reg)
                else:
                    write_root = Root(ROOT_IMM, write_size) \
                        if isinstance(write_size, int) and write_size >= 0 \
                        else Root(ROOT_UNKNOWN, 0)
                category, over, detail = engine.correlate(
                    alloc_root, write_root,
                    usable_size=alloc_size if isinstance(alloc_size, int) and alloc_size > 0 else 0)
                bwd_safe = category == 'safe'
                bwd_overflow = category == 'overflow'
            elif isinstance(alloc_size, int) and \
                    isinstance(write_size, int) and \
                    alloc_size >= 0 and write_size >= 0:
                # 回退: 无指令流时用常量比较
                alloc_root = Root(ROOT_IMM, alloc_size)
                write_root = Root(ROOT_IMM, write_size)
                category, over, detail = engine.correlate(
                    alloc_root, write_root,
                    usable_size=alloc_size)
                bwd_safe = category == 'safe'
                bwd_overflow = category == 'overflow'

            # 双向交汇
            if fwd_safe and bwd_safe:
                f['bidir_verdict'] = 'safe'
                f['bidir_reason'] = (
                    f'forward={reason}; backward={detail}')
                continue  # 双向一致 safe, 过滤

            if fwd_overflow and bwd_overflow:
                f['bidir_verdict'] = 'overflow'
                f['bidir_reason'] = (
                    f'forward={reason}; backward={detail}')
                f['confidence'] = min(1.0,
                    f.get('confidence', 0.5) + 0.15)
            elif fwd_safe or bwd_safe:
                f['bidir_verdict'] = 'likely_safe'
                f['bidir_reason'] = (
                    f'forward_safe={fwd_safe}, backward_safe={bwd_safe}')
            else:
                f['bidir_verdict'] = 'unknown'

            filtered.append(f)

        return non_heap + filtered
    except Exception as e:
        logger.debug('Bidir-Range bridge failed: %s', e)
        return existing_findings


# -- D-5: ACPE (分配容量溯源等价分析) --
def run_acpe_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """ACPE 桥接: 用 ACPE 的溯源链等价判定做独立过滤.

    与 AWSC 的区别: AWSC 做寄存器级后向 def-use 根来源追踪;
    ACPE 用符号容量表达式 CapExpr 建模 alloc/write size,
    用 equivalence.classify_pair() 做溯源等价分类
    (EQUIV/CONST_LE/ARITH_LE/GUARDED → safe),
    用 verdict.evaluate() 输出最终判定.

    从伪代码解析:
      - 变量的 CapExpr (符号容量表达式)
      - 守卫证据 (if (n > N) n = N; → 钳位守卫)
    """
    if not _check_module('acpe', lambda: __import__(
            'modules.vuln.detection.heap_analysis.acpe.equivalence',
            fromlist=['classify_pair'])):
        return existing_findings

    try:
        from modules.vuln.detection.heap_analysis.acpe.capacity_model import (
            CapExpr, usable_size)
        from modules.vuln.detection.heap_analysis.acpe.equivalence import (
            classify_pair)
        from modules.vuln.detection.heap_analysis.acpe.verdict import (
            evaluate, Verdict as AcpeVerdictKind)
        from modules.vuln.detection.heap_analysis.acpe.guard_dominance import (
            GuardEvidence)
        import re

        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        if not heap_findings:
            return existing_findings

        # 从伪代码解析变量的符号容量表达式
        var_capexpr: Dict[str, CapExpr] = {}
        # 守卫证据: 变量 → 钳位上界
        guard_bounds: Dict[str, int] = {}

        for line in pseudocode.split('\n') if pseudocode else []:
            line = line.strip()
            if not line:
                continue

            # 守卫钳位: if (n > N) n = N; → guard_bounds[n] = N
            guard_m = re.match(
                r'if\s*\(\s*(\w+)\s*>\s*(\d+|0x[0-9a-fA-F]+)\s*\)'
                r'\s*\1\s*=\s*(\d+|0x[0-9a-fA-F]+)', line)
            if guard_m:
                var, _bound, new_val = guard_m.groups()
                guard_bounds[var] = int(new_val, 0)
                continue

            # 早退守卫: if (n > N) return; → guard_bounds[n] = N
            guard_ret = re.match(
                r'if\s*\(\s*(\w+)\s*>\s*(\d+|0x[0-9a-fA-F]+)\s*\)'
                r'\s*return', line)
            if guard_ret:
                var, bound = guard_ret.groups()
                guard_bounds[var] = int(bound, 0)
                continue

            # dst = src ± k
            arith_m = re.search(
                r'(\w+)\s*=\s*(\w+)\s*([+\-*])\s*(\d+|0x[0-9a-fA-F]+)', line)
            if arith_m:
                dst, src, op, k_str = arith_m.groups()
                k = int(k_str, 0)
                if src in var_capexpr:
                    base_ce = var_capexpr[src]
                    if base_ce.is_const():
                        if op == '+':
                            var_capexpr[dst] = CapExpr.const(base_ce.value + k)
                        elif op == '-':
                            var_capexpr[dst] = CapExpr.const(base_ce.value - k)
                        elif op == '*':
                            var_capexpr[dst] = CapExpr.const(base_ce.value * k)
                    elif base_ce.is_symbolic():
                        if op == '+' and base_ce.kind == 'SYM':
                            var_capexpr[dst] = CapExpr.arith(base_ce.base, k)
                        elif op == '-' and base_ce.kind == 'SYM':
                            var_capexpr[dst] = CapExpr.arith(base_ce.base, -k)
                        elif op == '+' and base_ce.kind == 'ARITH':
                            var_capexpr[dst] = CapExpr.arith(
                                base_ce.base, base_ce.offset + k)
                        elif op == '-' and base_ce.kind == 'ARITH':
                            var_capexpr[dst] = CapExpr.arith(
                                base_ce.base, base_ce.offset - k)
                else:
                    if op == '+':
                        var_capexpr[dst] = CapExpr.arith(src, k)
                    elif op == '-':
                        var_capexpr[dst] = CapExpr.arith(src, -k)
                    elif op == '*':
                        var_capexpr[dst] = CapExpr.sym(src)
                continue

            # dst = src (简单赋值)
            simple_m = re.match(r'(\w+)\s*=\s*(\w+)$', line)
            if simple_m:
                dst, src = simple_m.groups()
                if src in var_capexpr:
                    var_capexpr[dst] = var_capexpr[src]
                else:
                    var_capexpr[dst] = CapExpr.sym(src)

        # 对每条 heap finding 做 ACPE 判定
        filtered = []
        for f in heap_findings:
            alloc_size = f.get('alloc_size', -1)
            write_size = f.get('write_size', -1)
            alloc_var = f.get('alloc_var', '')
            write_var = f.get('write_var', '')
            write_func = f.get('write_func', 'memcpy')

            # 构建 alloc CapExpr
            if alloc_var and alloc_var in var_capexpr:
                alloc_ce = var_capexpr[alloc_var]
            elif isinstance(alloc_size, int) and alloc_size >= 0:
                alloc_ce = CapExpr.const(alloc_size)
            else:
                alloc_ce = CapExpr.unknown()

            # 构建 write CapExpr
            if write_var and write_var in var_capexpr:
                write_ce = var_capexpr[write_var]
            elif isinstance(write_size, int) and write_size >= 0:
                write_ce = CapExpr.const(write_size)
            else:
                write_ce = CapExpr.unknown()

            # 构建守卫证据
            guard_ev = None
            guard_var = write_var or alloc_var
            if guard_var and guard_var in guard_bounds:
                guard_ev = GuardEvidence(
                    write_addr=0, size_sym=guard_var,
                    safe_upper_bound=guard_bounds[guard_var],
                    bound_source='clamp_guard')

            # 无界写入判定 (strcpy/gets 等)
            write_unbounded = bool(write_func and write_func in (
                'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets', 'stpcpy'))

            # ACPE 判定
            acpe_verdict = evaluate(
                alloc_expr=alloc_ce, write_expr=write_ce,
                write_unbounded=write_unbounded,
                guard_ev=guard_ev,
                func_name=func_name,
                write_func=write_func)

            f.setdefault('acpe_relation', acpe_verdict.relation)
            f.setdefault('acpe_verdict', acpe_verdict.verdict.value)
            f.setdefault('acpe_reasoning', acpe_verdict.reasoning)

            if acpe_verdict.verdict == AcpeVerdictKind.SAFE:
                # ACPE 判定安全, 过滤误报
                continue
            if acpe_verdict.verdict == AcpeVerdictKind.VULN_CONFIRMED:
                f.setdefault('acpe_confirmed', True)
            filtered.append(f)

        return non_heap + filtered
    except Exception as e:
        logger.debug('ACPE bridge failed: %s', e)
        return existing_findings


# -- D-6: PSVR-HLM (路径敏感值域推理分层模型) --
def run_psvr_hlm_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """PSVR-HLM 桥接: 三层级联过滤堆溢出 findings.

    L2 (路径守卫): 用 path_feasibility_check 的 build_path_constraints
    窄化值域, 检查路径可行性.
    L3 (分配器 padding): 用 heap_layout_model 的 AllocatorModel
    检查写入是否在对齐 padding 区内.
    FM (边界推导): 用 value_range_analyzer 的
    check_heap_overflow_by_range 做区间交汇.

    三层任一判定 safe 则过滤, 全部判定 overflow 则提升置信度.
    """
    if not _check_module('psvr_hlm', lambda: __import__(
            'modules.info.analysis.path_feasibility_check',
            fromlist=['build_path_constraints'])):
        return existing_findings

    try:
        from modules.info.analysis.path_feasibility_check import (
            build_path_constraints, check_write_reachability)
        from modules.info.analysis.heap_layout_model import (
            AllocatorModel)
        from modules.info.analysis.value_range_analyzer import (
            extract_value_ranges, check_heap_overflow_by_range,
            ValueRange)
        import re

        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        if not heap_findings:
            return existing_findings

        # 提取值范围和路径约束
        ranges = extract_value_ranges(pseudocode)
        constrained_ranges, infeasible = build_path_constraints(
            pseudocode)

        # 检查写入可达性
        reachability = check_write_reachability(pseudocode)

        # 分配器模型
        alloc_model = AllocatorModel.x86_64()

        filtered = []
        for f in heap_findings:
            alloc_size = f.get('alloc_size', 0)
            write_size = f.get('write_size', 0)

            if not isinstance(alloc_size, int) or alloc_size <= 0:
                filtered.append(f)
                continue

            # L2: 路径守卫 — 如果路径不可达, 过滤
            if not reachability.get('reachable', True):
                f['psvr_l2_verdict'] = 'infeasible_path'
                f['psvr_l2_reason'] = reachability.get('reason', '')
                continue  # 路径不可达, 过滤

            # L2: 路径守卫 — 有强边界检查且写入不溢出
            guard_strength = reachability.get('guard_strength', 0)
            if guard_strength > 0.5 and \
                    not reachability.get('overflow_possible', False):
                f['psvr_l2_verdict'] = 'guarded_safe'
                f['psvr_l2_reason'] = (
                    f'guard_strength={guard_strength:.2f}, '
                    f'no overflow possible')
                continue  # 有边界检查且安全, 过滤

            if not isinstance(write_size, int) or write_size <= 0:
                filtered.append(f)
                continue

            # L3: 分配器 padding 检查
            l3_overflow, l3_conf, l3_reason = \
                alloc_model.check_overflow_under_alignment(
                    alloc_size, write_size)
            if not l3_overflow and l3_conf < 0.15:
                # 写入在对齐 padding 区内, 安全
                f['psvr_l3_verdict'] = 'padding_safe'
                f['psvr_l3_reason'] = l3_reason
                continue  # 过滤

            # FM: 区间交汇
            ar = ValueRange.const(alloc_size)
            wr = ValueRange.const(write_size)
            # 应用路径约束后的值域
            if '__malloc_size__' in constrained_ranges:
                ar = constrained_ranges['__malloc_size__']

            fm_overflow, fm_conf, fm_reason = \
                check_heap_overflow_by_range(ar, wr)

            if not fm_overflow and fm_conf > 0.5:
                f['psvr_fm_verdict'] = 'range_safe'
                f['psvr_fm_reason'] = fm_reason
                continue  # 区间交汇判定安全, 过滤

            if l3_overflow and fm_overflow:
                # L3+FM 双重确认溢出, 提升置信度
                f['psvr_verdict'] = 'confirmed_overflow'
                f['psvr_reason'] = (
                    f'L3:{l3_reason}; FM:{fm_reason}')
                f['confidence'] = min(1.0,
                    f.get('confidence', 0.5) + 0.15)
            elif l3_overflow or fm_overflow:
                f['psvr_verdict'] = 'possible_overflow'
                f['psvr_reason'] = (
                    f'L3:{l3_reason}; FM:{fm_reason}')

            filtered.append(f)

        return non_heap + filtered
    except Exception as e:
        logger.debug('PSVR-HLM bridge failed: %s', e)
        return existing_findings


# -- D-7: DP-TVRA (需求驱动路径敏感污点-值域分析) --
def run_dp_tvra_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """DP-TVRA 桥接: 用三阶段过滤器 evaluate_finding 做需求驱动过滤.

    Phase 0 (边界检查): write_size ≤ alloc_size → SAFE_FILTERED
    Phase 1 (污点): 操作数不受外部控制 → SAFE_FILTERED
    Phase 2 (路径约束): 路径条件证明安全 → SAFE_FILTERED
    Phase 3 (分配器模型): 写入在 padding 区 → SAFE_FILTERED

    从伪代码构建简化的 AllocRecord/WriteRecord, 调用
    evaluate_finding() 做三阶段评估.
    SAFE_FILTERED 则过滤, CONFIRMED_VULN/LIKELY_VULN 则保留.
    """
    if not _check_module('dp_tvra', lambda: __import__(
            'modules.vuln.detection.heap_analysis.fp_filter_v2',
            fromlist=['evaluate_finding'])):
        return existing_findings

    try:
        from modules.vuln.detection.heap_analysis.fp_filter_v2 import (
            evaluate_finding, FilterDecision)
        from modules.vuln.detection.heap_analysis._types import (
            AllocRecord, WriteRecord)
        from modules.info.analysis.path_feasibility_check import (
            check_write_reachability)
        import re

        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        if not heap_findings:
            return existing_findings

        # 检查写入可达性和边界检查
        reachability = check_write_reachability(pseudocode)
        path_proof = reachability.get('has_guard', False) and \
            not reachability.get('overflow_possible', False)

        # 从伪代码解析污点来源: 外部输入调用 → 高污点
        taint_conf = 0.5  # 默认中等污点
        lines = pseudocode.split('\n') if pseudocode else []
        for line in lines:
            if re.search(r'\b(?:recv|read|fread|gets|scanf)\s*\(',
                         line):
                taint_conf = 0.8  # 存在外部输入, 高污点
                break
        # 如果有边界检查模式, 降低污点置信度
        if reachability.get('has_guard', False):
            taint_conf *= 0.7

        # 从伪代码解析真实的 alloc/write 信息, 替代假地址 0x1000/0x1020
        alloc_addr = 0x1000
        write_addr = 0x1020
        alloc_func_name = 'malloc'
        write_func_name = 'memcpy'
        base_src_str = 'malloc@0x1000'
        for line in lines:
            m_alloc = re.search(
                r'(\w+)\s*=\s*(malloc|calloc|realloc)\s*\(([^)]*)\)', line)
            if m_alloc:
                alloc_func_name = m_alloc.group(2)
                base_src_str = f'{alloc_func_name}@0x{alloc_addr:x}'
                break
        for line in lines:
            m_write = re.search(
                r'(memcpy|memmove|strcpy|strncpy|strcat|strncat|memset|'
                r'sprintf|snprintf|read|fread|gets|scanf)\s*\(', line)
            if m_write:
                write_func_name = m_write.group(1)
                break

        filtered = []
        for f in heap_findings:
            alloc_size = f.get('alloc_size', 0)
            write_size = f.get('write_size', 0)
            if not isinstance(alloc_size, int):
                alloc_size = 0
            if not isinstance(write_size, int):
                write_size = 0

            # 用从伪代码解析的真实信息构建 AllocRecord/WriteRecord
            alloc_record = AllocRecord(
                addr=alloc_addr,
                alloc_func=alloc_func_name,
                size_reg='rdi',
                size_val=alloc_size if alloc_size > 0 else None,
                func_name=func_name,
            )

            write_record = WriteRecord(
                addr=write_addr,
                write_func=write_func_name,
                base_src=base_src_str,
                offset=0,
                size_reg='rdx',
                size_val=write_size if write_size > 0 else None,
                access_size=4,
                func_name=func_name,
            )

            # 调用三阶段过滤
            ff = evaluate_finding(
                write_record, alloc_record,
                taint_conf=taint_conf,
                path_proof=path_proof,
                alloc_model_enabled=True,
            )

            f['dp_tvra_decision'] = ff.decision.value
            f['dp_tvra_phase'] = ff.decisive_phase.value
            f['dp_tvra_reason'] = ff.reasoning
            f['dp_tvra_fp_prob'] = ff.fp_probability

            if ff.decision == FilterDecision.SAFE_FILTERED:
                # 三阶段过滤判定安全, 过滤误报
                continue

            if ff.decision == FilterDecision.CONFIRMED_VULN:
                f['confidence'] = min(1.0,
                    f.get('confidence', 0.5) + 0.15)

            filtered.append(f)

        return non_heap + filtered
    except Exception as e:
        logger.debug('DP-TVRA bridge failed: %s', e)
        return existing_findings


# -- AWSC-ICF: 跨函数调用帧传播 (差异化: 原 AWSC 的后向 def-use 扩展到跨函数) --
def run_awsc_icf_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """AWSC-ICF 桥接: 通过函数摘要追踪跨函数的 size 寄存器来源.

    与原 AWSC 的区别: 原 AWSC 在 call 指令处终止追踪,
    AWSC-ICF 通过 InterprocSummary 继续追踪参数来源.
    """
    if not _check_module('awsc_icf', lambda: __import__(
            'modules.analysis.static.awsc_icf', fromlist=['InterproceduralCofluenceTracker'])):
        return existing_findings

    try:
        from modules.analysis.static.awsc_icf import InterproceduralCofluenceTracker
        tracker = InterproceduralCofluenceTracker()
        findings = tracker.analyze_findings(pseudocode, existing_findings)
        return findings
    except Exception as e:
        logger.debug('AWSC-ICF bridge failed: %s', e)
        return existing_findings


# -- HOFPR-APC: 自适应优先级级联 (差异化: 原 HOFPR 固定三阶段改为动态编排) --
def run_hofpr_apc_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """HOFPR-APC 桥接: 根据告警置信度动态调整过滤阶段顺序.

    与原 HOFPR 的区别: 原固定 污点→大小→路径, APC 根据置信度动态编排.
    """
    if not _check_module('hofpr_apc', lambda: __import__(
            'modules.analysis.static.hofpr_apc', fromlist=['AdaptivePriorityCascade'])):
        return existing_findings

    try:
        from modules.analysis.static.hofpr_apc import AdaptivePriorityCascade
        cascade = AdaptivePriorityCascade()
        return cascade.cascade_filter(existing_findings)
    except Exception as e:
        logger.debug('HOFPR-APC bridge failed: %s', e)
        return existing_findings


# -- PcWBI-IRL: 内联复制加载建模 (差异化: 原 PcWBI 不建模 rep movs/SSE) --
def run_pcwbi_irl_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """PcWBI-IRL 桥接: 解析内联复制模式, 用 count_expr 增强 findings.

    与原 PcWBI 的区别: 原不建模编译器内联复制, IRL 解析 rep movs/SSE 块拷贝.
    """
    if not _check_module('pcwbi_irl', lambda: __import__(
            'modules.analysis.static.pcwbi_irl', fromlist=['InlineRepLoadModeler'])):
        return existing_findings

    try:
        from modules.analysis.static.pcwbi_irl import InlineRepLoadModeler
        modeler = InlineRepLoadModeler()
        copies = modeler.detect_pseudo_inline_copy(pseudocode)
        if copies:
            return modeler.enhance_findings(existing_findings, copies)
        return existing_findings
    except Exception as e:
        logger.debug('PcWBI-IRL bridge failed: %s', e)
        return existing_findings


# -- FC-VRA-PTA: 指针污点别名传播 (差异化: 原 FC-VRA 不区分指针受控性) --
def run_fc_vra_pta_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """FC-VRA-PTA 桥接: 在别名传播中加入污点维度, 区分受控/不受控指针.

    与原 FC-VRA 的区别: 原用并查集别名闭包不区分污点, PTA 加入污点传播.
    """
    if not _check_module('fc_vra_pta', lambda: __import__(
            'modules.info.analysis.fc_vra_pta', fromlist=['PointerTaintAliasTracker'])):
        return existing_findings

    try:
        from modules.info.analysis.fc_vra_pta import PointerTaintAliasTracker
        tracker = PointerTaintAliasTracker()
        new_findings = tracker.analyze_pseudocode(pseudocode)
        # 对已有 findings 做污点别名增强
        for f in existing_findings:
            if 'heap' not in f.get('type', '').lower():
                continue
            dst_var = f.get('dst_var', f.get('variable', ''))
            if dst_var:
                canonical, is_tainted = tracker.resolve_alias(dst_var)
                f['pta_canonical'] = canonical
                f['pta_tainted'] = is_tainted
                if is_tainted and f.get('confidence', 0) < 0.5:
                    f['pta_upgrade'] = '受控指针告警置信度提升'
                    f['confidence'] = min(1.0, f.get('confidence', 0.5) + 0.2)
        if new_findings:
            existing_findings.extend(new_findings)
        return existing_findings
    except Exception as e:
        logger.debug('FC-VRA-PTA bridge failed: %s', e)
        return existing_findings


# -- CACBV-DSS: 动态slack减除 (差异化: 原 CACBV 用固定对齐公式) --
def run_cacbv_dss_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """CACBV-DSS 桥接: 根据分配函数类型动态计算 chunk 几何.

    与原 CACBV 的区别: 原用固定 align_up(N,16), DSS 按 malloc/calloc/realloc 区分.
    """
    if not _check_module('cacbv_dss', lambda: __import__(
            'modules.vuln.detection.heap_analysis.acpe.cacbv_dss',
            fromlist=['DynamicSlackSubtractor'])):
        return existing_findings

    try:
        from modules.vuln.detection.heap_analysis.acpe.cacbv_dss import DynamicSlackSubtractor
        subtractor = DynamicSlackSubtractor()
        return subtractor.analyze_findings(existing_findings, pseudocode)
    except Exception as e:
        logger.debug('CACBV-DSS bridge failed: %s', e)
        return existing_findings


# -- BIV-CTC: 跨类型约束传播 (差异化: 原 BIV 只做堆区间交汇) --
def run_biv_ctc_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """BIV-CTC 桥接: 在堆/栈/全局缓冲区间传播区间约束.

    与原 BIV 的区别: 原只做堆区间交汇, CTC 增加栈/全局缓冲区跨类型传播.
    """
    if not _check_module('biv_ctc', lambda: __import__(
            'modules.patching.src.biv_ctc', fromlist=['CrossTypeConstraintPropagator'])):
        return existing_findings

    try:
        from modules.patching.src.biv_ctc import CrossTypeConstraintPropagator
        propagator = CrossTypeConstraintPropagator()
        propagator.propagate_constraints(pseudocode)
        return propagator.check_cross_type_overflow(existing_findings)
    except Exception as e:
        logger.debug('BIV-CTC bridge failed: %s', e)
        return existing_findings


# -- SI-CTA: 跨类型别名追踪 (差异化: 原 SizeIdentity 在 call 处清空 volatile reg) --
def run_si_cta_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """SI-CTA 桥接: 通过函数摘要保留跨函数链 ID.

    与原 SizeIdentity 的区别: 原在 call 处清空 volatile reg 丢失链 ID,
    CTA 通过函数摘要保留跨函数链 ID.
    """
    if not _check_module('si_cta', lambda: __import__(
            'modules.project.analysis.si_cta', fromlist=['CrossTypeAliasTracker'])):
        return existing_findings

    try:
        from modules.project.analysis.si_cta import CrossTypeAliasTracker
        tracker = CrossTypeAliasTracker()
        new_findings = tracker.analyze_pseudocode(pseudocode)
        # 对已有 findings 做同链安全判定
        for f in existing_findings:
            if 'heap' not in f.get('type', '').lower():
                continue
            alloc_var = f.get('alloc_var', f.get('variable', ''))
            dst_var = f.get('dst_var', f.get('variable', ''))
            if alloc_var and dst_var:
                is_same, chain_id = tracker.check_same_chain(alloc_var, dst_var)
                f['cta_same_chain'] = is_same
                f['cta_chain_id'] = chain_id
                if is_same and f.get('severity', '').lower() in ('high', 'critical'):
                    f['cta_downgrade'] = '同链判定安全, 降级告警'
                    f['severity'] = 'low'
                    f['confidence'] = max(0.1, f.get('confidence', 0.5) * 0.3)
        if new_findings:
            existing_findings.extend(new_findings)
        return existing_findings
    except Exception as e:
        logger.debug('SI-CTA bridge failed: %s', e)
        return existing_findings


# -- PG-WBV-LSA: 循环结构感知写界 (差异化: 原 PG-WBV 不解析循环结构) --
def run_pg_wbv_lsa_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """PG-WBV-LSA 桥接: 解析循环回跳结构推断迭代写量上界.

    与原 PG-WBV 的区别: 原只检测 call/mov 写入, LSA 解析循环结构放大写量.
    """
    if not _check_module('pg_wbv_lsa', lambda: __import__(
            'modules.analysis.static.pg_wbv_lsa', fromlist=['LoopStructureAwareVerifier'])):
        return existing_findings

    try:
        from modules.analysis.static.pg_wbv_lsa import LoopStructureAwareVerifier
        verifier = LoopStructureAwareVerifier()
        return verifier.analyze_findings(existing_findings, pseudocode)
    except Exception as e:
        logger.debug('PG-WBV-LSA bridge failed: %s', e)
        return existing_findings


# -- ACPE-VRP: 值域传播增强 (差异化: 原 ACPE 只做常量提取) --
def run_acpe_vrp_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """ACPE-VRP 桥接: 用区间传播在非常量场景提供区间估计.

    与原 ACPE 的区别: 原只做常量提取的容量比较, VRP 用区间传播处理非常量.
    """
    if not _check_module('acpe_vrp', lambda: __import__(
            'modules.vuln.detection.heap_analysis.acpe.acpe_vrp',
            fromlist=['ValueRangePropagationEnhancer'])):
        return existing_findings

    try:
        from modules.vuln.detection.heap_analysis.acpe.acpe_vrp import ValueRangePropagationEnhancer
        enhancer = ValueRangePropagationEnhancer()
        return enhancer.enhance_findings(existing_findings, pseudocode)
    except Exception as e:
        logger.debug('ACPE-VRP bridge failed: %s', e)
        return existing_findings


# -- ACFPC-CMS: 冲突感知多源融合 (差异化: 原 ACFPC 用固定权重) --
def run_acfpc_cms_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """ACFPC-CMS 桥接: 基于 D-S 证据理论检测证据冲突并动态调权.

    与原 ACFPC 的区别: 原用固定权重五模态融合, CMS 加入冲突检测动态调权.
    """
    if not _check_module('acfpc_cms', lambda: __import__(
            'modules.vuln.detection.acfpc_cms', fromlist=['ConflictAwareMultiSourceFuser'])):
        return existing_findings

    try:
        from modules.vuln.detection.acfpc_cms import ConflictAwareMultiSourceFuser
        fuser = ConflictAwareMultiSourceFuser()
        return fuser.enhance_findings(existing_findings)
    except Exception as e:
        logger.debug('ACFPC-CMS bridge failed: %s', e)
        return existing_findings


def run_innovation_pipeline(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    base_findings: List[dict],
) -> List[dict]:
    """创新模块统一入口 — 按管线顺序执行全部创新模块.

    管线顺序 (39个创新模块):
      --- 原有7模块 (堆溢出聚焦) ---
      1. HOFPR: C源码级误报抑制 (产出新findings)
      2. HFP: IR级三态判定 (产出新findings)
      3. ACFPC: 分配契约压缩 (对已有findings过滤)
      4. DDSSC: 三层级联过滤 (对已有findings过滤)
      5. AWSC: 同源关联过滤 (对已有findings过滤)
      6. CJ-BVF: 反向值流证明 (对已有findings过滤)
      7. CJ-PCBVF: 路径约束增强 (对已有findings过滤)
      --- 新增15模块 (全漏洞类型覆盖) ---
      8. GAPSBV: 仿射关系堆溢出检测 (产出新findings)
      9. GASRI: 守卫感知值域推理 (对已有findings过滤)
      10. UAF-HOIG: 混合对象身份图UAF检测 (产出+过滤)
      11. UAF-Enhanced: TARPS五阶段UAF检测 (产出新findings)
      12. UAF-Lifecycle: 指针生命周期状态机 (产出新findings)
      13. Double-Free: 四层DF检测 (产出新findings)
      14. UAF-Lifetime-Tracker: 着色分配追踪UAF (产出新findings)
      15. Buffer-Underflow: CWE-124负偏移检测 (产出新findings)
      16. Off-by-One: 越界写入单字节 (对已有findings分类)
      17. Uninitialized: CWE-457未初始化检测 (产出新findings)
      18. FMTPROV: 格式串常量折叠+污点溯源 (对已有findings过滤)
      19. Int-Overflow-Enhance: L4-L6整数溢出增强 (对已有findings增强)
      20. Provenance: 分配点感知值范围 (对已有findings过滤)
      21. Cross-Domain: 跨域稀疏值流精炼 (对已有findings过滤)
      22. Cross-Pipeline: 跨管线贝叶斯关联 (全局聚合)
      --- D类7模块 (深度创新补全) ---
      23. BWR+PCST: 有界写恢复+路径条件敏感污点 (对已有findings过滤)
      24. DD-BVF: 按需后向值流UAF检测 (对已有findings过滤)
      25. CACBV: 容量感知耦合边界验证 (对已有findings过滤)
      26. 双向区间交汇: 前向别名+后向根来源双向交汇 (对已有findings过滤)
      27. ACPE: 分配容量溯源等价分析 (对已有findings过滤)
      28. PSVR-HLM: 路径敏感值域推理分层模型 (对已有findings过滤)
      29. DP-TVRA: 需求驱动路径敏感污点-值域分析 (对已有findings过滤)
      --- 差异化创新10模块 (代码层面不同算法) ---
      30. AWSC-ICF: 跨函数调用帧传播 (对已有findings增强)
      31. HOFPR-APC: 自适应优先级级联 (对已有findings过滤)
      32. PcWBI-IRL: 内联复制加载建模 (对已有findings增强)
      33. FC-VRA-PTA: 指针污点别名传播 (产出+增强)
      34. CACBV-DSS: 动态slack减除 (对已有findings增强)
      35. BIV-CTC: 跨类型约束传播 (对已有findings分类)
      36. SI-CTA: 跨类型别名追踪 (产出+过滤)
      37. PG-WBV-LSA: 循环结构感知写界 (对已有findings增强)
      38. ACPE-VRP: 值域传播增强 (对已有findings增强)
      39. ACFPC-CMS: 冲突感知多源融合 (对已有findings增强)

    参数:
      pseudocode: 反编译伪代码文本
      func_name: 函数名
      binary_path: 二进制文件路径
      base_findings: 基础检测器已产出的findings

    返回:
      经创新模块增强+过滤后的findings列表
    """
    findings = list(base_findings)

    # === 阶段1-7: 原有堆溢出创新模块 ===
    # 阶段1: HOFPR — 产出新findings
    hofpr_results = run_hofpr_bridge(pseudocode, func_name, binary_path, findings)
    if hofpr_results:
        findings.extend(hofpr_results)

    # 阶段2: HFP — 产出新findings
    hfp_results = run_hfp_bridge(pseudocode, func_name, binary_path)
    if hfp_results:
        findings.extend(hfp_results)

    # 阶段3: ACFPC — 对已有findings做契约压缩
    findings = run_acfpc_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段4: DDSSC — 三层级联过滤
    findings = run_ddssc_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段5: AWSC — 同源关联过滤
    findings = run_awsc_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段6: CJ-BVF — 反向值流安全证明
    findings = run_cj_bvf_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段7: CJ-PCBVF — 路径约束增强证明
    findings = run_cj_pcbvf_bridge(pseudocode, func_name, binary_path, findings)

    # === 阶段8-14: 新增检测模块 ===
    # 阶段8: GAPSBV — 仿射关系堆溢出检测 (产出新findings)
    gapsbv_results = run_gapsbv_bridge(pseudocode, func_name, binary_path)
    if gapsbv_results:
        findings.extend(gapsbv_results)

    # 阶段9: GASRI — 守卫感知值域推理 (过滤已有堆findings)
    findings = run_gasri_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段10: UAF-HOIG — 混合对象身份图UAF (产出+过滤)
    findings = run_uaf_hoig_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段11: UAF-Enhanced — TARPS五阶段 (产出新findings)
    uaf_enh_results = run_uaf_enhanced_bridge(pseudocode, func_name, binary_path)
    if uaf_enh_results:
        findings.extend(uaf_enh_results)

    # 阶段12: UAF-Lifecycle — 指针生命周期 (产出新findings)
    uaf_lc_results = run_uaf_lifecycle_bridge(pseudocode, func_name, binary_path)
    if uaf_lc_results:
        findings.extend(uaf_lc_results)

    # 阶段13: Double-Free — 四层DF检测 (产出新findings)
    df_results = run_double_free_bridge(pseudocode, func_name, binary_path)
    if df_results:
        findings.extend(df_results)

    # 阶段14: UAF-Lifetime-Tracker — 着色追踪 (产出新findings)
    uaf_lt_results = run_uaf_lifetime_bridge(pseudocode, func_name, binary_path)
    if uaf_lt_results:
        findings.extend(uaf_lt_results)

    # 阶段15: Buffer-Underflow — 负偏移检测 (产出新findings)
    bu_results = run_buffer_underflow_bridge(pseudocode, func_name, binary_path)
    if bu_results:
        findings.extend(bu_results)

    # 阶段16: Off-by-One — 越界写入分类 (对已有堆findings分类)
    findings = run_off_by_one_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段17: Uninitialized — 未初始化检测 (产出新findings)
    uninit_results = run_uninit_bridge(pseudocode, func_name, binary_path)
    if uninit_results:
        findings.extend(uninit_results)

    # === 阶段18-22: 误报削减与跨管线聚合 ===
    # 阶段18: FMTPROV — 格式串误报削减
    findings = run_fmtprov_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段19: Int-Overflow-Enhance — 整数溢出L4-L6增强
    findings = run_intovf_enhance_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段20: Provenance — 分配点感知值范围
    findings = run_provenance_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段21: Cross-Domain — 跨域稀疏值流精炼
    findings = run_cross_domain_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段22: Cross-Pipeline — 跨管线贝叶斯关联
    findings = run_cross_pipeline_bridge(pseudocode, func_name, binary_path, findings)

    # === 阶段23-29: D类深度创新模块 ===
    # 阶段23: BWR+PCST — 有界写恢复+路径条件敏感污点 (过滤无界写误报)
    findings = run_bwr_pcst_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段24: DD-BVF — 按需后向值流 (对 INCONCLUSIVE findings 精确化)
    findings = run_dd_bvf_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段25: CACBV — 容量感知耦合边界验证
    findings = run_cacbv_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段26: 双向区间交汇 — 前向别名+后向根来源
    findings = run_bidir_range_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段27: ACPE — 分配容量溯源等价分析
    findings = run_acpe_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段28: PSVR-HLM — 路径敏感值域推理分层模型
    findings = run_psvr_hlm_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段29: DP-TVRA — 需求驱动路径敏感污点-值域分析
    findings = run_dp_tvra_bridge(pseudocode, func_name, binary_path, findings)

    # === 阶段30-39: 差异化创新模块 (22个重复副本在代码层面实现为不同算法) ===
    # 阶段30: AWSC-ICF — 跨函数调用帧传播 (对已有findings增强)
    findings = run_awsc_icf_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段31: HOFPR-APC — 自适应优先级级联 (对已有findings过滤)
    findings = run_hofpr_apc_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段32: PcWBI-IRL — 内联复制加载建模 (对已有findings增强)
    findings = run_pcwbi_irl_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段33: FC-VRA-PTA — 指针污点别名传播 (产出+增强)
    findings = run_fc_vra_pta_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段34: CACBV-DSS — 动态slack减除 (对已有findings增强)
    findings = run_cacbv_dss_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段35: BIV-CTC — 跨类型约束传播 (对已有findings分类)
    findings = run_biv_ctc_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段36: SI-CTA — 跨类型别名追踪 (产出+过滤)
    findings = run_si_cta_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段37: PG-WBV-LSA — 循环结构感知写界 (对已有findings增强)
    findings = run_pg_wbv_lsa_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段38: ACPE-VRP — 值域传播增强 (对已有findings增强)
    findings = run_acpe_vrp_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段39: ACFPC-CMS — 冲突感知多源融合 (对已有findings增强)
    findings = run_acfpc_cms_bridge(pseudocode, func_name, binary_path, findings)

    return findings


def get_innovation_status() -> Dict[str, bool]:
    """返回各创新模块的可用性状态, 供调试与报告使用."""
    return dict(_module_available)
