"""
创新模块桥接层 — 将 106 个创新模块统一接入 core/pipeline.py 主链路的 rule 检测段.

各模块原始接口异构 (输入有伪代码/IR/C源码/二进制路径, 输出有dict/dataclass),
本层做签名归一化: (pseudocode, func_name, binary_path) → List[dict] findings.
每个模块的适配函数:
  - 将 pipeline 的 pseudocode 转为模块所需输入格式
  - 调用模块主入口
  - 将模块返回值转为 pipeline统一的 dict finding 格式
  - 任何模块异常都被捕获, 不影响主链路运行

调用顺序 (106个创新模块):
  HOFPR → HFP → ACFPC → DDSSC → AWSC → CJ-BVF → CJ-PCBVF →
  GAPSBV → GASRI → UAF-HOIG → UAF-Enhanced → UAF-Lifecycle →
  Double-Free → UAF-Lifetime-Tracker → Buffer-Underflow → Off-by-One →
  Uninitialized → FMTPROV → Int-Overflow-Enhance → Provenance →
  Cross-Domain → Cross-Pipeline →
  BWR+PCST → DD-BVF → CACBV → 双向区间交汇 → ACPE → PSVR-HLM → DP-TVRA →
  AWSC-ICF → HOFPR-APC → PcWBI-IRL → FC-VRA-PTA → CACBV-DSS →
  BIV-CTC → SI-CTA → PG-WBV-LSA → ACPE-VRP → ACFPC-CMS →
  PCFV → TOVS → MIVR → FSTP → INT-SHIFT → SHIELD → INT-RANGE →
  DRIFT → FMT-SPEC → PcWBI原版 → FC-VRA原版 → CACBV-DSS原版 →
  轻量符号+4-Filter → BWR原版 → PG-WBV原版 →
  RW-CallCtxSaturation → RW-LivenessRoleTemplate → RW-JccPolarityMap →
  RW-SpecDangerProfile → RW-CorrelatedWrapCheck → RW-DomFrontierWitness →
  RW-SevenStageFanout → RW-ScaledIndexLinear → RW-FreedAliasEpoch →
  RW-RetAddrChainStitch → RW-EvalHarnessReplica → RW-TaintSourceGrading →
  RW-PtrUnionClosure → RW-RootIdentityKey → RW-SymbolicDiffSign →
  RW-HeapStackGlobalTri → RW-ChainEquivHash → RW-ContractPreserveFold →
  RW-DemandTriggerBudget → RW-MinChunkGeometry → RW-RecoverySoundnessGate →
  RW-RdataConstRegion → RW-GuardAliasTransitive → RW-WalkStrideModel →
  RW-UseDerefLattice → RW-ImmPropAbsorb → RW-CallConvDuality →
  RW-WrapperGraphMatch → RW-TwoVarDiffBound → RW-ExitDominanceCheck →
  RW-CrossTypeEvidencePool → RW-ColorClassQuad → RW-WidenThreshold →
  RW-FourLevelAdjudicator → RW-ProvenanceOctagon → RW-SevenDimWeighted →
  RW-AbiAutoDetect → RW-ReductionRateAudit → RW-GuardOpEnum →
  RW-ThreePathDisjoint → RW-StridedInterval3 → RW-DeadStoreElimTolerant →
  RW-InlineCopyBind → RW-FourVerdictScale → RW-AffineMeetDomain →
  RW-DeltaIntervalEval → RW-WriteSideFirst → RW-ChainIdCrossFunc →
  RW-HeapWriteOperandCap → RW-IrIntervalBacktrack →
  RW-FiveModalDSTheory → RW-KarrAffineDiff

前7模块聚焦堆溢出; 8-17扩展至UAF/DF/underflow/uninit等全类型; 18-22做误报削减与跨管线聚合;
23-29为D类深度创新补全, 覆盖有界写恢复/后向值流/容量耦合/双向区间/溯源等价/路径敏感分层/需求驱动污点;
30-39为差异化创新模块, 将22个重复副本在代码层面实现为不同算法;
40-53为A类原版模块接入, 14个独立完整模块按真实API接入管线端到端可跑通;
54为PG-WBV原版(giva)接入, 补齐A类最后一个未接入的独立创新点;
55-106为RW文献综述代码化模块, 52条Related Work条目逐一转化为
独立代码创新并接入管线 (告警注入/温和降权/消费替换/纯审计四类策略).
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
    """BWR+PCST 桥接: 双引擎协同的有界写验证.

    BWR 半边: 对已有堆溢出findings中涉及无界写入函数
    (strcpy/strcat/sprintf/gets)的告警, 恢复写尺寸上界做安全/溢出判定.
    将伪代码转为 x86-64 汇编指令序列, 变量映射到 callee-saved 寄存器,
    使 BWR 的 _resolve_src 能正确做反向 def-use 追踪,
    _compare 能通过 alloc_tracker._ptr_to_alloc 找到分配信息.

    PCST 半边: 按调用点参数语义表 (Per-Call Semantics Table) 对
    sized 写调用 (memcpy/read/snprintf/fread等) 做 (dst,size) 角色修正
    与分配配对判定 — 修正旧统一规则 dst恒index0/size恒index2 的
    系统性错位 (read的fd被当缓冲、snprintf的fmt指针被当size、
    fread乘积因子丢失), 判定结果以 pcst_verdict 三值标注.
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
        from analysis.pcst_impl import (
            pcst_scan, pcst_legacy_report,
            is_unsized_write as pcst_is_unsized, is_write_func)
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

        # ---- PCST 半边: 按调用点参数语义表对 sized 写调用做角色修正与配对判定 ----
        # 与 BWR 分工: BWR 管无界写 (strcpy等, 写量=源长), PCST 管 sized 写
        # (memcpy/read/snprintf/fread等, 写量=实参) — 修正旧规则
        # dst恒index0/size恒index2 的系统性错位.
        pcst_findings, pcst_stats = pcst_scan(pseudocode or '')
        pcst_corrections = pcst_legacy_report(pseudocode or '')
        # dst 原始实参 + 归一化基名双键索引, 提高配对命中率
        pcst_by_dst: Dict[str, dict] = {}
        for pf in pcst_findings:
            dst_key = pf.get('dst', '')
            pcst_by_dst.setdefault(dst_key, pf)
            base_key = _norm_var_name(dst_key)
            if base_key and base_key not in pcst_by_dst:
                pcst_by_dst[base_key] = pf

        # 语义表修正统计: 供日志审计, 不改变返回值
        logger.debug(
            'BWR+PCST stage 23: pcst_scan write_calls=%d, '
            '语义修正 %d 处, 无界写移交BWR=%d',
            pcst_stats.get('write_calls', 0), len(pcst_corrections),
            pcst_stats.get('unsized_writes_delegated_to_bwr', 0))

        # 对已有 findings 做 BWR + PCST 双重判定
        filtered = []
        for f in heap_findings:
            write_func = f.get('write_func', '')

            # PCST 优先处理 sized 写: 用语义表修正后的 (dst,size) 复核告警
            if write_func and is_write_func(write_func) \
                    and not pcst_is_unsized(write_func):
                # 候选键: finding 的缓冲变量及归一化形式
                pf = None
                for key in (f.get('write_var', ''), f.get('alloc_var', ''),
                            f.get('dst', ''), f.get('write_dst', '')):
                    if not key:
                        continue
                    pf = pcst_by_dst.get(key)
                    if pf is None:
                        pf = pcst_by_dst.get(_norm_var_name(key))
                    if pf is not None:
                        break
                if pf is None:
                    # 变量名未直接命中时按 write_func 兜底: 旧规则若错取了
                    # 参数 (如 read 的 fd), PCST 修正后的 dst 才是真实缓冲;
                    # 仅当该函数调用点唯一时采用, 避免同函数多点误配
                    func_matches = [c for c in pcst_findings
                                    if c.get('write_func') == write_func]
                    if len(func_matches) == 1:
                        pf = func_matches[0]
                if pf is not None:
                    verdict_kind = pf.get('verdict', '')
                    if verdict_kind == 'safe':
                        # 双条件守卫: PCST 对齐判定 safe 且写量上界不超过
                        # 分配请求量才过滤. usable 含 ptmalloc2 对齐余量,
                        # 仅凭 usable 过滤会把 "写量超出请求但未溢出 chunk"
                        # 的真实越界告警误杀, 与基础检测器的请求量基准
                        # 保持同一尺度.
                        bounds = pf.get('write_bounds') or [0.0, None]
                        alloc_req = pf.get('alloc_request')
                        whi = bounds[1] if len(bounds) > 1 else None
                        if (alloc_req is not None and whi is not None
                                and whi != float('inf')
                                and whi <= alloc_req):
                            f['pcst_verdict'] = 'safe'
                            f['pcst_reason'] = pf.get('reason', '')
                            continue  # 写量未超出请求范围 → 过滤
                        f['pcst_verdict'] = 'safe_within_chunk'
                        f['pcst_reason'] = (
                            '写量未超出对齐后chunk可用空间, 但超出分配'
                            '请求, 保守保留: ' + pf.get('reason', ''))
                    else:
                        f['pcst_verdict'] = verdict_kind
                        f['pcst_reason'] = pf.get('reason', '')
                        if verdict_kind == 'overflow':
                            f['pcst_overflow_bytes'] = pf.get(
                                'overflow_bytes', 0)
                        if verdict_kind in ('overflow', 'possible',
                                            'suspected'):
                            boost = (0.15 if verdict_kind == 'overflow'
                                     else 0.05)
                            f['confidence'] = min(
                                1.0,
                                (f.get('confidence', 0.5) or 0.5) + boost)
                # pf 为 None: PCST 无配对信息, 保留 finding 交由后续阶段

            # BWR 处理无界写
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


# -- A-1: PCFV (指针流约束验证完整管线, 反汇编级) --
def run_pcfv_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """PCFV 桥接: 反汇编→逐函数访问提取→守卫/常量/padding证明→五值判定.

    与已有 AWSC/GASRI (伪代码正则守卫) 的区别:
      PCFV 在真实汇编上做指令级追踪, Verdict 五值而非三值,
      SAFE_FILTERED 需"证明安全+过滤依据充分"双条件.
    有 binary_path 时反汇编真实二进制; 无二进制时从伪代码
    合成汇编供 AccessExtractor 提取访问点.
    """
    if not _check_module('pcfv', lambda: __import__(
            'modules.vuln.src.heap.pcfv.pipeline',
            fromlist=['analyze_heap_pcfv'])):
        return existing_findings

    try:
        import os
        report = None
        # 优先真实二进制
        if binary_path and os.path.isfile(binary_path):
            from modules.vuln.src.heap.pcfv.pipeline import analyze_heap_pcfv
            report = analyze_heap_pcfv(binary_path, timeout_s=10)
        if report is None or report.error:
            # 无二进制: 从伪代码合成 objdump 风格汇编文本
            asm_text = _pseudocode_to_pcfv_asm(pseudocode)
            report = _run_pcfv_on_asm_text(asm_text, binary_path or 'pseudo')
        if report is None:
            return existing_findings

        new_findings = []
        for fv in report.verdicts:
            if fv.verdict is None:
                continue
            vname = fv.verdict.name
            if vname == 'CONFIRMED':
                new_findings.append({
                    'type': 'heap-overflow', 'function': func_name,
                    'severity': 'High', 'cwe': 'CWE-122',
                    'confidence': 0.85,
                    'description': f'PCFV CONFIRMED: fn={fv.function} '
                                   f'addr=0x{fv.insn_addr:x} kind={fv.access_kind} '
                                   f'rule={fv.evidences[0].rule.name if fv.evidences else "NONE"}',
                    'verdict': 'DEFINITE', 'source': 'pcfv'})
            elif vname == 'LIKELY':
                new_findings.append({
                    'type': 'heap-overflow', 'function': func_name,
                    'severity': 'Medium', 'cwe': 'CWE-122',
                    'confidence': 0.55,
                    'description': f'PCFV LIKELY: fn={fv.function} '
                                   f'addr=0x{fv.insn_addr:x} kind={fv.access_kind}',
                    'verdict': 'POSSIBLE', 'source': 'pcfv'})
        return existing_findings + new_findings
    except Exception as e:
        logger.debug('PCFV bridge failed: %s', e)
        return existing_findings


def _pseudocode_to_pcfv_asm(pseudocode: str) -> str:
    """将伪代码转为 objdump -d -M intel 风格文本, 供 PCFV 函数解析.

    格式: 地址+十六进制字节+指令, 指令必须形如 "  addr:\tbytes\tmnemonic operands".
    """
    import re
    lines = []
    addr = 0x401000
    _var_reg = {}
    _regs = ['rbx', 'r12', 'r13', 'r14', 'r15', 'rbp']
    reg_seq = [0]

    def get_reg(v: str) -> str:
        if v not in _var_reg:
            if reg_seq[0] < len(_regs):
                _var_reg[v] = _regs[reg_seq[0]]
            else:
                _var_reg[v] = f'r{reg_seq[0]}'
            reg_seq[0] += 1
        return _var_reg[v]

    def add_ins(raw: str) -> None:
        nonlocal addr
        lines.append(f'  {addr:x}:\t48 8b 00    \t{raw}')
        addr += 4

    for line in (pseudocode or '').split('\n'):
        line = line.strip()
        if not line or line.startswith('//') or line.startswith('#'):
            continue
        m = re.match(
            r'(\w+)\s*=\s*malloc\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*\)', line)
        if m:
            var, size = m.group(1), m.group(2)
            add_ins(f'mov edi, {int(size, 0)}')
            add_ins('call malloc')
            add_ins(f'mov {get_reg(var)}, rax')
            continue
        m = re.match(r'(memcpy|memmove|memset|strcpy|strcat|sprintf)\s*\((.*)\)\s*;?\s*$',
                     line)
        if m:
            func, argstr = m.group(1), m.group(2)
            args = [a.strip() for a in argstr.split(',')]
            if func in ('memcpy', 'memmove'):
                if len(args) >= 3:
                    add_ins(f'mov rdi, {get_reg(args[0])}')
                    add_ins(f'mov rsi, {get_reg(args[1])}')
                    add_ins(f'mov rdx, {args[2] if args[2].isdigit() or "0x" in args[2] else get_reg(args[2])}')
                    add_ins(f'call {func}')
            elif func == 'memset':
                if len(args) >= 3:
                    add_ins(f'mov rdi, {get_reg(args[0])}')
                    add_ins(f'mov rsi, {args[1]}')
                    add_ins(f'mov rdx, {args[2] if args[2].isdigit() else get_reg(args[2])}')
                    add_ins('call memset')
            else:
                if len(args) >= 2:
                    add_ins(f'mov rdi, {get_reg(args[0])}')
                    add_ins(f'mov rsi, {get_reg(args[1])}')
                    add_ins(f'call {func}')
            continue
        m = re.match(r'free\s*\(\s*(\w+)\s*\)', line)
        if m:
            add_ins(f'mov rdi, {get_reg(m.group(1))}')
            add_ins('call free')
            continue
        m = re.match(
            r'\*\s*\(*\s*(\w+)\s*(?:\+\s*(\d+|0x[0-9a-fA-F]+))?\s*\)*\s*=\s*(\w+|\d+|0x[0-9a-fA-F]+)',
            line)
        if m:
            ptr_var, off, val = m.group(1), m.group(2) or '0', m.group(3)
            add_ins(f'mov {get_reg(ptr_var)}, {get_reg(ptr_var)}')
            add_ins(
                f'mov DWORD PTR [{get_reg(ptr_var)}+{int(off, 0)}], '
                f'{val if val.isdigit() or "0x" in val else get_reg(val)}')
            continue
    return '\n'.join(lines)


def _run_pcfv_on_asm_text(asm_text: str, sample_id: str):
    """在合成汇编文本上执行 PCFV 完整管线 (复用管线内部函数解析器)."""
    if not asm_text:
        return None
    try:
        import sys as _sys
        import os as _os
        _pcfv_dir = _os.path.join(
            _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
            'modules', 'vuln', 'src', 'heap')
        if _pcfv_dir not in _sys.path:
            _sys.path.insert(0, _pcfv_dir)
        from pcfv.pipeline import _parse_functions, PCFVReport, PCFVEngine
        from pcfv.access_extractor import AccessExtractor
        from pcfv.loop_bound import LoopBoundExtractor
        from pcfv.types import Verdict
        import time
        t0 = time.time()
        report = PCFVReport(binary_path=sample_id)
        functions = _parse_functions(asm_text)
        report.n_functions = len(functions)
        engine = PCFVEngine(None)
        for fn_name, insns in functions:
            if len(insns) < 3:
                continue
            extractor = AccessExtractor(fn_name, insns)
            loop_bx = LoopBoundExtractor(insns, extractor.tracer)
            mallocs = extractor.mallocs
            from pcfv.guard_dominance import GuardExtractor
            guard_extractor = GuardExtractor(insns)
            insn_index = {i.addr: i for i in insns}
            for acc in extractor.accesses:
                if acc['kind'] == 'store':
                    loop = loop_bx.is_in_loop(acc['addr'])
                    if loop is not None:
                        acc['kind'] = 'loop_store'
                        acc['loop_iters'] = loop['iters']
                        acc['loop_stride'] = loop['stride']
                fv = engine.evaluate_access(
                    acc, mallocs, insns, guard_extractor, insn_index)
                fv.sample_id = sample_id
                report.verdicts.append(fv)
                if fv.verdict == Verdict.SAFE_FILTERED:
                    report.filtered_fp += 1
                elif fv.verdict == Verdict.CONFIRMED:
                    report.confirmed += 1
                elif fv.verdict == Verdict.LIKELY:
                    report.likely += 1
                else:
                    report.uncertain += 1
        report.raw_findings = len(report.verdicts)
        total = max(1, report.raw_findings)
        report.fp_reduction_pct = round(report.filtered_fp / total * 100, 1)
        report.elapsed_sec = round(time.time() - t0, 3)
        return report
    except Exception:
        return None


# -- A-2: TOVS (时间序验证UAF, 反汇编级) --
def run_tovs_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """TOVS 桥接: free-use 候选对提取 + 分支敏感时间序验证.

    与已有 UAF-Lifecycle (正则状态机) 的区别:
      TOVS 在真实汇编上验证 free-use 支配关系与分支互斥性,
      三值判定 CONFIRMED/POSSIBLE/SAFE_FILTERED.
    """
    if not _check_module('tovs', lambda: __import__(
            'modules.vuln.src.heap.uaf_tovs.pipeline',
            fromlist=['analyze_uaf_tovs'])):
        return existing_findings

    try:
        import os
        report = None
        if binary_path and os.path.isfile(binary_path):
            from modules.vuln.src.heap.uaf_tovs.pipeline import analyze_uaf_tovs
            report = analyze_uaf_tovs(binary_path, timeout_s=10)
        if report is None or report.error:
            asm_text = _pseudocode_to_pcfv_asm(pseudocode)
            report = _run_tovs_on_asm_text(asm_text, binary_path or 'pseudo')
        if report is None:
            return existing_findings

        new_findings = []
        for pv in report.verdicts:
            if pv.verdict is None:
                continue
            vname = pv.verdict.name
            if vname == 'CONFIRMED':
                new_findings.append({
                    'type': 'use-after-free', 'function': func_name,
                    'severity': 'High', 'cwe': 'CWE-416',
                    'confidence': 0.85,
                    'description': f'TOVS CONFIRMED: fn={pv.pair.function} '
                                   f'free@0x{pv.pair.free_addr:x} use@0x{pv.pair.use_addr:x} '
                                   f'use_type={pv.pair.use_type}',
                    'verdict': 'DEFINITE', 'source': 'tovs'})
            elif vname == 'POSSIBLE':
                new_findings.append({
                    'type': 'use-after-free', 'function': func_name,
                    'severity': 'Medium', 'cwe': 'CWE-416',
                    'confidence': 0.50,
                    'description': f'TOVS POSSIBLE: fn={pv.pair.function} '
                                   f'free@0x{pv.pair.free_addr:x} use@0x{pv.pair.use_addr:x}',
                    'verdict': 'POSSIBLE', 'source': 'tovs'})
        return existing_findings + new_findings
    except Exception as e:
        logger.debug('TOVS bridge failed: %s', e)
        return existing_findings


def _run_tovs_on_asm_text(asm_text: str, sample_id: str):
    """在合成汇编文本上执行 TOVS (复用管线内部解析与验证引擎)."""
    if not asm_text:
        return None
    try:
        import sys as _sys
        import os as _os
        _tovs_dir = _os.path.join(
            _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
            'modules', 'vuln', 'src', 'heap')
        if _tovs_dir not in _sys.path:
            _sys.path.insert(0, _tovs_dir)
        from uaf_tovs.pipeline import _parse_functions, TovsReport
        from uaf_tovs.free_use_pairs import extract_pairs
        from uaf_tovs.cross_fn_events import extract_cross_fn_pairs
        from uaf_tovs.engine import TovsEngine
        from uaf_tovs.types import TovsVerdict
        import time
        t0 = time.time()
        report = TovsReport(binary_path=sample_id)
        functions = _parse_functions(asm_text)
        report.n_functions = len(functions)
        malloc_summary = {}
        for fn_name, insns in functions:
            if len(insns) < 3:
                continue
            fa = None
            try:
                from uaf_tovs.pipeline import _analyze_function
                fa = _analyze_function(fn_name, insns)
            except Exception:
                fa = None
            if fa is None:
                continue
            pairs = extract_pairs(fa, fn_name)
            pairs.extend(extract_cross_fn_pairs(insns, fn_name, malloc_summary))
            if not pairs:
                continue
            tracer = None
            try:
                from uaf_tovs.pipeline import _make_tracer
                tracer = _make_tracer(insns)
            except Exception:
                tracer = None
            if tracer is None:
                continue
            engine = TovsEngine(insns, tracer)
            for pair in pairs:
                pv = engine.evaluate(pair, sample_id)
                report.verdicts.append(pv)
                report.n_pairs += 1
                if pv.verdict == TovsVerdict.CONFIRMED:
                    report.confirmed += 1
                elif pv.verdict == TovsVerdict.POSSIBLE:
                    report.possible += 1
                else:
                    report.filtered += 1
        report.elapsed_ms = round((time.time() - t0) * 1000, 1)
        return report
    except Exception:
        return None


# -- A-3: MIVR (多变量区间约束传播证明) --
def run_mivr_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """MIVR 桥接: alloc-write 对的三层路径敏感约束传播证明.

    与已有 GAPSBV (7维仿射) 的区别:
      MIVR 专注守卫→写入约束传播的传递性解析,
      L1 守卫硬证明 / L2 仿射传递 / L3 常量偏移语义, 逐级降级.
    仅当证明 SAFE 时过滤对应 heap findings.
    """
    if not _check_module('mivr', lambda: __import__(
            'analysis.mivr_pipeline',
            fromlist=['detect_heap_overflow_mivr'])):
        return existing_findings

    try:
        from analysis.mivr_pipeline import detect_heap_overflow_mivr
        verdict, conf, proofs = detect_heap_overflow_mivr(pseudocode)
        if verdict == 'SAFE' and conf >= 0.70:
            # MIVR 硬证明安全 → 过滤 heap findings
            heap = [f for f in existing_findings
                    if 'heap' in f.get('type', '').lower()]
            if heap:
                for f in heap:
                    f['mivr_safe'] = True
                    f['mivr_reason'] = proofs[0].proof_detail[:120] if proofs else ''
                return [f for f in existing_findings
                        if 'heap' not in f.get('type', '').lower()]
        elif verdict == 'OVERFLOW' and conf >= 0.60:
            heap = [f for f in existing_findings
                    if 'heap' in f.get('type', '').lower()]
            for f in heap:
                f['mivr_overflow'] = True
                f['mivr_conf'] = conf
        return existing_findings
    except Exception as e:
        logger.debug('MIVR bridge failed: %s', e)
        return existing_findings


# -- A-4: FSTP (格式说明符语义污点传播) --
def run_fstp_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """FSTP 桥接: 5级语义分类 (CLEAN→USER_WRITE) + 污点传播验证格式串告警.

    与已有 FMTPROV (常量折叠) 的区别:
      FSTP 区分语义类别: 用户输入+清理→SAFE, %n→写风险, %s→泄露.
    """
    if not _check_module('fstp', lambda: __import__(
            'analysis.fmt_semantic_taint',
            fromlist=['FmtSemanticTaintPropagator'])):
        return existing_findings

    try:
        from analysis.fmt_semantic_taint import (
            FmtSemanticTaintPropagator, SemClass)
        prop = FmtSemanticTaintPropagator()
        verdicts, stats = prop.analyze(pseudocode)
        if not verdicts:
            return existing_findings

        new_findings = []
        for v in verdicts:
            if v.sem_class == SemClass.SEM_USER_WRITE:
                new_findings.append({
                    'type': 'format-string', 'function': func_name,
                    'severity': 'High', 'cwe': 'CWE-134',
                    'confidence': v.confidence,
                    'description': f'FSTP SEM_USER_WRITE: line={v.call_line} '
                                   f'func={v.func_name} arg={v.fmt_arg} — {v.reason}',
                    'verdict': 'DEFINITE' if v.is_cwe134 else 'POSSIBLE',
                    'source': 'fstp'})
            elif v.sem_class == SemClass.SEM_USER_READ:
                new_findings.append({
                    'type': 'format-string', 'function': func_name,
                    'severity': 'Medium', 'cwe': 'CWE-134',
                    'confidence': v.confidence,
                    'description': f'FSTP SEM_USER_READ: line={v.call_line} '
                                   f'func={v.func_name} — {v.reason}',
                    'verdict': 'POSSIBLE', 'source': 'fstp'})

        # 已有 format findings 中被 FSTP 证明清理过的 → 过滤
        filtered = []
        for f in existing_findings:
            ftype = f.get('type', '').lower()
            if ('format' in ftype or 'fmt' in ftype) and f.get('fstp_clean'):
                continue
            filtered.append(f)
        return filtered + new_findings
    except Exception as e:
        logger.debug('FSTP bridge failed: %s', e)
        return existing_findings


# -- A-5: INT-SHIFT (整数溢出8模式汇编检测) --
def run_int_shift_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """INT-SHIFT 桥接: 8模式 x86-64 汇编整数溢出检测.

    与已有 Int-Overflow-Enhance (伪代码 L4-L6) 的区别:
      INT-SHIFT 在汇编指令级检测 movabs大立即数/截断/移位/16bit回绕等.
    从伪代码合成汇编后运行真实检测器.
    """
    if not _check_module('int_shift', lambda: __import__(
            'analysis.int_shift_impl',
            fromlist=['IntOverflowDetector'])):
        return existing_findings

    try:
        from analysis.int_shift_impl import IntOverflowDetector
        asm_lines = _pseudocode_to_intx_asm(pseudocode)
        if not asm_lines:
            return existing_findings
        detector = IntOverflowDetector()
        findings = detector.analyze(asm_lines, function_name=func_name)
        new_findings = []
        for f in findings:
            new_findings.append({
                'type': 'integer-overflow', 'function': func_name,
                'severity': 'High' if f.confidence >= 0.7 else 'Medium',
                'cwe': 'CWE-190',
                'confidence': f.confidence,
                'description': f'INT-SHIFT {f.overflow_type.name}: '
                               f'{f.description} size_source={f.size_source}',
                'verdict': 'POSSIBLE', 'source': 'int_shift'})
        return existing_findings + new_findings
    except Exception as e:
        logger.debug('INT-SHIFT bridge failed: %s', e)
        return existing_findings


def _pseudocode_to_intx_asm(pseudocode: str) -> List[str]:
    """将伪代码转为 INT-SHIFT 检测所需 x86-64 汇编行 (objdump 风格)."""
    import re
    lines = []
    addr = 0x401000

    def add(raw: str) -> None:
        nonlocal addr
        lines.append(f'  {addr:x}:\t{raw}')
        addr += 4

    for line in (pseudocode or '').split('\n'):
        line = line.strip()
        if not line or line.startswith('//'):
            continue
        # malloc(N) → mov ecx, N; call malloc
        m = re.match(
            r'(\w+)\s*=\s*(?:\(?\w+\*?\)?)?\s*malloc\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*\)',
            line)
        if m:
            add(f'mov ecx, {int(m.group(2), 0)}')
            add('call malloc')
            continue
        # malloc(var) → mov ecx, [rbp-0x8]; call malloc
        m = re.match(
            r'(\w+)\s*=\s*(?:\(?\w+\*?\)?)?\s*malloc\s*\(\s*(\w+)\s*\)', line)
        if m and not m.group(2).isdigit():
            add('mov eax, dword ptr [rbp-0x8]')
            add('mov ecx, eax')
            add('call malloc')
            continue
        # n * K → imul
        m = re.match(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\d+|0x[0-9a-fA-F]+)', line)
        if m:
            add(f'mov eax, dword ptr [rbp-0x8]')
            add(f'imul eax, eax, {int(m.group(3), 0)}')
            add('mov dword ptr [rbp-0x8], eax')
            continue
        # n << K → shl
        m = re.match(r'(\w+)\s*=\s*(\w+)\s*<<\s*(\d+)', line)
        if m:
            add('mov eax, dword ptr [rbp-0x8]')
            add(f'shl eax, {m.group(3)}')
            add('mov dword ptr [rbp-0x8], eax')
            add('cdqe')
            continue
        # memcpy(d, s, n*K) → imul + memcpy
        m = re.match(
            r'memcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\*\s*(\d+)\s*\)',
            line)
        if m:
            add('mov eax, dword ptr [rbp-0x8]')
            add(f'imul eax, eax, {m.group(4)}')
            add('mov rdx, eax')
            add(f'mov rdi, {m.group(1)}')
            add(f'mov rsi, {m.group(2)}')
            add('call memcpy')
            continue
        # memcpy(d, s, n)
        m = re.match(r'memcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)', line)
        if m:
            add(f'mov rdi, {m.group(1)}')
            for call_reg, var in (('rsi', m.group(2)), ('rdx', m.group(3))):
                if var.isdigit() or var.startswith('0x'):
                    add(f'mov {call_reg}, {var}')
                else:
                    add(f'mov {call_reg}, {var}')
            add('call memcpy')
            continue
        # n += C / n = n + C
        m = re.match(r'(\w+)\s*(?:\+=|=\s*\1\s*\+)\s*(\d+|0x[0-9a-fA-F]+)', line)
        if m:
            add('mov eax, dword ptr [rbp-0x8]')
            add(f'add eax, {int(m.group(2), 0)}')
            add('mov dword ptr [rbp-0x8], eax')
            continue
    return lines


# -- A-6: SHIELD (三引擎堆溢出误报消减) --
def run_shield_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """SHIELD 桥接: 指针溯源→不相交证明→尺寸约束关联 三引擎串联过滤.

    与已有 BWR+PCST (伪代码合成 BWR 调用) 的区别:
      SHIELD 的三引擎在指令序列上做全局 provenance 分析,
      任一引擎证明安全即滤除. findings 需带 insn_addr/access_offset.
    """
    if not _check_module('shield', lambda: __import__(
            'modules.vuln.src.heap.shield_orchestrator',
            fromlist=['ShieldOrchestrator'])):
        return existing_findings

    try:
        from modules.vuln.src.heap.shield_orchestrator import ShieldOrchestrator
        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        if not heap_findings:
            return existing_findings

        # 用 PCFV 同款汇编合成器产指令列表 (SHIELD 期望 List[str])
        asm_lines = _pseudocode_to_intx_asm(pseudocode)
        if not asm_lines:
            return existing_findings

        # findings 需转成 SHIELD 期望的 dict 字段
        shield_in = []
        for i, f in enumerate(heap_findings):
            alloc_size = f.get('alloc_size', 0)
            if not isinstance(alloc_size, int) or alloc_size <= 0:
                alloc_size = 64
            shield_in.append({
                'insn_addr': f.get('insn_addr', 0x401000 + i * 4),
                'alloc_site': f.get('alloc_site', 0),
                'access_offset': f.get('access_offset',
                                        f.get('overflow_bytes', 0)),
                'access_size': f.get('access_size', 4),
                'alloc_size_requested': alloc_size,
                'description': f.get('description', f'finding_{i}'),
            })

        orch = ShieldOrchestrator()
        report = orch.analyze(asm_lines, shield_in)
        kept = []
        for f, v in zip(heap_findings, report.verdicts):
            if v.is_safe:
                f['shield_filtered'] = True
                f['shield_engine'] = v.engine
                f['shield_reason'] = v.reasoning[:120]
                continue  # 三引擎证明安全 → 过滤
            f.setdefault('shield_confirmed', True)
            kept.append(f)
        return non_heap + kept
    except Exception as e:
        logger.debug('SHIELD bridge failed: %s', e)
        return existing_findings


def _probe_int_range() -> None:
    """INT-RANGE 探测: 注入 BinMind 根到 sys.path 使 deemo namespace package 可解析.

    int_range_analyzer 属 modules.vuln.detection.src 包, 该包 __init__
    以 deemo.* 绝对路径导入 logger/config 等. deemo 目录无 __init__.py,
    需 BinMind 根在 sys.path 才能作为 namespace package 被解析.
    """
    import os, sys
    _project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _binmind_root = os.path.dirname(_project_root)
    if _binmind_root not in sys.path:
        sys.path.insert(0, _binmind_root)
    __import__(
        'modules.vuln.detection.src.int_overflow.int_range_analyzer',
        fromlist=['IntegerRangeAnalyzer'])


def _probe_fc_vra_orig() -> None:
    """FC-VRA 原版探测: 按拓扑序包加载依赖 + 裸名别名注册.

    fc_vra_detector 的依赖链混用相对导入与裸名导入
    (如 from size_expr_evaluator import ... 和 from .value_range_analyzer import ...),
    裸名导入在 deemo/ 作为 sys.path[0] 时无法解析. 这里以包形式
    加载全部依赖并注册裸名别名, 使两种导入风格都能命中.
    同时用导入版 detect_direct_writes 覆盖 fc_vra_detector 内
    L206 的本地遮蔽定义 (本地版缺少 get_allocator_model/extract_heap_ptrs
    等符号导入, 运行时必 NameError).
    """
    import importlib, sys
    _info_pkg = 'modules.info.analysis'
    _bare_deps = [
        'value_range_analyzer', 'pointer_tracker', 'heap_layout_model',
        'path_feasibility_check', 'size_expr_evaluator',
        'flow_pair_generator', 'size_equivalence',
        'allocator_slack', 'guard_dominance', 'taint_confirm',
        'heap_overflow_v2', 'fc_size_proof', 'fc_direct_writes',
    ]
    for _n in _bare_deps:
        _m = importlib.import_module(f'{_info_pkg}.{_n}')
        sys.modules.setdefault(_n, _m)
    _fcd = importlib.import_module(f'{_info_pkg}.fc_vra_detector')
    from modules.info.analysis.fc_direct_writes import (
        detect_direct_writes as _imported_ddw)
    _fcd.detect_direct_writes = _imported_ddw
    __import__('modules.info.analysis.fc_vra_detector',
               fromlist=['detect_heap_overflow_fcv3'])


# -- A-7: INT-RANGE (整数溢出区间分析器) --
def run_int_range_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """INT-RANGE 桥接: 算术运算位宽约束 + 符号/无符号转换区间分析.

    与 INT-SHIFT (模式匹配) 的区别:
      INT-RANGE 做四角点区间算术 (lo*lo, lo*hi, hi*lo, hi*hi),
      检测 mul/shl/add 的 wrap/truncation/sign_mismatch.
    """
    if not _check_module('int_range', _probe_int_range):
        return existing_findings

    try:
        from modules.vuln.detection.src.int_overflow.int_range_analyzer import (
            IntegerRangeAnalyzer)
        import re
        analyzer = IntegerRangeAnalyzer()
        addr_seq = [0x401000]

        # 从伪代码提取运算并馈入分析器
        for line in (pseudocode or '').split('\n'):
            line = line.strip()
            # n * K (乘法溢出)
            m = re.match(
                r'\w+\s*=\s*(\w+)\s*\*\s*(\d+|0x[0-9a-fA-F]+)\s*$', line)
            if m:
                analyzer.add_operation(
                    insn_addr=addr_seq[0], op='mul', width=32,
                    left_range=(0, 0xFFFFFFFF), right_range=(0, 0xFFFFFFFF))
                addr_seq[0] += 4
                continue
            # n << K (移位)
            m = re.match(r'\w+\s*=\s*(\w+)\s*<<\s*(\d+)\s*$', line)
            if m:
                shift = int(m.group(2))
                analyzer.add_operation(
                    insn_addr=addr_seq[0], op='shl', width=32,
                    left_range=(0, 0xFFFFFFFF), right_range=(shift, shift))
                addr_seq[0] += 4
                continue
            # n += C (加法回绕)
            m = re.match(r'\w+\s*\+=\s*(\d+|0x[0-9a-fA-F]+)\s*$', line)
            if m:
                analyzer.add_operation(
                    insn_addr=addr_seq[0], op='add', width=32,
                    left_range=(0, 0xFFFFFFFF), right_range=(0, 0xFFFFFFFF))
                addr_seq[0] += 4
                continue
            # malloc(n * K) — 溢出结果用于分配
            m = re.match(r'\w+\s*=\s*malloc\s*\(\s*(\w+)\s*\*\s*(\d+)\s*\)',
                         line)
            if m:
                addr_seq[0] += 4
                analyzer.mark_used_in_alloc(insn_addr=addr_seq[0])
                continue
            # malloc(0x...) 大小常量
            m = re.match(r'\w+\s*=\s*malloc\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)',
                         line)
            if m:
                size = int(m.group(1), 0)
                if size > 0xFFFFFFFF:
                    analyzer.add_operation(
                        insn_addr=addr_seq[0], op='mul', width=32,
                        left_range=(size, size), right_range=(1, 1))
                    analyzer.mark_used_in_alloc(insn_addr=addr_seq[0])
                addr_seq[0] += 4
                continue

        candidates = analyzer.analyze_all()
        new_findings = []
        for c in candidates:
            if not c.overflow_possible:
                continue
            new_findings.append({
                'type': 'integer-overflow', 'function': func_name,
                'severity': 'Critical' if c.risk_level == 'critical'
                            else 'High',
                'cwe': 'CWE-190',
                'confidence': 0.85 if c.risk_level == 'critical' else 0.60,
                'description': (
                    f'INT-RANGE {c.overflow_type}: op={c.operation} '
                    f'width={c.operand_width}bit '
                    f'left={c.left_range} right={c.right_range}'
                    + (f' used_in_alloc=1' if c.used_in_alloc else '')),
                'verdict': 'POSSIBLE', 'source': 'int_range'})
        return existing_findings + new_findings
    except Exception as e:
        logger.debug('INT-RANGE bridge failed: %s', e)
        return existing_findings


# -- A-8: DRIFT (对象身份感知UAF检测) --
def run_drift_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """DRIFT 桥接: objdump→对象身份追踪→free-use验证→时间路径验证.

    与已有 UAF-Lifetime-Tracker (着色追踪) 的区别:
      DRIFT 的 ObjIdTracker 做真实汇编对象身份消解,
      消除"不同对象同一寄存器"误报; 无二进制时从伪代码合成汇编.
    """
    if not _check_module('drift', lambda: __import__(
            'modules.vuln.src.uaf.drift_orchestrator',
            fromlist=['analyze_uaf'])):
        return existing_findings

    try:
        import os
        report = None
        if binary_path and os.path.isfile(binary_path):
            from modules.vuln.src.uaf.drift_orchestrator import analyze_uaf
            report = analyze_uaf(binary_path, timeout_s=10)
        if report is None or report.disasm_error:
            asm_lines = _pseudocode_to_intx_asm(pseudocode)
            report = _run_drift_on_asm_lines(asm_lines, binary_path or 'pseudo')
        if report is None:
            return existing_findings

        new_findings = []
        for r in report.findings:
            decision = r.get('decision', '')
            if decision in ('confirmed_uaf', 'likely_uaf'):
                new_findings.append({
                    'type': 'use-after-free', 'function': func_name,
                    'severity': 'High' if decision == 'confirmed_uaf' else 'Medium',
                    'cwe': 'CWE-416',
                    'confidence': r.get('confidence', 0.5),
                    'description': (
                        f'DRIFT {decision}: obj={r.get("obj_id")} '
                        f'free@{r.get("free_line")} use@{r.get("use_line")} '
                        f'phase={r.get("phase")} {r.get("reasoning", "")[:80]}'),
                    'verdict': 'DEFINITE' if decision == 'confirmed_uaf' else 'POSSIBLE',
                    'source': 'drift'})
            elif r.get('double_free'):
                new_findings.append({
                    'type': 'double-free', 'function': func_name,
                    'severity': 'High', 'cwe': 'CWE-415',
                    'confidence': r.get('confidence', 0.7),
                    'description': f'DRIFT double-free: obj={r.get("obj_id")}',
                    'verdict': 'DEFINITE', 'source': 'drift'})
        return existing_findings + new_findings
    except Exception as e:
        logger.debug('DRIFT bridge failed: %s', e)
        return existing_findings


def _run_drift_on_asm_lines(asm_lines: List[str], sample_id: str):
    """在合成汇编上执行 DRIFT 内部管线 (validator+filter+temporal)."""
    if not asm_lines:
        return None
    try:
        import sys as _sys
        import os as _os
        _drift_dir = _os.path.join(
            _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
            'modules', 'vuln', 'src', 'uaf')
        if _drift_dir not in _sys.path:
            _sys.path.insert(0, _drift_dir)
        from free_use_validator import FreeUseValidator, filter_infeasible_paths
        from drift_fp_filter import DriftFPFilter
        from temporal_path_verifier import TemporalPathVerifier
        import time
        t0 = time.time()
        validator = FreeUseValidator()
        validated, tracker = validator.validate(asm_lines)
        validated = filter_infeasible_paths(validated, asm_lines)
        findings_dicts = [v.to_dict() for v in validated]
        fp_filter = DriftFPFilter()
        filter_report = fp_filter.run_pipeline(
            findings_dicts, asm_lines, list(tracker.objects.values()))
        temporal_verifier = TemporalPathVerifier()
        filtered_findings = temporal_verifier.verify(asm_lines, findings_dicts)
        # 组装与 DriftReport 兼容的轻量结构
        class _LiteReport:
            pass
        report = _LiteReport()
        report.findings = []
        for v in validated:
            r = None
            for fr in filter_report.results:
                if (fr.finding.get('use_line') == v.use_line and
                        fr.finding.get('free_line') == v.free_line):
                    r = fr
                    break
            tv_match = next(
                (tf for tf in filtered_findings
                 if tf.get('use_line') == v.use_line and
                 tf.get('free_line') == v.free_line), None)
            decision = r.decision.value if r else 'uncertain'
            if tv_match is None and decision != 'uncertain':
                decision = 'temporal_filtered'
            report.findings.append({
                'obj_id': v.obj_id, 'alloc_func': v.alloc_func,
                'free_line': v.free_line, 'use_line': v.use_line,
                'double_free': v.double_free,
                'confidence': (tv_match.get('confidence', v.confidence)
                               if tv_match else v.confidence),
                'decision': decision,
                'phase': r.decisive_phase.value if r else 'object_identity',
                'reasoning': r.reasoning if r else '',
            })
        report.filtered_fp = filter_report.filtered_fp
        report.elapsed_sec = round(time.time() - t0, 3)
        return report
    except Exception:
        return None


# -- A-9: FMT-SPEC (格式说明符解析器) --
def run_fmt_spec_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """FMT-SPEC 桥接: POSIX 格式说明符解析 → 危险说明符检测.

    与已有 FMTPROV/FSTP 的区别:
      FMT-SPEC 解析完整说明符语法 (flags/width/prec/length/posarg),
      检测 %n 写风险、%s 泄露、%N$pos 任意读, 与语义无关的纯语法层.
    """
    if not _check_module('fmt_spec', lambda: __import__(
            'modules.vuln.src.format.fmt_spec_parser',
            fromlist=['parse_format_specs'])):
        return existing_findings

    try:
        from modules.vuln.src.format.fmt_spec_parser import (
            parse_format_specs, detect_format_danger)
        import re
        new_findings = []
        # 提取伪代码中的字符串字面量 (含 %)
        for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', pseudocode or ''):
            fmt_str = m.group(1)
            if '%' not in fmt_str:
                continue
            specs = parse_format_specs(fmt_str)
            danger = detect_format_danger(fmt_str, specs)
            if danger['risk_level'] == 'CRITICAL':
                new_findings.append({
                    'type': 'format-string', 'function': func_name,
                    'severity': 'High', 'cwe': 'CWE-134',
                    'confidence': 0.90,
                    'description': (
                        f'FMT-SPEC CRITICAL: fmt="{fmt_str[:40]}" '
                        f'dangerous_specs={danger["dangerous_specs"]} '
                        f'args_consumed={danger["args_consumed"]}'),
                    'verdict': 'DEFINITE', 'source': 'fmt_spec'})
            elif danger['risk_level'] == 'HIGH':
                new_findings.append({
                    'type': 'format-string', 'function': func_name,
                    'severity': 'High', 'cwe': 'CWE-134',
                    'confidence': 0.75,
                    'description': (
                        f'FMT-SPEC HIGH: fmt="{fmt_str[:40]}" '
                        f'positional access {danger["dangerous_specs"]}'),
                    'verdict': 'POSSIBLE', 'source': 'fmt_spec'})
            elif danger['risk_level'] == 'MEDIUM':
                new_findings.append({
                    'type': 'format-string', 'function': func_name,
                    'severity': 'Medium', 'cwe': 'CWE-134',
                    'confidence': 0.55,
                    'description': (
                        f'FMT-SPEC MEDIUM: fmt="{fmt_str[:40]}" '
                        f'leak specs ({danger["args_consumed"]} args)'),
                    'verdict': 'POSSIBLE', 'source': 'fmt_spec'})
        return existing_findings + new_findings
    except Exception as e:
        logger.debug('FMT-SPEC bridge failed: %s', e)
        return existing_findings


# -- A-10: PcWBI 原版 (来源约束写界推断) --
def run_pcwbi_orig_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """PcWBI 原版桥接: 五级来源格 CONSTANT<GUARDED<ALLOC_LINKED<INPUT_TAINTED<UNKNOWN.

    与差异化版 PcWBI-IRL (内联复制建模) 的区别:
      原版做真实写界推断三值判定 CONFIRMED/BENIGN/SUSPECTED,
      守卫别名传播走 ProvValue 对象同一性.
    """
    if not _check_module('pcwbi_orig', lambda: __import__(
            'analysis.pcwbi_impl',
            fromlist=['WriteBoundInferer'])):
        return existing_findings

    try:
        from analysis.pcwbi_impl import WriteBoundInferer
        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        if not heap_findings:
            return existing_findings

        # 从伪代码提取守卫约束, 构建 ProvValue 工厂
        import re
        guarded_bounds: Dict[str, int] = {}
        for line in (pseudocode or '').split('\n'):
            m = re.match(
                r'if\s*\(\s*(\w+)\s*[<>=!]+\s*(\d+)\s*\)\s*(\w+)\s*=',
                line)
            if m:
                guarded_bounds.setdefault(m.group(3), int(m.group(2)))
            m = re.match(r'if\s*\(\s*(\w+)\s*>\s*(\d+)\s*\)\s*return', line)
            if m:
                guarded_bounds.setdefault(m.group(1), int(m.group(2)) - 1)
        # 函数参数视为污点来源
        params = set()
        m = re.match(r'\w+\s+\w+\s*\(([^)]*)\)', pseudocode or '')
        if m:
            for p in m.group(1).split(','):
                p = p.strip().split()[-1].strip('*') if p.strip() else ''
                if p and p[0].isalpha():
                    params.add(p)
        tainted = params | set(re.findall(
            r'(\w+)\s*=\s*(?:atoi|recv|read|getenv|fread)\s*\(',
            pseudocode or ''))

        def get_write_prov(write_addr, size_reg):
            from analysis.pcwbi_impl import ProvValue, ProvClass
            if size_reg in guarded_bounds:
                return ProvValue(cls=ProvClass.GUARDED,
                                 bound=guarded_bounds[size_reg])
            if size_reg in tainted:
                return ProvValue(cls=ProvClass.INPUT_TAINTED, bound=None)
            m2 = re.match(r'(\d+|0x[0-9a-fA-F]+)$', str(size_reg))
            if m2:
                return ProvValue(cls=ProvClass.CONSTANT,
                                 bound=int(m2.group(1), 0))
            return None

        def get_alloc_prov(alloc_addr):
            from analysis.pcwbi_impl import ProvValue, ProvClass
            return ProvValue(cls=ProvClass.UNKNOWN, bound=None)

        inferer = WriteBoundInferer()
        results = inferer.infer(heap_findings, get_write_prov, get_alloc_prov)

        kept = []
        for f, res in zip(heap_findings, results):
            # WbVerdict 为字符串常量: confirmed/benign/suspected
            if res.verdict == 'benign':
                f['pcwbi_verdict'] = 'BENIGN'
                f['pcwbi_reason'] = res.reason[:120]
                continue  # 证明良性 → 过滤
            if res.verdict == 'confirmed':
                f['pcwbi_verdict'] = 'CONFIRMED'
                f['pcwbi_reason'] = res.reason[:120]
                f.setdefault('confidence', 0.5)
                f['confidence'] = min(1.0, f.get('confidence', 0.5) + 0.2)
            else:
                f['pcwbi_verdict'] = 'SUSPECTED'
                f['pcwbi_reason'] = res.reason[:120]
            kept.append(f)
        return non_heap + kept
    except Exception as e:
        logger.debug('PcWBI-orig bridge failed: %s', e)
        return existing_findings


# -- A-11: FC-VRA 原版 (流相关值域分析) --
def run_fc_vra_orig_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """FC-VRA 原版桥接: C0值流配对→C1大小等价→C2区间松弛→C3支配守卫→C4可控性.

    与差异化版 FC-VRA-PTA (指针污点别名) 的区别:
      原版做完整的五条件判定管线, findings 来自 flow-correlated pairs.
    """
    if not _check_module('fc_vra_orig', _probe_fc_vra_orig):
        return existing_findings

    try:
        from modules.info.analysis.fc_vra_detector import detect_heap_overflow_fcv3
        result = detect_heap_overflow_fcv3(
            code=pseudocode or '', func_name=func_name)
        new_findings = []
        for f in result.get('findings', []):
            new_findings.append({
                'type': 'heap-overflow', 'function': func_name,
                'severity': f.get('severity', 'Medium'),
                'cwe': 'CWE-122',
                'confidence': f.get('confidence', 0.5),
                'description': f'FC-VRA: alloc={f.get("alloc_func")} '
                               f'write={f.get("write_func")} '
                               f'buffer={f.get("buffer")} — {f.get("reason", "")[:80]}',
                'verdict': 'POSSIBLE', 'source': 'fc_vra'})
        return existing_findings + new_findings
    except Exception as e:
        logger.debug('FC-VRA-orig bridge failed: %s', e)
        return existing_findings


# -- A-12: CACBV-DSS 原版 (动态slack减除) --
def run_cacbv_dss_orig_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """CACBV-DSS 原版桥接: 按分配函数类型动态计算 chunk 几何.

    与 stage 34 (差异化 CACBV-DSS via analyze_findings) 的区别:
      原版直接调用 classify_overflow (SAFE/OVERFLOW/UNCERTAIN) 对
      逐条 finding 的 alloc_size/write_size 做分类判定.
    """
    if not _check_module('cacbv_dss_orig', lambda: __import__(
            'modules.vuln.detection.heap_analysis.acpe.cacbv_dss',
            fromlist=['DynamicSlackSubtractor'])):
        return existing_findings

    try:
        from modules.vuln.detection.heap_analysis.acpe.cacbv_dss import (
            DynamicSlackSubtractor)
        import re
        # 提取分配函数类型映射 var → func
        alloc_funcs: Dict[str, str] = {}
        for line in (pseudocode or '').split('\n'):
            m = re.match(
                r'(\w+)\s*=\s*(malloc|calloc|realloc|aligned_alloc)\s*\(',
                line, re.IGNORECASE)
            if m:
                alloc_funcs[m.group(1)] = m.group(2).lower()

        subtractor = DynamicSlackSubtractor()
        for f in existing_findings:
            if 'heap' not in f.get('type', '').lower():
                continue
            alloc_var = f.get('alloc_var', f.get('variable', ''))
            alloc_func = alloc_funcs.get(alloc_var, 'malloc')
            alloc_size = f.get('alloc_size', 0)
            write_size = f.get('write_size', 0)
            if (isinstance(alloc_size, int) and isinstance(write_size, int)
                    and alloc_size > 0 and write_size > 0):
                result = subtractor.classify_overflow(
                    alloc_func, alloc_size, write_size)
                f['dss_orig_verdict'] = result['verdict']
                f['dss_orig_geometry'] = {
                    k: result.get(k) for k in
                    ('usable', 'chunk_size', 'slack', 'header_size')}
                if result['verdict'] == 'OVERFLOW':
                    f.setdefault('confidence', 0.5)
                    f['confidence'] = min(1.0, f.get('confidence', 0.5) + 0.15)
                elif (result['verdict'] == 'UNCERTAIN'
                      and f.get('severity', '').lower() in ('high', 'critical')):
                    # 写入 slack 区, 精度提升: 降置信但保留
                    f['dss_orig_note'] = '写入落在slack区, 越界但未过chunk边界'
        return existing_findings
    except Exception as e:
        logger.debug('CACBV-DSS-orig bridge failed: %s', e)
        return existing_findings


# -- A-13: 轻量符号表达式 + 4-Filter (patching侧堆误报过滤) --
def run_symbolic_fp_filter_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """轻量符号+4-Filter 桥接: alloc站点扫描→污点追踪→区间抽象→可满足性求解.

    与 SHIELD (vuln侧三引擎) 的区别:
      本模块来自 patching 侧, 用 IntervalAbstractor + OverflowSatisfiabilitySolver
      对 malloc+memcpy 对做 cannot_overflow 判定, FILTER 误报.
    """
    if not _check_module('sym_fp_filter', lambda: __import__(
            'modules.patching.src.heap_fp_filter',
            fromlist=['HeapFPFilter'])):
        return existing_findings

    try:
        from modules.patching.src.heap_fp_filter import HeapFPFilter
        asm_lines = _pseudocode_to_intx_asm(pseudocode)
        if not asm_lines:
            return existing_findings
        engine = HeapFPFilter()
        report = engine.filter(asm_lines, function_name=func_name)

        # 报告中没有按 finding 逐条对应, 只有 alloc_line 级别判定;
        # 无法映射回现有 findings 时, 仅在有判定且发现 KEEP 时增强
        for f in existing_findings:
            if 'heap' not in f.get('type', '').lower():
                continue
            alloc_line = f.get('alloc_line', f.get('line', 0))
            for a in report.details:
                if a.alloc_line == alloc_line and a.action == 'KEEP':
                    f['symfp_keep'] = True
                    f.setdefault('confidence', 0.5)
                    f['confidence'] = min(1.0, f.get('confidence', 0.5) + 0.1)
                    break
        return existing_findings
    except Exception as e:
        logger.debug('Symbolic-FP-Filter bridge failed: %s', e)
        return existing_findings


# -- A-14: BWR 原版 (有界写恢复, 直接调用) --
def run_bwr_orig_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """BWR 原版桥接: 对无界写 (strcpy/strcat/sprintf/gets) 恢复写尺寸上界.

    与 stage 23 BWR+PCST 的区别:
      stage 23 将伪代码合成汇编后调用 recover(); 原版桥接复用同一
      底层 BoundedWriteRecovery 但以不同编排: 逐 finding 按其
      write_func/write_var 定位, 输出 BWRVerdict 三值标注.
    """
    if not _check_module('bwr_orig', lambda: __import__(
            'modules.analysis.static.bounded_write_recovery',
            fromlist=['BoundedWriteRecovery'])):
        return existing_findings

    try:
        from modules.analysis.static.bounded_write_recovery import (
            BoundedWriteRecovery)
        from modules.analysis.static.heap_write_semantics import is_unsized_write
        import re
        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        if not heap_findings:
            return existing_findings

        # 构建最小汇编上下文 (从伪代码), 复用 BWR+PCST 的合成逻辑
        instructions = _build_bwr_context(pseudocode)
        bwr = BoundedWriteRecovery()

        kept = []
        for f in heap_findings:
            wf = f.get('write_func', '')
            if not wf or not is_unsized_write(wf):
                kept.append(f)
                continue
            # 在合成指令中定位该函数调用
            call_idx = -1
            for i, ins in enumerate(instructions):
                if (ins.get('mnemonic') == 'call'
                        and ins.get('operands', [''])[0] == wf):
                    call_idx = i
                    break
            if call_idx < 0:
                kept.append(f)
                continue
            verdict = bwr.recover(
                instructions, call_idx, wf, _NullTracker(),
                dst_reg='rdi', src_reg='rsi')
            if verdict.kind == 'safe':
                f['bwr_orig_verdict'] = 'safe'
                f['bwr_orig_reason'] = verdict.reason[:120]
                continue  # 恢复上界证明安全 → 过滤
            if verdict.kind == 'overflow':
                f['bwr_orig_verdict'] = 'overflow'
                f['bwr_orig_reason'] = verdict.reason[:120]
                f.setdefault('confidence', 0.5)
                f['confidence'] = min(1.0, f.get('confidence', 0.5) + 0.15)
            else:
                f['bwr_orig_verdict'] = 'unknown'
            kept.append(f)
        return non_heap + kept
    except Exception as e:
        logger.debug('BWR-orig bridge failed: %s', e)
        return existing_findings


# -- A-15: PG-WBV 原版 (giva: 分配点感知写界验证, 抽象解释引擎级) --
def run_pg_wbv_orig_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """PG-WBV 原版桥接: 抽象解释引擎前向追踪分配点 + FpSuppressor 三层判定.

    与差异化版 PG-WBV-LSA (stage 37 循环结构感知伪代码正则) 的区别:
      原版在 objdump 指令流上运行完整 absint 引擎: _prescan_allocs
      前向记录分配大小, _step_one 逐指令状态传播, GivaInterpreter
      捕获堆写完整操作数, FpSuppressor 做归属/大小界定/循环界三层判定.
      判定基于 StridedValue 步长域抽象而非字符串模式.
    有 binary_path 时 objdump 真实反汇编; 无二进制时合成 objdump 文本.
    """
    if not _check_module('pg_wbv_orig', lambda: __import__(
            'modules.analysis.static.heap_analysis.giva_detector',
            fromlist=['GivaScanner'])):
        return existing_findings

    try:
        from modules.analysis.static.heap_analysis.giva_detector import (
            GivaScanner)
        import os as _os
        objdump_text = ''
        # 优先真实二进制: objdump 反汇编
        if binary_path and _os.path.isfile(binary_path):
            import subprocess as _sp
            try:
                out = _sp.run(
                    ['objdump', '-d', '-M', 'intel', binary_path],
                    capture_output=True, text=True, timeout=15)
                if out.returncode == 0 and out.stdout:
                    objdump_text = out.stdout
            except Exception:
                objdump_text = ''
        if not objdump_text:
            objdump_text = _pseudocode_to_giva_asm(pseudocode, func_name)
        if not objdump_text:
            return existing_findings

        scanner = GivaScanner(binary_path=binary_path or None)
        result = scanner.scan(objdump_text, sample_name=func_name)
        if result.get('error'):
            return existing_findings

        new_findings = []
        # real 组: giva 判定真实的堆溢出 (未通过三层抑制)
        for f in result.get('real', []):
            new_findings.append({
                'type': 'heap-overflow', 'function': func_name,
                'severity': 'High', 'cwe': 'CWE-122',
                'confidence': f.get('confidence', 0.5),
                'description': (
                    f'PG-WBV giva: {f.get("subtype", "giva")} '
                    f'fn={f.get("func", "?")} addr={f.get("address", "?")} '
                    f'write={f.get("write_size", 0)} '
                    f'alloc={f.get("alloc_size", 0)} '
                    f'usable={f.get("usable_size", 0)} — {f.get("reason", "")[:80]}'),
                'verdict': 'DEFINITE' if f.get('confidence', 0) >= 0.7
                           else 'POSSIBLE',
                'source': 'pg_wbv_giva',
                'insn_addr': f.get('insn_addr', 0),
                'alloc_size': f.get('alloc_size', 0),
                'write_size': f.get('write_size', 0),
            })
        # filtered 组: giva 证明安全 → 过滤对应已有 heap findings
        # 匹配规则: 已有 finding 的 write_size <= giva filtered 的 usable
        # 且函数名一致时视为同一判定对象的抑制证据
        non_heap = [f for f in existing_findings
                    if 'heap' not in f.get('type', '').lower()]
        heap_findings = [f for f in existing_findings
                         if 'heap' in f.get('type', '').lower()]
        filtered_evidence = result.get('filtered', [])
        kept_heap = []
        for f in heap_findings:
            suppressed = False
            for ev in filtered_evidence:
                ev_func = ev.get('func', '?')
                # 函数名匹配: 解析出函数名则精确匹配;
                # 合成场景无函数头时 func='?', 但管线逐函数调用,
                # 伪代码即当前函数, 视为同一函数证据
                func_match = (ev_func == f.get('function')) or (ev_func == '?')
                # 写入点匹配: 同一写入大小且 giva 证明 write<=usable
                size_match = (
                    ev.get('write_size', 0) == f.get('write_size', 0)
                    and ev.get('usable_size', 0) >= ev.get('write_size', 0))
                if func_match and size_match:
                    f['pg_wbv_giva_verdict'] = 'safe'
                    f['pg_wbv_giva_reason'] = (ev.get('reason', '') or '')[:120]
                    suppressed = True
                    break
            if not suppressed:
                kept_heap.append(f)
        return non_heap + kept_heap + new_findings
    except Exception as e:
        logger.debug('PG-WBV-orig bridge failed: %s', e)
        return existing_findings


def _pseudocode_to_giva_asm(pseudocode: str, func_name: str = '') -> str:
    """将伪代码合成为 giva InstructionParser 可解析的 objdump 文本.

    格式: "  addr:\thex bytes\tmnemonic operands" (与 _LINE_RE 匹配:
      ^\\s*([0-9a-f]+):\\s+(?:[0-9a-f]{2}\\s+)+\\s*(.+)$ ).
    首行插入函数头 "  addr <func_name>:" 供 parse_functions 解析,
    使 real/filtered 证据携带真实函数名.
    合成模式: malloc(N)/calloc(N,M)/危险调用/memcpy 三参数/堆写/守卫.
    """
    import re
    lines: List[str] = []
    addr = 0x1500
    if func_name:
        lines.append(f'  {addr:x} <{func_name}>:')
    _var_reg: Dict[str, str] = {}
    _reg_seq = [0]
    _regs = ['rbx', 'r12', 'r13', 'r14', 'r15', 'rbp']

    def get_reg(v: str) -> str:
        # 变量名 → 寄存器; 超出表用 rN 序列
        if v not in _var_reg:
            if _reg_seq[0] < len(_regs):
                _var_reg[v] = _regs[_reg_seq[0]]
            else:
                _var_reg[v] = f'r{_reg_seq[0]}'
            _reg_seq[0] += 1
        return _var_reg[v]

    def emit(mnem: str, ops: str = '') -> None:
        nonlocal addr
        ops_part = f'\t{ops}' if ops else ''
        lines.append(f'  {addr:x}:\t48 8b 00\t{mnem}{ops_part}')
        addr += 7

    for line in (pseudocode or '').split('\n'):
        line = line.strip()
        if not line or line.startswith('//') or line.startswith('#'):
            continue
        # p = malloc(N) — 分配: mov rdi,N; call malloc; mov var,rax
        m = re.match(
            r'(\w+)\s*=\s*malloc\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*\)', line)
        if m:
            emit('mov', f'rdi,{int(m.group(2), 0)}')
            emit('call', 'malloc')
            emit('mov', f'{get_reg(m.group(1))},rax')
            continue
        # p = malloc(var) — 动态大小, prescan 回退 128 默认
        m = re.match(r'(\w+)\s*=\s*malloc\s*\(\s*(\w+)\s*\)', line)
        if m:
            emit('mov', f'rdi,{get_reg(m.group(2))}')
            emit('call', 'malloc')
            emit('mov', f'{get_reg(m.group(1))},rax')
            continue
        # p = calloc(N, M) — rdi=N, rsi=M, rax 指针
        m = re.match(
            r'(\w+)\s*=\s*calloc\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*,\s*'
            r'(\d+|0x[0-9a-fA-F]+)\s*\)', line)
        if m:
            emit('mov', f'rdi,{int(m.group(2), 0)}')
            emit('mov', f'rsi,{int(m.group(3), 0)}')
            emit('call', 'calloc')
            emit('mov', f'{get_reg(m.group(1))},rax')
            continue
        # memcpy(dst, src, N) — 危险调用: rdi=dst, rsi=src, rdx=N
        m = re.match(
            r'memcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*'
            r'(\d+|0x[0-9a-fA-F]+)\s*\)', line)
        if m:
            emit('mov', f'rdi,{get_reg(m.group(1))}')
            emit('mov', f'rsi,{get_reg(m.group(2))}')
            emit('mov', f'rdx,{int(m.group(3), 0)}')
            emit('call', 'memcpy')
            continue
        # memcpy(dst, src, var)
        m = re.match(r'memcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)',
                     line)
        if m and m.group(3) not in ('0',) and not m.group(3).isdigit():
            emit('mov', f'rdi,{get_reg(m.group(1))}')
            emit('mov', f'rsi,{get_reg(m.group(2))}')
            emit('mov', f'rdx,{get_reg(m.group(3))}')
            emit('call', 'memcpy')
            continue
        # strcpy/strcat/sprintf/gets — 危险调用 (2参/1参)
        m = re.match(
            r'(strcpy|strcat|sprintf|gets|strncpy|snprintf)\s*\((.*)\)\s*;?\s*$',
            line)
        if m:
            func, argstr = m.groups()
            args = [a.strip() for a in argstr.split(',')]
            if func in ('strcpy', 'strcat'):
                if len(args) >= 2:
                    emit('mov', f'rdi,{get_reg(args[0])}')
                    emit('mov', f'rsi,{get_reg(args[1])}')
                    emit('call', func)
            elif func == 'gets':
                if args:
                    emit('mov', f'rdi,{get_reg(args[0])}')
                    emit('call', 'gets')
            elif func in ('strncpy', 'snprintf'):
                if len(args) >= 3:
                    emit('mov', f'rdi,{get_reg(args[0])}')
                    emit('mov', f'rsi,{get_reg(args[1])}')
                    emit('mov', f'rdx,{int(args[2], 0) if args[2].isdigit() else get_reg(args[2])}')
                    emit('call', func)
            elif func == 'sprintf':
                if len(args) >= 2:
                    emit('mov', f'rdi,{get_reg(args[0])}')
                    emit('mov', f'rsi,{get_reg(args[1])}')
                    emit('call', func)
            continue
        # 堆写: *(p + off) = val / p[off] = val
        m = re.match(
            r'\*?\s*\(?(\w+)(?:\s*\+\s*(\d+|0x[0-9a-fA-F]+))?\)?\s*\[?\s*(\d*)\s*\]?\s*=\s*'
            r'(\w+|\d+|0x[0-9a-fA-F]+)', line)
        if m:
            ptr_var, off, idx, val = m.groups()
            base_reg = get_reg(ptr_var)
            off_int = int(off, 0) if off else 0
            # 堆写需要基址为堆指针: 前一条 mov dst,[base+off] 形式
            # lea 先计算地址, 再 mov [地址], imm 写入
            emit('lea', f'rax,[{base_reg}+0x{off_int:x}]')
            if val.isdigit() or val.startswith('0x'):
                emit('mov', f'DWORD PTR [rax],{val}')
            else:
                emit('mov', f'DWORD PTR [rax],{get_reg(val)}')
            continue
        # 赋值别名: dst = src
        m = re.match(r'(\w+)\s*=\s*(\w+)\s*;?\s*$', line)
        if m and m.group(2) not in (
                'malloc', 'calloc', 'realloc', 'free', 'NULL'):
            emit('mov', f'{get_reg(m.group(1))},{get_reg(m.group(2))}')
            continue
    return '\n'.join(lines)


def _build_bwr_context(pseudocode: str) -> List[dict]:
    """为 BWR 原版桥接构建最小化汇编指令上下文."""
    import re
    instructions: List[dict] = []
    addr = 0x1000
    _var_reg = {}
    _regs = ['rbx', 'r12', 'r13', 'r14', 'r15']

    def get_reg(v: str) -> str:
        if v not in _var_reg:
            _var_reg[v] = _regs[len(_var_reg) % len(_regs)]
        return _var_reg[v]

    for line in (pseudocode or '').split('\n'):
        line = line.strip()
        if not line:
            continue
        m = re.match(
            r'(\w+)\s*=\s*malloc\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*\)', line)
        if m:
            size = int(m.group(2), 0)
            instructions.append({'address': addr, 'mnemonic': 'mov',
                                 'operands': ['rdi', str(size)]})
            addr += 4
            instructions.append({'address': addr, 'mnemonic': 'call',
                                  'operands': ['malloc']})
            addr += 4
            instructions.append({'address': addr, 'mnemonic': 'mov',
                                 'operands': [get_reg(m.group(1)), 'rax']})
            addr += 4
            continue
        m = re.match(
            r'(strcpy|strcat|stpcpy|sprintf|vsprintf)\s*\(\s*(\w+)\s*,\s*'
            r'(?:"([^"]*)"|(\w+))\s*\)', line)
        if m:
            func, dst = m.group(1), m.group(2)
            instructions.append({'address': addr, 'mnemonic': 'mov',
                                  'operands': ['rdi', get_reg(dst)]})
            addr += 4
            if m.group(3) is not None:
                instructions.append({
                    'address': addr, 'mnemonic': 'lea',
                    'operands': ['rsi', f'[rip+0x0] # "{m.group(3)}"']})
            else:
                instructions.append({'address': addr, 'mnemonic': 'mov',
                                     'operands': ['rsi', get_reg(m.group(4))]})
            addr += 4
            instructions.append({'address': addr, 'mnemonic': 'call',
                                  'operands': [func]})
            addr += 4
            continue
        m = re.match(r'gets\s*\(\s*(\w+)\s*\)', line)
        if m:
            instructions.append({'address': addr, 'mnemonic': 'mov',
                                 'operands': ['rdi', get_reg(m.group(1))]})
            addr += 4
            instructions.append({'address': addr, 'mnemonic': 'call',
                                 'operands': ['gets']})
            addr += 4
            continue
    return instructions


class _NullTracker:
    """BWR 原版桥接用占位 alloc_tracker — 无分配信息时保守 unknown."""

    _ptr_to_alloc: Dict[str, int] = {}


def _rw_apply_fp_vote(findings: List[dict], evidence: dict) -> None:
    """RW 安全证据温和降权: 同类型已有 findings conf*0.85 + fp_votes 计数.

    与 SHIELD 硬过滤不同, RW 模块证据多为启发式判定, 采用保守的
    降权不删除策略, 累积 fp_votes/fp_sources 供下游融合阶段参考.
    """
    t = evidence.get('type', '')
    src = evidence.get('source', '')
    if not t:
        return
    for f in findings:
        if t in f.get('type', ''):
            f['confidence'] = round(f.get('confidence', 0.5) * 0.85, 2)
            f['fp_votes'] = f.get('fp_votes', 0) + 1
            if src:
                votes = f.get('fp_sources', [])
                if src not in votes:
                    votes.append(src)
                    f['fp_sources'] = votes


def run_rw_call_ctx_saturation_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-CallCtxSaturation 桥接 (stage 55): 调用点饱和度计分.

    消费型模块: 输出 = 分配点审计条目 + 饱和度降权后的原 findings.
    审计条目 (description 以 alloc@ 开头) 属画像类证据, 不注入
    主列表, 仅保留降权加工后的原 findings.
    """
    if not _check_module('rw_call_ctx_saturation', lambda: __import__(
            'modules.analysis.static.rw_innovations.call_ctx_saturation',
            fromlist=['run_call_ctx_saturation'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.call_ctx_saturation import (
            run_call_ctx_saturation)
        if not existing_findings:
            return existing_findings
        results = run_call_ctx_saturation(pseudocode, func_name,
                                          existing_findings)
        return [r for r in results
                if not (r.get('description') or '').startswith('alloc@')]
    except Exception as e:
        logger.debug('RW call_ctx_saturation bridge failed: %s', e)
        return existing_findings


def run_rw_liveness_role_template_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-LivenessRoleTemplate 桥接 (stage 56): 调用点参数角色模板投票.

    消费型模块: 输出 = call 点角色投票审计条目 + 投票不一致降权后的
    原 findings. 审计条目 (description 以 call@ 开头) 不注入主列表.
    """
    if not _check_module('rw_liveness_role_template', lambda: __import__(
            'modules.analysis.static.rw_innovations.liveness_role_template',
            fromlist=['run_liveness_role_template'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.liveness_role_template import (
            run_liveness_role_template)
        if not existing_findings:
            return existing_findings
        results = run_liveness_role_template(pseudocode, func_name,
                                             existing_findings)
        return [r for r in results
                if not (r.get('description') or '').startswith('call@')]
    except Exception as e:
        logger.debug('RW liveness_role_template bridge failed: %s', e)
        return existing_findings


def run_rw_jcc_polarity_map_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-JccPolarityMap 桥接 (stage 57): 条件跳转极性图.

    写入点仅在反极性路径可达时产出 filtered 证据, 对同类型已有
    findings 温和降权; reachable/ambiguous 属路径画像不注入.
    """
    if not _check_module('rw_jcc_polarity_map', lambda: __import__(
            'modules.analysis.static.rw_innovations.jcc_polarity_map',
            fromlist=['run_jcc_polarity_map'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.jcc_polarity_map import (
            run_jcc_polarity_map)
        results = run_jcc_polarity_map(pseudocode, func_name, None)
        if not any(r.get('verdict') == 'filtered' for r in results):
            return existing_findings
        findings = list(existing_findings)
        for r in results:
            if r.get('verdict') == 'filtered':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW jcc_polarity_map bridge failed: %s', e)
        return existing_findings


def run_rw_spec_danger_profile_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-SpecDangerProfile 桥接 (stage 58): 格式串说明符危险画像.

    %n/%s 等逐 token 加权危险分超阈值且非字面量时产出 danger 告警
    (format_string), 白名单注入; benign 属画像不注入.
    """
    if not _check_module('rw_spec_danger_profile', lambda: __import__(
            'modules.analysis.static.rw_innovations.spec_danger_profile',
            fromlist=['run_spec_danger_profile'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.spec_danger_profile import (
            run_spec_danger_profile)
        results = run_spec_danger_profile(pseudocode, func_name, None)
        alerts = [r for r in results if r.get('verdict') == 'danger']
        if not alerts:
            return existing_findings
        return list(existing_findings) + alerts
    except Exception as e:
        logger.debug('RW spec_danger_profile bridge failed: %s', e)
        return existing_findings


def run_rw_correlated_wrap_check_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-CorrelatedWrapCheck 桥接 (stage 59): 复合表达式相关回绕检查.

    运算树中子节点回绕被父节点吸收 (mask/加法截断) 时产出
    missed_wrap 漏报候选 (integer_overflow), 白名单注入.
    """
    if not _check_module('rw_correlated_wrap_check', lambda: __import__(
            'modules.analysis.static.rw_innovations.correlated_wrap_check',
            fromlist=['run_correlated_wrap_check'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.correlated_wrap_check import (
            run_correlated_wrap_check)
        results = run_correlated_wrap_check(pseudocode, func_name, None)
        alerts = [r for r in results if r.get('verdict') == 'missed_wrap']
        if not alerts:
            return existing_findings
        return list(existing_findings) + alerts
    except Exception as e:
        logger.debug('RW correlated_wrap_check bridge failed: %s', e)
        return existing_findings


def run_rw_dom_frontier_witness_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-DomFrontierWitness 桥接 (stage 60): 支配边界 UAF 误报见证.

    free 块支配边界不含 use 块时产出 false_positive 见证, 对
    use_after_free 类已有 findings 温和降权.
    """
    if not _check_module('rw_dom_frontier_witness', lambda: __import__(
            'modules.analysis.static.rw_innovations.dom_frontier_witness',
            fromlist=['run_dom_frontier_witness'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.dom_frontier_witness import (
            run_dom_frontier_witness)
        results = run_dom_frontier_witness(pseudocode, func_name, None)
        if not any(r.get('verdict') == 'false_positive' for r in results):
            return existing_findings
        findings = list(existing_findings)
        for r in results:
            if r.get('verdict') == 'false_positive':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW dom_frontier_witness bridge failed: %s', e)
        return existing_findings


def run_rw_seven_stage_fanout_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-SevenStageFanout 桥接 (stage 61): 七阶段扇出覆盖率审计.

    输出为管线覆盖率画像 (safe/unsafe), 属审计类证据, 真实调用
    但不注入 findings 主列表, 避免画像类噪声.
    """
    if not _check_module('rw_seven_stage_fanout', lambda: __import__(
            'modules.analysis.static.rw_innovations.seven_stage_fanout',
            fromlist=['run_seven_stage_fanout'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.seven_stage_fanout import (
            run_seven_stage_fanout)
        run_seven_stage_fanout(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW seven_stage_fanout bridge failed: %s', e)
        return existing_findings


def run_rw_scaled_index_linear_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-ScaledIndexLinear 桥接 (stage 62): scaled-index 线性化判定.

    [base+idx*scale+off] 写地址 scale 相容性数学判定: overflow 白名单
    注入, safe 作为安全证据对同类型已有 findings 温和降权.
    """
    if not _check_module('rw_scaled_index_linear', lambda: __import__(
            'modules.analysis.static.rw_innovations.scaled_index_linear',
            fromlist=['run_scaled_index_linear'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.scaled_index_linear import (
            run_scaled_index_linear)
        results = run_scaled_index_linear(pseudocode, func_name, None)
        findings = list(existing_findings)
        injected = False
        for r in results:
            v = r.get('verdict')
            if v == 'overflow':
                findings.append(r)
                injected = True
            elif v == 'safe':
                _rw_apply_fp_vote(findings, r)
        return findings if injected else findings
    except Exception as e:
        logger.debug('RW scaled_index_linear bridge failed: %s', e)
        return existing_findings


def run_rw_freed_alias_epoch_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-FreedAliasEpoch 桥接 (stage 63): 释放别名纪元判定.

    写点命中"已释放未重生"纪元产出 use_after_free 告警注入;
    reborn (realloc 重生) 作为消解证据对 UAF 类 findings 温和降权.
    """
    if not _check_module('rw_freed_alias_epoch', lambda: __import__(
            'modules.analysis.static.rw_innovations.freed_alias_epoch',
            fromlist=['run_freed_alias_epoch'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.freed_alias_epoch import (
            run_freed_alias_epoch)
        results = run_freed_alias_epoch(pseudocode, func_name, None)
        findings = list(existing_findings)
        for r in results:
            v = r.get('verdict')
            if v == 'use_after_free':
                findings.append(r)
            elif v == 'reborn':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW freed_alias_epoch bridge failed: %s', e)
        return existing_findings


def run_rw_ret_addr_chain_stitch_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-RetAddrChainStitch 桥接 (stage 64): 返回地址链缝合.

    caller alloc 证据与 callee 写证据在返回点缝合闭合 (stitched_safe)
    时, 对同类型已有 findings 温和降权; unstitched 属路径画像不注入.
    """
    if not _check_module('rw_ret_addr_chain_stitch', lambda: __import__(
            'modules.analysis.static.rw_innovations.ret_addr_chain_stitch',
            fromlist=['run_ret_addr_chain_stitch'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.ret_addr_chain_stitch import (
            run_ret_addr_chain_stitch)
        results = run_ret_addr_chain_stitch(pseudocode, func_name, None)
        if not any(r.get('verdict') == 'stitched_safe' for r in results):
            return existing_findings
        findings = list(existing_findings)
        for r in results:
            if r.get('verdict') == 'stitched_safe':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW ret_addr_chain_stitch bridge failed: %s', e)
        return existing_findings


def run_rw_eval_harness_replica_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-EvalHarnessReplica 桥接 (stage 65): 端到端评估复算.

    消费型模块: 对已有 findings 在迷你评估器上复算 TP/FP 语义一致性,
    不一致的 conf 减半 (verdict=inconsistent), 输出 1:1 替换输入.
    必须传真实 findings, 传 None 会自产占位条目.
    """
    if not _check_module('rw_eval_harness_replica', lambda: __import__(
            'modules.analysis.static.rw_innovations.eval_harness_replica',
            fromlist=['run_eval_harness_replica'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.eval_harness_replica import (
            run_eval_harness_replica)
        if not existing_findings:
            return existing_findings
        return run_eval_harness_replica(pseudocode, func_name,
                                        existing_findings)
    except Exception as e:
        logger.debug('RW eval_harness_replica bridge failed: %s', e)
        return existing_findings


def run_rw_taint_source_grading_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-TaintSourceGrading 桥接 (stage 66): 污点源分级.

    scanf(4)/recv(3)/argv(2)/env(1) 分级: 高级污点且无守卫
    (high_taint) 作为弱告警注入; mid/low/unknown 属画像不注入.
    """
    if not _check_module('rw_taint_source_grading', lambda: __import__(
            'modules.analysis.static.rw_innovations.taint_source_grading',
            fromlist=['run_taint_source_grading'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.taint_source_grading import (
            run_taint_source_grading)
        results = run_taint_source_grading(pseudocode, func_name, None)
        alerts = [r for r in results if r.get('verdict') == 'high_taint']
        if not alerts:
            return existing_findings
        return list(existing_findings) + alerts
    except Exception as e:
        logger.debug('RW taint_source_grading bridge failed: %s', e)
        return existing_findings


def run_rw_ptr_union_closure_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-PtrUnionClosure 桥接 (stage 67): 指针并查集闭包.

    写入目标与分配点集合根不同 (cross_buffer_fp) 时, 对同类型已有
    findings 温和降权; same_set 属集合画像不注入.
    """
    if not _check_module('rw_ptr_union_closure', lambda: __import__(
            'modules.analysis.static.rw_innovations.ptr_union_closure',
            fromlist=['run_ptr_union_closure'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.ptr_union_closure import (
            run_ptr_union_closure)
        results = run_ptr_union_closure(pseudocode, func_name, None)
        if not any(r.get('verdict') == 'cross_buffer_fp' for r in results):
            return existing_findings
        findings = list(existing_findings)
        for r in results:
            if r.get('verdict') == 'cross_buffer_fp':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW ptr_union_closure bridge failed: %s', e)
        return existing_findings


def run_rw_root_identity_key_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-RootIdentityKey 桥接 (stage 68): 根身份键判定.

    alloc 与 write 的 size 表达式归一化四元组键相等 (identity_safe)
    时, 对同类型已有 findings 温和降权; identity_diff 属画像不注入.
    """
    if not _check_module('rw_root_identity_key', lambda: __import__(
            'modules.analysis.static.rw_innovations.root_identity_key',
            fromlist=['run_root_identity_key'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.root_identity_key import (
            run_root_identity_key)
        results = run_root_identity_key(pseudocode, func_name, None)
        if not any(r.get('verdict') == 'identity_safe' for r in results):
            return existing_findings
        findings = list(existing_findings)
        for r in results:
            if r.get('verdict') == 'identity_safe':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW root_identity_key bridge failed: %s', e)
        return existing_findings


def run_rw_symbolic_diff_sign_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-SymbolicDiffSign 桥接 (stage 69): 符号差符号判定.

    写极值与分配大小差 diff_const 判定: 正差 overflow 告警白名单
    注入; 负差 safe 作为安全证据温和降权同类型已有 findings.
    """
    if not _check_module('rw_symbolic_diff_sign', lambda: __import__(
            'modules.analysis.static.rw_innovations.symbolic_diff_sign',
            fromlist=['run_symbolic_diff_sign'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.symbolic_diff_sign import (
            run_symbolic_diff_sign)
        results = run_symbolic_diff_sign(pseudocode, func_name, None)
        findings = list(existing_findings)
        for r in results:
            v = r.get('verdict')
            if v == 'overflow':
                findings.append(r)
            elif v == 'safe':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW symbolic_diff_sign bridge failed: %s', e)
        return existing_findings


def run_rw_heap_stack_global_tri_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-HeapStackGlobalTri 桥接 (stage 70): 堆/栈/全局三分域分类.

    写操作目标域分类画像 (heap_write/stack_write/global_write),
    属审计类证据, 真实调用但不注入 findings 主列表.
    """
    if not _check_module('rw_heap_stack_global_tri', lambda: __import__(
            'modules.analysis.static.rw_innovations.heap_stack_global_tri',
            fromlist=['run_heap_stack_global_tri'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.heap_stack_global_tri import (
            run_heap_stack_global_tri)
        run_heap_stack_global_tri(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW heap_stack_global_tri bridge failed: %s', e)
        return existing_findings


def run_rw_chain_equiv_hash_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-ChainEquivHash 桥接 (stage 71): 溯源链等价哈希.

    alloc 链与 write 链滚动哈希相等 (equiv_safe) 时, 对同类型已有
    findings 温和降权; not_equiv 属链画像不注入.
    """
    if not _check_module('rw_chain_equiv_hash', lambda: __import__(
            'modules.analysis.static.rw_innovations.chain_equiv_hash',
            fromlist=['run_chain_equiv_hash'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.chain_equiv_hash import (
            run_chain_equiv_hash)
        results = run_chain_equiv_hash(pseudocode, func_name, None)
        if not any(r.get('verdict') == 'equiv_safe' for r in results):
            return existing_findings
        findings = list(existing_findings)
        for r in results:
            if r.get('verdict') == 'equiv_safe':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW chain_equiv_hash bridge failed: %s', e)
        return existing_findings


def run_rw_contract_preserve_fold_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-ContractPreserveFold 桥接 (stage 72): 契约保持折叠.

    消费型模块: 共享同 alloc 契约的 findings 分组, 组内任一
    overflow/conf>=0.8 一票否决全组保留, 否则折叠为代表性条目.
    输出 1:1 替换输入, 必须传真实 findings.
    """
    if not _check_module('rw_contract_preserve_fold', lambda: __import__(
            'modules.analysis.static.rw_innovations.contract_preserve_fold',
            fromlist=['run_contract_preserve_fold'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.contract_preserve_fold import (
            run_contract_preserve_fold)
        if not existing_findings:
            return existing_findings
        return run_contract_preserve_fold(pseudocode, func_name,
                                         existing_findings)
    except Exception as e:
        logger.debug('RW contract_preserve_fold bridge failed: %s', e)
        return existing_findings


def run_rw_demand_trigger_budget_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-DemandTriggerBudget 桥接 (stage 73): 按需触发预算管理.

    消费型模块: 全局配额内高级分析, 低置信度先用轻量证据, 配额
    耗尽走保守路径 (conservative conf 减半). 输出 1:1 替换输入.
    """
    if not _check_module('rw_demand_trigger_budget', lambda: __import__(
            'modules.analysis.static.rw_innovations.demand_trigger_budget',
            fromlist=['run_demand_trigger_budget'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.demand_trigger_budget import (
            run_demand_trigger_budget)
        if not existing_findings:
            return existing_findings
        return run_demand_trigger_budget(pseudocode, func_name,
                                        existing_findings)
    except Exception as e:
        logger.debug('RW demand_trigger_budget bridge failed: %s', e)
        return existing_findings


def run_rw_min_chunk_geometry_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-MinChunkGeometry 桥接 (stage 74): 最小块几何判定.

    写偏移超出 malloc 最小块几何 (beyond_minsize) 作为弱告警注入;
    safe_minsize 作为安全证据温和降权同类型已有 findings.
    """
    if not _check_module('rw_min_chunk_geometry', lambda: __import__(
            'modules.analysis.static.rw_innovations.min_chunk_geometry',
            fromlist=['run_min_chunk_geometry'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.min_chunk_geometry import (
            run_min_chunk_geometry)
        results = run_min_chunk_geometry(pseudocode, func_name, None)
        findings = list(existing_findings)
        for r in results:
            v = r.get('verdict')
            if v == 'beyond_minsize':
                findings.append(r)
            elif v == 'safe_minsize':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW min_chunk_geometry bridge failed: %s', e)
        return existing_findings


def run_rw_recovery_soundness_gate_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-RecoverySoundnessGate 桥接 (stage 75): 恢复可靠性门.

    BWR 恢复值超上界 (unsound) 属恢复过程审计画像, 真实调用但
    不注入 findings 主列表, 避免恢复中间态噪声.
    """
    if not _check_module('rw_recovery_soundness_gate', lambda: __import__(
            'modules.analysis.static.rw_innovations.recovery_soundness_gate',
            fromlist=['run_recovery_soundness_gate'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.recovery_soundness_gate import (
            run_recovery_soundness_gate)
        run_recovery_soundness_gate(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW recovery_soundness_gate bridge failed: %s', e)
        return existing_findings


def run_rw_rdata_const_region_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-RdataConstRegion 桥接 (stage 76): .rdata 常量区判定.

    格式串来自 .rdata/.rodata 常量区 (const_safe) 时, 对
    format_string 类已有 findings 温和降权; mutable 属来源画像不注入.
    """
    if not _check_module('rw_rdata_const_region', lambda: __import__(
            'modules.analysis.static.rw_innovations.rdata_const_region',
            fromlist=['run_rdata_const_region'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.rdata_const_region import (
            run_rdata_const_region)
        results = run_rdata_const_region(pseudocode, func_name, None)
        if not any(r.get('verdict') == 'const_safe' for r in results):
            return existing_findings
        findings = list(existing_findings)
        for r in results:
            if r.get('verdict') == 'const_safe':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW rdata_const_region bridge failed: %s', e)
        return existing_findings


def run_rw_guard_alias_transitive_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-GuardAliasTransitive 桥接 (stage 77): 守卫别名传递闭包.

    guarded_safe/guarded_var_off/unguarded 均为守卫覆盖画像
    (冒烟实测 unguarded 在安全场景也触发, 不可作为告警依据),
    真实调用但不注入 findings 主列表.
    """
    if not _check_module('rw_guard_alias_transitive', lambda: __import__(
            'modules.analysis.static.rw_innovations.guard_alias_transitive',
            fromlist=['run_guard_alias_transitive'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.guard_alias_transitive import (
            run_guard_alias_transitive)
        run_guard_alias_transitive(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW guard_alias_transitive bridge failed: %s', e)
        return existing_findings


def run_rw_walk_stride_model_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-WalkStrideModel 桥接 (stage 78): 步长模型覆盖检查.

    base+stride*count 步长覆盖超出分配 (maybe_overflow) 作为弱告警
    注入; in_bounds 作为安全证据温和降权同类型已有 findings.
    """
    if not _check_module('rw_walk_stride_model', lambda: __import__(
            'modules.analysis.static.rw_innovations.walk_stride_model',
            fromlist=['run_walk_stride_model'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.walk_stride_model import (
            run_walk_stride_model)
        results = run_walk_stride_model(pseudocode, func_name, None)
        findings = list(existing_findings)
        for r in results:
            v = r.get('verdict')
            if v == 'maybe_overflow':
                findings.append(r)
            elif v == 'in_bounds':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW walk_stride_model bridge failed: %s', e)
        return existing_findings


def run_rw_use_deref_lattice_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-UseDerefLattice 桥接 (stage 79): 解引用格模型.

    use 点解引用深度判定: confirmed_uaf/weak_uaf 告警注入;
    not_dangling 作为消解证据温和降权 UAF 类已有 findings.
    """
    if not _check_module('rw_use_deref_lattice', lambda: __import__(
            'modules.analysis.static.rw_innovations.use_deref_lattice',
            fromlist=['run_use_deref_lattice'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.use_deref_lattice import (
            run_use_deref_lattice)
        results = run_use_deref_lattice(pseudocode, func_name, None)
        findings = list(existing_findings)
        for r in results:
            v = r.get('verdict')
            if v in ('confirmed_uaf', 'weak_uaf'):
                findings.append(r)
            elif v == 'not_dangling':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW use_deref_lattice bridge failed: %s', e)
        return existing_findings


def run_rw_imm_prop_absorb_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-ImmPropAbsorb 桥接 (stage 80): 立即数属性吸收.

    写入值常量被吸收为尺寸证据的画像 (const_exact/unknown_size),
    属审计类证据, 真实调用但不注入 findings 主列表.
    """
    if not _check_module('rw_imm_prop_absorb', lambda: __import__(
            'modules.analysis.static.rw_innovations.imm_prop_absorb',
            fromlist=['run_imm_prop_absorb'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.imm_prop_absorb import (
            run_imm_prop_absorb)
        run_imm_prop_absorb(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW imm_prop_absorb bridge failed: %s', e)
        return existing_findings


def run_rw_call_conv_duality_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-CallConvDuality 桥接 (stage 81): 调用约定对偶校验.

    SysV/Win64 双调用约定尺寸解释画像 (dual_agree/dual_conflict/
    sysv_only/win_only), 属审计类证据, 真实调用但不注入主列表.
    """
    if not _check_module('rw_call_conv_duality', lambda: __import__(
            'modules.analysis.static.rw_innovations.call_conv_duality',
            fromlist=['run_call_conv_duality'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.call_conv_duality import (
            run_call_conv_duality)
        run_call_conv_duality(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW call_conv_duality bridge failed: %s', e)
        return existing_findings


def run_rw_wrapper_graph_match_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-WrapperGraphMatch 桥接 (stage 82): 包装函数图同构匹配.

    同构匹配画像 (isomorphic), 属审计类证据, 真实调用但
    不注入 findings 主列表.
    """
    if not _check_module('rw_wrapper_graph_match', lambda: __import__(
            'modules.analysis.static.rw_innovations.wrapper_graph_match',
            fromlist=['run_wrapper_graph_match'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.wrapper_graph_match import (
            run_wrapper_graph_match)
        run_wrapper_graph_match(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW wrapper_graph_match bridge failed: %s', e)
        return existing_findings


def run_rw_two_var_diff_bound_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-TwoVarDiffBound 桥接 (stage 83): 双变量差界判定.

    alloc 与 write 的双变量差超界 (diff_overflow) 告警白名单注入;
    diff_safe 作为安全证据温和降权同类型已有 findings.
    """
    if not _check_module('rw_two_var_diff_bound', lambda: __import__(
            'modules.analysis.static.rw_innovations.two_var_diff_bound',
            fromlist=['run_two_var_diff_bound'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.two_var_diff_bound import (
            run_two_var_diff_bound)
        results = run_two_var_diff_bound(pseudocode, func_name, None)
        findings = list(existing_findings)
        for r in results:
            v = r.get('verdict')
            if v == 'diff_overflow':
                findings.append(r)
            elif v == 'diff_safe':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW two_var_diff_bound bridge failed: %s', e)
        return existing_findings


def run_rw_exit_dominance_check_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-ExitDominanceCheck 桥接 (stage 84): 出口支配 UAF 误报检查.

    return 块支配 free 块 (free 不可达) 时产出 false_positive 见证,
    对 use_after_free 类已有 findings 温和降权.
    """
    if not _check_module('rw_exit_dominance_check', lambda: __import__(
            'modules.analysis.static.rw_innovations.exit_dominance_check',
            fromlist=['run_exit_dominance_check'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.exit_dominance_check import (
            run_exit_dominance_check)
        results = run_exit_dominance_check(pseudocode, func_name, None)
        if not any(r.get('verdict') == 'false_positive' for r in results):
            return existing_findings
        findings = list(existing_findings)
        for r in results:
            if r.get('verdict') == 'false_positive':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW exit_dominance_check bridge failed: %s', e)
        return existing_findings


def run_rw_cross_type_evidence_pool_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-CrossTypeEvidencePool 桥接 (stage 85): 跨类型证据池.

    消费型模块: 同函数 >=2 种类型告警互相印证 (conf+0.1), 输出
    1:1 加工替换输入. 必须传真实 findings, 传 None 会自产占位条目.
    """
    if not _check_module('rw_cross_type_evidence_pool', lambda: __import__(
            'modules.analysis.static.rw_innovations.cross_type_evidence_pool',
            fromlist=['run_cross_type_evidence_pool'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.cross_type_evidence_pool import (
            run_cross_type_evidence_pool)
        if not existing_findings:
            return existing_findings
        return run_cross_type_evidence_pool(pseudocode, func_name,
                                            existing_findings)
    except Exception as e:
        logger.debug('RW cross_type_evidence_pool bridge failed: %s', e)
        return existing_findings


def run_rw_color_class_quad_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-ColorClassQuad 桥接 (stage 86): 四色类域分类.

    写操作四色分类画像 (heap_write/stack_write/global_write/
    unknown_color), 属审计类证据, 真实调用但不注入主列表.
    """
    if not _check_module('rw_color_class_quad', lambda: __import__(
            'modules.analysis.static.rw_innovations.color_class_quad',
            fromlist=['run_color_class_quad'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.color_class_quad import (
            run_color_class_quad)
        run_color_class_quad(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW color_class_quad bridge failed: %s', e)
        return existing_findings


def run_rw_widen_threshold_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-WidenThreshold 桥接 (stage 87): 加宽阈值监控.

    区间加宽 topped/stable 状态画像, 属审计类证据,
    真实调用但不注入 findings 主列表.
    """
    if not _check_module('rw_widen_threshold', lambda: __import__(
            'modules.analysis.static.rw_innovations.widen_threshold',
            fromlist=['run_widen_threshold'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.widen_threshold import (
            run_widen_threshold)
        run_widen_threshold(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW widen_threshold bridge failed: %s', e)
        return existing_findings


def run_rw_four_level_adjudicator_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-FourLevelAdjudicator 桥接 (stage 88): 四级裁决器.

    L1-L4 四级证据裁决: overflow 告警白名单注入; safe 作为安全
    证据温和降权同类型已有 findings; inconclusive 不注入.
    """
    if not _check_module('rw_four_level_adjudicator', lambda: __import__(
            'modules.analysis.static.rw_innovations.four_level_adjudicator',
            fromlist=['run_four_level_adjudicator'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.four_level_adjudicator import (
            run_four_level_adjudicator)
        results = run_four_level_adjudicator(pseudocode, func_name, None)
        findings = list(existing_findings)
        for r in results:
            v = r.get('verdict')
            if v == 'overflow':
                findings.append(r)
            elif v == 'safe':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW four_level_adjudicator bridge failed: %s', e)
        return existing_findings


def run_rw_provenance_octagon_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-ProvenanceOctagon 桥接 (stage 89): 八角域溯源.

    指针溯源八角域分类画像 (heap_prov/non_heap_prov), 属审计类
    证据, 真实调用但不注入 findings 主列表.
    """
    if not _check_module('rw_provenance_octagon', lambda: __import__(
            'modules.analysis.static.rw_innovations.provenance_octagon',
            fromlist=['run_provenance_octagon'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.provenance_octagon import (
            run_provenance_octagon)
        run_provenance_octagon(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW provenance_octagon bridge failed: %s', e)
        return existing_findings


def run_rw_seven_dim_weighted_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-SevenDimWeighted 桥接 (stage 90): 七维加权融合.

    七维独立证据加权投票. 冒烟实测 veto_safe 在溢出场景也触发
    (16进制值被十进制正则误解析), 一票否决过于激进, 故 veto_safe
    不作为降权依据; weighted_unsafe 作为弱告警注入, weighted_unknown
    属不确定画像不注入.
    """
    if not _check_module('rw_seven_dim_weighted', lambda: __import__(
            'modules.analysis.static.rw_innovations.seven_dim_weighted',
            fromlist=['run_seven_dim_weighted'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.seven_dim_weighted import (
            run_seven_dim_weighted)
        results = run_seven_dim_weighted(pseudocode, func_name, None)
        alerts = [r for r in results
                  if r.get('verdict') == 'weighted_unsafe']
        if not alerts:
            return existing_findings
        return list(existing_findings) + alerts
    except Exception as e:
        logger.debug('RW seven_dim_weighted bridge failed: %s', e)
        return existing_findings


def run_rw_abi_auto_detect_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-AbiAutoDetect 桥接 (stage 91): ABI 自动探测.

    序言/寄存器用法 ABI 探测画像 (abi_confirmed/abi_partial/
    abi_unknown), 属审计类证据, 真实调用但不注入主列表.
    """
    if not _check_module('rw_abi_auto_detect', lambda: __import__(
            'modules.analysis.static.rw_innovations.abi_auto_detect',
            fromlist=['run_abi_auto_detect'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.abi_auto_detect import (
            run_abi_auto_detect)
        run_abi_auto_detect(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW abi_auto_detect bridge failed: %s', e)
        return existing_findings


def run_rw_reduction_rate_audit_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-ReductionRateAudit 桥接 (stage 92): 减除率审计.

    管线各级过滤减除率审计画像 (no_data/recheck/ok), 属元审计
    类证据, 真实调用但不注入 findings 主列表.
    """
    if not _check_module('rw_reduction_rate_audit', lambda: __import__(
            'modules.analysis.static.rw_innovations.reduction_rate_audit',
            fromlist=['run_reduction_rate_audit'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.reduction_rate_audit import (
            run_reduction_rate_audit)
        run_reduction_rate_audit(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW reduction_rate_audit bridge failed: %s', e)
        return existing_findings


def run_rw_guard_op_enum_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-GuardOpEnum 桥接 (stage 93): 守卫操作枚举.

    边界检查操作枚举画像 (guard_sem), 属审计类证据,
    真实调用但不注入 findings 主列表.
    """
    if not _check_module('rw_guard_op_enum', lambda: __import__(
            'modules.analysis.static.rw_innovations.guard_op_enum',
            fromlist=['run_guard_op_enum'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.guard_op_enum import (
            run_guard_op_enum)
        run_guard_op_enum(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW guard_op_enum bridge failed: %s', e)
        return existing_findings


def run_rw_three_path_disjoint_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-ThreePathDisjoint 桥接 (stage 94): 三路径不相交判定.

    写范围与分配范围差集: 差集非空 (outside_alloc) 告警注入;
    within_alloc 作为安全证据温和降权; live_disjoint 属
    meta_audit 不注入.
    """
    if not _check_module('rw_three_path_disjoint', lambda: __import__(
            'modules.analysis.static.rw_innovations.three_path_disjoint',
            fromlist=['run_three_path_disjoint'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.three_path_disjoint import (
            run_three_path_disjoint)
        results = run_three_path_disjoint(pseudocode, func_name, None)
        findings = list(existing_findings)
        for r in results:
            v = r.get('verdict')
            if v == 'outside_alloc':
                findings.append(r)
            elif v == 'within_alloc':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW three_path_disjoint bridge failed: %s', e)
        return existing_findings


def run_rw_strided_interval3_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-StridedInterval3 桥接 (stage 95): 三元组步长区间.

    out_domain/in_domain/unknown 均为区间域画像 (冒烟实测
    out_domain 在安全场景也触发, 不可作为告警依据), 真实调用
    但不注入 findings 主列表.
    """
    if not _check_module('rw_strided_interval3', lambda: __import__(
            'modules.analysis.static.rw_innovations.strided_interval3',
            fromlist=['run_strided_interval3'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.strided_interval3 import (
            run_strided_interval3)
        run_strided_interval3(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW strided_interval3 bridge failed: %s', e)
        return existing_findings


def run_rw_dead_store_elim_tolerant_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-DeadStoreElimTolerant 桥接 (stage 96): 容忍型死存储消除.

    写槽活跃性画像 (live_slot/dead_slot), dead_slot 表示写槽被
    后续写覆盖, 属审计类证据, 真实调用但不注入主列表.
    """
    if not _check_module('rw_dead_store_elim_tolerant', lambda: __import__(
            'modules.analysis.static.rw_innovations.dead_store_elim_tolerant',
            fromlist=['run_dead_store_elim_tolerant'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.dead_store_elim_tolerant import (
            run_dead_store_elim_tolerant)
        run_dead_store_elim_tolerant(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW dead_store_elim_tolerant bridge failed: %s', e)
        return existing_findings


def run_rw_inline_copy_bind_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-InlineCopyBind 桥接 (stage 97): 内联复制绑定.

    rep movs 系列计数绑定: count_unbound (计数寄存器不可静态绑定)
    作为弱告警注入 (memory_copy); bound/count_missing 属绑定画像
    不注入.
    """
    if not _check_module('rw_inline_copy_bind', lambda: __import__(
            'modules.analysis.static.rw_innovations.inline_copy_bind',
            fromlist=['run_inline_copy_bind'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.inline_copy_bind import (
            run_inline_copy_bind)
        results = run_inline_copy_bind(pseudocode, func_name, None)
        alerts = [r for r in results if r.get('verdict') == 'count_unbound']
        if not alerts:
            return existing_findings
        return list(existing_findings) + alerts
    except Exception as e:
        logger.debug('RW inline_copy_bind bridge failed: %s', e)
        return existing_findings


def run_rw_four_verdict_scale_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-FourVerdictScale 桥接 (stage 98): 四级判决标尺.

    CONFIRMED/LIKELY/UNCERTAIN/FILTERED 为概率标尺画像 (冒烟实测
    CONFIRMED 在安全场景也出现, 是置信度标尺而非告警判定),
    真实调用但不注入 findings 主列表.
    """
    if not _check_module('rw_four_verdict_scale', lambda: __import__(
            'modules.analysis.static.rw_innovations.four_verdict_scale',
            fromlist=['run_four_verdict_scale'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.four_verdict_scale import (
            run_four_verdict_scale)
        run_four_verdict_scale(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW four_verdict_scale bridge failed: %s', e)
        return existing_findings


def run_rw_affine_meet_domain_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-AffineMeetDomain 桥接 (stage 99): 仿射交汇域.

    仿射关系交汇域画像 (affine_bounded/affine_top), 属审计类
    证据, 真实调用但不注入 findings 主列表.
    """
    if not _check_module('rw_affine_meet_domain', lambda: __import__(
            'modules.analysis.static.rw_innovations.affine_meet_domain',
            fromlist=['run_affine_meet_domain'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.affine_meet_domain import (
            run_affine_meet_domain)
        run_affine_meet_domain(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW affine_meet_domain bridge failed: %s', e)
        return existing_findings


def run_rw_delta_interval_eval_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-DeltaIntervalEval 桥接 (stage 100): 差区间极值判定.

    写区间与分配区间差: delta 下界>0 (overflow) 告警白名单注入;
    上界<0 (safe) 作为安全证据温和降权; bounded 不注入.
    """
    if not _check_module('rw_delta_interval_eval', lambda: __import__(
            'modules.analysis.static.rw_innovations.delta_interval_eval',
            fromlist=['run_delta_interval_eval'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.delta_interval_eval import (
            run_delta_interval_eval)
        results = run_delta_interval_eval(pseudocode, func_name, None)
        findings = list(existing_findings)
        for r in results:
            v = r.get('verdict')
            if v == 'overflow':
                findings.append(r)
            elif v == 'safe':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW delta_interval_eval bridge failed: %s', e)
        return existing_findings


def run_rw_write_side_first_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-WriteSideFirst 桥接 (stage 101): 写侧优先检查.

    写侧上界优先判定画像 (write_bounded/cannot_hold), cannot_hold
    仅表示无法定界 (非告警), 属审计类证据, 真实调用但
    不注入 findings 主列表.
    """
    if not _check_module('rw_write_side_first', lambda: __import__(
            'modules.analysis.static.rw_innovations.write_side_first',
            fromlist=['run_write_side_first'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.write_side_first import (
            run_write_side_first)
        run_write_side_first(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW write_side_first bridge failed: %s', e)
        return existing_findings


def run_rw_chain_id_cross_func_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-ChainIdCrossFunc 桥接 (stage 102): 跨函数链 id.

    跨函数别名链干净度画像 (chain_clean/chain_dirty), 属审计类
    证据, 真实调用但不注入 findings 主列表.
    """
    if not _check_module('rw_chain_id_cross_func', lambda: __import__(
            'modules.analysis.static.rw_innovations.chain_id_cross_func',
            fromlist=['run_chain_id_cross_func'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.chain_id_cross_func import (
            run_chain_id_cross_func)
        run_chain_id_cross_func(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW chain_id_cross_func bridge failed: %s', e)
        return existing_findings


def run_rw_heap_write_operand_cap_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-HeapWriteOperandCap 桥接 (stage 103): 写操作数容量上限.

    写操作数超容量上限 (cap_exceed) 告警白名单注入; cap_ok 作为
    安全证据温和降权同类型已有 findings.
    """
    if not _check_module('rw_heap_write_operand_cap', lambda: __import__(
            'modules.analysis.static.rw_innovations.heap_write_operand_cap',
            fromlist=['run_heap_write_operand_cap'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.heap_write_operand_cap import (
            run_heap_write_operand_cap)
        results = run_heap_write_operand_cap(pseudocode, func_name, None)
        findings = list(existing_findings)
        for r in results:
            v = r.get('verdict')
            if v == 'cap_exceed':
                findings.append(r)
            elif v == 'cap_ok':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW heap_write_operand_cap bridge failed: %s', e)
        return existing_findings


def run_rw_ir_interval_backtrack_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-IrIntervalBacktrack 桥接 (stage 104): IR 区间回溯.

    IR 层区间回溯画像 (backtraced/unknown), 属审计类证据,
    真实调用但不注入 findings 主列表.
    """
    if not _check_module('rw_ir_interval_backtrack', lambda: __import__(
            'modules.analysis.static.rw_innovations.ir_interval_backtrack',
            fromlist=['run_ir_interval_backtrace'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.ir_interval_backtrack import (
            run_ir_interval_backtrace)
        run_ir_interval_backtrace(pseudocode, func_name, None)
        return existing_findings
    except Exception as e:
        logger.debug('RW ir_interval_backtrack bridge failed: %s', e)
        return existing_findings


def run_rw_five_modal_ds_theory_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-FiveModalDSTheory 桥接 (stage 105): 五模态 D-S 证据组合.

    五模态 mass 函数 + D-S 组合: dominant=OVERFLOW (ds_overflow)
    时告警白名单注入; dominant=SAFE (ds_safe) 作为安全证据温和
    降权; ds_unknown/ds_conflict/ds_filtered 不注入.
    """
    if not _check_module('rw_five_modal_ds_theory', lambda: __import__(
            'modules.analysis.static.rw_innovations.five_modal_ds_theory',
            fromlist=['run_five_modal_ds_theory'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.five_modal_ds_theory import (
            run_five_modal_ds_theory)
        results = run_five_modal_ds_theory(pseudocode, func_name, None)
        findings = list(existing_findings)
        for r in results:
            v = r.get('verdict')
            if v == 'ds_overflow':
                findings.append(r)
            elif v == 'ds_safe':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW five_modal_ds_theory bridge failed: %s', e)
        return existing_findings


def run_rw_karr_affine_diff_bridge(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    existing_findings: List[dict],
) -> List[dict]:
    """RW-KarrAffineDiff 桥接 (stage 106): Karr 仿射差判定.

    Karr 仿射关系求差区间极值: 下界>0 (overflow) 告警白名单注入;
    上界<0 (safe) 作为安全证据温和降权; bounded 不注入.
    """
    if not _check_module('rw_karr_affine_diff', lambda: __import__(
            'modules.analysis.static.rw_innovations.karr_affine_diff',
            fromlist=['run_karr_affine_diff'])):
        return existing_findings

    try:
        from modules.analysis.static.rw_innovations.karr_affine_diff import (
            run_karr_affine_diff)
        results = run_karr_affine_diff(pseudocode, func_name, None)
        findings = list(existing_findings)
        for r in results:
            v = r.get('verdict')
            if v == 'overflow':
                findings.append(r)
            elif v == 'safe':
                _rw_apply_fp_vote(findings, r)
        return findings
    except Exception as e:
        logger.debug('RW karr_affine_diff bridge failed: %s', e)
        return existing_findings


def run_innovation_pipeline(
    pseudocode: str,
    func_name: str,
    binary_path: str,
    base_findings: List[dict],
) -> List[dict]:
    """创新模块统一入口 — 按管线顺序执行全部创新模块.

    管线顺序 (106个创新模块):
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
      23. BWR+PCST: BWR无界写恢复 + PCST按调用点参数语义表修正sized写角色与配对判定 (对已有findings过滤)
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
      --- A类14模块 (原版独立模块接入) ---
      40. PCFV: 反汇编级指针流约束验证管线 (产出新findings)
      41. TOVS: 时间序验证UAF检测 (产出新findings)
      42. MIVR: 多变量区间约束传播证明 (对已有findings过滤)
      43. FSTP: 格式说明符语义污点传播 (产出+过滤)
      44. INT-SHIFT: 整数溢出8模式汇编检测 (产出新findings)
      45. SHIELD: 三引擎堆溢出误报消减 (对已有findings过滤)
      46. INT-RANGE: 整数溢出区间分析 (产出新findings)
      47. DRIFT: 对象身份感知UAF检测 (产出新findings)
      48. FMT-SPEC: 格式说明符解析器 (产出新findings)
      49. PcWBI原版: 来源约束写界推断 (对已有findings过滤)
      50. FC-VRA原版: 流相关值域分析 (产出新findings)
      51. CACBV-DSS原版: 动态slack减除 (对已有findings增强)
      52. 轻量符号+4-Filter: patching侧堆误报过滤 (对已有findings增强)
      53. BWR原版: 有界写恢复 (对已有findings过滤)
      54. PG-WBV原版: giva分配点感知写界验证 (产出+过滤)

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
    # 阶段23: BWR+PCST — BWR无界写恢复 + PCST语义表sized写配对判定 (过滤误报)
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

    # === 阶段40-53: A类原版模块接入 (14个独立模块真实API调用) ===
    # 阶段40: PCFV — 反汇编级指针流约束验证完整管线 (产出新findings)
    findings = run_pcfv_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段41: TOVS — 时间序验证UAF检测 (产出新findings)
    findings = run_tovs_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段42: MIVR — 多变量区间约束传播证明 (对已有findings过滤)
    findings = run_mivr_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段43: FSTP — 格式说明符语义污点传播 (产出+过滤)
    findings = run_fstp_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段44: INT-SHIFT — 整数溢出8模式汇编检测 (产出新findings)
    findings = run_int_shift_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段45: SHIELD — 三引擎堆溢出误报消减 (对已有findings过滤)
    findings = run_shield_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段46: INT-RANGE — 整数溢出区间分析 (产出新findings)
    findings = run_int_range_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段47: DRIFT — 对象身份感知UAF检测 (产出新findings)
    findings = run_drift_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段48: FMT-SPEC — 格式说明符解析器 (产出新findings)
    findings = run_fmt_spec_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段49: PcWBI原版 — 来源约束写界推断 (对已有findings过滤)
    findings = run_pcwbi_orig_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段50: FC-VRA原版 — 流相关值域分析 (产出新findings)
    findings = run_fc_vra_orig_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段51: CACBV-DSS原版 — 动态slack减除 (对已有findings增强)
    findings = run_cacbv_dss_orig_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段52: 轻量符号+4-Filter — patching侧堆误报过滤 (对已有findings增强)
    findings = run_symbolic_fp_filter_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段53: BWR原版 — 有界写恢复 (对已有findings过滤)
    findings = run_bwr_orig_bridge(pseudocode, func_name, binary_path, findings)

    # === 阶段54: PG-WBV原版 (giva 抽象解释引擎级) ===
    # 阶段54: PG-WBV原版 — 分配点感知写界验证 (产出新findings + 对已有findings过滤)
    findings = run_pg_wbv_orig_bridge(pseudocode, func_name, binary_path, findings)

    # === 阶段55-106: RW文献综述代码化模块 (52个, Related Work → 代码创新) ===
    # 阶段55: RW-CallCtxSaturation — 调用点饱和度计分 (对已有findings降权)
    findings = run_rw_call_ctx_saturation_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段56: RW-LivenessRoleTemplate — 调用点参数角色模板投票 (对已有findings降权)
    findings = run_rw_liveness_role_template_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段57: RW-JccPolarityMap — 条件跳转极性图 (对已有findings降权)
    findings = run_rw_jcc_polarity_map_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段58: RW-SpecDangerProfile — 格式串说明符危险画像 (产出新findings)
    findings = run_rw_spec_danger_profile_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段59: RW-CorrelatedWrapCheck — 复合表达式相关回绕检查 (产出新findings)
    findings = run_rw_correlated_wrap_check_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段60: RW-DomFrontierWitness — 支配边界UAF误报见证 (对已有findings降权)
    findings = run_rw_dom_frontier_witness_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段61: RW-SevenStageFanout — 七阶段扇出覆盖率审计 (纯审计调用)
    findings = run_rw_seven_stage_fanout_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段62: RW-ScaledIndexLinear — scaled-index线性化 (产出+降权)
    findings = run_rw_scaled_index_linear_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段63: RW-FreedAliasEpoch — 释放别名纪元 (产出+降权)
    findings = run_rw_freed_alias_epoch_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段64: RW-RetAddrChainStitch — 返回地址链缝合 (对已有findings降权)
    findings = run_rw_ret_addr_chain_stitch_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段65: RW-EvalHarnessReplica — 端到端评估复算 (对已有findings复算降权)
    findings = run_rw_eval_harness_replica_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段66: RW-TaintSourceGrading — 污点源分级 (产出弱告警)
    findings = run_rw_taint_source_grading_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段67: RW-PtrUnionClosure — 指针并查集闭包 (对已有findings降权)
    findings = run_rw_ptr_union_closure_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段68: RW-RootIdentityKey — 根身份键判定 (对已有findings降权)
    findings = run_rw_root_identity_key_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段69: RW-SymbolicDiffSign — 符号差符号判定 (产出+降权)
    findings = run_rw_symbolic_diff_sign_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段70: RW-HeapStackGlobalTri — 堆/栈/全局三分域分类 (纯审计调用)
    findings = run_rw_heap_stack_global_tri_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段71: RW-ChainEquivHash — 溯源链等价哈希 (对已有findings降权)
    findings = run_rw_chain_equiv_hash_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段72: RW-ContractPreserveFold — 契约保持折叠 (对已有findings分组折叠)
    findings = run_rw_contract_preserve_fold_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段73: RW-DemandTriggerBudget — 按需触发预算管理 (对已有findings预算分类)
    findings = run_rw_demand_trigger_budget_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段74: RW-MinChunkGeometry — 最小块几何判定 (产出弱告警+降权)
    findings = run_rw_min_chunk_geometry_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段75: RW-RecoverySoundnessGate — 恢复可靠性门 (纯审计调用)
    findings = run_rw_recovery_soundness_gate_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段76: RW-RdataConstRegion — .rdata常量区判定 (对已有findings降权)
    findings = run_rw_rdata_const_region_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段77: RW-GuardAliasTransitive — 守卫别名传递闭包 (纯审计调用)
    findings = run_rw_guard_alias_transitive_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段78: RW-WalkStrideModel — 步长模型覆盖检查 (产出弱告警+降权)
    findings = run_rw_walk_stride_model_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段79: RW-UseDerefLattice — 解引用格模型 (产出+降权)
    findings = run_rw_use_deref_lattice_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段80: RW-ImmPropAbsorb — 立即数属性吸收 (纯审计调用)
    findings = run_rw_imm_prop_absorb_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段81: RW-CallConvDuality — 调用约定对偶校验 (纯审计调用)
    findings = run_rw_call_conv_duality_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段82: RW-WrapperGraphMatch — 包装函数图同构匹配 (纯审计调用)
    findings = run_rw_wrapper_graph_match_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段83: RW-TwoVarDiffBound — 双变量差界判定 (产出+降权)
    findings = run_rw_two_var_diff_bound_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段84: RW-ExitDominanceCheck — 出口支配UAF误报检查 (对已有findings降权)
    findings = run_rw_exit_dominance_check_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段85: RW-CrossTypeEvidencePool — 跨类型证据池 (对已有findings互证提升)
    findings = run_rw_cross_type_evidence_pool_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段86: RW-ColorClassQuad — 四色类域分类 (纯审计调用)
    findings = run_rw_color_class_quad_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段87: RW-WidenThreshold — 加宽阈值监控 (纯审计调用)
    findings = run_rw_widen_threshold_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段88: RW-FourLevelAdjudicator — 四级裁决器 (产出+降权)
    findings = run_rw_four_level_adjudicator_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段89: RW-ProvenanceOctagon — 八角域溯源 (纯审计调用)
    findings = run_rw_provenance_octagon_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段90: RW-SevenDimWeighted — 七维加权融合 (产出弱告警)
    findings = run_rw_seven_dim_weighted_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段91: RW-AbiAutoDetect — ABI自动探测 (纯审计调用)
    findings = run_rw_abi_auto_detect_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段92: RW-ReductionRateAudit — 减除率审计 (纯审计调用)
    findings = run_rw_reduction_rate_audit_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段93: RW-GuardOpEnum — 守卫操作枚举 (纯审计调用)
    findings = run_rw_guard_op_enum_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段94: RW-ThreePathDisjoint — 三路径不相交判定 (产出+降权)
    findings = run_rw_three_path_disjoint_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段95: RW-StridedInterval3 — 三元组步长区间 (纯审计调用)
    findings = run_rw_strided_interval3_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段96: RW-DeadStoreElimTolerant — 容忍型死存储消除 (纯审计调用)
    findings = run_rw_dead_store_elim_tolerant_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段97: RW-InlineCopyBind — 内联复制绑定 (产出弱告警)
    findings = run_rw_inline_copy_bind_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段98: RW-FourVerdictScale — 四级判决标尺 (纯审计调用)
    findings = run_rw_four_verdict_scale_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段99: RW-AffineMeetDomain — 仿射交汇域 (纯审计调用)
    findings = run_rw_affine_meet_domain_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段100: RW-DeltaIntervalEval — 差区间极值判定 (产出+降权)
    findings = run_rw_delta_interval_eval_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段101: RW-WriteSideFirst — 写侧优先检查 (纯审计调用)
    findings = run_rw_write_side_first_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段102: RW-ChainIdCrossFunc — 跨函数链id (纯审计调用)
    findings = run_rw_chain_id_cross_func_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段103: RW-HeapWriteOperandCap — 写操作数容量上限 (产出+降权)
    findings = run_rw_heap_write_operand_cap_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段104: RW-IrIntervalBacktrack — IR区间回溯 (纯审计调用)
    findings = run_rw_ir_interval_backtrack_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段105: RW-FiveModalDSTheory — 五模态D-S证据组合 (产出+降权)
    findings = run_rw_five_modal_ds_theory_bridge(pseudocode, func_name, binary_path, findings)

    # 阶段106: RW-KarrAffineDiff — Karr仿射差判定 (产出+降权)
    findings = run_rw_karr_affine_diff_bridge(pseudocode, func_name, binary_path, findings)

    return findings


# 创新模块探测注册表: (键名, 探测函数), 与各 bridge 入口的
# _check_module 调用保持一致. 新增 bridge 时需同步登记,
# 保证 get_innovation_status 主动探测时覆盖全部模块.
_INNOVATION_PROBES: List[Tuple[str, Any]] = [
    ('hofpr', lambda: __import__(
        'modules.exploit.src.analysis.hofpr', fromlist=['run_hofpr_pipeline'])),
    ('hfp', lambda: __import__(
        'modules.hfp.hfp_engine', fromlist=['detect_heap_overflow_hfp'])),
    ('acfpc', lambda: __import__(
        'modules.vuln.src.heap.acfpc.acfpc_pipeline',
        fromlist=['run_acfpc_pipeline'])),
    ('ddssc', lambda: __import__(
        'modules.analysis.static.ddssc_coordinator',
        fromlist=['DDSSCCoordinator'])),
    ('awsc', lambda: __import__(
        'modules.analysis.static.co_source_engine',
        fromlist=['AWSCEngine'])),
    ('cj_bvf', lambda: __import__(
        'core.cj_bvf_filter', fromlist=['filter_by_bvf'])),
    ('cj_pcbvf', lambda: __import__(
        'core.cj_pcbvf_filter', fromlist=['filter_by_pcbvf'])),
    ('uaf_hoig', lambda: __import__(
        'analysis.uaf_hoig_pipeline', fromlist=['UafHoigPipeline'])),
    ('gapsbv', lambda: __import__(
        'analysis.gapsbv_pipeline', fromlist=['detect_heap_overflow_gapsbv'])),
    ('fmtprov', lambda: __import__(
        'analysis.fmt_verifier', fromlist=['verify_fmt_candidates'])),
    ('gasri', lambda: __import__(
        'core.guard_correlator', fromlist=['correlate_write'])),
    ('uaf_enhanced', lambda: __import__(
        'core.uaf_enhanced', fromlist=['detect_uaf_enhanced'])),
    ('uaf_lifecycle', lambda: __import__(
        'core.uaf_pointer_lifecycle', fromlist=['analyze_pointer_lifecycle'])),
    ('double_free', lambda: __import__(
        'modules.core.compat.double_free', fromlist=['FreeHistory'])),
    ('buffer_underflow', lambda: __import__(
        'modules.core.compat.buffer_underflow', fromlist=['detect_buffer_underflow'])),
    ('off_by_one', lambda: __import__(
        'modules.core.compat.off_by_one', fromlist=['detect_off_by_one'])),
    ('uninit', lambda: __import__(
        'modules.core.compat.uninitialized_memory', fromlist=['InitTracker'])),
    ('intovf_enhance', lambda: __import__(
        'modules.core.compat.int_overflow_enhance',
        fromlist=['CongruenceWrapAnalyzer'])),
    ('cross_pipeline', lambda: __import__(
        'modules.core.compat.cross_pipeline_correlate',
        fromlist=['batch_correlate'])),
    ('cross_domain', lambda: __import__(
        'modules.exploit.src.analysis.cross_domain_refiner',
        fromlist=['CrossDomainRefiner'])),
    ('uaf_lifetime', lambda: __import__(
        'modules.exploit.src.analysis.uaf_lifetime_tracker',
        fromlist=['UAF_LifetimeTracker'])),
    ('provenance', lambda: __import__(
        'modules.analysis.static.heap_analysis.provenance_aware_filter',
        fromlist=['ProvenanceAwareFilter'])),
    ('bwr_pcst', lambda: __import__(
        'modules.analysis.static.bounded_write_recovery',
        fromlist=['BoundedWriteRecovery'])),
    ('dd_bvf', lambda: __import__(
        'core.cj_bvf_solver_bridge', fromlist=['try_bvf_proof'])),
    ('cacbv', lambda: __import__(
        'modules.vuln.detection.heap_analysis.acpe.verdict',
        fromlist=['evaluate', 'Verdict', 'AcpeVerdict'])),
    ('bidir_range', lambda: __import__(
        'modules.info.analysis.pointer_tracker',
        fromlist=['extract_heap_ptrs'])),
    ('acpe', lambda: __import__(
        'modules.vuln.detection.heap_analysis.acpe.equivalence',
        fromlist=['classify_pair'])),
    ('psvr_hlm', lambda: __import__(
        'modules.info.analysis.path_feasibility_check',
        fromlist=['build_path_constraints'])),
    ('dp_tvra', lambda: __import__(
        'modules.vuln.detection.heap_analysis.fp_filter_v2',
        fromlist=['evaluate_finding'])),
    ('awsc_icf', lambda: __import__(
        'modules.analysis.static.awsc_icf', fromlist=['InterproceduralCofluenceTracker'])),
    ('hofpr_apc', lambda: __import__(
        'modules.analysis.static.hofpr_apc', fromlist=['AdaptivePriorityCascade'])),
    ('pcwbi_irl', lambda: __import__(
        'modules.analysis.static.pcwbi_irl', fromlist=['InlineRepLoadModeler'])),
    ('fc_vra_pta', lambda: __import__(
        'modules.info.analysis.fc_vra_pta', fromlist=['PointerTaintAliasTracker'])),
    ('cacbv_dss', lambda: __import__(
        'modules.vuln.detection.heap_analysis.acpe.cacbv_dss',
        fromlist=['DynamicSlackSubtractor'])),
    ('biv_ctc', lambda: __import__(
        'modules.patching.src.biv_ctc', fromlist=['CrossTypeConstraintPropagator'])),
    ('si_cta', lambda: __import__(
        'modules.project.analysis.si_cta', fromlist=['CrossTypeAliasTracker'])),
    ('pg_wbv_lsa', lambda: __import__(
        'modules.analysis.static.pg_wbv_lsa', fromlist=['LoopStructureAwareVerifier'])),
    ('acpe_vrp', lambda: __import__(
        'modules.vuln.detection.heap_analysis.acpe.acpe_vrp',
        fromlist=['ValueRangePropagationEnhancer'])),
    ('acfpc_cms', lambda: __import__(
        'modules.vuln.detection.acfpc_cms', fromlist=['ConflictAwareMultiSourceFuser'])),
    ('pcfv', lambda: __import__(
        'modules.vuln.src.heap.pcfv.pipeline',
        fromlist=['analyze_heap_pcfv'])),
    ('tovs', lambda: __import__(
        'modules.vuln.src.heap.uaf_tovs.pipeline',
        fromlist=['analyze_uaf_tovs'])),
    ('mivr', lambda: __import__(
        'analysis.mivr_pipeline',
        fromlist=['detect_heap_overflow_mivr'])),
    ('fstp', lambda: __import__(
        'analysis.fmt_semantic_taint',
        fromlist=['FmtSemanticTaintPropagator'])),
    ('int_shift', lambda: __import__(
        'analysis.int_shift_impl',
        fromlist=['IntOverflowDetector'])),
    ('shield', lambda: __import__(
        'modules.vuln.src.heap.shield_orchestrator',
        fromlist=['ShieldOrchestrator'])),
    ('int_range', _probe_int_range),
    ('drift', lambda: __import__(
        'modules.vuln.src.uaf.drift_orchestrator',
        fromlist=['analyze_uaf'])),
    ('fmt_spec', lambda: __import__(
        'modules.vuln.src.format.fmt_spec_parser',
        fromlist=['parse_format_specs'])),
    ('pcwbi_orig', lambda: __import__(
        'analysis.pcwbi_impl',
        fromlist=['WriteBoundInferer'])),
    ('fc_vra_orig', _probe_fc_vra_orig),
    ('cacbv_dss_orig', lambda: __import__(
        'modules.vuln.detection.heap_analysis.acpe.cacbv_dss',
        fromlist=['DynamicSlackSubtractor'])),
    ('sym_fp_filter', lambda: __import__(
        'modules.patching.src.heap_fp_filter',
        fromlist=['HeapFPFilter'])),
    ('bwr_orig', lambda: __import__(
        'modules.analysis.static.bounded_write_recovery',
        fromlist=['BoundedWriteRecovery'])),
    ('pg_wbv_orig', lambda: __import__(
        'modules.analysis.static.heap_analysis.giva_detector',
        fromlist=['GivaScanner'])),
    ('rw_call_ctx_saturation', lambda: __import__(
        'modules.analysis.static.rw_innovations.call_ctx_saturation',
        fromlist=['run_call_ctx_saturation'])),
    ('rw_liveness_role_template', lambda: __import__(
        'modules.analysis.static.rw_innovations.liveness_role_template',
        fromlist=['run_liveness_role_template'])),
    ('rw_jcc_polarity_map', lambda: __import__(
        'modules.analysis.static.rw_innovations.jcc_polarity_map',
        fromlist=['run_jcc_polarity_map'])),
    ('rw_spec_danger_profile', lambda: __import__(
        'modules.analysis.static.rw_innovations.spec_danger_profile',
        fromlist=['run_spec_danger_profile'])),
    ('rw_correlated_wrap_check', lambda: __import__(
        'modules.analysis.static.rw_innovations.correlated_wrap_check',
        fromlist=['run_correlated_wrap_check'])),
    ('rw_dom_frontier_witness', lambda: __import__(
        'modules.analysis.static.rw_innovations.dom_frontier_witness',
        fromlist=['run_dom_frontier_witness'])),
    ('rw_seven_stage_fanout', lambda: __import__(
        'modules.analysis.static.rw_innovations.seven_stage_fanout',
        fromlist=['run_seven_stage_fanout'])),
    ('rw_scaled_index_linear', lambda: __import__(
        'modules.analysis.static.rw_innovations.scaled_index_linear',
        fromlist=['run_scaled_index_linear'])),
    ('rw_freed_alias_epoch', lambda: __import__(
        'modules.analysis.static.rw_innovations.freed_alias_epoch',
        fromlist=['run_freed_alias_epoch'])),
    ('rw_ret_addr_chain_stitch', lambda: __import__(
        'modules.analysis.static.rw_innovations.ret_addr_chain_stitch',
        fromlist=['run_ret_addr_chain_stitch'])),
    ('rw_eval_harness_replica', lambda: __import__(
        'modules.analysis.static.rw_innovations.eval_harness_replica',
        fromlist=['run_eval_harness_replica'])),
    ('rw_taint_source_grading', lambda: __import__(
        'modules.analysis.static.rw_innovations.taint_source_grading',
        fromlist=['run_taint_source_grading'])),
    ('rw_ptr_union_closure', lambda: __import__(
        'modules.analysis.static.rw_innovations.ptr_union_closure',
        fromlist=['run_ptr_union_closure'])),
    ('rw_root_identity_key', lambda: __import__(
        'modules.analysis.static.rw_innovations.root_identity_key',
        fromlist=['run_root_identity_key'])),
    ('rw_symbolic_diff_sign', lambda: __import__(
        'modules.analysis.static.rw_innovations.symbolic_diff_sign',
        fromlist=['run_symbolic_diff_sign'])),
    ('rw_heap_stack_global_tri', lambda: __import__(
        'modules.analysis.static.rw_innovations.heap_stack_global_tri',
        fromlist=['run_heap_stack_global_tri'])),
    ('rw_chain_equiv_hash', lambda: __import__(
        'modules.analysis.static.rw_innovations.chain_equiv_hash',
        fromlist=['run_chain_equiv_hash'])),
    ('rw_contract_preserve_fold', lambda: __import__(
        'modules.analysis.static.rw_innovations.contract_preserve_fold',
        fromlist=['run_contract_preserve_fold'])),
    ('rw_demand_trigger_budget', lambda: __import__(
        'modules.analysis.static.rw_innovations.demand_trigger_budget',
        fromlist=['run_demand_trigger_budget'])),
    ('rw_min_chunk_geometry', lambda: __import__(
        'modules.analysis.static.rw_innovations.min_chunk_geometry',
        fromlist=['run_min_chunk_geometry'])),
    ('rw_recovery_soundness_gate', lambda: __import__(
        'modules.analysis.static.rw_innovations.recovery_soundness_gate',
        fromlist=['run_recovery_soundness_gate'])),
    ('rw_rdata_const_region', lambda: __import__(
        'modules.analysis.static.rw_innovations.rdata_const_region',
        fromlist=['run_rdata_const_region'])),
    ('rw_guard_alias_transitive', lambda: __import__(
        'modules.analysis.static.rw_innovations.guard_alias_transitive',
        fromlist=['run_guard_alias_transitive'])),
    ('rw_walk_stride_model', lambda: __import__(
        'modules.analysis.static.rw_innovations.walk_stride_model',
        fromlist=['run_walk_stride_model'])),
    ('rw_use_deref_lattice', lambda: __import__(
        'modules.analysis.static.rw_innovations.use_deref_lattice',
        fromlist=['run_use_deref_lattice'])),
    ('rw_imm_prop_absorb', lambda: __import__(
        'modules.analysis.static.rw_innovations.imm_prop_absorb',
        fromlist=['run_imm_prop_absorb'])),
    ('rw_call_conv_duality', lambda: __import__(
        'modules.analysis.static.rw_innovations.call_conv_duality',
        fromlist=['run_call_conv_duality'])),
    ('rw_wrapper_graph_match', lambda: __import__(
        'modules.analysis.static.rw_innovations.wrapper_graph_match',
        fromlist=['run_wrapper_graph_match'])),
    ('rw_two_var_diff_bound', lambda: __import__(
        'modules.analysis.static.rw_innovations.two_var_diff_bound',
        fromlist=['run_two_var_diff_bound'])),
    ('rw_exit_dominance_check', lambda: __import__(
        'modules.analysis.static.rw_innovations.exit_dominance_check',
        fromlist=['run_exit_dominance_check'])),
    ('rw_cross_type_evidence_pool', lambda: __import__(
        'modules.analysis.static.rw_innovations.cross_type_evidence_pool',
        fromlist=['run_cross_type_evidence_pool'])),
    ('rw_color_class_quad', lambda: __import__(
        'modules.analysis.static.rw_innovations.color_class_quad',
        fromlist=['run_color_class_quad'])),
    ('rw_widen_threshold', lambda: __import__(
        'modules.analysis.static.rw_innovations.widen_threshold',
        fromlist=['run_widen_threshold'])),
    ('rw_four_level_adjudicator', lambda: __import__(
        'modules.analysis.static.rw_innovations.four_level_adjudicator',
        fromlist=['run_four_level_adjudicator'])),
    ('rw_provenance_octagon', lambda: __import__(
        'modules.analysis.static.rw_innovations.provenance_octagon',
        fromlist=['run_provenance_octagon'])),
    ('rw_seven_dim_weighted', lambda: __import__(
        'modules.analysis.static.rw_innovations.seven_dim_weighted',
        fromlist=['run_seven_dim_weighted'])),
    ('rw_abi_auto_detect', lambda: __import__(
        'modules.analysis.static.rw_innovations.abi_auto_detect',
        fromlist=['run_abi_auto_detect'])),
    ('rw_reduction_rate_audit', lambda: __import__(
        'modules.analysis.static.rw_innovations.reduction_rate_audit',
        fromlist=['run_reduction_rate_audit'])),
    ('rw_guard_op_enum', lambda: __import__(
        'modules.analysis.static.rw_innovations.guard_op_enum',
        fromlist=['run_guard_op_enum'])),
    ('rw_three_path_disjoint', lambda: __import__(
        'modules.analysis.static.rw_innovations.three_path_disjoint',
        fromlist=['run_three_path_disjoint'])),
    ('rw_strided_interval3', lambda: __import__(
        'modules.analysis.static.rw_innovations.strided_interval3',
        fromlist=['run_strided_interval3'])),
    ('rw_dead_store_elim_tolerant', lambda: __import__(
        'modules.analysis.static.rw_innovations.dead_store_elim_tolerant',
        fromlist=['run_dead_store_elim_tolerant'])),
    ('rw_inline_copy_bind', lambda: __import__(
        'modules.analysis.static.rw_innovations.inline_copy_bind',
        fromlist=['run_inline_copy_bind'])),
    ('rw_four_verdict_scale', lambda: __import__(
        'modules.analysis.static.rw_innovations.four_verdict_scale',
        fromlist=['run_four_verdict_scale'])),
    ('rw_affine_meet_domain', lambda: __import__(
        'modules.analysis.static.rw_innovations.affine_meet_domain',
        fromlist=['run_affine_meet_domain'])),
    ('rw_delta_interval_eval', lambda: __import__(
        'modules.analysis.static.rw_innovations.delta_interval_eval',
        fromlist=['run_delta_interval_eval'])),
    ('rw_write_side_first', lambda: __import__(
        'modules.analysis.static.rw_innovations.write_side_first',
        fromlist=['run_write_side_first'])),
    ('rw_chain_id_cross_func', lambda: __import__(
        'modules.analysis.static.rw_innovations.chain_id_cross_func',
        fromlist=['run_chain_id_cross_func'])),
    ('rw_heap_write_operand_cap', lambda: __import__(
        'modules.analysis.static.rw_innovations.heap_write_operand_cap',
        fromlist=['run_heap_write_operand_cap'])),
    ('rw_ir_interval_backtrack', lambda: __import__(
        'modules.analysis.static.rw_innovations.ir_interval_backtrack',
        fromlist=['run_ir_interval_backtrace'])),
    ('rw_five_modal_ds_theory', lambda: __import__(
        'modules.analysis.static.rw_innovations.five_modal_ds_theory',
        fromlist=['run_five_modal_ds_theory'])),
    ('rw_karr_affine_diff', lambda: __import__(
        'modules.analysis.static.rw_innovations.karr_affine_diff',
        fromlist=['run_karr_affine_diff'])),
]


def get_innovation_status() -> Dict[str, bool]:
    """返回各创新模块的可用性状态, 供调试与报告使用.

    _module_available 为惰性缓存, 仅当某个 bridge 首次被调用后才
    记录探测结果, 直接 import 后调用本函数会拿到不完整数据.
    这里依据 _INNOVATION_PROBES 注册表主动补全全部 106 个模块
    的探测, 保证任意时刻返回的都是全量状态.
    """
    for _name, _probe in _INNOVATION_PROBES:
        _check_module(_name, _probe)
    return dict(_module_available)
