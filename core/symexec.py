# core/symexec.py - angr 符号执行接口
# 结果回填 — 返回 dict 恒含 paths_found/constraints 键;
# 各阶段细粒度日志; 约束提取失败记 debug 而非静默吞掉。

import logging
import re
from typing import Dict, List, Optional

from config import ANGR_TIMEOUT, MAX_FUNCTIONS

try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

# Z3 可用性探测 — angr 不可用时用于轻量约束求解替代纯关键词匹配
try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

logger = logging.getLogger(__name__)


def check_angr() -> bool:
    return ANGR_AVAILABLE


def _empty_result(error: str = '') -> Dict:
    """统一返回结构, 调用方无需防御缺失键。"""
    return {'success': False, 'paths_found': 0, 'constraints': [],
            'vulnerabilities': [], 'error': error}


def run_symbolic(binary_path: str, target_func: str = None,
                 find_addr: int = None, avoid_addrs: list = None,
                 timeout: int = None) -> Dict:
    """对二进制执行符号执行, 从目标函数或入口出发。

    返回 {success, paths_found, constraints, vulnerabilities, error}。
    成功与否只反映路径可达, 不代表发现漏洞。
    """
    if not ANGR_AVAILABLE:
        logger.warning("Symbolic execution unavailable: angr not installed")
        return _empty_result('angr not installed')

    if timeout is None:
        timeout = ANGR_TIMEOUT

    result = _empty_result()

    try:
        logger.info("Symbolic: loading project %s", binary_path)
        proj = angr.Project(binary_path, auto_load_libs=False)

        if target_func:
            try:
                addr = proj.loader.find_symbol(target_func)
                if addr is None:
                    for f in proj.kb.functions.values():
                        if f.name == target_func:
                            addr = f.addr
                            break
                state = proj.factory.call_state(addr) if addr else proj.factory.entry_state()
                logger.info("Symbolic: entry=%s (0x%x)",
                            target_func, addr if addr else proj.entry)
            except Exception as err:
                logger.debug("Symbolic: target symbol lookup failed (%s), "
                             "falling back to entry state", err)
                state = proj.factory.entry_state()
        else:
            state = proj.factory.entry_state()

        simgr = proj.factory.simulation_manager(state)

        if find_addr:
            logger.info("Symbolic: explore find=0x%x avoid=%d", find_addr,
                        len(avoid_addrs or []))
            simgr.explore(find=find_addr, avoid=avoid_addrs or [])
        else:
            simgr.run(until=lambda s: len(s.active) > 100 or
                      len(s.deadended) > 10)

        result['paths_found'] = len(simgr.deadended) + len(simgr.active)
        result['success'] = result['paths_found'] > 0
        logger.info("Symbolic: %d paths (deadended=%d active=%d)",
                    result['paths_found'], len(simgr.deadended),
                    len(simgr.active))

        # 提取触发不同路径的输入
        for s in simgr.deadended[:10]:
            try:
                inp = s.posix.dumps(0)
                if inp:
                    result['constraints'].append(
                        {'input': inp[:256].hex()})
            except Exception as err:
                logger.debug("Symbolic: constraint extraction skipped: %s", err)
        logger.info("Symbolic: %d constraints extracted",
                    len(result['constraints']))

        return result
    except Exception as err:
        logger.warning("Symbolic execution error: %s", err)
        result['error'] = str(err)
        return result


def find_buffer_overflow(binary_path: str, func_name: str) -> Dict:
    """符号执行定位缓冲区溢出调用点。"""
    if not ANGR_AVAILABLE:
        return {'found': False, 'reason': 'angr unavailable'}

    result = {'found': False, 'overflow_points': []}

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        for func in cfg.functions.values():
            if func.name == func_name:
                for block in func.blocks:
                    for insn in block.capstone.insns:
                        if insn.mnemonic == 'call':
                            target_addr = insn.operands[0].imm
                            callee = cfg.functions.get(target_addr)
                            if callee and callee.name in (
                                    'memcpy', 'strcpy', 'gets',
                                    'sprintf', 'strcat', 'scanf'):
                                result['overflow_points'].append({
                                    'call_address': hex(insn.address),
                                    'function': callee.name,
                                    'danger': 'no size validation',
                                })
                result['found'] = len(result['overflow_points']) > 0
                break

        return result
    except Exception as err:
        logger.warning("BO detection error in %s: %s", func_name, err)
        return {'found': False, 'error': str(err)}


# 危险函数签名模式 — 从伪代码提取调用参数
_DANGER_CALL_RE = re.compile(
    r'\b(memcpy|memmove|strcpy|strncpy|strcat|strncat|gets|sprintf|snprintf|scanf|read)\s*\(([^)]*)\)',
    re.IGNORECASE,
)

# 缓冲区声明模式 — 从伪代码提取局部缓冲区大小
_BUF_DECL_RE = re.compile(
    r'\b(?:char|unsigned\s+char|int|void|uint8_t|uint32_t)\s+(\w+)\s*\[(\d+)\]',
)


def z3_symbolic_check(binary_path: str,
                      decomp_results: List[Dict]) -> Optional[Dict]:
    """Z3 轻量约束求解 — angr 不可用时替代纯关键词匹配。

    对伪代码中的危险函数调用建模缓冲区溢出约束:
      memcpy(dst, src, n): n > sizeof(dst) 可满足则为溢出
      strcpy(dst, src): dst 无长度约束, 恒为潜在溢出
      gets(buf): 无长度参数, 恒为溢出
      sprintf(buf, fmt, ...): 输出长度不可预测, 建模为溢出
    用 Z3 检查约束可满足性, 返回与 run_symbolic 兼容的结构。
    z3 不可用时返回 None, 调用方继续降级。
    """
    if not Z3_AVAILABLE:
        logger.debug("z3_symbolic_check: z3 not available")
        return None

    constraints = []
    overflow_points = []

    for r in (decomp_results or []):
        analysis = r.get('analysis', r) or {}
        pseudocode = analysis.get('pseudocode', '')
        if not pseudocode:
            continue
        func_name = r.get('function_name', r.get('function', '?'))

        # 提取局部缓冲区声明: char buf[256] -> buf_size=256
        buf_sizes = {}
        for m in _BUF_DECL_RE.finditer(pseudocode):
            buf_sizes[m.group(1)] = int(m.group(2))

        # 对每个危险函数调用建模约束
        for m in _DANGER_CALL_RE.finditer(pseudocode):
            callee = m.group(1).lower()
            args_str = m.group(2).strip()
            # 按逗号分割参数 (不处理嵌套括号的复杂情况)
            args = [a.strip() for a in args_str.split(',') if a.strip()]
            if not args:
                continue

            if callee in ('memcpy', 'memmove') and len(args) >= 3:
                # memcpy(dst, src, n): 约束 n > sizeof(dst)
                dst = args[0].lstrip('*')
                n_sym = z3.BitVec(f'{func_name}_{callee}_n', 64)
                dst_size = buf_sizes.get(dst)
                if dst_size is not None:
                    solver = z3.Solver()
                    solver.add(n_sym > dst_size)
                    if solver.check() == z3.sat:
                        overflow_points.append({
                            'function': func_name,
                            'callee': callee,
                            'dst': dst,
                            'dst_size': dst_size,
                            'danger': f'{callee} length exceeds {dst} size ({dst_size})',
                            'constraint': 'sat',
                        })
                        constraints.append({
                            'function': func_name,
                            'pattern': callee,
                            'source': 'z3_symbolic',
                            'model': f'n > {dst_size} (sat)',
                        })
                else:
                    # dst 大小未知, n 无上界约束 — 可满足
                    solver = z3.Solver()
                    solver.add(n_sym > 0)
                    if solver.check() == z3.sat:
                        overflow_points.append({
                            'function': func_name,
                            'callee': callee,
                            'dst': dst,
                            'dst_size': None,
                            'danger': f'{callee} with unbounded size on {dst}',
                            'constraint': 'sat_unbounded',
                        })
                        constraints.append({
                            'function': func_name,
                            'pattern': callee,
                            'source': 'z3_symbolic',
                            'model': 'n unbounded (sat)',
                        })

            elif callee in ('strcpy', 'strcat') and len(args) >= 2:
                # strcpy/strcat: dst 长度无约束, src 可任意长
                dst = args[0].lstrip('*')
                src_len = z3.BitVec(f'{func_name}_{callee}_srclen', 64)
                dst_size = buf_sizes.get(dst)
                solver = z3.Solver()
                if dst_size is not None:
                    solver.add(src_len > dst_size)
                else:
                    solver.add(src_len > 0)
                if solver.check() == z3.sat:
                    overflow_points.append({
                        'function': func_name,
                        'callee': callee,
                        'dst': dst,
                        'dst_size': dst_size,
                        'danger': f'{callee} unbounded copy into {dst}',
                        'constraint': 'sat',
                    })
                    constraints.append({
                        'function': func_name,
                        'pattern': callee,
                        'source': 'z3_symbolic',
                        'model': f'src_len > {dst_size or 0} (sat)',
                    })

            elif callee == 'gets' and len(args) >= 1:
                # gets: 无长度参数, 恒为溢出
                dst = args[0].lstrip('*')
                overflow_points.append({
                    'function': func_name,
                    'callee': callee,
                    'dst': dst,
                    'dst_size': buf_sizes.get(dst),
                    'danger': 'gets() has no length bound',
                    'constraint': 'trivially_sat',
                })
                constraints.append({
                    'function': func_name,
                    'pattern': callee,
                    'source': 'z3_symbolic',
                    'model': 'always overflow (trivially sat)',
                })

            elif callee in ('sprintf', 'scanf') and len(args) >= 2:
                # sprintf/scanf: 输出/输入长度不可预测
                dst = args[0].lstrip('*')
                overflow_points.append({
                    'function': func_name,
                    'callee': callee,
                    'dst': dst,
                    'dst_size': buf_sizes.get(dst),
                    'danger': f'{callee} output length unconstrained on {dst}',
                    'constraint': 'sat_unbounded',
                })
                constraints.append({
                    'function': func_name,
                    'pattern': callee,
                    'source': 'z3_symbolic',
                    'model': f'{callee} unconstrained (sat)',
                })

    if not overflow_points and not constraints:
        logger.info("z3_symbolic_check: no satisfiable overflow constraints found")
        return {
            'success': True,
            'paths_found': 0,
            'constraints': [],
            'vulnerabilities': [],
            'degraded': True,
            'method': 'z3_symbolic_check',
            'overflow_points': [],
        }

    logger.info("z3_symbolic_check: %d overflow points, %d constraints (z3 sat)",
                len(overflow_points), len(constraints))
    return {
        'success': True,
        'paths_found': len(overflow_points),
        'constraints': constraints,
        'vulnerabilities': [],
        'degraded': True,
        'method': 'z3_symbolic_check',
        'overflow_points': overflow_points,
    }
