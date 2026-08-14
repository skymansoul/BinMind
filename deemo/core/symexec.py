# core/symexec.py - angr 符号执行接口
# FIX: 2026-08-15 结果回填 — 返回 dict 恒含 paths_found/constraints 键;
# 各阶段细粒度日志; 约束提取失败记 debug 而非静默吞掉。

import logging
from typing import Dict, List, Optional

from config import ANGR_TIMEOUT, MAX_FUNCTIONS

try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

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
