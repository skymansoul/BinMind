"""
Symbolic execution interface via angr. The engine is optional —
the tool functions without it, but symbolic execution enables
deeper path exploration and constraint solving.
"""

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


def run_symbolic(binary_path: str, target_func: str = None,
                 find_addr: int = None, avoid_addrs: list = None,
                 timeout: int = None) -> Dict:
    """
    Perform symbolic execution on a binary starting from a target
    function or the entry point. Returns {success, paths_found,
    constraints, vulnerabilities}.
    """
    if not ANGR_AVAILABLE:
        return {'success': False, 'error': 'angr not installed'}

    if timeout is None:
        timeout = ANGR_TIMEOUT

    result = {
        'success': False,
        'paths_found': 0,
        'constraints': [],
        'vulnerabilities': [],
    }

    try:
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
            except Exception:
                state = proj.factory.entry_state()
        else:
            state = proj.factory.entry_state()

        simgr = proj.factory.simulation_manager(state)

        if find_addr:
            simgr.explore(find=find_addr, avoid=avoid_addrs or [])
        else:
            simgr.run(until=lambda s: len(s.active) > 100 or
                      len(s.deadended) > 10)

        result['paths_found'] = len(simgr.deadended) + len(simgr.active)
        result['success'] = result['paths_found'] > 0

        # extract inputs that trigger different paths
        for s in simgr.deadended[:10]:
            try:
                inp = s.posix.dumps(0)
                if inp:
                    result['constraints'].append(
                        {'input': inp[:256].hex()})
            except Exception:
                pass

        return result
    except Exception as err:
        logger.warning("Symbolic execution error: %s", err)
        return {'success': False, 'error': str(err)}


def find_buffer_overflow(binary_path: str, func_name: str) -> Dict:
    """Try to find buffer overflow conditions via symbolic execution."""
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
