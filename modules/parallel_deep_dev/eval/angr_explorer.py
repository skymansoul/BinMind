"""Angr 探索器 — 调用图可达的危险函数调用点分析。

对 PE/ELF 二进制构建 CFGFast + 函数调用图, 从入口按调用图 BFS,
统计可达的危险函数调用点数量。危险函数按名称匹配(外部桩保留
导入名, 兼容 stripped 二进制)。未安装 angr 时返回 skipped。
"""

import logging
import os
import sys
import threading
import time
from pathlib import Path

DANGER = ['memcpy', 'memmove', 'memset', 'strcpy', 'strncpy', 'strcat',
          'sprintf', 'snprintf', 'gets', 'read', 'recv', 'fread',
          'malloc', 'calloc', 'realloc', 'free']

try:
    import angr  # noqa: F401
    logging.getLogger('angr').setLevel(logging.ERROR)
    ANGR_OK = True
except ImportError:
    ANGR_OK = False


_ANGR_LOCK = threading.Lock()  # cle/angr 非线程安全: 实例构建串行化


def angr_explore(binary_path: str, timeout_sec: int = 180) -> dict:
    """返回 {tool, sample, success, reached_sites, duration_sec, error}。

    reached_sites = 从入口经调用图可达的危险函数调用点数。
    """
    t0 = time.time()
    base = {'tool': 'Angr', 'sample': os.path.basename(binary_path)}
    if not ANGR_OK:
        return {**base, 'success': False, 'reached_sites': 0,
                'duration_sec': 0.0, 'error': 'angr not installed'}
    if not Path(binary_path).exists():
        return {**base, 'success': False, 'reached_sites': 0,
                'duration_sec': 0.0, 'error': 'binary missing'}
    try:
        with _ANGR_LOCK:
            proj = angr.Project(binary_path, auto_load_libs=False)
            cfg = proj.analyses.CFGFast()
            danger_addrs = _danger_function_addrs(proj, cfg)
            call_sites = _danger_call_sites(cfg, danger_addrs)
            reached = _reachable_from_entry(proj, cfg, call_sites)
        return {**base, 'success': True, 'reached_sites': reached,
                'duration_sec': round(time.time() - t0, 3), 'error': ''}
    except Exception as e:
        return {**base, 'success': False, 'reached_sites': 0,
                'duration_sec': round(time.time() - t0, 3),
                'error': str(e)[:200]}


def _danger_function_addrs(proj, cfg) -> set:
    """名称匹配危险函数(含保留符号的外部桩与 CRT 包装)。"""
    addrs = set()
    for addr, f in cfg.functions.items():
        name = f.name.split('@')[0]
        if name in DANGER:
            addrs.add(addr)
    for name in DANGER:
        sym = proj.loader.find_symbol(name)
        if sym is not None:
            addrs.add(sym.rebased_addr)
    return addrs


def _danger_call_sites(cfg, danger_addrs: set) -> set:
    """调用危险函数的用户函数地址(排除危险函数自身, 消除 CRT 包装噪声)。"""
    cg = cfg.functions.callgraph
    sites = set()
    for daddr in danger_addrs:
        for caller in cg.predecessors(daddr):
            if caller not in danger_addrs:
                sites.add(caller)
    return sites


def _reachable_from_entry(proj, cfg, call_sites: set) -> int:
    if not call_sites:
        return 0
    cg = cfg.functions.callgraph
    entry_f = cfg.functions.get(proj.entry)
    if entry_f is None:
        return len(call_sites)  # 入口未知时保守返回全部
    visited = {entry_f.addr}
    queue = [entry_f.addr]
    reached = set()
    while queue:
        cur = queue.pop(0)
        if cur in call_sites:
            reached.add(cur)
        for succ in cg.successors(cur):
            if succ not in visited:
                visited.add(succ)
                queue.append(succ)
    return len(reached)


def scan_batch(binaries: list, timeout_sec: int = 180) -> list:
    return [angr_explore(b, timeout_sec) for b in binaries]


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: angr_explorer.py <binary> [binary ...]')
        sys.exit(1)
    import json
    print(json.dumps(scan_batch(sys.argv[1:]), indent=2))
