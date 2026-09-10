"""Angr 符号执行探索器 — 找出可达危险函数调用点.

方法 (对应任务定义: 利用Angr exploration找出可达危险函数调用点):
  1. CFGFast 恢复函数/调用图, 枚举危险函数 (malloc/memcpy/strcpy/
     memset/gets) 的调用点.
  2. 从入口探索 (explore), 统计实际可达的危险调用点.
  3. 判定: malloc 调用点可达 且 复制类调用点可达 → 报告危险路径.
  不做深度符号约束求解 — 与 Ghidra 启发式同为高误报对比基线,
  其固有高误报正是本文方法要压制的对象.

约定: 输出 dict: {tool, sample, findings, detected, error, time_ms,
                  reached_sites: [...]}
"""
import os
import sys
import time

from _common import try_import
angr = try_import('angr')
ANGR_OK = angr is not None

ALLOC_FUNCS = ('malloc', 'calloc', 'realloc', 'strdup')
DANGER_COPY = ('memcpy', 'memmove', 'memset', 'strcpy', 'strcat', 'gets')

_EXPLORE_STEPS = 200
_MAX_FIND = 20


def angr_scan(binary_path: str, timeout_sec: int = 60) -> dict:
    """入口探索 + 可达危险调用点统计."""
    t0 = time.time()
    result = {'tool': 'angr', 'sample': os.path.basename(binary_path),
              'findings': 0, 'detected': False, 'error': '',
              'time_ms': 0.0, 'reached_sites': []}
    if not ANGR_OK:
        result['error'] = 'angr not installed'
        result['time_ms'] = round((time.time() - t0) * 1000, 1)
        return result

    try:
        proj = angr.Project(binary_path, auto_load_libs=False,
                            load_debug_info=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=False)

# 1. 枚举危险调用点
        alloc_calls = []
        copy_calls = []
        danger_by_addr = {}
        for fn in cfg.functions.values():
            if fn.name in ALLOC_FUNCS:
                for caller in _callers_of(cfg, fn):
                    alloc_calls.append(caller)
            if fn.name in DANGER_COPY:
                for caller in _callers_of(cfg, fn):
                    copy_calls.append(caller)
        alloc_calls = list(set(alloc_calls))
        copy_calls = list(set(copy_calls))
        for a in alloc_calls:
            danger_by_addr[a] = 'alloc'
        for c in copy_calls:
            danger_by_addr[c] = 'copy'

# 2. 入口探索, 统计可达调用点
        reached = set()
        state = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state)
        find_addrs = list(danger_by_addr.keys())
        try:
            simgr.explore(find=find_addrs, num_find=_MAX_FIND,
                          step=min(_EXPLORE_STEPS, 100))
        except Exception:
            pass
        for st in simgr.found:
            try:
                reached.add(st.addr)
            except Exception:
                pass
        # 补充: 无 find 目标时用 deadended 已执行地址
        for st in list(simgr.deadended)[:50]:
            addrs = list(st.history.bbl_addrs)
            for a in addrs[-200:]:
                if a in danger_by_addr:
                    reached.add(a)

        n_alloc = sum(1 for a in reached if danger_by_addr[a] == 'alloc')
        n_copy = sum(1 for a in reached if danger_by_addr[a] == 'copy')
        result['reached_sites'] = sorted(reached)
        result['findings'] = n_alloc + n_copy
        result['detected'] = n_alloc > 0 and n_copy > 0
    except Exception as e:  # noqa: BLE001
        result['error'] = repr(e)[:200]
    result['time_ms'] = round((time.time() - t0) * 1000, 1)
    return result


def _callers_of(cfg, fn):
    """返回调用 fn 的调用点地址列表."""
    cg = getattr(cfg.functions, 'callgraph', None)
    if cg is not None:
        try:
            return list(cg.predecessors(fn.addr))
        except Exception:
            return []
    return []


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: python angr_explorer.py <binary>')
        sys.exit(1)
    import json
    print(json.dumps(angr_scan(sys.argv[1])))
