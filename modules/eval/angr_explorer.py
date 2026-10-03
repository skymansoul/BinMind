"""
Angr exploration 模式漏洞点分析 — 符号执行搜索危险函数可达路径.

合并说明 (BinMind/eval ↔ deemo/modules/eval 两个版本功能合并):
  - BinMind/eval 版: explore() — CFGFast 调用点枚举, 输出危险调用明细
    reachable_calls (caller/callee/call_addr), 字段 time_ms.
  - deemo/modules/eval 版: angr_scan() — 符号执行 exploration
    (find 危险函数入口) + CFG 调用计数回退, 输出 success/findings/
    reached/duration_sec, 供 run_benchmark 汇总为 unavailable.
  - 两份常量表 _DANGEROUS / DANGER_FUNCS 与辅助函数全部保留.
  - CLI 输出合并字典, 同时满足两个 run_benchmark 消费者的字段需求;
    明细行打到 stderr, 保持 stdout 为纯 JSON (deemo 端 json.loads 解析).

以 angr 的 CFGFast + 符号执行 exploration 找出二进制中
可达的堆危险函数调用点 (memcpy/malloc/free 等). 输出统一
dict 结构供 run_benchmark 消费: tool/sample/success/
findings/duration_sec. 环境缺失 angr 时降级: 返回 success=False
+ error 字段, 由 run_benchmark 汇总为 "unavailable" 而非崩溃.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Dict, List, Optional

_DANGEROUS = {"memcpy", "memmove", "strcpy", "strncpy", "strcat",
              "sprintf", "snprintf", "read", "fread", "recv", "memset"}

DANGER_FUNCS = [
    'strcpy', 'strcat', 'sprintf', 'gets', 'scanf', 'memcpy',
    'memmove', 'free', 'malloc', 'calloc', 'realloc', 'printf',
]

try:
    import angr
    ANGR_OK = True
except ImportError:
    ANGR_OK = False


def explore(binary: str, timeout: int = 60) -> dict:
    """[BinMind/eval 版] CFGFast 危险调用点枚举, 输出 reachable_calls 明细."""
    t0 = time.perf_counter()
    try:
        import angr
    except ImportError:
        return {"tool": "angr", "findings": 0, "reachable_calls": [],
                "time_ms": 0, "error": "angr not installed"}

    proj = angr.Project(binary, auto_load_libs=False)
    findings = []
    try:
        cfg = proj.analyses.CFGFast()
        for func in cfg.functions.values():
            for call in func.get_call_sites():
                target = func.get_call_target(call)
                if target is None:
                    continue
                callee = cfg.functions.get(target, None)
                name = callee.name if callee else f"0x{target:x}"
                if any(d in name for d in _DANGEROUS):
                    findings.append({
                        "caller": func.name,
                        "caller_addr": func.addr,
                        "callee": name,
                        "call_addr": call,
                    })
    except Exception as e:
        return {"tool": "angr", "findings": 0, "reachable_calls": [],
                "time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "error": f"{type(e).__name__}: {e}"}

    return {
        "tool": "angr",
        "findings": len(findings),
        "reachable_calls": findings[:50],
        "time_ms": round((time.perf_counter() - t0) * 1000, 2),
    }


def angr_scan(binary_path: str, timeout_sec: int = 180) -> Dict:
    """[deemo/modules/eval 版] 符号执行 exploration + CFG 回退, 供 benchmark 消费."""
    if not ANGR_OK:
        return {
            'tool': 'angr',
            'sample': os.path.basename(binary_path),
            'success': False,
            'error': 'angr not installed',
            'findings': 0,
            'duration_sec': 0.0,
        }
    t0 = time.time()
    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        findings = 0
        reached: List[str] = []
        try:
            state = proj.factory.blank_state(addr=proj.entry)
            simgr = proj.factory.simulation_manager(state)
            found = simgr.explore(
                find=lambda s: _is_danger_addr(s, proj),
                num_find=20)
            findings = len(found.found)
            reached = [_addr_label(s.addr, proj) for s in found.found[:5]]
        except Exception:
            pass
        if findings == 0:
            # 符号执行受限时回退到 CFG 静态统计
            for func in cfg.functions.values():
                for blk in func.blocks:
                    for insn in blk.capstone.insns:
                        if insn.mnemonic == 'call':
                            try:
                                tgt = insn.operands[0].imm
                                fn = cfg.functions.get(tgt)
                                if fn and fn.name in DANGER_FUNCS:
                                    findings += 1
                            except Exception:
                                pass
        dt = time.time() - t0
        return {
            'tool': 'angr',
            'sample': os.path.basename(binary_path),
            'success': True,
            'findings': findings,
            'reached': reached,
            'duration_sec': round(dt, 2),
        }
    except Exception as e:
        return {
            'tool': 'angr',
            'sample': os.path.basename(binary_path),
            'success': False,
            'error': str(e)[:200],
            'findings': 0,
            'duration_sec': round(time.time() - t0, 2),
        }


def _is_danger_addr(state, proj) -> bool:
    """判断当前状态地址是否为危险函数入口."""
    try:
        sym = proj.loader.find_symbol(state.addr)
        return bool(sym and sym.name in DANGER_FUNCS)
    except Exception:
        return False


def _addr_label(addr: int, proj) -> str:
    try:
        sym = proj.loader.find_symbol(addr)
        if sym:
            return f'{sym.name}@{addr:#x}'
    except Exception:
        pass
    return f'{addr:#x}'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--timeout", type=int, default=60)
    args = ap.parse_args()
    r = angr_scan(args.binary, args.timeout)
    detail = explore(args.binary, args.timeout)
    merged = dict(r)
    merged['reachable_calls'] = detail.get('reachable_calls', [])
    merged['time_ms'] = detail.get('time_ms', 0)
    if not merged.get('error'):
        merged['error'] = detail.get('error')
    print(json.dumps(merged, ensure_ascii=False, indent=2))
    for c in merged['reachable_calls']:
        print(f"  {c['caller']} @ 0x{c['call_addr']:x} -> {c['callee']}",
              file=sys.stderr)


if __name__ == "__main__":
    main()