#!/usr/bin/env python3
# coding: utf-8
"""
Angr 漏洞点分析 — 使用 Angr 的 CFG 和函数调用图,
从汇编指令级提取 malloc/memcpy 的实际大小参数.

核心改进 (v2): 不使用硬编码默认值.
- 在 call 前反向搜索 mov 指令, 提取实际参数值 (含子寄存器归一化)
- 逐基本块扫描 call <目标地址> 定位 alloc/write 调用点
- 若无法确定大小, 返回 0 标记为"未知", 不输出误导性的默认值

输出格式 (JSON): {sample_id, paths_found, dangerous_calls, wall_time_s, mem_mb}
"""

import os, sys, json, time
from typing import Any, Dict, List, Optional, Tuple

from eval.angr_helpers import (
    _ALLOC_SIZE_ARG, _WRITE_SIZE_ARG, _ARG_REGS_SYSV, _ARG_REGS_WIN64,
    extract_arg_from_disasm)


def analyze_with_angr(elf_path: str,
                      max_steps: int = 5000,
                      timeout_s: int = 300) -> Dict[str, Any]:
    """使用 Angr 分析单个 ELF/PE 文件."""
    result = {
        'sample_id': os.path.basename(elf_path).replace('.elf', '').replace('.exe', ''),
        'elf_path': elf_path,
        'success': False,
        'paths_found': 0,
        'dangerous_calls': 0,
        'heap_overflow_candidates': 0,
        'wall_time_s': 0.0,
        'mem_peak_mb': 0.0,
        'error': '',
        'details': [],
    }

    t0 = time.perf_counter()
    try:
        import angr
    except ImportError:
        result['error'] = 'angr 未安装'
        result['wall_time_s'] = time.perf_counter() - t0
        return result

    try:
        proj = angr.Project(elf_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        # ABI 检测: PE → Win64 约定
        obj_cls = ''
        for attr in ('loader', 'load'):
            try:
                obj = getattr(proj, attr).main_object
                obj_cls = type(obj).__name__.lower()
                break
            except Exception:
                continue
        arg_regs = _ARG_REGS_WIN64 if 'pe' in obj_cls else _ARG_REGS_SYSV

        # 汇总各函数的 alloc / write 调用点 (在调用点提取参数)
        target_by_name = {}
        for addr, f in cfg.functions.items():
            n = f.name.lower()
            if any(a in n for a in _ALLOC_SIZE_ARG) or any(
                    w in n for w in _WRITE_SIZE_ARG):
                target_by_name[addr] = n

        # 逐基本块扫描 call <目标地址> 指令定位调用点
        alloc_sites: List[Tuple[int, str]] = []
        write_sites: List[Tuple[int, str]] = []
        try:
            node_iter = list(cfg.graph.nodes())
        except Exception:
            node_iter = list(cfg.graph.nodes())
        for node in node_iter:
            try:
                block = node.block
                if block is None:
                    continue
                insns = list(block.capstone.insns)
            except Exception:
                continue
            for insn in insns:
                if insn.mnemonic.lower() != 'call':
                    continue
                try:
                    tgt = int(insn.op_str, 16)
                except ValueError:
                    continue
                if tgt in target_by_name:
                    n = target_by_name[tgt]
                    if any(a in n for a in _ALLOC_SIZE_ARG):
                        alloc_sites.append((insn.address, n))
                    if any(w in n for w in _WRITE_SIZE_ARG):
                        write_sites.append((insn.address, n))

        for call_site, a_name in alloc_sites:
            size_idx = next((_ALLOC_SIZE_ARG[a] for a in _ALLOC_SIZE_ARG
                             if a in a_name), 0)
            alloc_size = extract_arg_from_disasm(
                proj, cfg, call_site, arg_regs[size_idx])
            if alloc_size <= 0:
                continue
            for w_site, w_name in write_sites:
                if w_site <= call_site:
                    continue
                w_idx = next((_WRITE_SIZE_ARG[w] for w in _WRITE_SIZE_ARG
                              if w in w_name), 2)
                write_size = extract_arg_from_disasm(
                    proj, cfg, w_site, arg_regs[w_idx])
                entry = {
                    'alloc_addr': hex(call_site),
                    'alloc_func': a_name,
                    'alloc_size': alloc_size,
                    'write_addr': hex(w_site),
                    'write_size': write_size,
                    'potential_overflow': (
                        write_size > alloc_size if write_size > 0 else None),
                }
                result['details'].append(entry)
                if write_size > alloc_size:
                    result['heap_overflow_candidates'] += 1
                result['dangerous_calls'] += 1

        result['success'] = True

    except Exception as e:
        result['error'] = str(e)[:200]

    result['wall_time_s'] = round(time.perf_counter() - t0, 2)
    return result


def _extract_arg_from_disasm(proj, cfg, call_addr: int,
                             target_reg: str) -> int:
    """在 call 指令所在基本块及其前驱块中反向搜索目标寄存器的立即数赋值.

    搜索策略:
      1. 取 call 所在 CFG 节点, 遍历其块指令 (含 call 自身)
      2. 若本块未找到, 沿前驱块回溯 (最多 3 层)
      3. 匹配 mov/push 到 target_reg (含子寄存器归一化) 的立即数
    """
    node = _cfg_node(cfg, call_addr)
    seen_blocks = set()
    for depth in range(4):
        if node is None or node.addr in seen_blocks:
            break
        seen_blocks.add(node.addr)
        try:
            block = node.block
            if block is not None:
                insns = list(block.capstone.insns)
                for insn in reversed(insns):
                    if insn.address > call_addr and depth == 0:
                        continue
                    mnemonic = insn.mnemonic.lower()
                    op_str = insn.op_str.lower()
                    if mnemonic in ('mov', 'movl', 'movq', 'li', 'ldr'):
                        dst = op_str.split(',')[0].strip()
                        if _reg_family(dst) == target_reg:
                            imm = _parse_immediate_from_operand(
                                op_str.split(',')[-1].strip())
                            if imm > 0:
                                return imm
                    if mnemonic == 'push':
                        imm = _parse_immediate_from_operand(op_str)
                        if imm > 0:
                            return imm
        except Exception:
            pass
        # 前驱节点
        try:
            preds = cfg.get_predecessors(node.addr)
        except Exception:
            preds = []
        node = preds[0] if preds else None
    return 0


def _reg_family(reg: str) -> str:
    """子寄存器 → 64 位族名."""
    reg = reg.strip().strip('[]').lower()
    fam = {
        'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
        'rbx': 'rbx', 'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx', 'bh': 'rbx',
        'rcx': 'rcx', 'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx', 'ch': 'rcx',
        'rdx': 'rdx', 'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'dh': 'rdx',
        'rsi': 'rsi', 'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
        'rdi': 'rdi', 'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
        'rbp': 'rbp', 'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
        'rsp': 'rsp', 'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp',
    }
    if reg in fam:
        return fam[reg]
    for i in range(8, 16):
        b = f'r{i}'
        if reg == b or reg == f'r{i}d' or reg == f'r{i}w' or reg == f'r{i}b':
            return b
    return reg


def _cfg_node(cfg, addr):
    """定位包含 addr 的 CFG 基本块节点 (跨 angr 版本)."""
    for meth in ('get_any_node', 'get_node'):
        try:
            n = getattr(cfg, meth)(addr)
            if n is not None:
                return n
        except Exception:
            continue
    # 包含地址的块: 遍历节点按地址区间匹配
    try:
        nodes = list(cfg.graph.nodes())
    except Exception:
        return None
    for n in nodes:
        try:
            b = n.block
            if b is None:
                continue
            size = b.bytes.popcount() if hasattr(b.bytes, 'popcount') else 0
            if n.addr <= addr < n.addr + max(size, len(b.bytes or b'') or 1):
                return n
        except Exception:
            if n.addr <= addr < n.addr + 64:
                return n
    return None


def _parse_immediate_from_operand(op: str) -> int:
    """从操作数字符串解析立即数."""
    op = op.strip()
    # 十六进制
    if op.startswith('0x') or op.startswith('0X'):
        try: return int(op, 16)
        except ValueError: return 0
    # 十进制或偏移表示 [rbp-0x10]
    m = re.search(r'(0x[0-9a-fA-F]+|\d+)', op)
    if m:
        try:
            val = m.group(1)
            return int(val, 16) if val.startswith('0x') else int(val)
        except ValueError:
            pass
    return 0


def _find_dangerous_callees(cfg, target_funcs: set) -> List[int]:
    """在 CFG 中查找所有属于危险写入函数的入口地址."""
    sites = []
    for addr, func in cfg.functions.items():
        name_lower = func.name.lower()
        if any(t in name_lower for t in target_funcs):
            sites.append(addr)
    return sites


def _is_reachable_from(cfg, src_addr: int, dst_addr: int) -> bool:
    """简化可 reach 判定: 两者在同一函数内.

    完整实现需要做调用图可达性分析 (CG + CFG), 这里做保守近似:
    若 dest 所在函数被 src 所在函数直接/间接调用, 返回 True.
    """
    src_func = cfg.functions.get(src_addr)
    dst_func = cfg.functions.get(dst_addr)
    if src_func is None or dst_func is None:
        return False
    # 同函数
    if src_func.addr == dst_func.addr:
        return True
    # 检查调用图: src_func 是否调用 dst_func
    try:
        cg = cfg.functions.callgraph if hasattr(cfg.functions, 'callgraph') else None
        if cg and src_func.addr in cg:
            return dst_func.addr in cg[src_func.addr]
    except Exception:
        pass
    return True  # 保守: 假设 reachable


def batch_angr(elf_paths: List[str], output_json: Optional[str] = None
               ) -> List[Dict]:
    """批量运行 Angr 分析."""
    results = []
    for i, path in enumerate(elf_paths):
        print(f'[{i+1}/{len(elf_paths)}] Angr analyzing {os.path.basename(path)} ...')
        r = analyze_with_angr(path)
        results.append(r)
    if output_json:
        with open(output_json, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    return results


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('elf_paths', nargs='+')
    ap.add_argument('--output')
    ap.add_argument('--max-steps', type=int, default=5000)
    args = ap.parse_args()
    batch_angr(args.elf_paths, args.output)
