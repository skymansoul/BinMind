"""
控制流图提取器: 从 radare2 或 angr 获取函数级 CFG。
支持基本块粒度 (起始地址、指令数、后继块) 与函数级调用图, 可导出 JSON / DOT / 结构化 dict;
供 LLM 上下文增强、可视化报告与相似性分析使用。
回退链: angr CFGEmulated (精确但慢) - angr CFGFast - radare2 agfj (始终可用但信息量较少)。
"""

import json
import logging
import os
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

from core.cfg_extractor_r2 import (
    extract_cfg_r2 as _extract_cfg_r2,
    cfg_to_dot,
)

_log = logging.getLogger(__name__)

def extract_cfg(
    binary_path: str,
    func_name: Optional[str] = None,
    method: str = 'angr_fast',
    max_funcs: int = 20,
) -> Dict[str, Any]:
    """
    提取二进制文件或指定函数的控制流图。method 取 'angr_fast' | 'angr_accurate' | 'r2', func_name 为 None 时提取全部函数的调用图, max_funcs 限制函数数。

    返回结构: {'binary', 'functions': [{'name', 'addr', 'blocks': [{'addr', 'size', 'successors'}], 'callees'}], 'call_graph'}。
    """
    if not os.path.isfile(binary_path):
        return {'binary': binary_path, 'error': 'file not found', 'functions': []}

    if method.startswith('angr'):
        return _extract_cfg_angr(binary_path, func_name, max_funcs,
                                 accurate=method == 'angr_accurate')

    return _extract_cfg_r2(binary_path, func_name, max_funcs)

def _extract_cfg_angr(
    binary_path: str,
    func_name: Optional[str],
    max_funcs: int,
    accurate: bool = False,
) -> Dict[str, Any]:
    """通过 angr 提取 CFG。"""
    result: Dict[str, Any] = {
        'binary': binary_path,
        'method': 'angr_accurate' if accurate else 'angr_fast',
        'functions': [],
        'call_graph': {},
    }

    try:
        import angr
    except ImportError:
        _log.debug("angr unavailable for CFG extraction")
        return _extract_cfg_r2(binary_path, func_name, max_funcs)

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)

        if accurate and func_name:
            cfg = proj.analyses.CFGEmulated(
                fail_fast=True,
                starts=[_find_func_addr(proj, func_name)],
            )
        else:
            cfg = proj.analyses.CFGFast()

        call_graph: Dict[str, List[str]] = {}

        funcs_to_extract: List = []
        if func_name:
            for f in cfg.functions.values():
                if f.name == func_name:
                    funcs_to_extract.append(f)
                    break
        else:
            funcs_to_extract = sorted(
                cfg.functions.values(),
                key=lambda f: -f.size,
            )[:max_funcs]

        for func in funcs_to_extract:
            blocks = []
            callees: Set[str] = set()

            for block_addr in func.block_addrs_set:
                try:
                    node = cfg.model.get_any_node(block_addr)
                    successors = []
                    if node and node.successors:
                        successors = [s.addr for s in node.successors]
                    blocks.append({
                        'addr': block_addr,
                        'size': func.get_block_size(block_addr),
                        'successors': successors,
                    })
                except Exception:
                    blocks.append({
                        'addr': block_addr,
                        'size': 0,
                        'successors': [],
                    })

            # 收集被调用函数
            for block_addr in func.block_addrs_set:
                try:
                    block = proj.factory.block(block_addr)
                    for insn in block.capstone.insns:
                        if insn.mnemonic == 'call':
                            target = insn.operands[0].imm
                            target_func = cfg.functions.get(target)
                            if target_func and target_func.name:
                                callees.add(target_func.name)
                except Exception:
                    pass

            result['functions'].append({
                'name': func.name,
                'addr': func.addr,
                'size': func.size,
                'blocks': blocks,
                'callees': sorted(callees),
            })
            call_graph[func.name] = sorted(callees)

        result['call_graph'] = call_graph
        return result

    except Exception as e:
        _log.debug("angr CFG extraction failed: %s", e)
        return _extract_cfg_r2(binary_path, func_name, max_funcs)

def _find_func_addr(proj, func_name: str) -> int:
    """在 angr 项目中查找函数地址。"""
    for f in proj.kb.functions.values():
        if f.name == func_name:
            return f.addr
    # 尝试符号表
    sym = proj.loader.find_symbol(func_name)
    if sym:
        return sym.rebased_addr
    return proj.entry

def cfg_summary_for_llm(cfg_data: Dict[str, Any], func_name: str) -> str:
    """生成 CFG 的文本摘要供 LLM prompt 消费, 将控制流结构压缩为紧凑文本表示。参数为 extract_cfg() 返回值与目标函数名。"""
    for func in cfg_data.get('functions', []):
        if func['name'] != func_name:
            continue

        blocks = func.get('blocks', [])
        n_blocks = len(blocks)
        n_edges = sum(len(b.get('successors', [])) for b in blocks)

        # 检测循环（自循环或后向边）
        loops = 0
        addrs = {b['addr'] for b in blocks}
        for b in blocks:
            for succ in b.get('successors', []):
                if succ <= b['addr'] and succ in addrs:
                    loops += 1

        callees = func.get('callees', [])
        dangerous = [c for c in callees if c in (
            'system', 'execve', 'strcpy', 'gets', 'printf', 'memcpy',
        )]

        parts = [f"CFG: {n_blocks} blocks, {n_edges} edges"]
        if loops:
            parts.append(f"{loops} back-edges (possible loops)")
        if dangerous:
            parts.append(f"dangerous calls: {', '.join(dangerous)}")
        if callees:
            parts.append(f"all callees ({len(callees)}): {', '.join(callees[:10])}")

        return '; '.join(parts)

    return f"(CFG for {func_name} not found)"
