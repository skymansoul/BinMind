"""
控制流图提取器 —— 从 radare2 或 angr 获取函数级 CFG。

输出边列表格式（源块→目标块），支持:
  - 基本块粒度: 每个基本块的起始地址、指令数、后继块列表
  - 函数级聚合: 调用图（哪些函数调用了哪些函数）
  - 导出格式: JSON / DOT (Graphviz) / 结构化 dict

用于: LLM 上下文增强（在 prompt 中提供函数控制流结构），
     可视化报告生成，以及相似性分析的特征输入。

两层回退: angr CFGEmulated（精确但慢）→ angr CFGFast（快速但可能
遗漏间接调用）→ radare2 agfj（始终可用但信息量较少）。

参考:
  - Shoshitaishvili et al., 2016, IEEE S&P, "SOK: (State of) The Art of War"
  - Yakdan et al., 2015, USENIX Security, "No More Gotos: Decompilation Using
    Pattern-Independent Control-Flow Structuring"
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

from config import R2_PATH

_log = logging.getLogger(__name__)


def extract_cfg(
    binary_path: str,
    func_name: Optional[str] = None,
    method: str = 'angr_fast',
    max_funcs: int = 20,
) -> Dict[str, Any]:
    """
    提取二进制文件或指定函数的控制流图。

    Args:
        binary_path: ELF 文件路径
        func_name:   目标函数名，None 表示提取所有函数的调用图
        method:      提取方法 'angr_fast' | 'angr_accurate' | 'r2'
        max_funcs:   最大函数数（仅当 func_name=None 时生效）

    Returns:
        {
            'binary': str,
            'functions': [
                {
                    'name': str,
                    'addr': int,
                    'blocks': [{'addr': int, 'size': int, 'successors': [int]}],
                    'callees': [str],
                }
            ],
            'call_graph': {'caller': [callee_list]},
        }
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
            for ref in (proj.kb.xrefs.get_xrefs_by_ins_addr(f.addr) or []):
                pass  # xrefs 在 CFGFast 中可能不完整

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


def _extract_cfg_r2(
    binary_path: str,
    func_name: Optional[str],
    max_funcs: int,
) -> Dict[str, Any]:
    """通过 radare2 提取 CFG。"""
    result: Dict[str, Any] = {
        'binary': binary_path,
        'method': 'r2',
        'functions': [],
        'call_graph': {},
    }

    try:
        if func_name:
            # 单个函数的详细 CFG
            proc = subprocess.run(
                [R2_PATH, '-q', '-e', 'io.color=false',
                 '-c', f's {func_name}', '-c', 'agfj', binary_path],
                capture_output=True, text=True, timeout=30,
            )
            try:
                data = json.loads(proc.stdout)
                if isinstance(data, list):
                    data = data[0] if data else {}
                blocks = []
                for block in data.get('blocks', []):
                    blocks.append({
                        'addr': block.get('offset', 0),
                        'size': block.get('size', 0),
                        'successors': [
                            j.get('offset', 0) for j in block.get('jump', 0)
                        ] if isinstance(block.get('jump'), list) else [],
                    })
                result['functions'].append({
                    'name': func_name,
                    'addr': data.get('offset', 0),
                    'size': data.get('size', 0),
                    'blocks': blocks,
                    'callees': [],
                })
            except (json.JSONDecodeError, KeyError):
                pass
        else:
            # 批量提取: 仅获取函数调用关系
            proc = subprocess.run(
                [R2_PATH, '-q', '-e', 'io.color=false',
                 '-c', 'afl', '-c', 'agj', binary_path],
                capture_output=True, text=True, timeout=30,
            )
            try:
                data = json.loads(proc.stdout)
                if isinstance(data, list):
                    for func_node in data[:max_funcs]:
                        result['functions'].append({
                            'name': func_node.get('name', ''),
                            'addr': func_node.get('offset', 0),
                            'size': func_node.get('size', 0),
                            'blocks': [],
                            'callees': [],
                        })
            except json.JSONDecodeError:
                pass

    except Exception as e:
        _log.debug("r2 CFG extraction failed: %s", e)

    return result


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


def cfg_to_dot(cfg_data: Dict[str, Any], func_name: str = '') -> str:
    """
    将 CFG 数据转为 Graphviz DOT 格式。

    Args:
        cfg_data: extract_cfg() 的返回值
        func_name: 要渲染的函数名（空字符串 = 渲染调用图）

    Returns:
        DOT 格式字符串
    """
    lines = ['digraph CFG {', '  rankdir=TB;', '  node [shape=box];']

    for func in cfg_data.get('functions', []):
        if func_name and func['name'] != func_name:
            continue

        lines.append(f'  // Function: {func["name"]}')
        for block in func.get('blocks', []):
            addr = block['addr']
            label = f'{func["name"]}\\n{addr:#x}'
            lines.append(
                f'  n_{addr:x} [label="{label}",fontsize=10];'
            )
            for succ in block.get('successors', []):
                lines.append(f'  n_{addr:x} -> n_{succ:x};')

    lines.append('}')
    return '\n'.join(lines)


def cfg_summary_for_llm(cfg_data: Dict[str, Any], func_name: str) -> str:
    """
    生成 CFG 的文本摘要供 LLM prompt 消费。

    将控制流结构压缩为紧凑的文本表示，
    便于 LLM 在分析漏洞时理解函数的控制流逻辑。

    Args:
        cfg_data: extract_cfg() 的返回值
        func_name: 目标函数名

    Returns:
        例如 "CFG: 5 blocks, 2 loops, 1 call to system()"
    """
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
