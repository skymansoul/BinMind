# graph_builder.py -- CFG/CPG图构造器
# 从基本块列表构建控制流图和代码属性图
# 12维节点特征设计参考了Gemini和SAFE的嵌入策略，
# 但去掉了字符串常量特征（那是NLP的事）
# //// 数据依赖边保守策略：reg write集合有重叠就加边 ////

import re
import numpy as np
from collections import defaultdict

# ===== x86跳转指令识别 =====
_UNCOND_JUMPS = {'jmp', 'ret', 'retn', 'iret', 'iretd', 'iretq'}
_COND_JUMPS = {
    'je', 'jz', 'jne', 'jnz', 'jg', 'jnle', 'jge', 'jnl',
    'jl', 'jnge', 'jle', 'jng', 'ja', 'jnbe', 'jae', 'jnb',
    'jb', 'jnae', 'jbe', 'jna', 'jo', 'jno', 'js', 'jns',
    'jp', 'jpe', 'jnp', 'jpo', 'jcxz', 'jecxz', 'jrcxz',
    'loop', 'loope', 'loopz', 'loopne', 'loopnz',
}
_CALL_INSTRS = {'call', 'syscall', 'int', 'sysenter', 'vmmcall'}
_COND_BRANCH_ALL = _COND_JUMPS | {'loop', 'loope', 'loopz', 'loopne', 'loopnz'}
_ARITH_INSTRS = {'add', 'sub', 'mul', 'imul', 'div', 'idiv', 'inc', 'dec',
                 'neg', 'adc', 'sbb', 'cmp', 'lea', 'xadd', 'xchg'}
_LOGIC_INSTRS = {'and', 'or', 'xor', 'not', 'test', 'shl', 'shr', 'sar',
                 'rol', 'ror', 'rcl', 'rcr', 'sal', 'bt', 'bts', 'btr', 'btc', 'bsf', 'bsr'}
_MEM_INSTRS = {'mov', 'push', 'pop', 'pusha', 'popa', 'pushad', 'popad',
               'pushf', 'popf', 'pushfd', 'popfd', 'pushfq', 'popfq',
               'movsx', 'movzx', 'movsb', 'movsw', 'movsd', 'movsq',
               'cmov', 'cmove', 'cmovne', 'cmovg', 'cmovl', 'cmovge', 'cmovle',
               'stosb', 'stosw', 'stosd', 'stosq', 'lodsb', 'lodsw', 'lodsd', 'lodsq',
               'scasb', 'scasw', 'scasd', 'scasq', 'cmpsb', 'cmpsw', 'cmpsd', 'cmpsq'}

# 寄存器集合 -- 简洁版
_REG_SET_ALL = {
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp',
    'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp',
    'al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh',
    'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d',
    'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w',
    'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b',
    'xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7',
    'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15',
    'ymm0', 'ymm1', 'ymm2', 'ymm3', 'ymm4', 'ymm5', 'ymm6', 'ymm7',
    'ymm8', 'ymm9', 'ymm10', 'ymm11', 'ymm12', 'ymm13', 'ymm14', 'ymm15',
    'st0', 'st1', 'st2', 'st3', 'st4', 'st5', 'st6', 'st7',
    'mm0', 'mm1', 'mm2', 'mm3', 'mm4', 'mm5', 'mm6', 'mm7',
    'cr0', 'cr2', 'cr3', 'cr4', 'cr8', 'dr0', 'dr1', 'dr2', 'dr3', 'dr6', 'dr7',
    'rip', 'eip', 'ip', 'eflags', 'rflags',
}


def get_register_set(insn: str) -> tuple:
    """Parse an instruction string, return (reads: set, writes: set) of register names.

    Conservative heuristic: first operand is often a write target for binary ops,
    memory source operands count as reads.
    """
    _s = insn.strip()
    if not _s:
        return (set(), set())

    parts = _s.split(None, 1)
    mnem = parts[0].lower()
    op_str = parts[1] if len(parts) > 1 else ''

    # 提取所有寄存器token
    _all_toks = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', op_str)
    _all_regs = {t.lower() for t in _all_toks if t.lower() in _REG_SET_ALL}

    # 简单启发式：根据指令类型划分read/write
    _reads = set()
    _writes = set()

    # push: src is read
    if mnem == 'push':
        _reads = _all_regs
        _writes = {'rsp'}  # implicit
        return (_reads, _writes)

    # pop: dst is written
    if mnem == 'pop':
        _writes = _all_regs
        _reads = {'rsp'}  # implicit
        return (_reads, _writes)

    # call: 隐式读写
    if mnem in _CALL_INSTRS:
        _reads = _all_regs
        _writes = {'rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'}  # caller-saved
        return (_reads, _writes)

    # ret: 读rax（返回值）
    if mnem in _UNCOND_JUMPS and 'ret' in mnem:
        _reads = {'rax', 'rsp'}
        _writes = {'rsp', 'rip'}
        return (_reads, _writes)

    # 跳转指令：读标志位/比较寄存器
    if mnem in _COND_JUMPS or mnem.startswith('j'):
        _reads = _all_regs | {'eflags'}
        return (_reads, _writes)

    # 算术/逻辑指令：通常第一个操作数是write目标
    if mnem in _ARITH_INSTRS or mnem in _LOGIC_INSTRS:
        if _all_regs:
            _operands = [x.strip() for x in op_str.split(',')]
            if _operands:
                _first_toks = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', _operands[0])
                _first_regs = {t.lower() for t in _first_toks if t.lower() in _REG_SET_ALL}
                _writes = _first_regs
            _reads = _all_regs - _writes
            # lea特殊处理：目标不算read
            if mnem == 'lea':
                _reads = _all_regs - _writes
        return (_reads, _writes)

    # mov类型：dst=write, src=read
    if mnem in _MEM_INSTRS or mnem.startswith('mov') or mnem.startswith('cmov'):
        _operands = [x.strip() for x in op_str.split(',')]
        for _i, _op in enumerate(_operands):
            _toks = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', _op)
            _regs = {t.lower() for t in _toks if t.lower() in _REG_SET_ALL}
            if _i == 0:
                _writes.update(_regs)
            else:
                _reads.update(_regs)
        return (_reads, _writes)

    # 默认：全部算read（保守）
    return (_all_regs, set())


# ===== 指令分类计数器 =====
def _classify_insn(mnem: str) -> str:
    _m = mnem.lower()
    if _m in _CALL_INSTRS:
        return 'call'
    if _m in _COND_BRANCH_ALL or _m.startswith('j') or _m == 'loop':
        return 'branch'
    if _m in _ARITH_INSTRS:
        return 'arith'
    if _m in _LOGIC_INSTRS:
        return 'logic'
    if _m in _MEM_INSTRS or _m.startswith('mov') or _m.startswith('cmov'):
        return 'mem'
    return 'other'


def _compute_block_features(block: dict, idx: int, total_blocks: int,
                             in_deg: int, out_deg: int,
                             loop_blocks: set) -> np.ndarray:
    """Compute 12-dim node features for one basic block."""
    insns = block.get('instructions', block.get('insns', []))
    _n = len(insns)

    _n_call = 0
    _n_arith = 0
    _n_logic = 0
    _n_mem = 0
    _n_branch = 0
    _size = 0

    for _i in insns:
        _s = _i.strip()
        if not _s:
            continue
        _parts = _s.split(None, 1)
        _mnem = _parts[0].lower() if _parts else ''
        _cat = _classify_insn(_mnem)
        if _cat == 'call':
            _n_call += 1
        elif _cat == 'arith':
            _n_arith += 1
        elif _cat == 'logic':
            _n_logic += 1
        elif _cat == 'mem':
            _n_mem += 1
        elif _cat == 'branch':
            _n_branch += 1
        _size += len(_i.encode('utf-8', errors='replace'))

    # Cyclomatic complexity contribution: 每个条件分支+1
    _cyclo = 1 + _n_branch  # base 1 + branches

    _feat = np.array([
        float(in_deg),                    # 0: in_degree
        float(out_deg),                   # 1: out_degree
        float(_n),                        # 2: num_instructions
        float(_n_call),                   # 3: num_calls
        float(_n_arith),                  # 4: num_arith
        float(_n_logic),                  # 5: num_logic
        float(_n_mem),                    # 6: num_mem
        float(_n_branch),                 # 7: num_branch
        float(_size),                     # 8: size_bytes
        1.0 if idx in loop_blocks else 0.0,  # 9: has_loop
        float(_cyclo),                    # 10: cyclomatic_contrib
        1.0 if idx == 0 else 0.0,        # 11: is_entry
    ], dtype=np.float64)

    return _feat


# ----- 环检测：DFS找后向边 -----
def _find_loop_blocks(edges: list, num_nodes: int) -> set:
    """简易DFS环检测 -- 后向边指向的节点标记为循环头"""
    _adj = defaultdict(list)
    for _s, _d in edges:
        _adj[_s].append(_d)

    _loop_heads = set()
    _visited = [0] * num_nodes  # 0=white, 1=gray, 2=black

    def _dfs(_u):
        _visited[_u] = 1
        for _v in _adj.get(_u, []):
            if _visited[_v] == 1:
                _loop_heads.add(_v)  # 回边 → v是循环头
            elif _visited[_v] == 0:
                _dfs(_v)
        _visited[_u] = 2

    for _i in range(num_nodes):
        if _visited[_i] == 0:
            _dfs(_i)

    # 循环头所在循环的所有节点也标记
    _all_loop = set(_loop_heads)
    # BFS从循环头反向找循环体
    _rev_adj = defaultdict(list)
    for _s, _d in edges:
        _rev_adj[_d].append(_s)

    for _head in _loop_heads:
        _q = [_head]
        _seen = {_head}
        while _q:
            _u = _q.pop(0)
            for _pred in _rev_adj.get(_u, []):
                if _pred not in _seen and _pred >= _head:  # 后代节点
                    _seen.add(_pred)
                    _all_loop.add(_pred)
                    _q.append(_pred)

    return _all_loop


# //// build_cfg_graph -- 主入口 ////
def build_cfg_graph(basic_blocks: list) -> dict:
    """Construct CFG from basic blocks with 12-dim node features.

    Args:
        basic_blocks: list of dicts with keys 'address', 'instructions', optionally 'successors'.

    Returns:
        dict with keys 'nodes' (list of block dicts), 'edges' (list of (src, dst) tuples),
        'features' (Nx12 numpy array), 'adj' (NxN adjacency matrix).
    """
    _n = len(basic_blocks)
    if _n == 0:
        return {'nodes': [], 'edges': [], 'features': np.zeros((0, 12)), 'adj': np.zeros((0, 0))}

    # 构建地址到索引的映射
    _addr_to_idx = {}
    for _i, _blk in enumerate(basic_blocks):
        _addr = _blk.get('address', _blk.get('addr', hex(_i)))
        if isinstance(_addr, str):
            _addr = int(_addr, 16) if _addr.startswith('0x') else int(_addr)
        _addr_to_idx[_addr] = _i

    # 构建边：优先用显式successors，否则fallthrough推断
    _edges = []
    _in_deg = [0] * _n
    _out_deg = [0] * _n

    for _i, _blk in enumerate(basic_blocks):
        _succs = _blk.get('successors', _blk.get('succs', []))
        _insns = _blk.get('instructions', _blk.get('insns', []))

        if _succs:
            for _s_addr in _succs:
                if isinstance(_s_addr, str):
                    _s_addr = int(_s_addr, 16) if _s_addr.startswith('0x') else int(_s_addr)
                if _s_addr in _addr_to_idx:
                    _j = _addr_to_idx[_s_addr]
                    _edges.append((_i, _j))
                    _out_deg[_i] += 1
                    _in_deg[_j] += 1
        else:
            # 没有显式successors时：根据最后一条指令推断
            _fallthrough = True
            if _insns:
                _last = _insns[-1].strip()
                _last_parts = _last.split(None, 1)
                _last_mnem = _last_parts[0].lower() if _last_parts else ''

                if _last_mnem in _UNCOND_JUMPS:
                    _fallthrough = False
                    # 尝试从call/jmp的操作数获取目标
                    if _last_mnem == 'call':
                        # call: 有隐含的fallthrough（返回后继续）
                        _fallthrough = True
                    elif _last_mnem == 'ret':
                        _fallthrough = False  # ret不fallthrough

                # 条件跳转：给一条fallthrough边
                if _last_mnem in _COND_BRANCH_ALL and _i + 1 < _n:
                    _edges.append((_i, _i + 1))
                    _out_deg[_i] += 1
                    _in_deg[_i + 1] += 1
                    # 也尝试解析跳转目标
                    if len(_last_parts) > 1:
                        _tgt_str = _last_parts[1].strip()
                        try:
                            if _tgt_str.startswith('0x'):
                                _tgt = int(_tgt_str, 16)
                            else:
                                _tgt = int(_tgt_str)
                            if _tgt in _addr_to_idx:
                                _j = _addr_to_idx[_tgt]
                                _edges.append((_i, _j))
                                _out_deg[_i] += 1
                                _in_deg[_j] += 1
                        except (ValueError, AttributeError):
                            pass
                    _fallthrough = False

            # 顺序fallthrough
            if _fallthrough and _i + 1 < _n:
                _edges.append((_i, _i + 1))
                _out_deg[_i] += 1
                _in_deg[_i + 1] += 1

    # 去重边
    _edges = list(set(_edges))

    # 循环检测
    _loop_blocks = _find_loop_blocks(_edges, _n)

    # 计算每个block的特征
    _feats = np.zeros((_n, 12), dtype=np.float64)
    for _i, _blk in enumerate(basic_blocks):
        _feats[_i] = _compute_block_features(_blk, _i, _n, _in_deg[_i], _out_deg[_i], _loop_blocks)

    _adj = adjacency_from_edges(_edges, _n)

    return {
        'nodes': basic_blocks,
        'edges': _edges,
        'features': _feats,
        'adj': _adj,
    }


# ===== 数据依赖边构建 =====
def _build_data_edges(basic_blocks: list) -> list:
    """Conservative inter-block data dependency edges.

    For each pair of blocks, compute read/write register sets.
    If block A writes a register R and block B reads R (and no intervening
    block kills R), add edge A -> B.
    简化版：对每条CFG路径只做一层传播，不做全流分析。
    """
    _n = len(basic_blocks)
    _edge_set = set()

    # 预计算每个block的寄存器读写集
    _block_regs = []
    for _blk in basic_blocks:
        _insns = _blk.get('instructions', _blk.get('insns', []))
        _all_reads = set()
        _all_writes = set()
        for _insn in _insns:
            _r, _w = get_register_set(_insn)
            _all_reads |= _r
            _all_writes |= _w
        _block_regs.append((_all_reads, _all_writes))

    # O(n^2) 但实际中一个函数的basic block数量通常<100，可接受
    _edge_set = set()
    for _i in range(_n):
        _ri, _wi = _block_regs[_i]
        for _j in range(_n):
            if _i == _j:
                continue
            _rj, _wj = _block_regs[_j]
            # _i写 -> _j读 且 存在重叠
            if _wi and _rj and (_wi & _rj):
                _edge_set.add((_i, _j))
            # 如果_i写 -> _j也写同一个寄存器（WAR依赖，保守添加）
            if _wi and _wj and (_wi & _wj):
                _edge_set.add((_i, _j))

    return list(_edge_set)


def build_cpg_graph(basic_blocks: list) -> dict:
    """Build Code Property Graph: CFG + data dependency combined.

    Returns same structure as build_cfg_graph, with extra data-dependency edges
    in the 'edges' list and a 'data_edges' key.
    """
    _cfg = build_cfg_graph(basic_blocks)
    _n = len(basic_blocks)

    _data_edges = _build_data_edges(basic_blocks)

    # 合并控制流边和数据边
    _all_edges = list(set(_cfg['edges'] + _data_edges))

    _adj = adjacency_from_edges(_all_edges, _n) if _n > 0 else np.zeros((0, 0))

    return {
        'nodes': basic_blocks,
        'edges': _all_edges,
        'data_edges': _data_edges,
        'features': _cfg['features'],
        'adj': _adj,
    }


def adjacency_from_edges(edges: list, num_nodes: int) -> np.ndarray:
    """Convert edge list to NxN adjacency matrix."""
    _adj = np.zeros((num_nodes, num_nodes), dtype=np.float64)
    for _s, _d in edges:
        if 0 <= _s < num_nodes and 0 <= _d < num_nodes:
            _adj[_s, _d] = 1.0
    return _adj
