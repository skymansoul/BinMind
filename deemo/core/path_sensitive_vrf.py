"""路径敏感的值域流分析器 — CFG 上 branch-sensitive 区间传播 (fork-not-join)。
BasicBlock CFG + AffineInterval + PathCondition → malloc/memcpy 不等式检查，
处理仿射表达式(malloc(n*4+8))、嵌套malloc、别名指针循环写；复杂度O(B·V)。"""

import re
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple
from .symbolic_range import AffineInterval, PathCondition
from .cfg_parser import split_into_blocks, BasicBlock
from .heap_expr_parser import parse_size_expr, split_args, judge_overflow
from .array_write_detector import detect_array_writes


@dataclass
class AllocSite:
    """malloc 调用点记录, 含路径上下文。"""
    var_name: str; size_expr: str; size_range: AffineInterval
    path_cond: PathCondition; block_id: int; lineno: int; func_name: str = ""

@dataclass
class WriteSite:
    """堆写入点记录, 含路径上下文。"""
    var_name: str; write_size: AffineInterval; write_call: str
    path_cond: PathCondition; block_id: int; lineno: int

@dataclass
class VerifiedFinding:
    """路径敏感验证后的最终发现。"""
    alloc_site: AllocSite; write_site: WriteSite; verdict: str
    overflow_bytes: int; confidence: float; description: str


_RE_MALLOC = re.compile(
    r'(\w[\w.\->]*)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?(malloc|calloc|realloc)\s*\(')
_RE_MALLOC_NESTED = re.compile(
    r'(?:^|[;{}(,=\s])(malloc|calloc|realloc)\s*\(')
_RE_MEMCPY = re.compile(
    r'(memcpy|memmove|strcpy|strncpy|strcat|strncat|sprintf|snprintf|memset|'
    r'read|fread|recv|scanf|fscanf|sscanf|gets|fgets|bcopy)\s*\(')
_RE_ASSIGN = re.compile(r'(\w[\w.\->]*)\s*=\s*(.+?)\s*;')
_RE_PTR_BASE = re.compile(r'^(\w[\w.\->]*)')
_RE_CONST_ASSIGN = re.compile(r'\b(\w+)\s*=\s*(\d+)\s*;')  # 整数常量赋值传播
_RE_COMMENTS = re.compile(r'//[^\n]*|/\*.*?\*/', re.DOTALL)


def _strip_comments(code: str) -> str:
    """剥离 C 风格注释, 避免注释中的 malloc/memcpy 文字被误解析为分配点。"""
    return _RE_COMMENTS.sub('', code)


def _extract_paren_args(text: str, start: int) -> str:
    """从 text[start] 的 '(' 之后提取括号内参数 (处理嵌套括号)。"""
    depth, i = 1, start
    while i < len(text) and depth > 0:
        if text[i] == '(': depth += 1
        elif text[i] == ')': depth -= 1
        i += 1
    return text[start:i-1] if depth == 0 else text[start:]


def path_sensitive_heap_analysis(
    code: str, func_name: str = "",
) -> List[VerifiedFinding]:
    """路径敏感的堆溢出检测主入口。

    返回: VerifiedFinding 列表。
    """
    code = _strip_comments(code)
    blocks = split_into_blocks(code)
    if not blocks:
        return []

    env: Dict[str, AffineInterval] = {}
    path_cond = PathCondition()
    visited: Set[Tuple[int, ...]] = set()
    alloc_sites: List[AllocSite] = []
    write_sites: List[WriteSite] = []

    _explore_paths(blocks, 0, env, path_cond, alloc_sites, write_sites,
                   visited, func_name)

    # 循环写入检测 (补充 memcpy 匹配不到的 for/while 写)
    from .loop_write_detector import detect_loop_writes
    detect_loop_writes(code, alloc_sites, write_sites)

    findings: List[VerifiedFinding] = []

    # realloc 去重: 同变量多 AllocSite 只保留最后一个, 旧分配过小致误报
    last_real = {a.var_name: id(a) for a in alloc_sites
                 if a.size_expr != "__synthetic__"}

    for alloc in alloc_sites:
        if (alloc.var_name in last_real
                and last_real[alloc.var_name] != id(alloc)):
            continue
        for write in write_sites:
            if write.var_name != alloc.var_name:
                continue
            ra = alloc.path_cond.refine_interval(alloc.size_expr, alloc.size_range)
            rw = write.path_cond.refine_interval("", write.write_size)
            verdict, overflow, conf = judge_overflow(ra, rw)
            desc = (f"{write.write_call}({write.var_name}, size={write.write_size}) "
                    f"into {alloc.var_name} (size={alloc.size_range}) "
                    f"[{verdict}@L{alloc.lineno}/{write.lineno}]")
            findings.append(VerifiedFinding(alloc, write, verdict, overflow, conf, desc))
    return findings


def _explore_paths(
    blocks: List[BasicBlock], bid: int,
    env: Dict[str, AffineInterval], path_cond: PathCondition,
    alloc_sites: List[AllocSite], write_sites: List[WriteSite],
    visited: Set[Tuple[int, ...]], func_name: str, depth: int = 0,
):
    """DFS 探索所有路径, 传播 env 和 path_cond。"""
    if bid < 0 or bid >= len(blocks) or depth > 64:
        return

    env_key = (bid, tuple(sorted(env.keys())))
    if env_key in visited:
        return
    visited.add(env_key)

    block = blocks[bid]
    env = dict(env)
    pc = path_cond.clone()

    if block.is_conditional:
        cv, op, val = block.condition_var, block.condition_op, block.condition_val

        # True 分支: 根据比较操作符收紧区间
        env_t = dict(env); pc_t = pc.clone()
        if cv in env_t:
            if op in ("<", "<="):
                adj = 0 if op == "<=" else 1
                env_t[cv] = env_t[cv].refine_hi(val - adj)
                pc_t.add_le(cv, val - adj)
            elif op in (">", ">="):
                adj = 0 if op == ">=" else 1
                env_t[cv] = env_t[cv].refine_lo(val + adj)
                pc_t.add_ge(cv, val + adj)
            elif op == "==":
                env_t[cv] = env_t[cv].refine_lo(val).refine_hi(val)
                pc_t.add_eq(cv, val)
        else:
            # 外部输入变量 (atoi/scanf/argv 等未入 env): 反编译伪代码无
            # 赋值链可查时, 仍要把分支约束纳入 path_cond 并绑定占位区间,
            # 否则 if(idx<64) 守卫下的 buf[idx] 写会因 idx 值域未知而误报.
            # 下界按非负索引保守取 0; 负索引 C 语义下同样越界, 不在此收紧.
            if op in ("<", "<="):
                adj = 0 if op == "<=" else 1
                env_t[cv] = AffineInterval.symbolic(cv, lo=0, hi=val - adj)
                pc_t.add_le(cv, val - adj)
            elif op in (">", ">="):
                adj = 0 if op == ">=" else 1
                env_t[cv] = AffineInterval.symbolic(cv, lo=val + adj)
                pc_t.add_ge(cv, val + adj)
            elif op == "==":
                env_t[cv] = AffineInterval.constant(val)
                pc_t.add_eq(cv, val)
        _process_block(blocks, bid, env_t, pc_t, alloc_sites, write_sites, func_name)
        for succ in block.successors[:1] if block.successors else []:
            _explore_paths(blocks, succ, env_t, pc_t, alloc_sites, write_sites,
                           visited, func_name, depth + 1)

        # False 分支
        env_f = dict(env); pc_f = pc.clone()
        if cv in env_f:
            if op in ("<", "<="):
                env_f[cv] = env_f[cv].refine_lo(val); pc_f.add_ge(cv, val)
            elif op in (">", ">="):
                env_f[cv] = env_f[cv].refine_hi(val); pc_f.add_le(cv, val)
        else:
            if op in ("<", "<="):
                env_f[cv] = AffineInterval.symbolic(cv, lo=val, hi=2**31 - 1)
                pc_f.add_ge(cv, val)
            elif op in (">", ">="):
                env_f[cv] = AffineInterval.symbolic(cv, lo=-1, hi=val)
                pc_f.add_le(cv, val)
        _process_block(blocks, bid, env_f, pc_f, alloc_sites, write_sites, func_name)
        for succ in block.successors[1:2] if len(block.successors) > 1 else []:
            _explore_paths(blocks, succ, env_f, pc_f, alloc_sites, write_sites,
                           visited, func_name, depth + 1)
        return

    # 顺序块
    _process_block(blocks, bid, env, pc, alloc_sites, write_sites, func_name)
    for succ in block.successors:
        _explore_paths(blocks, succ, env, pc, alloc_sites, write_sites,
                       visited, func_name, depth + 1)


def _process_block(
    blocks: List[BasicBlock], bid: int,
    env: Dict[str, AffineInterval], pc: PathCondition,
    alloc_sites: List[AllocSite], write_sites: List[WriteSite],
    func_name: str,
):
    """处理基本块中的赋值/malloc/memcpy — 嵌套malloc、指针基变量提取、合成AllocSite。"""
    block = blocks[bid]
    for line in block.lines:
        # 普通整数常量赋值传播 (size_t sz = 64; n = 1024;)
        # 使 parse_size_expr 能查到具体值, 抑制符号路径误报
        for cm in _RE_CONST_ASSIGN.finditer(line):
            cv = cm.group(1)
            cval = int(cm.group(2))
            env[cv] = AffineInterval.constant(cval)

        # 直接 malloc / calloc / realloc (var = malloc(...))
        for m in _RE_MALLOC.finditer(line):
            var = m.group(1)
            alloc_func = m.group(2)
            size_expr = _extract_paren_args(line, m.end()).strip()
            if not size_expr:
                continue
            # calloc(nmemb, size) → nmemb * size 乘法处理
            if alloc_func == 'calloc':
                args = split_args(size_expr)
                if len(args) >= 2:
                    ai_nmemb = parse_size_expr(args[0].strip(), env)
                    ai_size = parse_size_expr(args[1].strip(), env)
                    if ai_nmemb.const_val is not None and ai_size.const_val is not None:
                        ai = AffineInterval.constant(ai_nmemb.const_val * ai_size.const_val)
                    elif ai_nmemb.const_val is not None and ai_nmemb.const_val == 1:
                        ai = ai_size  # calloc(1, expr) → expr
                    else:
                        ai = AffineInterval.top()
                else:
                    ai = parse_size_expr(size_expr, env)
            else:
                # realloc(ptr, new_size) → 只取第二个参数作为大小
                if alloc_func == 'realloc':
                    r_args = split_args(size_expr)
                    if len(r_args) >= 2:
                        size_expr = r_args[1].strip()
                ai = parse_size_expr(size_expr, env)
            env[var] = ai
            alloc_sites.append(AllocSite(
                var_name=var, size_expr=size_expr, size_range=ai,
                path_cond=pc.clone(), block_id=bid,
                lineno=block.start_lineno, func_name=func_name,
            ))

        # 嵌套 malloc (wrapper: b=alloc(c,4) 内含 malloc)
        assign_m = _RE_ASSIGN.search(line)
        assign_var = assign_m.group(1) if assign_m else None

        for m_n in _RE_MALLOC_NESTED.finditer(line):
            # 跳过已由 _RE_MALLOC 处理的直接赋值形式
            if m_n.group(0).startswith('='):
                continue
            size_expr = _extract_paren_args(line, m_n.end()).strip()
            if not size_expr:
                continue
            ai = parse_size_expr(size_expr, env)
            # 关联到同一行的赋值目标变量
            var = assign_var if assign_var else f"_heap_{bid}_{m_n.start()}"
            env[var] = ai
            alloc_sites.append(AllocSite(
                var_name=var, size_expr=size_expr, size_range=ai,
                path_cond=pc.clone(), block_id=bid,
                lineno=block.start_lineno, func_name=func_name,
            ))

        # memcpy / strcpy 等写入函数 (finditer: 同行可能有多个)
        for m_w in _RE_MEMCPY.finditer(line):
            call = m_w.group(1)
            args_str = _extract_paren_args(line, m_w.end())
            if not args_str:
                continue
            args = split_args(args_str)
            if not args:
                continue
            dst_raw = args[0].strip()

            # 提取指针基变量 (nb+n→nb) 和偏移量 (p+32→offset=32)
            base_m = _RE_PTR_BASE.match(dst_raw)
            dst = base_m.group(1) if base_m else dst_raw
            _write_offset = 0
            if base_m:
                _rest = dst_raw[base_m.end():]
                _off_m = re.match(r'\s*\+\s*(\d+)', _rest)
                if _off_m:
                    _write_offset = int(_off_m.group(1))

            if call in ('memcpy', 'strncpy', 'read', 'fread', 'recv',
                        'snprintf', 'memset', 'fgets') and len(args) >= 3:
                size_arg = args[2].strip()
            elif call in ('strcpy', 'strcat'):
                size_arg = args[1].strip() if len(args) > 1 else ""
            elif call == 'sprintf':
                size_arg = args[1].strip() if len(args) > 1 else ""
            elif call in ('scanf', 'fscanf', 'sscanf', 'gets'):
                size_arg = "__unbounded__"
            else:
                size_arg = args[-1].strip() if len(args) > 1 else ""

            ws = parse_size_expr(size_arg, env)
            # 偏移量纳入write_size: memmove(p+32, src, 64) → write_end=32+64=96
            if _write_offset > 0 and ws.const_val is not None:
                ws = AffineInterval.constant(ws.const_val + _write_offset)
            elif _write_offset > 0:
                ws = AffineInterval(
                    lo=ws.lo + _write_offset if ws.lo >= 0 else _write_offset,
                    hi=ws.hi + _write_offset if ws.hi < 2**31 - 1 else 2**31 - 1)
            write_sites.append(WriteSite(
                var_name=dst, write_size=ws,
                write_call=call, path_cond=pc.clone(),
                block_id=bid, lineno=block.start_lineno,
            ))

    # 数组下标写入 buf[expr] = val
    detect_array_writes(block, bid, pc, env, write_sites)

    # 合成 AllocSite: 写入目标无已知分配的, 保守创建 ⊤ 分配
    known_alloc_vars = {a.var_name for a in alloc_sites}
    for ws in write_sites:
        if ws.var_name not in known_alloc_vars:
            alloc_sites.append(AllocSite(
                var_name=ws.var_name, size_expr="__synthetic__",
                size_range=AffineInterval.top(), path_cond=pc.clone(),
                block_id=bid, lineno=block.start_lineno, func_name=func_name,
            )); known_alloc_vars.add(ws.var_name)
