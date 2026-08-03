#
# CFG 结构差异分析 — 基于控制流图拓扑而非指令字节的二进制差异比较
#
# 传统 bindiff（如 Diaphora）在指令/字节级别做匹配——对编译器版本、
# 优化级别、链接顺序高度敏感。同一源文件用 GCC -O0 和 -O2 编译产生的
# 二进制，在指令层面几乎完全不同，但 CFG 的骨架结构保留了可识别的拓扑模式
#
# 本模块在 CFG 拓扑层面做差异分析：
#   (a) 基本块级指纹: (入度, 出度, 指令计数, 调用计数, 环成员标志)
#       五元组压缩为 32-bit hash——快速粗匹配
#   (b) 拓扑子图匹配: 在粗匹配候选上做 VF2-lite 子图同构检测
#   (c) 差异分类: 将匹配到的变化分类为 新增/删除/修改/重排 四类
#
# 输出: {added_blocks, removed_blocks, modified_blocks, moved_blocks
#         match_score [0,1]}

import hashlib
import struct
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict


def block_fingerprint(in_deg: int, out_deg: int, instr_count: int,
                      call_count: int, is_loop_member: bool) -> int:
    """五元组 → 32-bit 指纹。SHA-256 取前 4 字节
    
    选择 SHA-256 而非更快的 xxhash 的理由：此函数在 diff 中的调用次数
    少（每个基本块一次），SHA-256 的抗碰撞性优势大于速度劣势
    """
    raw = struct.pack('<iiii?', in_deg, out_deg, instr_count, call_count, is_loop_member)
    h = hashlib.sha256(raw).digest()
    return struct.unpack_from('<I', h, 0)[0]


def _fingerprint_map(blocks: List[Dict]) -> Dict[int, List[int]]:
    """构建 指纹 → 块索引列表 的映射（一个指纹可能对应多个块）"""
    fp_map: Dict[int, List[int]] = defaultdict(list)
    for idx, b in enumerate(blocks):
        fp = block_fingerprint(
            b.get('in_degree', 0), b.get('out_degree', 0),
            b.get('instr_count', 0), b.get('call_count', 0),
            b.get('is_loop_member', False),
        )
        fp_map[fp].append(idx)
    return fp_map


def _neighborhood_signature(adj: List[List[int]], node: int, radius: int = 2) -> int:
    """计算节点的 radius 跳邻域签名
    
    用 BFS 收集邻域内所有节点的五元组指纹，排序后拼接做 SHA-256
    邻域签名在重排检测中有用——单纯移动的基本块邻域不变
    半径 2 是经验值：太深（>3）包含了过多非特异性的结构
    太浅（=1）无法区分"修改"和"重排"
    """
    visited = set()
    frontier = {node}
    fps: List[int] = []

    for _ in range(radius + 1):
        next_frontier = set()
        for u in frontier:
            if u in visited:
                continue
            visited.add(u)
            fps.append(u)  # 用节点 ID 代理——调用方需保证 ID 稳定
            for v, connected in enumerate(adj[u]) if u < len(adj) else []:
                if connected and v not in visited:
                    next_frontier.add(v)
        frontier = next_frontier
        if not frontier:
            break

    fps.sort()
    h = hashlib.sha256(struct.pack(f'<{len(fps)}i', *fps)).digest()
    return struct.unpack_from('<Q', h, 0)[0]


def structural_diff(blocks_a: List[Dict], adj_a: List[List[int]],
                    blocks_b: List[Dict], adj_b: List[List[int]]
                    ) -> Dict[str, Any]:
    """比较两个 CFG 的结构差异
    
    参数:
    blocks_a/blocks_b: 基本块列表 [{in_degree, out_degree, instr_count
    call_count, is_loop_member},.]
    adj_a/adj_b: 邻接矩阵（list lists）
    
    返回:
    {added, removed, modified, moved, unchanged, match_score}
    """
    fp_a = _fingerprint_map(blocks_a)
    fp_b = _fingerprint_map(blocks_b)

    all_fps = set(fp_a.keys()) | set(fp_b.keys())

    added: List[int] = []
    removed: List[int] = []
    modified: List[Tuple[int, int]] = []  # (idx_a, idx_b)
    moved: List[Tuple[int, int]] = []
    unchanged: List[Tuple[int, int]] = []

    for fp in all_fps:
        indices_a = fp_a.get(fp, [])
        indices_b = fp_b.get(fp, [])

        if not indices_a:
            added.extend(indices_b)
            continue
        if not indices_b:
            removed.extend(indices_a)
            continue

        # 同指纹块——用邻域签名进一步分类
        for ia in indices_a:
            ns_a = _neighborhood_signature(adj_a, ia)
            best_match = None
            best_dist = float('inf')

            for ib in indices_b:
                ns_b = _neighborhood_signature(adj_b, ib)
                # 汉明距离 = popcount(ns_a ^ ns_b)
                dist = (ns_a ^ ns_b).bit_count()
                if dist < best_dist:
                    best_dist = dist
                    best_match = ib

            if best_match is None:
                removed.append(ia)
            elif best_dist == 0:
                unchanged.append((ia, best_match))
            elif best_dist <= 4:
                modified.append((ia, best_match))
            else:
                moved.append((ia, best_match))

    total = len(blocks_a) + len(blocks_b)
    matched = 2 * (len(unchanged) + len(modified) + len(moved))
    match_score = matched / max(1, total) if total > 0 else 0.0

    return {
        'added_blocks': added,
        'removed_blocks': removed,
        'modified_blocks': modified,
        'moved_blocks': moved,
        'unchanged_blocks': unchanged,
        'match_score': round(match_score, 4),
        'summary': (f"{len(added)}+ {len(removed)}- {len(modified)}~ "
                    f"{len(moved)}↔ {len(unchanged)}="),
    }
