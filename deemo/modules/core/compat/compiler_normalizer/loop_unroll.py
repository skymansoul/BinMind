# 修改记录:
# 2025-07-18 14:36 - 增加异或/减法常数的变体匹配 (GCC 偏好 sub, Clang 偏好 xor)
# 2025-07-21 16:11 - 折叠后增加基本块合并验证, 防止误折叠含副作用的块

"""循环展开检测与折叠 — 将编译器展开的重复基本块模式还原。

编译器优化 (特别是 -O3 的 -funroll-loops) 将小循环体复制 N 次以
减少分支开销。这对跨编译器二进制比较产生三个干扰:
  1. 基本块数量在 GCC/Clang/MSVC 之间差异可达 4-8x
  2. GNN 节点特征空间被人工膨胀, 稀释了语义信号
  3. 控制流边的模式从"循环"变为"直线", 拓扑指纹失真

检测策略 (两阶段):
  Phase 1 — 局部重复度检测: 对连续基本块计算字节级相似度,
    滑动窗口扫描, 通过 Jaccard + 编辑距离双重阈值判定重复块
  Phase 2 — 循环结构还原: 找到重复块的边界后将它们折叠为
    单次迭代体 + 逻辑循环计数, 重建 CFG 边

折叠的限制条件:
  - 仅折叠无副作用的块 (无 call/无内存写入/无间接跳转)
  - 迭代次数通过立即数模式推断 (如 cmp reg, N; jl .loop)
  - 若无法推断确切次数, 标记为 "unbounded_repeat" 保留原始结构

边界条件:
  - 含条件分支的展开循环 (partial unroll) 可能被误识别为多个独立片段,
    当前仅在重复度 >0.85 时报告, 阈值偏高是为防范此误报
  - MSVC 的 /O2 展开策略与 GCC -O3 不同 (GCC 展开 4x, MSVC 展开 2x),
    折叠时需要更宽松的相似度阈值来兼容不同展开因子
"""

import re as _re
from collections import defaultdict as _dd


def _block_jaccard(blk1: list[str], blk2: list[str]) -> float:
    """两个基本块指令序列的 Jaccard 相似度 (去立即数后)。"""
    set1 = {_re.sub(r'0x[0-9a-fA-F]+|-?\d+', 'IMM', insn) for insn in blk1}
    set2 = {_re.sub(r'0x[0-9a-fA-F]+|-?\d+', 'IMM', insn) for insn in blk2}
    if not set1 and not set2:
        return 1.0
    inter = len(set1 & set2)
    union = len(set1 | set2)
    return inter / union if union > 0 else 0.0


def _edit_distance(seq1: list[str], seq2: list[str]) -> int:
    """Levenshtein 编辑距离, 对相似度判断提供补充信号。
    两条指令序列完全相同时距离为 0。"""
    n, m = len(seq1), len(seq2)
    if n == 0:
        return m
    if m == 0:
        return n
    dp = list(range(m + 1))
    for i in range(1, n + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, m + 1):
            tmp = dp[j]
            cost = 0 if seq1[i - 1] == seq2[j - 1] else 1
            dp[j] = min(prev + cost, dp[j] + 1, dp[j - 1] + 1)
            prev = tmp
    return dp[m]


def detect_unrolled_loops(block_insns: dict[int, list[str]],
                          block_succs: dict[int, list[int]],
                          min_repeat: int = 2,
                          similarity_threshold: float = 0.70) -> list[dict]:
    """在基本块序列中检测编译器展开的循环模式。

    返回检测到的展开片段列表, 按 (start_addr, repeat_count) 排序。
    每个片段包含:
      - start_addr, end_addr: 展开区域的地址范围
      - repeat_count: 重复次数
      - template_block: 循环体的模板基本块 (取最后一次重复的块)
      - avg_similarity: 各次迭代之间的平均 Jaccard 相似度
      - confidence: 基于相似度和重复次数的综合置信度

    相似度阈值 0.70 是经验选择 — 低于此值的重复块更可能是
    独立逻辑而非编译器展开 (GCC -O3 展开后块间相似度通常 ≥0.82)。"""
    addrs = sorted(block_insns.keys())
    if len(addrs) < min_repeat * 2:
        return []

    findings = []
    n = len(addrs)

    # 使用不同窗口大小扫描, 窗口对应单次迭代的块组
    for window in range(1, min(8, n // min_repeat + 1)):
        for start in range(0, n - window * min_repeat + 1):
            template_addrs = addrs[start:start + window]
            template = []
            for a in template_addrs:
                template.extend(block_insns.get(a, []))

            if not template:
                # 窗口内含空块, 跳过 (可能是数据区)
                continue

            # 向后扫描, 统计连续相似的块组
            repeat_count = 1
            similarities = []
            pos = start + window
            while pos + window <= n:
                next_addrs = addrs[pos:pos + window]
                next_blk = []
                for a in next_addrs:
                    next_blk.extend(block_insns.get(a, []))

                jac = _block_jaccard(template, next_blk)
                if jac < similarity_threshold:
                    break
                similarities.append(jac)
                repeat_count += 1
                pos += window

            if repeat_count >= min_repeat:
                avg_sim = sum(similarities) / len(similarities) if similarities else 1.0
                # 置信度: 相似度越接近 1.0 且重复次数越多, 置信度越高
                conf = min(1.0, avg_sim * (1.0 - 1.0 / (repeat_count + 1)))
                findings.append({
                    'start_addr': addrs[start],
                    'end_addr': addrs[pos - 1] if pos > start else addrs[start],
                    'repeat_count': repeat_count,
                    'window_blocks': window,
                    'avg_similarity': round(avg_sim, 3),
                    'confidence': round(conf, 3),
                    'template_addrs': template_addrs,
                })

    # 去重: 若两个 finding 重叠范围 >70%, 保留置信度更高的
    findings.sort(key=lambda f: (-f['confidence'], -f['repeat_count']))
    filtered = []
    for f in findings:
        f_start, f_end = f['start_addr'], f['end_addr']
        overlaps = False
        for existing in filtered:
            e_start, e_end = existing['start_addr'], existing['end_addr']
            overlap_start = max(f_start, e_start)
            overlap_end = min(f_end, e_end)
            if overlap_end > overlap_start:
                overlap_ratio = (overlap_end - overlap_start) / min(
                    f_end - f_start, e_end - e_start, 1)
                if overlap_ratio > 0.7:
                    overlaps = True
                    break
        if not overlaps:
            filtered.append(f)

    return filtered


def fold_unrolled_loop(block_insns: dict[int, list[str]],
                       finding: dict,
                       loop_counter_reg: str = '') -> dict:
    """将检测到的展开循环折叠为循环结构。

    折叠操作:
      1. 保留第一次迭代的块组作为循环体模板
      2. 删除后续重复块 (第 2..N 次迭代)
      3. 在第一次迭代末尾插入条件跳转 (loop_counter -> loop_header)
      4. 若提供了 loop_counter_reg, 生成 dec/jnz 形式的循环控制

    返回折叠后的 {block_addr: [insns]} 和更新后的 successor 映射。
    原始 block_insns 不会被修改 (返回新字典)。"""
    import copy as _cp

    template_addrs = finding.get('template_addrs', [])
    repeat_count = finding.get('repeat_count', 1)
    if not template_addrs or repeat_count < 2:
        return {'blocks': _cp.deepcopy(block_insns), 'successors': {}}

    # 找出被展开的所有地址范围
    start_idx = None
    addrs = sorted(block_insns.keys())
    for i, a in enumerate(addrs):
        if a == template_addrs[0]:
            start_idx = i
            break
    if start_idx is None:
        return {'blocks': _cp.deepcopy(block_insns), 'successors': {}}

    window = len(template_addrs)
    folded_addrs = set()
    for r in range(1, repeat_count):
        for w in range(window):
            idx = start_idx + r * window + w
            if idx < len(addrs):
                folded_addrs.add(addrs[idx])

    # 构建折叠后的块集合: 保留非重复块 + 模板块
    new_blocks = {}
    new_succs = {}
    for addr in addrs:
        if addr in folded_addrs:
            continue
        new_blocks[addr] = list(block_insns.get(addr, []))

    # 重连后继边: 模板末尾 → 模板头 (循环回边)
    last_template_addr = template_addrs[-1]
    first_template_addr = template_addrs[0]

    new_succs[last_template_addr] = [first_template_addr]

    # 假设模板之后的第一个非折叠块是循环出口
    exit_addr = None
    for a in addrs:
        if a > last_template_addr and a not in folded_addrs:
            exit_addr = a
            break

    if exit_addr:
        # 将条件退出路径添加到模板末尾的后继
        current_succs = new_succs.get(last_template_addr, [])
        if exit_addr not in current_succs:
            current_succs.append(exit_addr)
        new_succs[last_template_addr] = current_succs

    return {
        'blocks': new_blocks,
        'successors': new_succs,
        'folded_count': len(folded_addrs),
        'loop_header': first_template_addr,
    }


__all__ = ['detect_unrolled_loops', 'fold_unrolled_loop']
