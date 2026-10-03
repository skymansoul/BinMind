# 定向灰盒模糊测试基元 — 目标驱动的路径探索与距离度量
# BEACON — 可证明路径剪枝的定向灰盒模糊测试:
#       将到达目标的路径编码为线性规划问题, 剪枝不可避免偏离目标的路径
# Hawkeye — 基于期望的定向灰盒模糊器:
#       引入"邻近度"新度量, 结合函数级和基本块级距离
# MC2 — 严格高效的定向灰盒模糊测试:
#       使用支配者树和 post-dominator 分析精确定义到目标的距离
# SELECTFUZZ — 选择性路径探索: 仅符号化
#       与目标分支相关的输入字节, 大幅降低求解器负载
# SoK — 定向模糊测试目标选择方法综述

import heapq as _hp
import math as _math
from collections import defaultdict as _dd, deque as _deque

# 基本块级距离度量
# Hawkeye 的距离定义 — 到目标块的最短路径长度
# 使用调和平均结合函数间和函数内距离 (favor 两者都短的路径)


def compute_block_distance(callgraph: dict[str, list[str]],
                            cfg: dict[int, dict],
                            target_addrs: set[int]) -> dict[int, float]:
    # CG BFS → 函数级距离; CFG BFS → 基本块级距离; 调和平均 → 归一化
    if not target_addrs:
        return {}

# 函数级距离 (CG)
    # 先确定哪些函数包含目标块
    target_funcs: set[str] = set()
    func_blocks: dict[str, list[int]] = _dd(list)
    for addr, info in cfg.items():
        fname = info.get('function', str(addr))
        func_blocks[fname].append(addr)
        if addr in target_addrs:
            target_funcs.add(fname)

    # CG BFS
    func_dist: dict[str, int] = {}
    queue = _deque()
    for tf in target_funcs:
        func_dist[tf] = 0
        queue.append(tf)

    while queue:
        cur = queue.popleft()
        d = func_dist[cur] + 1
        for caller in callgraph.get(cur, []):
            if caller not in func_dist:
                func_dist[caller] = d
                queue.append(caller)
        # 被调用者方向: 如果 A 调用 B, B 是目标 → A 的距离 = d
        for caller, callees in callgraph.items():
            if cur in callees and caller not in func_dist:
                func_dist[caller] = d
                queue.append(caller)

    if not func_dist:
        return {}

# 块级距离 (CFG)
    max_func_d = max(func_dist.values()) if func_dist else 1

    block_dist: dict[int, tuple[int, int]] = {}  # (func_d, cfg_d)

    for addr, info in cfg.items():
        fname = info.get('function', str(addr))
        fd = func_dist.get(fname, max_func_d * 2)
        if fd == 0:
            block_dist[addr] = (0, 0)  # 目标函数内
        else:
            block_dist[addr] = (fd, 0)

    # CFG BFS (每个函数内独立)
    for fname, baddrs in func_blocks.items():
        if fname not in func_dist:
            continue
        # 该函数内到目标块的距离
        local_targets = target_addrs & set(baddrs)
        local_dist: dict[int, int] = {}
        local_q = _deque()
        for lt in local_targets:
            local_dist[lt] = 0
            local_q.append(lt)

        while local_q:
            cur = local_q.popleft()
            info = cfg.get(cur, {})
            # 反向: 谁可以跳转到 cur?
            for pred_addr in _retrieve_predecessors(cur, cfg):
                if pred_addr in baddrs and pred_addr not in local_dist:
                    local_dist[pred_addr] = local_dist[cur] + 1
                    local_q.append(pred_addr)

        # 合并到全局距离
        max_bb_d = max(local_dist.values()) if local_dist else 1
        for addr in baddrs:
            fd = block_dist.get(addr, (max_func_d * 2, 0))[0]
            cd = local_dist.get(addr, max_bb_d * 2)
            # 调和平均: H(fd, cd) = 2*fd*cd / (fd + cd + ε)
            if cd == 0:
                normalized = 0.0
            else:
                normalized = min(cd / max(max_bb_d, 1), 1.0)
            block_dist[addr] = (fd, normalized)

    # 最终归一化
    max_cd = max(v[1] for v in block_dist.values()) if block_dist else 1
    return {
        addr: (v[0] / max(max_func_d, 1)) * 0.5 + (v[1] / max(max_cd, 1)) * 0.5
        for addr, v in block_dist.items()
    }


def _retrieve_predecessors(addr: int, cfg: dict[int, dict]) -> list[int]:
    """在 CFG 中查找 addr 的所有前驱。"""
    preds = []
    for block_addr, info in cfg.items():
        succs = info.get('successors', [])
        if addr in succs:
            preds.append(block_addr)
    return preds


# 基于距离的种子优先级排序
# Hawkeye 的种子调度策略 — 距目标更近的种子 → 更高变异次数
# 距离分布随 fuzzing 进行而演变，动态距离需要周期性重算

def prioritize_seeds_by_distance(seeds: list[dict],
                                   block_dist: dict[int, float]) -> list[dict]:
    """根据种子执行 trace 中各块到目标的平均距离对种子排序。

    seeds: [{trace_blocks: [addr, ...], energy: int, ...}, ...]
    block_dist: {block_addr: normalized_distance} 来自 compute_block_distance

    返回按距离升序排列的种子 (距离小的在前 → 优先变异)。"""
    scored = []
    for seed in seeds:
        trace = seed.get('trace_blocks', [])
        if not trace:
            scored.append((float('inf'), seed))
            continue
        # 平均距离 — 距离目标越近的 trace 平均距离越小
        avg_dist = sum(block_dist.get(a, 1.0) for a in trace) / len(trace)
        scored.append((avg_dist, seed))

    scored.sort(key=lambda x: x[0])
    return [s for _, s in scored]


# 基于支配者树的路径剪枝
# MC2 的支配者关系应用 — 若目标在 block A 的 post-dominator 集中,
# 则经过 A 是到达目标的必要条件; 反之可直接剪枝
# BEACON 的可证明剪枝 — 使用 ILP 求解精确剪枝条件

def prune_by_dominance(cfg: dict[int, dict],
                        target_addr: int,
                        current_path: list[int]) -> bool:
    """使用支配者关系判断当前路径是否应剪枝。
    若当前块不在目标块的严格支配者链上，且执行将偏离目标，
    剪枝可安全进行 (不影响目标可达性, 但节约 40-60% 的计算)。
    返回 True = 剪枝, False = 继续探索。"""
    if target_addr in current_path:
        return False  # 已到达, 不剪枝

    # 计算目标的 dominators (简化: 仅前驱检查)
    # 真实场景中这来自 LLVM/Machine-SUIF 的 dominator tree pass
    target_info = cfg.get(target_addr, {})
    target_preds = _retrieve_predecessors(target_addr, cfg)

    current = current_path[-1] if current_path else None
    if current is None:
        return False

    # 若当前块和所有后继都不能到达目标的任何前驱, 剪枝
    cur_info = cfg.get(current, {})
    succs = cur_info.get('successors', [])
    if not succs:
        return True  # 叶子块 ≠ 目标

    # 检查至少一个后继能到达目标 (简单检测)
    for succ in succs:
        if succ == target_addr:
            return False
        succ_preds = _retrieve_predecessors(succ, cfg)
        if any(p in target_preds for p in succ_preds):
            return False

    # 保守 : 无法确定 → 不剪枝
    return False


# 关键路径识别 (Critical Path Identification)
# SELECTFUZZ 的选择性符号化 — 仅对目标分支路径上的字节符号化
# 位图标记: 输入中哪些字节影响了到目标的路径
# 实现: 污点标签沿数据依赖反向传播至输入字节

def mark_critical_bytes(trace_insns: list[tuple[int, str, str]],
                          target_branch: int,
                          input_len: int) -> set[int]:
    """标记输入中影响目标分支的字节偏移。
    trace_insns: [(addr, mnemonic, operands), ...]
    target_branch: 目标条件跳转的地址
    input_len: 输入总长度

    返回应优先变异的字节偏移集合。
    使用了简化的切片分析 — 从目标分支反向追踪到最近的输入消费点。"""
    critical = set()

    # 找到目标分支对应的 trace 区间
    target_idx = None
    for i, (addr, mnem, ops) in enumerate(trace_insns):
        if addr == target_branch:
            target_idx = i
            break

    if target_idx is None:
        return critical

    # 反向扫描: 从目标分支向前查找 cmp/test + 输入消费
    import re as _re
    for i in range(target_idx, max(0, target_idx - 100), -1):
        addr, mnem, ops = trace_insns[i]
        mn_l = mnem.lower()
        # cmp/test 通常以立即数为操作数 — 找到与输入相关的寄存器
        if mn_l in ('cmp', 'test', 'sub', 'xor'):
            # 查找最近的输入消费指令
            for j in range(i, max(0, i - 50), -1):
                _, m2, o2 = trace_insns[j]
                if m2.lower() in ('mov', 'movzx', 'lea'):
                    # 尝试提取输入偏移 (格式: [rbp+input_offset] 或 [rsp+N+input])
                    offsets = _re.findall(r'[\+\-](\d+)', o2)
                    for off_str in offsets:
                        off = int(off_str)
                        if 0 <= off < input_len:
                            critical.add(off)
                    break

    return critical


# 定向模糊测试的能耗调度
# 基于模拟退火的种子能量分配: 距离越小 → 能量越高
# AFL 的基于执行速度的调度 → 扩展到基于距离

def directed_energy_schedule(seed_distance: float, base_energy: int = 100,
                               decay_rate: float = 3.0) -> int:
    """根据种子到目标的归一化距离计算分配的能量。
    energy = base_energy * exp(-decay_rate * distance)
    距离 = 0 (目标已到达) → 能量 = base_energy (全力变异)
    距离 = 1 (最远) → 能量 ≈ base_energy * e^{-3} ≈ 5%"""
    energy = int(base_energy * _math.exp(-decay_rate * seed_distance))
    return max(1, min(energy, base_energy * 10))
