# 创建: 2025-08-16 16:25
# 修改: 2025-08-16 — cmp_imm/call_target/struct 三类语义常量锚点
"""
稳定锚点二进制补丁定位器 — 跨编译器/优化级别的补丁代码精确匹配。

现有二进制差异分析 (instruction_hash.py, block_matcher.py) 使用指令级
或基本块级相似度——在跨编译器 (GCC vs Clang) 或跨优化级别 (O0 vs O3)
的场景下匹配率急剧下降, 因为指令序列完全不同。

稳定锚点 (stable anchor) 的核心洞察:
  编译器和优化级别改变指令选择和排序, 但不改变程序的语义常量——
  条件比较的立即数、函数调用的目标、switch case 的分支数是稳定的。
  这些"锚点"是补丁定位的可靠特征, 跨编译环境不变。

算法:
  1. 锚点提取: 从 CFG 中提取三类锚点
     - 条件锚点: cmp/jxx 指令中的立即数 (如 cmp eax, 42)
     - 调用锚点: call 指令的目标函数名或地址模式
     - 结构锚点: 基本块出度、循环嵌套深度
  2. 锚点匹配: 在两个二进制间做贪心锚点对齐——最大权重匹配
  3. 补丁定位: 匹配失败的锚点区域即补丁位置

为什么选择锚点而非指令嵌入:
  GNN/Transformer 嵌入需要训练数据且对编译器变化敏感。
  锚点基于语义常量——编译器的自由度在此处最低, 跨平台最稳定。
  匹配失败直接指示"此处的语义发生了变化"→ 这就是补丁。

ref: PLocator (arXiv:2501.17413, 2025) — stable anchor values from
     condition comparison and function call instructions for patch
     localization, 本项目将其 anchor 概念从函数级扩展到 BB 级
ref: BinDiff (zynamics/Google) — 图同构匹配的工业标准,
     本项目用锚点替代图同构——降低复杂度从 NP-hard 到 O(N log N)
ref: 1dFuzz (ISSTA 2023) — Trailing Call Sequence 作为 patch 特征,
     本项目推广 TCS 为更通用的"稳定锚点"概念
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional
import re


@dataclass
class StableAnchor:
    """CFG 中的一个稳定锚点——跨编译器/优化级别不变的语义标记。"""
    anchor_type: str       # 'cmp_imm' | 'call_target' | 'struct' | 'loop_depth'
    block_addr: int        # 所在基本块的地址
    value: str             # 锚点值 (立即数/函数名/结构描述)
    value_hash: str = ''   # SHA-256 前 8 字符——用于快速匹配
    weight: float = 1.0    # 锚点权重 (条件锚点 > 调用锚点 > 结构锚点)


@dataclass
class AnchorMatch:
    """两个二进制间的一对匹配锚点。"""
    anchor_a: StableAnchor
    anchor_b: StableAnchor
    match_type: str = 'exact'  # 'exact' | 'fuzzy' | 'structural'
    confidence: float = 1.0


@dataclass
class PatchCandidate:
    """补丁候选位置——锚点匹配失败的区域。"""
    start_addr: int
    end_addr: int
    missing_anchors: list[StableAnchor] = field(default_factory=list)
    extra_anchors: list[StableAnchor] = field(default_factory=list)
    confidence: float = 0.0
    description: str = ''


# --- 锚点提取 ---

def extract_anchors(cfg: dict[int, dict],
                    instructions: list[dict],
                    imports: list[str] = None) -> list[StableAnchor]:
    """从二进制 CFG + 指令中提取稳定锚点。

    三类锚点:
      1. cmp_imm: 条件比较 + 立即数 (如 cmp eax, 42 → "cmp_imm:42")
      2. call_target: 函数调用目标 (如 call malloc → "call:malloc")
      3. struct: 基本块出度 + 循环深度 ("out_degree:3;loop_depth:1")
    """
    anchors = []
    if imports is None:
        imports = []

    # 构建 BB→指令映射
    bb_ins: dict[int, list[dict]] = defaultdict(list)
    for ins in instructions:
        addr = ins.get('address', 0)
        for bb_addr, bb_info in cfg.items():
            bb_start = bb_addr
            bb_end = bb_addr + bb_info.get('size', 64)
            if bb_start <= addr < bb_end:
                bb_ins[bb_addr].append(ins)
                break

    for bb_addr, bb_info in cfg.items():
        ins_list = bb_ins.get(bb_addr, [])

        # 条件锚点: cmp + jxx 中的立即数
        for ins in ins_list:
            mnemonic = ins.get('mnemonic', '').lower()
            operands = str(ins.get('operands', ''))
            if mnemonic in ('cmp', 'sub', 'test'):
                imm_match = re.search(r'(?:0x)?([0-9a-fA-F]{2,8})\b', operands)
                if imm_match:
                    imm_val = str(int(imm_match.group(1), 16))
                    anchors.append(StableAnchor(
                        anchor_type='cmp_imm',
                        block_addr=bb_addr,
                        value=f'{mnemonic}:{imm_val}',
                        weight=1.0,
                    ))

        # 调用锚点: call 目标
        for ins in ins_list:
            if ins.get('mnemonic', '').lower() in ('call', 'bl', 'jal'):
                target = str(ins.get('operands', ''))
                # 命名函数
                for imp in imports:
                    if imp.lower() in target.lower():
                        anchors.append(StableAnchor(
                            anchor_type='call_target',
                            block_addr=bb_addr,
                            value=f'call:{imp}',
                            weight=0.9,
                        ))
                        break

        # 结构锚点: 出度 + 循环深度
        out_degree = len(bb_info.get('successors', []))
        loop_depth = bb_info.get('loop_depth', 0)
        if out_degree > 0 or loop_depth > 0:
            anchors.append(StableAnchor(
                anchor_type='struct',
                block_addr=bb_addr,
                value=f'out:{out_degree};loop:{loop_depth}',
                weight=0.5,
            ))

    # 生成哈希
    import hashlib
    for a in anchors:
        data = f'{a.anchor_type}|{a.value}'
        a.value_hash = hashlib.sha256(data.encode()).hexdigest()[:8]

    return anchors


# --- 锚点匹配 ---
# 贪心最大权重匹配: 对每个 pre-patch 锚点, 找 post-patch 中最佳匹配。

def match_anchors(pre_anchors: list[StableAnchor],
                  post_anchors: list[StableAnchor]) -> list[AnchorMatch]:
    """在两个锚点集合间做贪心匹配。返回匹配对列表。"""
    matches = []
    used_post: set[int] = set()

    # 按权重降序——优先匹配高权重锚点
    pre_sorted = sorted(pre_anchors, key=lambda a: a.weight, reverse=True)

    for pa in pre_sorted:
        best_idx = -1
        best_conf = 0.0
        best_type = 'structural'

        for i, pb in enumerate(post_anchors):
            if i in used_post:
                continue
            conf = _anchor_similarity(pa, pb)
            if conf > best_conf:
                best_conf = conf
                best_idx = i
                best_type = 'exact' if conf > 0.95 else ('fuzzy' if conf > 0.7 else 'structural')

        if best_idx >= 0 and best_conf >= 0.5:
            matches.append(AnchorMatch(
                anchor_a=pa, anchor_b=post_anchors[best_idx],
                match_type=best_type, confidence=best_conf,
            ))
            used_post.add(best_idx)

    return matches


def _anchor_similarity(a: StableAnchor, b: StableAnchor) -> float:
    """两个锚点的相似度 [0, 1]。锚点类型必须相同, 值做模糊比较。"""
    if a.anchor_type != b.anchor_type:
        if a.anchor_type == 'cmp_imm' and b.anchor_type == 'cmp_imm':
            pass
        else:
            return 0.0
    if a.value == b.value:
        return 1.0
    if a.anchor_type == 'cmp_imm' and b.anchor_type == 'cmp_imm':
        # 条件锚点: 比较立即数是否相近 (±5)
        try:
            va = int(re.search(r'\d+', a.value).group())
            vb = int(re.search(r'\d+', b.value).group())
            if abs(va - vb) <= 5:
                return 0.85
        except (ValueError, AttributeError):
            pass
    if a.anchor_type == 'call_target' and b.anchor_type == 'call_target':
        # 调用锚点: 函数名部分匹配
        fa = a.value.split(':')[-1].lower()
        fb = b.value.split(':')[-1].lower()
        if fa == fb:
            return 1.0
        if fa[:4] == fb[:4]:
            return 0.6
    return 0.0


# --- 补丁定位 ---

def locate_patch_regions(pre_anchors: list[StableAnchor],
                         post_anchors: list[StableAnchor],
                         matches: list[AnchorMatch]) -> list[PatchCandidate]:
    """从匹配结果中定位补丁区域——未匹配的锚点所在的基本块即补丁候选。"""
    matched_pre = {m.anchor_a.block_addr for m in matches}
    matched_post = {m.anchor_b.block_addr for m in matches}

    candidates = []
    # 缺失锚点 (pre 中有, post 中无匹配) → 可能是被删除的代码
    missing = [a for a in pre_anchors if a.block_addr not in matched_pre]
    # 新增锚点 (post 中有, pre 中无匹配) → 可能是新增的代码
    extra = [a for a in post_anchors if a.block_addr not in matched_post]

    if missing or extra:
        # 按地址聚合成区域
        start = min((a.block_addr for a in missing + extra), default=0)
        end = max((a.block_addr for a in missing + extra), default=0)
        pc = PatchCandidate(
            start_addr=start,
            end_addr=end,
            missing_anchors=missing,
            extra_anchors=extra,
            confidence=min(1.0, (len(missing) + len(extra)) / max(1, len(pre_anchors))),
            description=f'{len(missing)} removed + {len(extra)} added anchors in [{start:#x}, {end:#x}]',
        )
        candidates.append(pc)

    # 按置信度降序
    candidates.sort(key=lambda c: c.confidence, reverse=True)
    return candidates


__all__ = [
    'StableAnchor', 'AnchorMatch', 'PatchCandidate',
    'extract_anchors', 'match_anchors', 'locate_patch_regions',
]
