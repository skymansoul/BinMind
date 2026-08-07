# CFG变换操作集——对抗性CFG伪装的具体变换实现
#
# 变换操作与评估器独立管理, AdversarialCFGTransformer 通过 dispatch 表调用。
# 未来可在不修改主引擎的前提下扩展新的变换操作。

from __future__ import annotations

import random
from collections import defaultdict
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from .adversarial_cfg import (
    AdversarialCFGResult,
    BasicBlock,
    CFGSpec,
    TransformOp,
    TransformStep,
)

if TYPE_CHECKING:
    from .adversarial_cfg import AdversarialCFGTransformer


# 变换操作 (独立函数, 不依赖 Transformer 实例)

def _sim_split_block(cfg: CFGSpec, block: BasicBlock,
                      rng: Optional[random.Random] = None) -> Optional[TransformStep]:
    if block.instruction_count < 2:
        return None
    new_id = max(cfg.blocks.keys()) + 1 if cfg.blocks else 1
    split_pt = block.instruction_count // 2
    new_block = BasicBlock(
        block_id=new_id,
        instruction_count=block.instruction_count - split_pt,
    )
    block.instruction_count = split_pt
    old_succs = list(block.successors)
    block.successors = [new_id]
    new_block.successors = old_succs
    new_block.predecessors = [block.block_id]
    cfg.blocks[new_id] = new_block
    cfg.adjacency[block.block_id] = [new_id]
    cfg.adjacency[new_id] = old_succs
    cfg.block_sizes[new_id] = new_block.instruction_count
    cfg.block_sizes[block.block_id] = split_pt
    return TransformStep(
        op=TransformOp.SPLIT_BLOCK, target_block=block.block_id,
        description=f"拆分 BB#{block.block_id} → #{block.block_id} + #{new_id}",
        entropy_delta=0.08, size_delta=0,
    )


def _sim_merge_blocks(cfg: CFGSpec, block: BasicBlock,
                       rng: Optional[random.Random] = None) -> Optional[TransformStep]:
    if len(block.successors) != 1:
        return None
    succ_id = block.successors[0]
    succ = cfg.blocks.get(succ_id)
    if succ is None or len(succ.predecessors) != 1:
        return None
    block.instruction_count += succ.instruction_count
    block.successors = list(succ.successors)
    for s in succ.successors:
        sblk = cfg.blocks.get(s)
        if sblk:
            sblk.predecessors = [
                block.block_id if p == succ_id else p
                for p in sblk.predecessors
            ]
    cfg.blocks.pop(succ_id)
    cfg.adjacency.pop(succ_id, None)
    cfg.block_sizes.pop(succ_id, None)
    cfg.adjacency[block.block_id] = block.successors
    cfg.block_sizes[block.block_id] = block.instruction_count
    return TransformStep(
        op=TransformOp.MERGE_BLOCKS, target_block=block.block_id,
        description=f"合并 BB#{block.block_id} + #{succ_id}",
        entropy_delta=-0.05, size_delta=0,
    )


def _sim_insert_nop_block(cfg: CFGSpec, block: BasicBlock,
                           rng: Optional[random.Random] = None) -> Optional[TransformStep]:
    new_id = max(cfg.blocks.keys()) + 1 if cfg.blocks else 1
    nop_block = BasicBlock(block_id=new_id, instruction_count=3)
    if not block.successors:
        return None
    orig_succ = block.successors[0]
    block.successors = [new_id]
    nop_block.successors = [orig_succ]
    nop_block.predecessors = [block.block_id]
    cfg.blocks[new_id] = nop_block
    cfg.adjacency[block.block_id] = [new_id]
    cfg.adjacency[new_id] = [orig_succ]
    cfg.block_sizes[new_id] = 3
    if orig_succ in cfg.blocks:
        cfg.blocks[orig_succ].predecessors = [
            new_id if p == block.block_id else p
            for p in cfg.blocks[orig_succ].predecessors
        ]
    return TransformStep(
        op=TransformOp.INSERT_NOP_BLOCK, target_block=block.block_id,
        description=f"插入 NOP 块 #{new_id} 在 BB#{block.block_id} 之后",
        entropy_delta=0.06, size_delta=3,
    )


def _sim_reorder_blocks(cfg: CFGSpec, block: BasicBlock,
                         rng: Optional[random.Random] = None) -> Optional[TransformStep]:
    if len(cfg.blocks) < 2:
        return None
    others = [bid for bid in cfg.blocks if bid != block.block_id]
    if not others:
        return None
    # 确定性选择而非随机, 保证可复现
    swap_id = others[0] if rng is None else (rng.choice(others) if rng else others[0])
    cfg.adjacency[block.block_id], cfg.adjacency[swap_id] = (
        cfg.adjacency.get(swap_id, []),
        cfg.adjacency.get(block.block_id, []),
    )
    return TransformStep(
        op=TransformOp.REORDER_BLOCKS, target_block=block.block_id,
        description=f"重排 BB#{block.block_id} ↔ BB#{swap_id}",
        entropy_delta=0.02, size_delta=0,
    )


def _sim_duplicate_block(cfg: CFGSpec, block: BasicBlock,
                          rng: Optional[random.Random] = None) -> Optional[TransformStep]:
    new_id = max(cfg.blocks.keys()) + 1 if cfg.blocks else 1
    dup_block = BasicBlock(
        block_id=new_id,
        instruction_count=block.instruction_count,
        successors=list(block.successors),
    )
    cfg.blocks[new_id] = dup_block
    cfg.adjacency[new_id] = list(block.successors)
    cfg.block_sizes[new_id] = block.instruction_count
    return TransformStep(
        op=TransformOp.DUPLICATE_BLOCK, target_block=block.block_id,
        description=f"复制 BB#{block.block_id} → #{new_id}",
        entropy_delta=0.10, size_delta=block.instruction_count,
    )


def _sim_equivalent_instr(cfg: CFGSpec, block: BasicBlock,
                           rng: Optional[random.Random] = None) -> Optional[TransformStep]:
    delta = -1 if (rng is None) else (rng.choice([-1, 1]) if rng else -1)
    new_size = max(1, block.instruction_count + delta)
    old_size = block.instruction_count
    block.instruction_count = new_size
    cfg.block_sizes[block.block_id] = new_size
    return TransformStep(
        op=TransformOp.EQUIVALENT_INSTR, target_block=block.block_id,
        description=f"等价指令替换 BB#{block.block_id} ({old_size}→{new_size} 指令)",
        entropy_delta=0.03, size_delta=delta,
    )


def _sim_clone_then_guard(cfg: CFGSpec, block: BasicBlock,
                           rng: Optional[random.Random] = None) -> Optional[TransformStep]:
    if block.is_exit:
        return None
    new_id = max(cfg.blocks.keys()) + 1 if cfg.blocks else 1
    guard_id = new_id + 1
    clone = BasicBlock(
        block_id=new_id,
        instruction_count=block.instruction_count,
        successors=list(block.successors),
    )
    guard = BasicBlock(
        block_id=guard_id, instruction_count=2,
        successors=[block.block_id],
    )
    cfg.blocks[new_id] = clone
    cfg.blocks[guard_id] = guard
    cfg.adjacency[guard_id] = [block.block_id, new_id]
    cfg.adjacency[new_id] = list(block.successors)
    cfg.block_sizes[new_id] = block.instruction_count
    cfg.block_sizes[guard_id] = 2
    return TransformStep(
        op=TransformOp.CLONE_THEN_GUARD, target_block=block.block_id,
        description=f"克隆守卫: BB#{block.block_id} + #{new_id} + guard #{guard_id}",
        entropy_delta=0.15, size_delta=block.instruction_count + 2,
    )


# Dispatch 表 — 操作符 → 函数

_SIM_DISPATCH = {
    TransformOp.SPLIT_BLOCK: _sim_split_block,
    TransformOp.MERGE_BLOCKS: _sim_merge_blocks,
    TransformOp.INSERT_NOP_BLOCK: _sim_insert_nop_block,
    TransformOp.REORDER_BLOCKS: _sim_reorder_blocks,
    TransformOp.DUPLICATE_BLOCK: _sim_duplicate_block,
    TransformOp.EQUIVALENT_INSTR: _sim_equivalent_instr,
    TransformOp.CLONE_THEN_GUARD: _sim_clone_then_guard,
}


def simulate_transform(cfg: CFGSpec, block_id: int, op: TransformOp,
                        rng: Optional[random.Random] = None) -> Optional[TransformStep]:
    """对指定基本块模拟变换操作——修改 cfg 并返回 TransformStep。"""
    block = cfg.blocks.get(block_id)
    if block is None:
        return None
    handler = _SIM_DISPATCH.get(op)
    if handler is None:
        return None
    return handler(cfg, block, rng)


def apply_transform(cfg: CFGSpec, step: TransformStep,
                     rng: Optional[random.Random] = None) -> None:
    """将 TransformStep 应用到实际的 working CFG 上。"""
    block = cfg.blocks.get(step.target_block)
    if block is None:
        return
    handler = _SIM_DISPATCH.get(step.op)
    if handler:
        handler(cfg, block, rng)


# 鲁棒性评估器

class CFGRobustnessEvaluator:
    """CFG 相似性检测器的鲁棒性评估器。

    评估流程:
      1. 从目标二进制提取 CFG 集合
      2. 对每个 CFG 生成对抗性变换
      3. 使用检测器做匹配, 计算变换前后 Top-1/Top-3 匹配率差异
    """

    def __init__(self, matcher=None):
        self._matcher = matcher
        # 延迟构造, 避免模块级循环导入
        from .adversarial_cfg import AdversarialCFGTransformer
        self._transformer = AdversarialCFGTransformer()

    def evaluate(self,
                 cfg_specs: List[CFGSpec],
                 target_distance: float = 0.25,
                 ) -> Dict[str, Any]:
        results: List[AdversarialCFGResult] = []
        for cfg in cfg_specs:
            try:
                adv_result = self._transformer.transform(
                    cfg, target_distance=target_distance, max_steps=10)
                results.append(adv_result)
            except Exception:
                continue

        if not results:
            return {"error": "无有效变换结果"}

        n = len(results)
        avg_dist = sum(r.cosine_distance for r in results) / n
        avg_robustness = sum(r.robustness_score for r in results) / n
        avg_size = sum(r.size_increase_pct for r in results) / n
        max_dist = max(r.cosine_distance for r in results)

        return {
            "total_cfgs": len(cfg_specs),
            "transformed": n,
            "avg_cosine_distance": round(avg_dist, 4),
            "max_cosine_distance": round(max_dist, 4),
            "avg_robustness_score": round(avg_robustness, 4),
            "avg_size_increase_pct": round(avg_size, 2),
            "evasion_potential": (
                "high" if avg_dist > 0.2
                else "medium" if avg_dist > 0.1
                else "low"
            ),
        }
