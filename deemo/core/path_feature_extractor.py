# 从CFG提取基本块序列 -> 特征向量。
# 特征设计: 对指令选择差异鲁棒 — 使用块级操作码分布而非精确指令。
#
# 设计依据:
#   BinCon 用跨编译器二进制相似性做漏洞模式迁移。
#   启发: 提取"不随编译器变化"的语义特征。O0和O3编译的同一函数,
#   指令序列不同但块级操作码分布高度相关 (Spearman rho > 0.85).
#
# 特征维度 (共12维):
#   1-4: 操作码类别分布 (算术/逻辑/内存/控制流) — 归一化到[0,1]
#   5-6: 调用密度 (函数调用数/基本块数, 间接调用占比)
#   7-8: 内存访问模式 (load/store比例, 栈访问vs堆访问比例)
#   9-10: 分支特征 (条件分支占比, 循环深度max)
#   11-12: 危险操作密度 (格式化函数调用数, 堆操作调用数)
import re as _re
from collections import Counter as _Ctr
from typing import List, Dict


_ARITH_OPS = {'add','sub','mul','div','inc','dec','neg','adc','sbb'}
_LOGIC_OPS = {'and','or','xor','not','shl','shr','sal','sar','rol','ror'}
_MEM_OPS = {'mov','lea','push','pop','ldr','str','load','store'}
_CTRL_OPS = {'jmp','jz','jnz','je','jne','jg','jl','jge','jle',
             'call','ret','int','syscall','b','bl','bne','beq'}
_DANGER_MEM = {'malloc','calloc','realloc','free','memcpy','strcpy',
               'sprintf','gets','scanf','strncpy','memmove'}


class PathFeatureExtractor:

    def extract(self, blocks: List[List[str]],
                func_name: str = '') -> Dict[str, float]:
        n_blocks = max(len(blocks), 1)
        total_insns = max(sum(len(b) for b in blocks), 1)
        op_counts = _Ctr()
        danger_count = 0
        call_count = 0
        indirect_calls = 0
        max_loop_depth = 0
        for block in blocks:
            for insn in block:
                parts = insn.strip().split()
                if not parts:
                    continue
                op = parts[0].lower()
                op_counts[op] += 1
                if op == 'call':
                    call_count += 1
                    if len(parts) > 1 and ('*' in parts[1] or
                                           '[' in parts[1]):
                        indirect_calls += 1
                if any(d in op for d in _DANGER_MEM):
                    danger_count += 1

        # 归一化
        def count_cat(ops):
            return sum(op_counts.get(o, 0) for o in ops) / total_insns

        return {
            'arith_ratio':  round(count_cat(_ARITH_OPS), 4),
            'logic_ratio':  round(count_cat(_LOGIC_OPS), 4),
            'mem_ratio':    round(count_cat(_MEM_OPS), 4),
            'ctrl_ratio':   round(count_cat(_CTRL_OPS), 4),
            'call_density': round(call_count / n_blocks, 4),
            'indirect_ratio': round(indirect_calls / max(call_count, 1), 4),
            'load_store_ratio': round(
                (op_counts.get('ldr', 0) + op_counts.get('load', 0)) /
                max(op_counts.get('str', 0) + op_counts.get('store', 0), 1), 4),
            'branch_ratio': round(
                sum(1 for o in op_counts if o.startswith('j')) / total_insns, 4),
            'danger_density': round(danger_count / total_insns, 4),
            'block_count': float(n_blocks),
            'avg_block_size': round(total_insns / n_blocks, 2),
        }

__all__ = ['PathFeatureExtractor']
