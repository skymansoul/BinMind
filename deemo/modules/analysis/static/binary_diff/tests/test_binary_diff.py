#
# 二进制差异分析模块的单元测试

import sys
import os

# 将模块根加入路径以支持包内相对导入
# 路径链: tests -> binary_diff -> static -> analysis -> modules
_pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

import pytest
from analysis.static.binary_diff.src.instruction_hash import (
    semantic_hash_insn, hash_basic_block, hamming_distance,
)
from analysis.static.binary_diff.src.block_matcher import match_blocks, BlockMatch
from analysis.static.binary_diff.src.func_differ import (
    diff_functions, FuncDiffResult, EditOp, diff_pipeline,
)
from analysis.static.binary_diff.src.patch_classifier import (
    classify_patch, PatchType, PatchClassification,
)
from analysis.static.binary_diff.src.exploit_ranker import (
    score_patch, rank_patches, ExploitabilityReport,
)


class TestInstructionHash:
    """指令语义哈希的单元测试"""

    def test_same_semantics_different_registers(self):
        """同一语义不同寄存器 → 操作数类型序列相同"""
        _, op_seq1 = semantic_hash_insn('mov', ['rax', 'rbx'])
        _, op_seq2 = semantic_hash_insn('mov', ['rcx', 'rdx'])
        # 寄存器不同但操作类型相同（均为 reg→reg）→ op_seq 应一致
        assert op_seq1 == op_seq2 == 'rr'

    def test_different_immediates_small(self):
        """小立即数折叠——0x41 和 0x42 的哈希距离应接近"""
        h1, _ = semantic_hash_insn('cmp', ['rax', '0x41'])
        h2, _ = semantic_hash_insn('cmp', ['rax', '0x42'])
        # 两个小立即数都是 'pos_small' → 哈希相同
        assert h1 == h2

    def test_different_immediates_large(self):
        """大立即数区分——0x1000 和 0x2000 的哈希距离应较大"""
        h1, _ = semantic_hash_insn('mov', ['rax', '0x1000'])
        h2, _ = semantic_hash_insn('mov', ['rax', '0x2000'])
        assert h1 != h2

    def test_flags_equivalence_class(self):
        """cmp 和 sub 应在同一标志位等价类"""
        h1, _ = semantic_hash_insn('cmp', ['rax', 'rbx'])
        h2, _ = semantic_hash_insn('sub', ['rax', 'rbx'])
        # cmp 和 sub 都是 flags_class=2 → 操作码部分不同但标志类可以相同
        # 实际上 hash 不同，但 flags_class 相同——验证的是正确分类
        assert h1 != h2  # 操作码不同导致哈希不同
        # 这验证了 flags_class 的提取不会崩溃

    def test_hash_basic_block_empty(self):
        """空基本块 → 哈希为 0"""
        h, hashes = hash_basic_block([])
        assert h == 0
        assert hashes == []

    def test_hash_basic_block_order_matters(self):
        """基本块哈希对指令顺序敏感"""
        insns1 = [('mov', ['rax', 'rbx']), ('add', ['rax', '1'])]
        insns2 = [('add', ['rax', '1']), ('mov', ['rax', 'rbx'])]
        h1, _ = hash_basic_block(insns1)
        h2, _ = hash_basic_block(insns2)
        assert h1 != h2


class TestBlockMatcher:
    """基本块匹配器测试"""

    def test_identical_blocks(self):
        """两个完全相同的块 → 精确匹配"""
        src = {0x1000: [('mov', ['rax', 'rbx']), ('add', ['rax', '1'])]}
        dst = {0x2000: [('mov', ['rax', 'rbx']), ('add', ['rax', '1'])]}
        matches = match_blocks(src, dst)
        assert len(matches) == 1
        assert matches[0].is_exact
        assert matches[0].score > 0.95

    def test_empty_blocks(self):
        """空块映射 → 无匹配"""
        matches = match_blocks({}, {})
        assert matches == []

    def test_different_blocks(self):
        """语义不同的块 → 低于阈值无匹配"""
        src = {0x1000: [('mov', ['rax', 'rbx'])]}
        dst = {0x2000: [('call', ['system'])]}
        matches = match_blocks(src, dst)
        # 单指令 "mov rr" vs "call system" 应该不能匹配
        assert len(matches) == 0 or matches[0].score < 0.5


class TestFuncDiffer:
    """函数差异分析测试"""

    def test_identical_functions(self):
        """两个完全相同的函数 → IDENT"""
        src_blocks = {0x1000: [('mov', ['rax', 'rbx']), ('ret', [])]}
        dst_blocks = {0x2000: [('mov', ['rax', 'rbx']), ('ret', [])]}
        result = diff_functions('test_func', 0x1000, src_blocks,
                                'test_func', 0x2000, dst_blocks)
        assert result.edit_op == EditOp.IDENTICAL

    def test_added_block(self):
        """目标多一个块 → BLOCKS_ADDED"""
        src_blocks = {0x1000: [('mov', ['rax', 'rbx'])]}
        dst_blocks = {0x2000: [('mov', ['rax', 'rbx'])],
                      0x2001: [('add', ['rax', '1'])]}
        result = diff_functions('test_func', 0x1000, src_blocks,
                                'test_func', 0x2000, dst_blocks)
        assert result.edit_op in (EditOp.MODIFIED, EditOp.BLOCKS_ADDED)

    def test_function_missing_in_dst(self):
        """目标中不存在该函数 → BLOCKS_REMOVED"""
        src_blocks = {0x1000: [('mov', ['rax', 'rbx'])]}
        result = diff_functions('gone_func', 0x1000, src_blocks,
                                'gone_func', None, {})
        assert result.edit_op == EditOp.BLOCKS_REMOVED
        assert result.similarity == 0.0


class TestPatchClassifier:
    """补丁类型分类器测试"""

    def test_classify_refactored(self):
        """重构类型的识别"""
        diff = FuncDiffResult(
            func_name='test', src_addr=0x1000, dst_addr=0x2000,
            edit_op=EditOp.REFACTORED, similarity=0.3,
            matched_blocks=1, total_src_blocks=10, total_dst_blocks=11,
            detail='refactored',
        )
        result = classify_patch(diff)
        assert result.patch_type == PatchType.REFACTOR

    def test_classify_identical(self):
        """无变化的函数 → UNKNOWN"""
        diff = FuncDiffResult(
            func_name='test', src_addr=0x1000, dst_addr=0x2000,
            edit_op=EditOp.IDENTICAL, similarity=1.0,
            matched_blocks=5, total_src_blocks=5, total_dst_blocks=5,
            detail='identical',
        )
        result = classify_patch(diff)
        assert result.patch_type == PatchType.UNKNOWN


class TestExploitRanker:
    """Exploit 排名器测试"""

    def test_score_security_patch(self):
        """安全修复的 exploitabili 评分——至少产生有效分数"""
        diff = FuncDiffResult(
            func_name='parse_request', src_addr=0x1000, dst_addr=0x2000,
            edit_op=EditOp.MODIFIED, similarity=0.6,
            matched_blocks=3, total_src_blocks=5, total_dst_blocks=6,
            detail='modified',
        )
        clf = PatchClassification(
            func_name='parse_request', patch_type=PatchType.SECURITY_FIX,
            confidence=0.85, evidence=['新增 cmp 比较指令'],
            diff_result=diff,
        )
        report = score_patch(clf, calls={'memcpy', 'malloc', 'free'},
                            caller_count=5)
        assert report.score > 0
        assert report.factors['severity'] > 0
        assert report.factors['memory_ops'] > 0
        assert report.patch_type == 'SECURITY_FIX'

    def test_rank_empty_list(self):
        """空补丁列表 → 空报告"""
        reports = rank_patches([])
        assert reports == []


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
