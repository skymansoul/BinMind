"""DCG差分约束图单元测试——验证FW传递闭包、约束提取、安全证明"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.difference_constraint import (
    DifferenceConstraintGraph, DCGBuilder, verify_heap_safety, _INF)


class TestDCGCore:
    """DCG核心: 图构建+Floyd-Warshall+查询"""

    def test_add_and_query_direct(self):
        """直接约束: rbx ≤ rax + 0 → query(rbx, rax) = 0"""
        dcg = DifferenceConstraintGraph()
        dcg.add_constraint('rbx', 'rax', 0)
        dcg.close()
        assert dcg.query('rbx', 'rax') == 0

    def test_transitive_closure(self):
        """传递闭包: rbx≤rax, rcx≤rbx+16 → rcx≤rax+16"""
        dcg = DifferenceConstraintGraph()
        dcg.add_constraint('rbx', 'rax', 0)    # rbx ≤ rax
        dcg.add_constraint('rcx', 'rbx', 16)    # rcx ≤ rbx + 16
        dcg.close()
        assert dcg.query('rcx', 'rax') == 16

    def test_equality(self):
        """等式: rbx = rax → rbx≤rax ∧ rax≤rbx"""
        dcg = DifferenceConstraintGraph()
        dcg.add_equal('rbx', 'rax')
        dcg.close()
        assert dcg.query('rbx', 'rax') == 0
        assert dcg.query('rax', 'rbx') == 0

    def test_bound(self):
        """绝对值约束: rax ≤ 256 → rax - ZERO ≤ 256"""
        dcg = DifferenceConstraintGraph()
        dcg.add_bound('rax', 256, is_upper=True)
        dcg.close()
        assert dcg.query('rax', 'ZERO') == 256

    def test_lower_bound(self):
        """下界: rax ≥ 32 → ZERO - rax ≤ -32"""
        dcg = DifferenceConstraintGraph()
        dcg.add_bound('rax', 32, is_upper=False)
        dcg.close()
        assert dcg.query('ZERO', 'rax') == -32

    def test_bidirectional(self):
        """双向查询: copy-alloc上界+下界"""
        dcg = DifferenceConstraintGraph()
        dcg.add_constraint('copy', 'alloc', 8)   # copy ≤ alloc + 8
        dcg.add_constraint('alloc', 'copy', -4)   # alloc ≤ copy - 4 → copy ≥ alloc + 4
        dcg.close()
        upper, lower = dcg.query_bidirectional('copy', 'alloc')
        assert upper == 8
        assert lower == 4

    def test_no_negative_cycle_normal(self):
        """正常无负环"""
        dcg = DifferenceConstraintGraph()
        dcg.add_constraint('rbx', 'rax', 0)
        dcg.close()
        assert not dcg.has_negative_cycle()

    def test_negative_cycle_detected(self):
        """检测负环: x≤y-1, y≤x-1 → x<x 矛盾"""
        dcg = DifferenceConstraintGraph()
        dcg.add_constraint('rbx', 'rax', -1)
        dcg.add_constraint('rax', 'rbx', -1)
        dcg.close()
        assert dcg.has_negative_cycle()

    def test_no_path(self):
        """无约束路径→返回None"""
        dcg = DifferenceConstraintGraph()
        dcg.add_constraint('rbx', 'rax', 0)
        dcg.close()
        assert dcg.query('rcx', 'rdx') is None

    def test_register_alias(self):
        """32→64位寄存器归一化: eax→rax"""
        dcg = DifferenceConstraintGraph()
        dcg.add_constraint('eax', 'ebx', 0)
        dcg.close()
        assert dcg.query('rax', 'rbx') == 0

    def test_reachable_vars(self):
        """可达变量集合——约束rbx≤rax+0, rcx≤rbx+16 → 从rcx可达rax和rbx"""
        dcg = DifferenceConstraintGraph()
        dcg.add_constraint('rbx', 'rax', 0)     # rbx ≤ rax → dist[rbx][rax]=0
        dcg.add_constraint('rcx', 'rbx', 16)    # rcx ≤ rbx+16 → dist[rcx][rbx]=16
        dcg.close()
        # FW: rcx→rbx→rax → dist[rcx][rax]=16, dist[rcx][rbx]=16
        reachable = dcg.reachable_vars('rcx')
        assert 'rax' in reachable   # rcx经过传递闭包可达rax
        assert 'rbx' in reachable   # rcx可直接达rbx

    def test_max_nodes(self):
        """节点上限保护"""
        dcg = DifferenceConstraintGraph(max_nodes=3)
        assert dcg._get_idx('rax') >= 0
        assert dcg._get_idx('rbx') >= 0
        assert dcg._get_idx('rcx') >= 0
        assert dcg._get_idx('rdx') == -1  # 超限

    def test_close_idempotent(self):
        dcg = DifferenceConstraintGraph()
        dcg.add_constraint('rbx', 'rax', 0)
        dcg.close()
        q1 = dcg.query('rbx', 'rax')
        dcg.close()  # 二次close不变
        assert dcg.query('rbx', 'rax') == q1


class TestDCGBuilder:
    """DCGBuilder: 从指令序列提取约束"""

    def test_mov_equality(self):
        """mov %rax, %rbx → rbx = rax"""
        builder = DCGBuilder()
        dcg = builder.build(['mov %rax, %rbx'])
        assert dcg.query('rbx', 'rax') == 0
        assert dcg.query('rax', 'rbx') == 0

    def test_add_immediate(self):
        """add $16, %rbx → rbx ≤ PRE_rbx + 16"""
        builder = DCGBuilder()
        dcg = builder.build(['mov %rax, %rbx', 'add $16, %rbx'])
        # PRE_rbx ≤ rax (from mov), rbx ≤ PRE_rbx+16 → rbx ≤ rax+16
        assert dcg.query('rbx', 'rax') <= 16

    def test_xor_zero(self):
        """xor %rax, %rax → rax = 0"""
        builder = DCGBuilder()
        dcg = builder.build(['xor %rax, %rax'])
        assert dcg.query('rax', 'ZERO') == 0

    def test_detect_intel_syntax(self):
        """Intel语法检测"""
        builder = DCGBuilder()
        dcg = builder.build(['mov rbx, rax'])  # Intel: dst, src
        assert dcg.query('rbx', 'rax') == 0

    def test_empty_instructions(self):
        builder = DCGBuilder()
        dcg = builder.build([])
        assert len(dcg._vars) == 0

    def test_semicolon_skip(self):
        builder = DCGBuilder()
        dcg = builder.build(['; comment', 'mov %rax, %rbx'])
        assert dcg.query('rbx', 'rax') == 0


class TestVerifyHeapSafety:
    """verify_heap_safety: 高层判定API"""

    def test_provable_safe(self):
        dcg = DifferenceConstraintGraph()
        dcg.add_constraint('copy_reg', 'alloc_reg', 8)  # copy ≤ alloc + 8
        dcg.close()
        report = verify_heap_safety(dcg, 'alloc_reg', 'copy_reg', margin=16)
        assert report.is_provable_safe

    def test_not_provable_safe(self):
        dcg = DifferenceConstraintGraph()
        dcg.add_constraint('copy_reg', 'alloc_reg', 256)  # copy ≤ alloc+256
        dcg.close()
        report = verify_heap_safety(dcg, 'alloc_reg', 'copy_reg', margin=8)
        assert not report.is_provable_safe

    def test_no_constraint_path(self):
        dcg = DifferenceConstraintGraph()
        dcg.add_constraint('rbx', 'rax', 0)
        dcg.close()
        report = verify_heap_safety(dcg, 'rcx', 'rdx', margin=8)
        assert not report.is_provable_safe
        assert len(report.proof_chain) == 1

    def test_realistic_scenario(self):
        """真实场景: alloc通过rax→rbx链, copy通过rcx, 但rbx≤rcx+0可证"""
        dcg = DifferenceConstraintGraph()
        # alloc_size → rax → rbx (mov链)
        dcg.add_equal('rax', 'alloc_reg')
        dcg.add_equal('rbx', 'rax')
        # copy_size → rcx
        dcg.add_equal('rcx', 'copy_reg')
        # 关键约束: rcx ≤ rbx + 16 (add后copy上限已知)
        dcg.add_constraint('rcx', 'rbx', 16)
        dcg.close()
        report = verify_heap_safety(dcg, 'alloc_reg', 'copy_reg', margin=16)
        assert report.is_provable_safe
        assert 'SAFE' in report.proof_chain[1]
