#
# 二进制级常量时间验证的单元测试

import sys
import os
_pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

import pytest
from analysis.static.const_time.src.secret_tracker import (
    SecretSource, SecretClass, SecretTaint,
    identify_secret_sources, propagate_taint_intraprocedural,
)
from analysis.static.const_time.src.branch_checker import (
    check_secret_dependent_branches, BranchViolation,
)
from analysis.static.const_time.src.mem_checker import (
    check_secret_dependent_memory, MemoryViolation,
)
from analysis.static.const_time.src.loop_checker import (
    check_secret_dependent_loops, LoopViolation,
)
from analysis.static.const_time.src.const_time_pipeline import (
    verify_constant_time, ConstTimeReport, ViolationSeverity,
)


class TestSecretTracker:
    """秘密源识别和污点传播测试"""

    def test_identify_key_param(self):
        """AES_set_encrypt_key 的 arg1(userKey) → KEY_PARAM"""
        sources = identify_secret_sources(
            'AES_set_encrypt_key', 0x1000,
            params=['userKey', 'bits', 'expandedKey'],
            imports=[], global_vars={},
        )
        # userKey 被 API 参数模式识别为 KEY_PARAM
        # expandedKey 被参数名匹配识别为 INFERRED（含'key'子串）
        assert len(sources) >= 1
        key_params = [s for s in sources if s.source_class == SecretClass.KEY_PARAM]
        assert len(key_params) == 1
        assert key_params[0].source_id == 'userKey'

    def test_identify_global_secret(self):
        """全局变量 'sbox' → GLOBAL_SECRET"""
        sources = identify_secret_sources(
            'encrypt_block', 0x1000, params=['data', 'len'],
            imports=[], global_vars={'sbox': 0x600000, 'buffer': 0x601000},
        )
        assert any(s.source_id == 'sbox' for s in sources)

    def test_no_secret_in_ordinary_func(self):
        """普通函数 → 无秘密源"""
        sources = identify_secret_sources(
            'printf', 0x1000, params=['fmt', '...'],
            imports=[], global_vars={},
        )
        assert sources == []

    def test_taint_propagation_mov(self):
        """mov dst, src → dst 继承 src 的污点"""
        sources = [SecretSource('rsi', SecretClass.KEY_PARAM, 'test', 0, 0.9)]
        insns = [('mov', ['rdi', 'rsi']), ('mov', ['rax', 'rdi'])]
        taints = propagate_taint_intraprocedural(sources, insns)
        assert 'rdi' in taints
        assert 'rax' in taints

    def test_taint_propagation_xor(self):
        """xor 保留双输入的污点"""
        sources = [SecretSource('rsi', SecretClass.KEY_PARAM, 'test', 0, 0.9)]
        insns = [('xor', ['rdi', 'rsi'])]
        taints = propagate_taint_intraprocedural(sources, insns)
        assert 'rdi' in taints


class TestBranchChecker:
    """秘密依赖分支检测测试"""

    def test_je_after_secret_cmp(self):
        """cmp 操作数被污染 → 后续 je 为违规"""
        sources = [SecretSource('rsi', SecretClass.KEY_PARAM, 'test', 0, 0.9)]
        insns = [('mov', ['rdi', 'rsi']), ('cmp', ['rdi', '0x41']), ('je', ['0x2000'])]
        taints = propagate_taint_intraprocedural(sources, insns)
        violations = check_secret_dependent_branches('test', insns, taints)
        assert len(violations) >= 1
        assert violations[0].severity == 'MEDIUM'

    def test_no_violation_without_taint(self):
        """无污染时不应报告违规"""
        sources = []
        insns = [('cmp', ['rdi', '0x41']), ('je', ['0x2000'])]
        taints = propagate_taint_intraprocedural(sources, insns)
        violations = check_secret_dependent_branches('test', insns, taints)
        assert len(violations) == 0

    def test_cmov_not_violation(self):
        """cmov 不视为分支违规"""
        sources = [SecretSource('rsi', SecretClass.KEY_PARAM, 'test', 0, 0.9)]
        insns = [('mov', ['rdi', 'rsi']), ('cmove', ['rax', 'rdi'])]
        taints = propagate_taint_intraprocedural(sources, insns)
        violations = check_secret_dependent_branches('test', insns, taints)
        # cmov 系列不应出现在违规中
        assert len(violations) == 0


class TestMemoryChecker:
    """秘密依赖访存检测测试"""

    def test_secret_as_memory_index(self):
        """secret → [reg] 模式检测"""
        sources = [SecretSource('rsi', SecretClass.KEY_PARAM, 'test', 0, 0.9)]
        insns = [('mov', ['rax', '[rsi + 0x10]'])]
        taints = propagate_taint_intraprocedural(sources, insns)
        violations = check_secret_dependent_memory('test', insns, taints)
        assert len(violations) >= 1
        assert violations[0].severity == 'HIGH'

    def test_stack_access_not_violation(self):
        """[rsp+N] 不视为违规"""
        sources = [SecretSource('rsi', SecretClass.KEY_PARAM, 'test', 0, 0.9)]
        insns = [('mov', ['rax', '[rsp + 0x8]'])]
        taints = propagate_taint_intraprocedural(sources, insns)
        violations = check_secret_dependent_memory('test', insns, taints)
        # 栈访问不违规——即使 rsp 可能被标记为污点（它不会被标记——这里测试的是误报抑制）
        assert len(violations) == 0


class TestConstTimePipeline:
    """管线集成测试"""

    def test_clean_function_no_violations(self):
        """无秘密数据的普通函数 → is_constant_time=True"""
        func_insns = {
            'add_numbers': (0x1000, [
                ('add', ['rax', 'rbx']),
                ('ret', []),
            ]),
        }
        report = verify_constant_time('/tmp/test', func_insns)
        assert report.is_constant_time
        assert report.functions_with_secrets == 0

    def test_aes_key_branch_detected(self):
        """AES_set_encrypt_key 的密钥参数应被检测"""
        func_insns = {
            'AES_set_encrypt_key': (0x1000, [
                ('cmp', ['userKey', '0']),
                ('je', ['0x1050']),
                ('ret', []),
            ]),
        }
        func_params = {'AES_set_encrypt_key': ['userKey', 'bits', 'expandedKey']}
        report = verify_constant_time(
            '/tmp/test', func_insns, func_params=func_params,
        )
        # 应检测到秘密源
        assert report.functions_with_secrets == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
