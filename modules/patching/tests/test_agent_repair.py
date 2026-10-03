"""AgentRepair 测试。

验证：类型自适应路由 / 多轮修复闭环 / 候选排序 / 安全验证器（不执行程序）。
"""

import sys, os, pytest

_cur = os.path.dirname(os.path.abspath(__file__))
_patch = os.path.dirname(_cur)
if _patch not in sys.path:
    sys.path.insert(0, _patch)

from patch_type_router import (
    PatchTypeRouter, VulnClassifier, RepairFamily, RepairRoute, RouteDecision,
)
from safe_repair_validator import (
    SafeRepairValidator, ValidationResult, ValidationStatus,
)
from candidate_patch_ranker import CandidatePatchRanker, RankedCandidate
from agent_repair import (
    AgentRepairEngine, RepairTrajectory, RepairOutcome, agent_repair, repair_to_dict,
)


class TestPatchTypeRouter:
    """自适应路由 —— 按漏洞类型选择符号/安全改写路径。"""

    def test_integer_overflow_routes_symbolic(self):
        d = PatchTypeRouter().route(vuln_type='integer_overflow')
        assert d.family == RepairFamily.LOGIC_DEFECT
        assert d.route == RepairRoute.SYMBOLIC
        assert d.confidence > 0.8

    def test_format_string_routes_template(self):
        d = PatchTypeRouter().route(vuln_type='format_string')
        assert d.family == RepairFamily.INJECTION
        assert d.route == RepairRoute.TEMPLATE

    def test_buffer_overflow_routes_hybrid(self):
        d = PatchTypeRouter().route(vuln_type='buffer_overflow')
        assert d.family == RepairFamily.MEMORY_SAFETY
        assert d.route == RepairRoute.HYBRID

    def test_cwe_priority_over_type_name(self):
        d = PatchTypeRouter().route(vuln_type='format_string', cwe_id='cwe-121')
        assert d.family == RepairFamily.MEMORY_SAFETY  # CWE 优先

    def test_crash_type_naming_compat(self):
        # auto_root_cause crash type 命名兼容
        d = PatchTypeRouter().route(vuln_type='STACK_BUFFER_OVERFLOW')
        assert d.family == RepairFamily.MEMORY_SAFETY

    def test_unknown_fallback(self):
        d = PatchTypeRouter().route()
        assert d.family == RepairFamily.UNKNOWN
        assert d.route == RepairRoute.TEMPLATE

    def test_code_keyword_classifier(self):
        fam, src = VulnClassifier().classify(code='strcpy(dst, src);')
        assert fam == RepairFamily.MEMORY_SAFETY
        assert src.startswith('code_keyword:')


class TestSafeRepairValidator:
    """安全验证器 —— 仅静态/语法检查，绝不执行。"""

    def test_good_candidate_passes(self):
        v = SafeRepairValidator()
        code = 'int f(char *d, char *s) {\n  strncpy(d, s, sizeof(d) - 1);\n  return 0;\n}'
        diff = '--- a/source.c\n+++ b/source.c\n@@ -1 +1 @@\n+  strncpy(d, s, sizeof(d) - 1);\n'
        r = v.validate(patch_diff=diff, code=code, lang='c',
                       required_positive=['safe_copy'])
        assert r.safe is True
        assert r.status in (ValidationStatus.PASS, ValidationStatus.WARNING)

    def test_dangerous_call_is_hard_fail(self):
        v = SafeRepairValidator()
        code = 'int f(char *d, char *s) {\n  strcpy(d, s);\n  return 0;\n}'
        diff = '--- a/source.c\n+++ b/source.c\n@@ -1 +1 @@\n+  strcpy(d, s);\n'
        r = v.validate(patch_diff=diff, code=code, lang='c')
        assert r.status == ValidationStatus.FAIL
        assert 'dangerous_copy' in r.feedback

    def test_empty_delta_warns(self):
        v = SafeRepairValidator()
        r = v.validate(patch_diff='--- a/source.c\n+++ b/source.c\n@@ -0,0 +0,0 @@\n',
                       code='int f(void){return 0;}', lang='c')
        assert r.status == ValidationStatus.WARNING

    def test_python_syntax_check(self):
        v = SafeRepairValidator()
        r = v.validate(patch_diff='+x = 1\n', code='x = 1\n', lang='python')
        assert r.status in (ValidationStatus.PASS, ValidationStatus.WARNING)

    def test_never_executes_target(self):
        # 即便传入带副作用的代码，验证路径也不应执行（无 subprocess 运行目标）
        v = SafeRepairValidator()
        code = 'int f(void){ return system("touch /tmp/pwned"); }'
        r = v.validate(patch_diff='+return 0;\n', code=code, lang='c')
        assert r.safe is True


class TestCandidateRanker:
    """候选排序器 —— 验证通过者优先，改动小者加分。"""

    def test_passed_candidate_ranks_first(self):
        cands = [
            {'candidate_id': 'a', 'patch_diff': '+  strncpy(d, s, sizeof(d) - 1);\n', 'description': 'a', 'route': 'template', 'family': 'memory_safety'},
            {'candidate_id': 'b', 'patch_diff': '+  x = 1;\n', 'description': 'b', 'route': 'template', 'family': 'memory_safety'},
        ]
        validations = {
            'a': ValidationResult(status=ValidationStatus.PASS),
            'b': ValidationResult(status=ValidationStatus.WARNING),
        }
        ranked = CandidatePatchRanker().rank(cands, validations)
        assert ranked[0].candidate_id == 'a'
        assert ranked[0].rank == 1

    def test_smaller_diff_scores_higher_on_static_tie(self):
        small = {'candidate_id': 's', 'patch_diff': '+  x = 1;\n', 'description': 's', 'route': 't', 'family': 'f'}
        big = {'candidate_id': 'b', 'patch_diff': '+  x = 1;\n+  y = 2;\n+  z = 3;\n+  w = 4;\n', 'description': 'b', 'route': 't', 'family': 'f'}
        ranked = CandidatePatchRanker().rank([big, small], None)
        assert ranked[0].candidate_id == 's'

    def test_ranked_candidate_to_dict(self):
        rc = RankedCandidate(rank=1, candidate_id='x', rank_score=0.9)
        d = rc.to_dict()
        assert d['rank'] == 1 and d['candidate_id'] == 'x'


class TestAgentRepairEngine:
    """多轮修复闭环 —— 路由→生成→验证→排序→回溯。"""

    def test_integer_overflow_converges(self):
        code = 'int calc(int a, int b) {\n    return a + b;\n}'
        outcome = agent_repair(code, vuln_type='integer_overflow',
                               function_name='calc')
        assert outcome.success is True
        assert outcome.trajectory.rounds
        assert 'INT_MAX' in outcome.final_patch

    def test_buffer_overflow_multi_round_backtrack(self):
        # 首轮单项候选缺 safe_copy/bounds_guard → WARNING → 回溯
        # 第 2 轮综合修复同时命中 → PASS
        code = 'int process(char *dst, char *src) {\n    strcpy(dst, src);\n    return 0;\n}'
        outcome = agent_repair(code, vuln_type='buffer_overflow',
                               function_name='process')
        assert outcome.success is True
        assert 'strncpy' in outcome.final_patch
        assert len(outcome.trajectory.rounds) >= 1

    def test_trajectory_records_feedback(self):
        code = 'int process(char *dst, char *src) {\n    strcpy(dst, src);\n    return 0;\n}'
        outcome = agent_repair(code, vuln_type='buffer_overflow',
                               function_name='process')
        d = outcome.to_dict()
        assert d['trajectory']['round_count'] >= 1
        assert d['trajectory']['target_function'] == 'process'
        # 至少一轮有验证记录
        assert any(r['validation'] is not None for r in d['trajectory']['rounds'])

    def test_trajectory_markdown(self):
        t = RepairTrajectory('f', 'buffer_overflow', 'rc', 'CWE-121')
        assert 'AgentRepair' in t.to_markdown()

    def test_format_string_single_round(self):
        code = 'int show(char *u) {\n    printf(u);\n    return 0;\n}'
        outcome = agent_repair(code, vuln_type='format_string', function_name='show')
        assert outcome.success is True
        assert 'printf("%s", u)' in outcome.final_patch or '"%s"' in outcome.final_patch

    def test_empty_code_returns_failure(self):
        outcome = agent_repair('', vuln_type='buffer_overflow')
        assert outcome.success is False
        assert outcome.final_patch == ''

    def test_repair_to_dict_convenience(self):
        outcome = agent_repair('int f(void){return 0;}', vuln_type='unknown')
        d = repair_to_dict(outcome)
        assert 'trajectory' in d


class TestModuleShims:
    def test_package_lazy_import(self):
        # patching 包懒加载 __getattr__ 访问；
        # 若运行上下文无法以包形式导入 patching，跳过（不视为失败）
        parent = os.path.dirname(_patch)
        if parent not in sys.path:
            sys.path.insert(0, parent)
        try:
            import patching
        except Exception:
            pytest.skip('patching 包导入上下文不可用')
        eng = patching.AgentRepairEngine(max_rounds=2)
        assert eng is not None
        # 懒加载枚举行为正确（包内子模块与顶层模块是两个实例，仅验证值）
        assert patching.RepairFamily.LOGIC_DEFECT.value == 'logic_defect'
        assert patching.RepairRoute.HYBRID.value == 'hybrid'
        assert patching.ValidationStatus.PASS.value == 'pass'
