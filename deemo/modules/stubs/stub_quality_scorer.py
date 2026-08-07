# stub_quality_scorer.py — 实现就绪度评分 (Implementation Readiness Level)
# 超越二元 pass/fail 验证，从五个维度评估桩实现的质量:
#   结构性、文档化、类型安全、验证深度、溯源完整性。
# 输出 IRL 1-5 级别 + 各维度分项评分。
#
# 问题:
#   ContractVerifier 给出 pass/fail 判定，但不区分"刚好及格"与"优秀"。
#   一个 50 行模板生成的骨架与一个经过 MR+非相干性+对抗测试的实现
#   在当前的验证框架下同为 pass，但运维风险完全不同。
#
# IRL 定义:
#   L1 STUB       — 纯占位 (pass/...), score < 0.2
#   L2 SKELETON   — 签名正确但有 NotImplementedError, 0.2 ≤ s < 0.4
#   L3 FUNCTIONAL — 编译通过+签名+IO验证, 0.4 ≤ s < 0.6
#   L4 VERIFIED   — 通过 MR 检查 + 非相干性校验, 0.6 ≤ s < 0.85
#   L5 HARDENED   — 对抗测试无显著异常+溯源链完整+文档齐全, s ≥ 0.85
#
# 区别于 RACE 和 CodeQUEST:
#   两者评估通用 LLM 代码生成的 Readability/Maintainability/Correctness/Efficiency。
#   本模块专门针对桩实现的质量剖面，结合验证阶段深度与溯源完整性，
#   这两个维度在通用代码质量评估中不存在。
import ast as _ast
import os as _os
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

from modules.stubs.stub_contract import (
    StubContract as _StubContract,
    FuncContract as _FuncContract,
    StubContractor as _StubContractor,
)


@_dc
class QualityScores:
    """五维质量分项 (0~1)。"""
    structural: float = 0.0     # 结构质量: 无过度嵌套/超长函数
    documentation: float = 0.0  # 文档覆盖: docstring + 参数说明
    type_safety: float = 0.0    # 类型安全: 注解覆盖率
    verification: float = 0.0   # 验证深度: 通过了几层验证
    provenance: float = 0.0     # 溯源完整性: 链长度+最后验证状态


@_dc
class IRLReport:
    """单个模块的 IRL 评估报告。"""
    module_name: str
    scores: QualityScores = _field(default_factory=QualityScores)
    composite: float = 0.0        # 加权综合分 (0~1)
    irl: int = 1                  # 1-5
    irl_label: str = 'STUB'
    recommendation: str = ''


class QualityScorer:
    """实现就绪度评分器。

    权重分配:
      verification(0.30) > type_safety(0.22) > structural(0.20)
      > documentation(0.15) > provenance(0.13)
    验证深度权重最高 — 对于安全分析桩而言，未经过充分验证的实现
    比未实现更危险（给人以"可用"的假象）。
    """

    WEIGHTS = {
        'structural': 0.20,
        'documentation': 0.15,
        'type_safety': 0.22,
        'verification': 0.30,
        'provenance': 0.13,
    }

    IRL_LABELS = {
        1: 'STUB',
        2: 'SKELETON',
        3: 'FUNCTIONAL',
        4: 'VERIFIED',
        5: 'HARDENED',
    }

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self.contractor = _StubContractor(stubs_dir=stubs_dir)

    def score(self, module_name: str, source: str = None) -> IRLReport:
        """对指定模块计算 IRL 评分。source 为 None 时从磁盘读取。"""
        contract = self.contractor.get(module_name)
        if contract is None:
            contract = self.contractor.build_contract(module_name)

        if source is None:
            source = self._read_source(module_name)

        report = IRLReport(module_name=module_name)
        sq = QualityScores()

        if source:
            sq.structural = self._score_structural(source)
            sq.documentation = self._score_documentation(source, contract)
            sq.type_safety = self._score_type_safety(contract)
        else:
            sq.structural = 0.0
            sq.documentation = 0.0
            sq.type_safety = self._score_type_safety(contract)

        sq.verification = self._score_verification(module_name)
        sq.provenance = self._score_provenance(module_name)

        report.scores = sq
        w = self.WEIGHTS
        report.composite = round(
            w['structural'] * sq.structural +
            w['documentation'] * sq.documentation +
            w['type_safety'] * sq.type_safety +
            w['verification'] * sq.verification +
            w['provenance'] * sq.provenance,
            3)

        report.irl = self._to_irl(report.composite)
        report.irl_label = self.IRL_LABELS[report.irl]
        report.recommendation = self._recommend(report)
        return report

    def score_all(self) -> list[IRLReport]:
        """批量评分全部模块。"""
        contracts = self.contractor.scan_all()
        reports = []
        for name in contracts:
            if name.startswith('stub_'):
                continue
            reports.append(self.score(name))
        reports.sort(key=lambda r: -r.composite)
        return reports

# 各维度评分
    @staticmethod
    def _score_structural(source: str) -> float:
        """结构质量: 检查嵌套深度、函数长度、pass/... 占比。"""
        try:
            tree = _ast.parse(source)
        except SyntaxError:
            return 0.0

        funcs = [n for n in _ast.walk(tree)
                if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef))]
        if not funcs:
            return 0.0

        penalties = 0.0
        max_penalty = len(funcs) * 3.0
        if max_penalty < 1:
            return 0.5  # 只有 module-level 代码时给中性分

        for fn in funcs:
            # 统计非 pass/.../docstring 的语句
            body = fn.body
            meaningful = [
                s for s in body
                if not isinstance(s, _ast.Pass)
                and not (isinstance(s, _ast.Expr)
                        and isinstance(getattr(s, 'value', None), _ast.Constant)
                        and (isinstance(s.value.value, str)
                            or s.value.value is ...))
            ]
            if not meaningful:
                penalties += 2.0  # 占位函数 → 高惩罚
                continue

            line_count = len(body)
            if line_count > 80:
                penalties += 1.5
            elif line_count > 40:
                penalties += 0.5

            # 嵌套深度
            max_depth = QualityScorer._max_nesting(body)
            if max_depth > 5:
                penalties += 1.0
            elif max_depth > 3:
                penalties += 0.3

        score = 1.0 - (penalties / max_penalty)
        return max(0.0, min(score, 1.0))

    @staticmethod
    def _max_nesting(body: list) -> int:
        max_d = 0
        for stmt in body:
            for node in _ast.walk(stmt):
                if isinstance(node, (_ast.If, _ast.For, _ast.While,
                                    _ast.Try, _ast.With)):
                    d = QualityScorer._nest_depth(node)
                    if d > max_d:
                        max_d = d
        return max_d

    @staticmethod
    def _nest_depth(node) -> int:
        d = 0
        cur = node
        while hasattr(cur, 'parent'):
            cur = cur.parent
            if isinstance(cur, (_ast.If, _ast.For, _ast.While,
                               _ast.Try, _ast.With)):
                d += 1
        return d

    @staticmethod
    def _score_documentation(source: str,
                             contract: _StubContract) -> float:
        """文档覆盖: docstring 比例 + 参数说明完整性。"""
        if not contract or not contract.functions:
            return 0.0

        total = len(contract.functions)
        has_doc = sum(1 for f in contract.functions if f.doc_summary)
        doc_ratio = has_doc / total if total > 0 else 0.0

        # 参数文档: raises 声明视为"有意识地标注了异常语义"
        has_raises = sum(1 for f in contract.functions if f.raises)
        raises_bonus = min(has_raises / max(total, 1), 0.3)

        return min(doc_ratio * 0.7 + raises_bonus, 1.0)

    @staticmethod
    def _score_type_safety(contract: _StubContract) -> float:
        """类型安全: 参数+返回值注解覆盖率。含返回类型注解覆盖率 — 缺返回注解的函数更可能导致调用方类型错误。"""
        if not contract or not contract.functions:
            return 0.0

        total_params = 0
        annotated_params = 0
        annotated_returns = 0

        for fc in contract.functions:
            native_params = [p for p in fc.params
                           if p.kind not in ('varargs', 'varkw')]
            total_params += len(native_params)
            annotated_params += sum(1 for p in native_params
                                   if p.annotation and p.annotation.strip())
            if fc.return_ann and fc.return_ann.strip():
                annotated_returns += 1

        n_funcs = len(contract.functions)
        param_cov = annotated_params / max(total_params, 1)
        ret_cov = annotated_returns / max(n_funcs, 1)

        return param_cov * 0.6 + ret_cov * 0.4

    def _score_verification(self, module_name: str) -> float:
        """验证深度: 基于溯源链中的验证通过记录。
        通过更多验证阶段 → 更高分。未记录溯源的模块按状态估算。
        """
        try:
            from modules.stubs.stub_provenance_chain import ProvenanceChain
            pc = ProvenanceChain(stubs_dir=self.stubs_dir)
            chain = pc.history(module_name)
            if not chain:
                return self._estimate_verification_from_status(module_name)
            # 取最新一条
            last = chain[-1]
            score = 0.1  # 基线: 有溯源记录
            if last.verification_ok:
                score += 0.3
            if last.incoherence_rate >= 0:
                # 运行了双策略检验
                score += 0.2
                if last.incoherence_rate < 0.1:
                    score += 0.2  # 低非相干性 → 高质量信号
            if len(chain) >= 2:
                score += 0.1  # 多次实现 → 迭代改进
            if len(chain) >= 3:
                score += 0.1
            return min(score, 1.0)
        except ImportError:
            return self._estimate_verification_from_status(module_name)

    def _estimate_verification_from_status(self, module_name: str) -> float:
        contract = self.contractor.get(module_name)
        if contract is None:
            return 0.0
        status = contract.status
        if status == 'implemented':
            return 0.5
        if status == 'mixed':
            return 0.4
        if status in ('re_export', 'placeholder'):
            return 0.15
        return 0.0

    def _score_provenance(self, module_name: str) -> float:
        """溯源完整性: 链长度 + 链有效性 + 策略多样性。"""
        try:
            from modules.stubs.stub_provenance_chain import ProvenanceChain
            pc = ProvenanceChain(stubs_dir=self.stubs_dir)
            chain = pc.history(module_name)
            if not chain:
                return 0.0
            vr = pc.verify(module_name)
            score = 0.0
            if vr['valid']:
                score += 0.4
            score += min(len(chain) / 5.0, 0.3)
            strategies = set(e.strategy for e in chain)
            if len(strategies) >= 2:
                score += 0.2  # 多策略尝试
            last = chain[-1]
            if last.verification_ok:
                score += 0.1
            return min(score, 1.0)
        except ImportError:
            return 0.0

    @staticmethod
    def _to_irl(composite: float) -> int:
        if composite < 0.2:
            return 1
        if composite < 0.4:
            return 2
        if composite < 0.6:
            return 3
        if composite < 0.85:
            return 4
        return 5

    @staticmethod
    def _recommend(report: IRLReport) -> str:
        if report.irl <= 2:
            return '需自动或人工实现; 当前不可用于生产'
        if report.irl == 3:
            return '功能可用但验证不充分; 建议运行 MR+非相干性检验'
        if report.irl == 4:
            return '验证较充分; 建议补充对抗测试达到 L5'
        return '可投入生产使用'

    def _read_source(self, module_name: str) -> _Opt[str]:
        path = _os.path.join(self.stubs_dir, f'{module_name}.py')
        if not _os.path.isfile(path):
            return None
        try:
            return open(path, encoding='utf-8').read()
        except (OSError, UnicodeDecodeError):
            return None


__all__ = ['QualityScores', 'IRLReport', 'QualityScorer']
