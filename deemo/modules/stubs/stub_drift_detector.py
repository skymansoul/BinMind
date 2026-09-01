# stub_drift_detector.py — 合约-实现漂移检测
# 比较桩模块的接口契约与实际 AST 实现，检测偏差：
#   函数在实现中存在但合约中缺失 / 合约声明但实现中不存在 /
#   参数签名不一致 / 返回注解漂移。
# 漂移信号供 StubGradual 判断"已实现的桩是否需要重新生成合约"。
#
# 问题场景:
#   1. 人工实现桩模块后，实现可能偏离初始合约（新增/删除函数、改签名）。
#   2. 合约从文档/调用点推断后，实际实现可能有不同的参数默认值或类型。
#   3. 持续集成中需要检测"实现与合约的一致性漂移"作为质量门禁。
#
# 本模块做合约-实现差异检测，与跨实现diff工具
# 解决的问题不同:
# 跨实现diff: 同一协议的不同实现间的一致性 (如 ParDiff)
# 合约-实现diff: 同一模块的规格与实际代码的一致性 (本模块)
#   两种diff在桩管理中是互补的: 前者发现"A和B行为不一致"，
#   后者发现"规格说A但实际不是A"。
import ast as _ast
import os as _os
from dataclasses import dataclass as _dc, field as _field

from modules.stubs.stub_contract import (
    StubContract as _StubContract,
    FuncContract as _FuncContract,
    ParamSpec as _ParamSpec,
    StubContractor as _StubContractor,
)


class DriftSeverity:
    """漂移严重度级别。"""
    CRITICAL = 'critical'    # 函数缺失或签名不兼容 — 调用方会崩溃
    WARNING = 'warning'      # 注解不一致但运行时兼容
    INFO = 'info'            # 仅文档级差异


@_dc
class DriftEntry:
    """单条漂移记录。"""
    severity: str = DriftSeverity.INFO
    category: str = ''         # func_missing | func_extra | param_mismatch |
                               # return_drift | annotation_drift | default_drift
    func_name: str = ''
    detail: str = ''
    # 合约侧信息
    contract_sig: str = ''
    # 实现侧信息
    impl_sig: str = ''
    line_no: int = 0


@_dc
class DriftReport:
    """单个模块的漂移检测完整报告。"""
    module_name: str
    contract_status: str = ''
    total_funcs_contract: int = 0
    total_funcs_impl: int = 0
    drift_entries: list = _field(default_factory=list)  # list[DriftEntry]
    critical_count: int = 0
    warning_count: int = 0
    info_count: int = 0
    drift_score: float = 0.0     # 0=无漂移, 1=严重漂移
    is_drifted: bool = False     # drift_score ≥ 0.3


class DriftDetector:
    """合约-实现漂移检测器。

    流程:
      1. 从 stub_contract 获取模块的接口契约（期望状态）
      2. 从磁盘读取模块源码，AST 解析出实际实现（实际状态）
      3. 逐函数比对:
         a) 合约声明但实现中不存在的函数 → CRITICAL 漂移
         b) 实现中存在但合约未声明的函数 → WARNING 漂移（未文档化扩展）
         c) 参数签名差异 → 按差异类型分级
         d) 返回注解差异 → WARNING
         e) 默认值差异 → INFO
      4. 综合漂移评分: CRITICAL 权重 0.4, WARNING 权重 0.2, INFO 权重 0.05
    """

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self.contractor = _StubContractor(stubs_dir=stubs_dir)

    def detect(self, module_name: str) -> DriftReport:
        """对单个模块执行漂移检测。"""
        contract = self.contractor.get(module_name)
        if contract is None:
            contract = self.contractor.build_contract(module_name)

        report = DriftReport(
            module_name=module_name,
            contract_status=contract.status,
        )

        # 解析实际实现
        impl_funcs = self._parse_impl(module_name)
        report.total_funcs_impl = len(impl_funcs)
        report.total_funcs_contract = len(contract.functions)

        contract_map = {f.name: f for f in contract.functions}

        # 方向1: 合约声明的函数在实现中是否存在
        for fc in contract.functions:
            if fc.name not in impl_funcs:
                report.drift_entries.append(DriftEntry(
                    severity=DriftSeverity.CRITICAL,
                    category='func_missing',
                    func_name=fc.name,
                    detail=f'合约声明 {fc.name} 但实现中不存在',
                    contract_sig=self._render_sig(fc),
                ))
                continue

            impl_info = impl_funcs[fc.name]
            self._compare_signatures(fc, impl_info, report)

        # 方向2: 实现中存在但合约未声明的函数
        for imp_name, imp_info in impl_funcs.items():
            if imp_name not in contract_map:
                # 跳过私有函数和 dunder
                if imp_name.startswith('_') and not imp_name.startswith('__'):
                    continue
                report.drift_entries.append(DriftEntry(
                    severity=DriftSeverity.WARNING,
                    category='func_extra',
                    func_name=imp_name,
                    detail=f'实现中存在 {imp_name} 但合约未声明',
                    impl_sig=imp_info.get('sig', ''),
                    line_no=imp_info.get('lineno', 0),
                ))

        # 统计与评分
        report.critical_count = sum(
            1 for e in report.drift_entries if e.severity == DriftSeverity.CRITICAL)
        report.warning_count = sum(
            1 for e in report.drift_entries if e.severity == DriftSeverity.WARNING)
        report.info_count = sum(
            1 for e in report.drift_entries if e.severity == DriftSeverity.INFO)

        total = max(report.total_funcs_contract, 1)
        report.drift_score = round(min(
            (report.critical_count * 0.4 +
             report.warning_count * 0.2 +
             report.info_count * 0.05) / total,
            1.0), 3)
        report.is_drifted = report.drift_score >= 0.3

        return report

    def detect_all(self) -> list[DriftReport]:
        """扫描全部桩模块的漂移状态。"""
        contracts = self.contractor.scan_all()
        reports = []
        for name in contracts:
            if name.startswith('stub_'):
                continue
            reports.append(self.detect(name))
        reports.sort(key=lambda r: -r.drift_score)
        return reports

    def _parse_impl(self, module_name: str) -> dict[str, dict]:
        """解析模块源码，提取所有顶层函数的基本信息。"""
        path = _os.path.join(self.stubs_dir, f'{module_name}.py')
        if not _os.path.isfile(path):
            return {}

        try:
            src = open(path, encoding='utf-8').read()
            tree = _ast.parse(src, filename=path)
        except (OSError, SyntaxError, UnicodeDecodeError):
            return {}

        funcs = {}
        for node in tree.body:
            if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                params = []
                for arg in node.args.args:
                    ann = ''
                    if arg.annotation:
                        try:
                            ann = _ast.unparse(arg.annotation)
                        except Exception:
                            ann = ''
                    params.append(f'{arg.arg}:{ann}' if ann else arg.arg)

                ret_ann = ''
                if node.returns:
                    try:
                        ret_ann = _ast.unparse(node.returns)
                    except Exception:
                        ret_ann = ''

                sig = f'({", ".join(params)})'
                if ret_ann:
                    sig += f' -> {ret_ann}'

                funcs[node.name] = {
                    'sig': sig,
                    'params': params,
                    'return_ann': ret_ann,
                    'lineno': node.lineno,
                    'has_body': len(node.body) > 0,
                    'is_placeholder': self._body_is_trivial(node.body),
                    'defaults': len(node.args.defaults),
                }

        return funcs

    def _compare_signatures(self, fc: _FuncContract,
                            impl_info: dict, report: DriftReport) -> None:
        """比较合约函数与实际实现的签名差异。"""
        c_params = {p.name: p for p in fc.params
                   if p.kind not in ('varargs', 'varkw')}
        i_param_names = set()
        for p_str in impl_info.get('params', []):
            name = p_str.split(':')[0] if ':' in p_str else p_str
            i_param_names.add(name)

        # 合约声明但实现中无此参数
        for pname in c_params:
            if pname not in i_param_names:
                report.drift_entries.append(DriftEntry(
                    severity=DriftSeverity.CRITICAL,
                    category='param_mismatch',
                    func_name=fc.name,
                    detail=f'参数 {pname} 在合约中声明但实现中缺失',
                    contract_sig=self._render_sig(fc),
                    impl_sig=impl_info.get('sig', ''),
                    line_no=impl_info.get('lineno', 0),
                ))

        # 实现中有但合约未声明的参数
        for pname in i_param_names:
            if pname not in c_params:
                report.drift_entries.append(DriftEntry(
                    severity=DriftSeverity.WARNING,
                    category='param_mismatch',
                    func_name=fc.name,
                    detail=f'参数 {pname} 在实现中存在但合约未声明',
                    contract_sig=self._render_sig(fc),
                    impl_sig=impl_info.get('sig', ''),
                    line_no=impl_info.get('lineno', 0),
                ))

        # 返回注解漂移
        c_ret = fc.return_ann.strip().lower() if fc.return_ann else ''
        i_ret = impl_info.get('return_ann', '').strip().lower()
        if c_ret and i_ret and c_ret != i_ret:
            report.drift_entries.append(DriftEntry(
                severity=DriftSeverity.WARNING,
                category='return_drift',
                func_name=fc.name,
                detail=f'返回注解漂移: 合约={fc.return_ann}, 实现={impl_info.get("return_ann", "")}',
                contract_sig=self._render_sig(fc),
                impl_sig=impl_info.get('sig', ''),
                line_no=impl_info.get('lineno', 0),
            ))

        # 默认值漂移
        c_defaults = sum(1 for p in fc.params if p.has_default)
        i_defaults = impl_info.get('defaults', 0)
        if c_defaults != i_defaults:
            report.drift_entries.append(DriftEntry(
                severity=DriftSeverity.INFO,
                category='default_drift',
                func_name=fc.name,
                detail=f'默认值数量漂移: 合约={c_defaults}, 实现={i_defaults}',
                contract_sig=self._render_sig(fc),
                impl_sig=impl_info.get('sig', ''),
                line_no=impl_info.get('lineno', 0),
            ))

    @staticmethod
    def _render_sig(fc: _FuncContract) -> str:
        """将 FuncContract 渲染为可读的签名字符串。"""
        parts = []
        for p in fc.params:
            piece = p.name
            if p.annotation:
                piece += f': {p.annotation}'
            if p.has_default:
                piece += f' = {p.default_repr}'
            parts.append(piece)
        sig = f'({", ".join(parts)})'
        if fc.return_ann:
            sig += f' -> {fc.return_ann}'
        return sig

    @staticmethod
    def _body_is_trivial(body: list) -> bool:
        """判定函数体是否为空/占位（仅 pass, ..., 或 docstring）。"""
        meaningful = [
            s for s in body
            if not isinstance(s, _ast.Pass)
            and not (isinstance(s, _ast.Expr)
                    and isinstance(getattr(s, 'value', None), _ast.Constant)
                    and (isinstance(s.value.value, str) or s.value.value is ...))
        ]
        return len(meaningful) == 0

    def drift_summary(self, reports: list[DriftReport] = None) -> str:
        """生成 Markdown 漂移摘要。"""
        if reports is None:
            reports = self.detect_all()

        drifted = [r for r in reports if r.is_drifted]
        lines = [
            '# 合约-实现漂移检测报告',
            f'扫描模块: {len(reports)}',
            f'检测到漂移: {len(drifted)}',
            '',
        ]

        if drifted:
            lines.append('| 模块 | 漂移分 | Critical | Warning | Info | 合约/实现函数数 |')
            lines.append('|------|-------:|---------:|--------:|-----:|---------------:|')
            for r in drifted[:30]:
                lines.append(
                    f'| {r.module_name} | {r.drift_score:.2f} | '
                    f'{r.critical_count} | {r.warning_count} | {r.info_count} | '
                    f'{r.total_funcs_contract}/{r.total_funcs_impl} |')

        return '\n'.join(lines)


def detect_drift(module_name: str) -> DriftReport:
    """一行式漂移检测。"""
    return DriftDetector().detect(module_name)


__all__ = [
    'DriftSeverity', 'DriftEntry', 'DriftReport',
    'DriftDetector', 'detect_drift',
]
