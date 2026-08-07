"""Serverless安全分析：函数链分析与调度中枢。

FunctionChainAnalyzer: 函数链权限提升检测
ServerlessAnalyzer: 安全分析调度中枢（集成8个检测模块）
analyze_serverless: 便捷入口
"""
import logging
from typing import Dict, Any, List, Optional, Set, Tuple

from .serverless_types import (
    CloudProvider, TriggerType, FindingSeverity, Finding, FunctionConfig,
    ColdStartSideChannelDetector,
)
from .serverless_detectors import (
    SharedEnvironmentEscapeDetector, IamPermissionBoundaryAnalyzer,
    EventInjectionScanner, EnvSecretExtractor,
    TmpPersistenceDetector, ResourceExhaustionDetector,
)

log = logging.getLogger(__name__)


class FunctionChainAnalyzer:
    """函数链权限提升——构建调用图，检测环路与权限放大路径。"""

    _DANGEROUS: Set[str] = {
        'iam:*', 'iam:Create*', 's3:*', 'dynamodb:*', 'lambda:*', 'kms:*',
        'sts:AssumeRole*', 'ec2:*', 'rds:*', 'secretsmanager:*', 'ssm:GetParameter*', 'sqs:*', 'sns:*',
    }

    def __init__(self):
        self._funcs: Dict[str, FunctionConfig] = {}
        self._edges: List[Tuple[str, str, str]] = []

    def add_function(self, func: FunctionConfig) -> None:
        self._funcs[func.name] = func

    def add_invocation_edge(self, source: str, target: str, relation: str = "direct_invoke") -> None:
        self._edges.append((source, target, relation))

    def analyze(self) -> List[Finding]:
        findings: List[Finding] = []
        if not self._edges:
            return findings

        callees: Dict[str, List[str]] = {}
        callers: Dict[str, List[str]] = {}
        for s, t, _ in self._edges:
            callees.setdefault(s, []).append(t)
            callers.setdefault(t, []).append(s)

        def _dfs(node: str, path: List[str], visited: Set[str]) -> None:
            if node in path:
                cycle = path[path.index(node):] + [node]
                findings.append(Finding(
                    title="函数调用环路检出", severity=FindingSeverity.HIGH,
                    category="chain_cycle",
                    description=f"环路：{' -> '.join(cycle)}",
                    evidence=f"cycle={' -> '.join(cycle)}",
                    remediation="添加 max_retries / max_concurrency 限制；审计循环依赖。",
                    cvss_score=6.5, cwe_id="CWE-674",
                ))
                return
            if node in visited:
                return
            visited.add(node)
            path.append(node)
            for callee in callees.get(node, []):
                _dfs(callee, path, visited)
            path.pop()

        for name in list(self._funcs.keys()):
            _dfs(name, [], set())

        for s, t, _ in self._edges:
            sf = self._funcs.get(s)
            tf = self._funcs.get(t)
            if not sf or not tf:
                continue
            sd = self._count_danger(sf.iam_policy or [])
            td = self._count_danger(tf.iam_policy or [])
            if td > sd:
                findings.append(Finding(
                    title="函数链权限提升", severity=FindingSeverity.CRITICAL if td >= 3 else FindingSeverity.HIGH,
                    category="chain_priv_esc", provider=sf.provider,
                    description=f"'{s}'（{sd} 高危权限）-> '{t}'（{td} 高危权限）——可能逐步提权。",
                    evidence=f"source={s}({sd}), target={t}({td})",
                    remediation="按函数实施最小权限；在函数间传递限定凭证。",
                    cvss_score=9.1 if td >= 3 else 7.5, cwe_id="CWE-269",
                ))

        for name, caller_list in callers.items():
            if len(caller_list) > 3:
                findings.append(Finding(
                    title="函数入口面过大", severity=FindingSeverity.MEDIUM,
                    category="chain_blast_radius",
                    description=f"'{name}' 被 {len(caller_list)} 个调用方引用：{caller_list[:5]}。",
                    evidence=f"function={name}, callers={caller_list[:10]}",
                    remediation="缩减入口面；在各入口点强制认证。",
                    cvss_score=5.0, cwe_id="CWE-937",
                ))

        return findings

    def _count_danger(self, policy: List[Dict[str, Any]]) -> int:
        cnt = 0
        for stmt in policy:
            actions = stmt.get('Action', stmt.get('actions', []))
            if isinstance(actions, str):
                actions = [actions]
            for a in actions:
                if any(a.startswith(d.rstrip('*')) for d in self._DANGEROUS):
                    cnt += 1
        return cnt


class ServerlessAnalyzer:
    """Serverless 安全分析调度中枢——集成 8 个检测模块，执行云函数全面审计。"""

    def __init__(self):
        self.cold_start = ColdStartSideChannelDetector()
        self.env_escape = SharedEnvironmentEscapeDetector()
        self.iam = IamPermissionBoundaryAnalyzer()
        self.events = EventInjectionScanner()
        self.secrets = EnvSecretExtractor()
        self.tmp = TmpPersistenceDetector()
        self.chains = FunctionChainAnalyzer()
        self.resource_exhaust = ResourceExhaustionDetector()

    def analyze(self,
                source_code: str = "",
                runtime: str = "python",
                function_configs: Optional[List[Dict[str, Any]]] = None,
                env_vars: Optional[Dict[str, str]] = None,
                config_text: str = "",
                iam_statements: Optional[List[Dict[str, Any]]] = None,
                invocation_edges: Optional[List[Tuple[str, str, str]]] = None,
                init_timings: Optional[List[float]] = None,
                tmp_usage_bytes: int = 0,
                provider: CloudProvider = CloudProvider.AWS_LAMBDA,
                **kwargs) -> Dict[str, Any]:
        """运行完整 Serverless 安全分析流水线，涵盖全部可用模块。"""
        all_findings: List[Dict[str, Any]] = []
        stats: Dict[str, int] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        def _add(findings: List[Finding]):
            for f in findings:
                f.provider = provider
                all_findings.append(f.to_dict())
                stats[f.severity.value] += 1

        if init_timings:
            for t in init_timings:
                self.cold_start.feed(t)
            _add(self.cold_start.detect())

        if source_code:
            _add(self.env_escape.detect(source_code, runtime))

        if iam_statements:
            _add(self.iam.analyze(iam_statements, provider))

        if source_code:
            trigger = None
            if function_configs:
                for fc in function_configs:
                    tr = fc.get('triggers', fc.get('Triggers', []))
                    if tr:
                        try:
                            trigger = TriggerType(tr[0]) if isinstance(tr[0], str) else tr[0]
                        except (ValueError, TypeError):
                            pass
                        break
            _add(self.events.scan(source_code, trigger))

        if env_vars or config_text:
            _add(self.secrets.extract(env_vars, config_text, provider))

        if source_code or tmp_usage_bytes > 0:
            _add(self.tmp.detect(source_code, tmp_usage_bytes))

        if source_code:
            _add(self.resource_exhaust.detect(source_code))

        if function_configs:
            for fc in function_configs:
                func = FunctionConfig(
                    name=fc.get('name', fc.get('FunctionName', 'unknown')),
                    provider=provider,
                    runtime=fc.get('runtime', fc.get('Runtime', runtime)),
                    handler=fc.get('handler', fc.get('Handler', '')),
                    memory_mb=fc.get('memory_mb', fc.get('MemorySize', 128)),
                    timeout_seconds=fc.get('timeout_seconds', fc.get('Timeout', 3)),
                    env_vars=fc.get('env_vars', fc.get('Environment', {}).get('Variables', {})),
                    iam_policy=fc.get('iam_policy'),
                    vpc_config=fc.get('vpc_config', fc.get('VpcConfig')),
                    layers=fc.get('layers', fc.get('Layers', [])),
                )
                self.chains.add_function(func)
            if invocation_edges:
                for s, t, r in invocation_edges:
                    self.chains.add_invocation_edge(s, t, r)
            _add(self.chains.analyze())

        total = sum(stats.values())
        weights = {'critical': 10.0, 'high': 5.0, 'medium': 2.0, 'low': 0.5, 'info': 0.1}
        risk_score = min(round(sum(weights[k] * v for k, v in stats.items()), 1), 100.0)

        result: Dict[str, Any] = {
            'success': True, 'provider': provider.value,
            'total_findings': total, 'severity_counts': stats,
            'risk_score': risk_score, 'findings': all_findings,
        }
        log.info(f"Serverless 分析完成：{provider.value}, 检出={total}, "
                 f"严重={stats['critical']}, 高危={stats['high']}, 风险分={risk_score}")
        return result


def analyze_serverless(source_code: str = "",
                       runtime: str = "python",
                       function_configs: Optional[List[Dict[str, Any]]] = None,
                       env_vars: Optional[Dict[str, str]] = None,
                       config_text: str = "",
                       iam_statements: Optional[List[Dict[str, Any]]] = None,
                       invocation_edges: Optional[List[Tuple[str, str, str]]] = None,
                       init_timings: Optional[List[float]] = None,
                       tmp_usage_bytes: int = 0,
                       provider: CloudProvider = CloudProvider.AWS_LAMBDA,
                       **kwargs) -> Dict[str, Any]:
    """分析入口——参数均可选，仅对已提供数据的模块执行检测。"""
    return ServerlessAnalyzer().analyze(
        source_code=source_code, runtime=runtime,
        function_configs=function_configs, env_vars=env_vars,
        config_text=config_text, iam_statements=iam_statements,
        invocation_edges=invocation_edges, init_timings=init_timings,
        tmp_usage_bytes=tmp_usage_bytes, provider=provider, **kwargs)


__all__ = [
    "ServerlessAnalyzer", "FunctionChainAnalyzer", "analyze_serverless",
    # 透传子模块
    "CloudProvider", "TriggerType", "FindingSeverity", "Finding", "FunctionConfig",
    "ColdStartSideChannelDetector",
    "SharedEnvironmentEscapeDetector", "IamPermissionBoundaryAnalyzer",
    "EventInjectionScanner", "EnvSecretExtractor",
    "TmpPersistenceDetector", "ResourceExhaustionDetector",
]
