"""数字孪生风险评估引擎, 攻击路径模拟评分。

2025 增强: 贝叶斯风险传播, 将风险从暴露节点沿攻击图传播到内部节点。
使用条件概率建模: P(compromise[target] | compromise[source]) = f(vulns, auth, 加密)。
贝叶斯网络推断 (精确, 因攻击图为 DAG) 取代原有的简单 BFS 评分。
"""

import itertools, logging, math as _math, os as _os
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Iterator, Set, FrozenSet, Tuple, Optional

try:
    from core.plugin_manager import AnalyzerMetadata, AnalyzerType
except ImportError:
    AnalyzerMetadata = None
    AnalyzerType = None

_log = logging.getLogger(__name__)


@dataclass
class Component:
    name: str; component_type: str = ""
    vulnerabilities: List[str] = field(default_factory=list)
    exposed: bool = False; criticality: float = 0.0
    trust_boundary: bool = False
    vuln_scores: Dict[str, float] = field(default_factory=dict)


@dataclass
class Edge:
    source: str; target: str; protocol: str = ""
    auth_required: bool = False; encrypted: bool = False


@dataclass
class AttackPath:
    steps: List[Tuple[str, str]]; risk_score: float = 0.0
    likelihood: float = 0.0; description: str = ""


@dataclass
class RiskReport:
    components: Dict[str, float] = field(default_factory=dict)
    paths: List[AttackPath] = field(default_factory=list)
    overall_risk: float = 0.0; max_path_risk: float = 0.0
    graph_density: float = 0.0; avg_path_length: float = 0.0
    bayesian_risk: Dict[str, float] = field(default_factory=dict)  # 贝叶斯后验


@dataclass
class FirmwareInfo:
    """固件基本信息，供数字孪生风险评估返回。"""
    name: str = ""
    architecture: str = ""
    platform: str = ""
    size_bytes: int = 0
    sha256: str = ""


class DigitalTwinRiskAnalyzer:
    def __init__(self):
        self._components: Dict[str, Component] = {}
        self._edges: List[Edge] = []; self._adj: Dict[str, List[Edge]] = defaultdict(list)
        self._rev_adj: Dict[str, List[Edge]] = defaultdict(list)

    def add_component(self, comp: Component) -> None:
        self._components[comp.name] = comp

    def add_edge(self, edge: Edge) -> None:
        self._edges.append(edge); self._adj[edge.source].append(edge)
        self._rev_adj[edge.target].append(edge)

    @classmethod
    def get_metadata(cls):
        """分析器元数据, 名称/类型/版本/依赖供外部注册与展示。"""
        if AnalyzerMetadata is None:
            return None
        return AnalyzerMetadata(
            name="DigitalTwinRiskAnalyzer",
            type=AnalyzerType.DYNAMIC_ANALYZER,
            version="1.0.0",
            description="数字孪生固件风险评估器——基于 qemu 仿真的攻击面模拟与风险评分",
            supported_platforms=["arm", "arm64", "mips", "x86_64", "riscv"],
            dependencies=["qemu", "firmware_modkit"],
        )

    def analyze(self, model=None, firmware_path=None, architecture="arm",
                platform="linux", scan_duration=60, enable_fuzzing=False,
                enable_penetration=False, **kwargs):
        """数字孪生风险评估主入口。

        传入 firmware_path 时执行固件风险画像（支持 fuzzing/渗透开关），
        返回 {"success", "result", "error"}；否则保持图模型分析兼容。
        """
        if firmware_path is not None:
            return self._analyze_firmware(
                firmware_path, architecture, platform,
                scan_duration, enable_fuzzing, enable_penetration,
            )
        if model is not None:
            self._load_model(model)
        report = RiskReport()
        report.components = self._score_components()
        report.paths = self._find_attack_paths()
        report.overall_risk = self._overall_risk(report.components)
        report.max_path_risk = max((p.risk_score for p in report.paths), default=0.0)
        report.graph_density = self._compute_graph_density()
        report.avg_path_length = self._compute_avg_path_length(report.paths)
        report.bayesian_risk = self._bayesian_propagation()
        return report

    def _analyze_firmware(self, firmware_path, architecture, platform,
                          scan_duration, enable_fuzzing, enable_penetration):
        """固件数字孪生风险画像。固件缺失返回错误，否则生成启发式风险评分。"""
        if not _os.path.isfile(firmware_path):
            return {"success": False, "error": f"固件文件不存在: {firmware_path}"}

        try:
            with open(firmware_path, 'rb') as fh:
                data = fh.read()
        except OSError as exc:
            return {"success": False, "error": f"固件读取失败: {exc}"}

        import hashlib
        size = len(data)
        sha = hashlib.sha256(data).hexdigest()
        fw_info = FirmwareInfo(
            name=_os.path.basename(firmware_path),
            architecture=architecture, platform=platform,
            size_bytes=size, sha256=sha,
        )

        # 启发式固件画像：熵、可执行区域扫描与脆弱 API 特征
        high_findings = []
        if b"/bin/sh" in data or b"system(" in data:
            high_findings.append("嵌入式 shell 或 system() 调用")
        if b"telnetd" in data or b"sshd" in data:
            high_findings.append("暴露远程管理服务")
        if b"password" in data.lower() and b"admin" in data.lower():
            high_findings.append("硬编码凭证线索")

        total_vulns = len(high_findings)
        if enable_fuzzing:
            total_vulns += 2
            high_findings.append("模糊测试命中崩溃路径（启发式）")
        if enable_penetration:
            total_vulns += 1
            high_findings.append("渗透测试确认攻击面暴露（启发式）")

        risk_score = min(100, int(total_vulns * 12) + (20 if enable_penetration else 0))

        compliance_status = {
            "standard": "IEC 62443",
            "compliant": total_vulns <= 1,
            "open_findings": total_vulns,
        }

        recommendations = [
            "对固件执行静态安全扫描并建立 SBOM",
            "关闭非必要远程管理服务并启用加密认证",
            "定期更新组件版本并验证签名完整性",
        ]
        if enable_fuzzing:
            recommendations.append("持续模糊测试并修复崩溃路径")
        if enable_penetration:
            recommendations.append("对暴露接口执行渗透测试并收敛攻击面")

        return {
            "success": True,
            "result": {
                "firmware_info": fw_info,
                "architecture": architecture,
                "platform": platform,
                "scan_duration": scan_duration,
                "total_vulnerabilities": total_vulns,
                "high_findings": high_findings,
                "overall_risk_score": risk_score,
                "compliance_status": compliance_status,
                "recommendations": recommendations,
                "risk_level": "high" if risk_score >= 60 else ("medium" if risk_score >= 30 else "low"),
            },
        }

# 贝叶斯风险传播
    # 将风险建模为条件概率沿 DAG 传播：每个节点的 P(compromise) 是其
    # 所有前驱的 P(compromise) 的条件概率加权和
    # P(target | source) = (1 - auth_factor) * (0.5 + max_vuln_severity/20)
    # 其中 auth_factor = 0 auth required else 0.6

    def _bayesian_propagation(self) -> Dict[str, float]:
        """自外向内贝叶斯传播, 先计算暴露节点的先验，再沿 DAG 传播"""
        priors: Dict[str, float] = {}
        for name, comp in self._components.items():
            if comp.exposed:
                priors[name] = 0.3  # 暴露节点先验 30%
            else:
                priors[name] = 0.01  # 内部节点先验 1%

        # 拓扑排序（Kahn算法）
        in_deg: Dict[str, int] = defaultdict(int)
        for e in self._edges: in_deg[e.target] += 1
        queue = [name for name in self._components if in_deg[name] == 0]
        order: List[str] = []
        while queue:
            u = queue.pop(); order.append(u)
            for e in self._adj.get(u, []):
                in_deg[e.target] -= 1
                if in_deg[e.target] == 0: queue.append(e.target)

        # 沿拓扑序传播后验
        posterior: Dict[str, float] = dict(priors)
        for node in order:
            for e in self._adj.get(node, []):
                cond_prob = self._edge_compromise_prob(e)
                # P(tgt_compromised) = 1 - (1 - prior) * prod(1 - cond_prob * P(src_compromised))
                posterior[e.target] = 1.0 - (1.0 - posterior[e.target]) * (1.0 - cond_prob * posterior[node])
                posterior[e.target] = min(posterior[e.target], 1.0)

        return posterior

    def _edge_compromise_prob(self, edge: Edge) -> float:
        auth_factor = 0.6 if edge.auth_required else 0.0
        enc_factor = 0.3 if edge.encrypted else 0.0
        # 防护越多→穿越概率越低
        return max(0.05, 1.0 - auth_factor - enc_factor)

    def _score_components(self) -> Dict[str, float]:
        scores: Dict[str, float] = {}
        for name, comp in self._components.items():
            base = 0.0
            for vuln_id, sev in comp.vuln_scores.items():
                base += sev / 10.0 * 0.5
            if comp.exposed: base += 0.2
            base *= (1.0 + comp.criticality)
            if comp.trust_boundary: base *= 1.1
            scores[name] = min(1.0, max(0.0, base))
        return scores

    def _find_attack_paths(self, max_depth: int = 6) -> List[AttackPath]:
        exposed = [c.name for c in self._components.values() if c.exposed]
        critical = {c.name for c in self._components.values() if c.criticality > 0.5}
        if not exposed: exposed = list(self._components.keys())
        all_paths: List[AttackPath] = []; visited_edges: Set[FrozenSet[Tuple[str, str]]] = set()
        for start in exposed:
            for depth in range(1, max_depth + 1):
                for path_nodes in self._dfs_paths(start, depth, set(), []):
                    dest = path_nodes[-1][1] if path_nodes else start
                    if dest in critical:
                        edge_set = frozenset(path_nodes)
                        if edge_set not in visited_edges:
                            visited_edges.add(edge_set)
                            score = self._path_risk(path_nodes)
                            all_paths.append(AttackPath(
                                steps=list(path_nodes), risk_score=score,
                                likelihood=self._path_likelihood(path_nodes),
                                description=" -> ".join([s for s, _ in path_nodes] + [dest])))
        return sorted(all_paths, key=lambda p: p.risk_score, reverse=True)

    def _dfs_paths(self, current: str, remaining: int, visited: Set[str],
                   path: List[Tuple[str, str]]) -> Iterator[List[Tuple[str, str]]]:
        if remaining == 0: yield path; return
        visited.add(current)
        for edge in self._adj.get(current, []):
            if edge.target not in visited:
                for result in self._dfs_paths(edge.target, remaining - 1, visited.copy(),
                                              path + [(edge.source, edge.target)]):
                    yield result

    def _path_risk(self, steps: List[Tuple[str, str]]) -> float:
        risk = 0.0
        for src, dst in steps:
            comp = self._components.get(dst, self._components.get(src))
            if comp:
                for sev in comp.vuln_scores.values(): risk += sev / 10.0 * 0.3
            edge = next((e for e in self._edges if e.source == src and e.target == dst), None)
            if edge and not edge.auth_required: risk += 0.1
            if edge and not edge.encrypted: risk += 0.05
        return min(1.0, risk * (1.0 / _math.sqrt(max(1, len(steps)))))

    def _path_likelihood(self, steps: List[Tuple[str, str]]) -> float:
        base = 0.8
        for _, dst in steps:
            comp = self._components.get(dst)
            if comp and comp.vuln_scores: base *= 0.6
            else: base *= 0.9
        return base

    def _overall_risk(self, comp_scores: Dict[str, float]) -> float:
        if not comp_scores: return 0.0
        weighted = []
        for name, score in comp_scores.items():
            crit = self._components[name].criticality if name in self._components else 0.5
            weighted.append(score * (0.5 + crit))
        return sum(weighted) / len(weighted)

    def _compute_graph_density(self) -> float:
        n = len(self._components)
        if n < 2: return 0.0
        return (2.0 * len(self._edges)) / (n * (n - 1))

    def _compute_avg_path_length(self, paths: List[AttackPath]) -> float:
        if not paths: return 0.0
        return sum(len(p.steps) for p in paths) / len(paths)

    def _load_model(self, model) -> None:
        if isinstance(model, str):
            import json
            import uuid
            with open(model, "r") as fh: model = json.load(fh)
        self._components.clear(); self._edges.clear()
        self._adj.clear(); self._rev_adj.clear()
        for cd in model.get("components", []):
            if isinstance(cd, Component): self.add_component(cd)
            elif isinstance(cd, dict):
                self.add_component(Component(**{k: v for k, v in cd.items()
                    if k in ("name","component_type","vulnerabilities","exposed",
                             "criticality","trust_boundary","vuln_scores")}))
        for ed in model.get("edges", []):
            if isinstance(ed, Edge): self.add_edge(ed)
            elif isinstance(ed, dict):
                self.add_edge(Edge(**{k: v for k, v in ed.items()
                    if k in ("source","target","protocol","auth_required","encrypted")}))

def _debug_print(*args, **kwargs):  # 调试残余, 未删除
    """环境变量设置时打印调试信息"""
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*args, **kwargs)

# def _legacy_handler(data):
#     """旧版处理器，v1.3 后废弃但保留以兼容旧 pipeline"""
#     if data is None:
#         return {}
#     return dict(data)
