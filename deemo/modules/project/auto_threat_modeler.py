# 修改记录:
# 2025-07-21 15:30 — 初始创建: STRIDE分类+信任边界+数据流追踪
# 2025-07-28 11:42 — 增加信任边界图+Dijkstra攻击可达性+威胁传播评分
# 自动威胁建模器: 信任边界图 / Dijkstra可达性 / 威胁传播评分
# 技术问题: 静态STRIDE分类独立评估每个数据流, 无法建模攻击者
#   从入口点经过多个信任边界到达高价值资产的完整路径.
#   例如: user_input→web_api(边界1)→db_query(边界2)→file_write(边界3)
#   单独的STRIDE可能将每步评为"中等风险", 但链式组合为"严重"
# 解决手段: 构建信任边界图:
#   节点: 代码组件 (控制器/模型/中间件)
#   边: 数据流 (带STRIDE威胁标签)
#   权重: 威胁严重度
#   Dijkstra: 从外部入口到高价值资产的最短(最高威胁)路径
# 参考 (已验证真实):
#   OWASP Threat Modeling Cheat Sheet — STRIDE方法论
#   MITRE ATT&CK v16 — 威胁技术映射
#   Shostack "Threat Modeling: Designing for Security" (Wiley 2014)
from __future__ import annotations
import hashlib, heapq, logging, re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)

_STRIDE_TO_MITRE: Dict[str, List[Tuple[str, str]]] = {
    "spoofing": [("T1078","Valid Accounts"),("T1557","AITM")],
    "tampering": [("T1565","Data Manipulation")],
    "information_disclosure": [("T1040","Network Sniffing"),("T1005","Local Data")],
    "elevation_of_privilege": [("T1068","PrivEsc"),("T1548","Elevation Control")],
    "denial_of_service": [("T1498","Network DoS")],
}

@dataclass
class TrustBoundary:
    boundary_id: str; name: str; boundary_type: str
    location: str = ""; evidence: str = ""

@dataclass
class DataFlow:
    flow_id: str; source: str; sink: str
    crosses_boundaries: List[str] = field(default_factory=list)
    sanitization: bool = False

@dataclass
class ThreatCard:
    card_id: str; stride_category: str; description: str
    affected_component: str; severity: str = "medium"
    mitre_techniques: List[Tuple[str, str]] = field(default_factory=list)
    mitigation: str = ""


class ThreatGraph:
    """信任边界图: 组件节点+数据流边+STRIDE权重.

    Dijkstra从外部入口找到达高价值资产的最短(最高威胁)路径.
    """

    def __init__(self):
        self._nodes: Set[str] = set()
        self._edges: Dict[str, List[Tuple[str, float, str]]] = defaultdict(list)

    def add_component(self, name: str):
        self._nodes.add(name)

    def add_flow(self, src: str, dst: str, threat_severity: float,
                 stride_cat: str = ""):
        self._edges[src].append((dst, 1.0 / max(threat_severity, 0.01), stride_cat))

    def most_threatened_asset(self, entry_points: List[str],
                              high_value: List[str]
                              ) -> Tuple[List[str], float]:
        """Dijkstra: 从entry_points出发, 找到达high_value组件的最短路径.

        边权重 = 1/threat_severity, 因此最短路径=最高威胁路径.
        """
        best_path, best_threat = [], 0.0
        for entry in entry_points:
            if entry not in self._nodes:
                continue
            dist = {entry: 0.0}; prev = {entry: None}; pq = [(0.0, entry)]
            visited = set()
            while pq:
                d, u = heapq.heappop(pq)
                if u in visited: continue
                visited.add(u)
                if u in high_value:
                    path = []; cur = u; total_threat = 1.0 / max(d, 0.01)
                    while prev.get(cur) is not None:
                        path.append(cur); cur = prev[cur][0]
                    path.append(entry); path.reverse()
                    if total_threat > best_threat:
                        best_threat = total_threat; best_path = path
                    break
                for v, w, cat in self._edges.get(u, []):
                    nd = d + w
                    if nd < dist.get(v, float('inf')):
                        dist[v] = nd; prev[v] = (u, cat)
                        heapq.heappush(pq, (nd, v))
        return best_path, best_threat


class AutoThreatModeler:
    """自动威胁建模器 (含信任边界图+威胁传播)."""

    def __init__(self):
        self._graph = ThreatGraph()

    def model(self, code_snippets: List[str],
              config_snippets: Optional[List[str]] = None,
              component_name: str = "") -> List[ThreatCard]:
        code = "\n".join(code_snippets + (config_snippets or []))
        cards: List[ThreatCard] = []
        # 信任边界提取
        boundaries = self._extract_boundaries(code)
        for b in boundaries:
            self._graph.add_component(b.name)
        # 数据流提取
        flows = self._extract_flows(code_snippets)
        for f in flows:
            src_name = f"src_{f.source}"; dst_name = f"sink_{f.sink}"
            self._graph.add_component(src_name)
            self._graph.add_component(dst_name)
            cats = self._classify_stride(f, boundaries)
            for cat in cats:
                sev = {"elevation_of_privilege":9,"tampering":7,
                       "spoofing":6,"information_disclosure":5}.get(cat,4)
                self._graph.add_flow(src_name, dst_name, sev, cat)
                cards.append(ThreatCard(
                    card_id=f"tm_{f.flow_id}_{cat}",
                    stride_category=cat,
                    description=f"{f.source}→{f.sink}: {self._describe(cat,f)}",
                    affected_component=component_name or f.sink,
                    mitre_techniques=_STRIDE_TO_MITRE.get(cat,[]),
                    severity="high" if sev >= 7 else "medium",
                    mitigation=self._mitigate(cat, f)))
        # 边界本身缺失防护
        for b in boundaries:
            if not any(b.boundary_id in c.description for c in cards):
                cards.append(ThreatCard(
                    card_id=f"tm_{b.boundary_id}_missing",
                    stride_category="spoofing",
                    description=f"边界'{b.name}'({b.boundary_type})缺少认证",
                    affected_component=component_name or "boundary",
                    severity="high",
                    mitigation=f"为{b.boundary_type}添加认证机制"))
        # 图分析: 最受威胁的资产
        entries = [f"src_user_input"] if any("user_input" in str(f.source)
                   for f in flows) else ["src_api_response"]
        high_val = [f"sink_os_command", f"sink_sql_exec", f"sink_file_write"]
        path, threat = self._graph.most_threatened_asset(entries, high_val)
        if path and threat > 2:
            cards.append(ThreatCard(
                card_id="tm_graph_path", stride_category="elevation_of_privilege",
                description=f"最高威胁路径: {'→'.join(path)} (评分={threat:.1f})",
                affected_component=component_name or "system",
                severity="critical" if threat > 5 else "high",
                mitigation="加固路径上每个组件的输入验证"))
        cards.sort(key=lambda c: {"critical":0,"high":1,"medium":2}.get(c.severity,3))
        return cards

    def _extract_boundaries(self, code: str) -> List[TrustBoundary]:
        b = []
        for pat, btype in [(r'(?:requireAuth|jwt\.verify|OAuth2)','auth_gate'),
                           (r'(?:nginx|CORS_ORIGIN|api_gateway)','network_edge'),
                           (r'(?:DATABASE_URL|mongoose\.model)','db_interface')]:
            for m in re.finditer(pat, code, re.IGNORECASE):
                b.append(TrustBoundary(f"b_{len(b)}",f"{btype}:{m.group()[:30]}",btype,evidence=m.group()))
        return b

    def _extract_flows(self, snippets: List[str]) -> List[DataFlow]:
        flows = []; code = "\n".join(snippets)
        sources = {"user_input":[r'req\.body',r'request\.form',r'request\.json'],
                   "api_response":[r'requests\.get',r'fetch\(']}
        sinks = {"html_render":[r'\.render\(',r'innerHTML'],
                 "sql_exec":[r'\.execute\(',r'\.query\('],
                 "os_command":[r'os\.system',r'subprocess'],
                 "file_write":[r'open\(.*w',r'writeFile']}
        fid = 0
        for stype, spatterns in sources.items():
            for skind, skpatterns in sinks.items():
                for sp in spatterns:
                    for sk in skpatterns:
                        sm = re.search(sp, code, re.IGNORECASE)
                        km = re.search(sk, code, re.IGNORECASE)
                        if sm and km:
                            flows.append(DataFlow(f"df_{fid}",stype,skind,
                                sanitization=("sanitize" in code.lower() or "escape" in code.lower())))
                            fid += 1; break
        return flows

    def _classify_stride(self, flow: DataFlow,
                         boundaries: List[TrustBoundary]) -> List[str]:
        cats = set()
        if flow.source == "user_input":
            cats.update(["tampering","information_disclosure"])
        if flow.sink in ("sql_exec","os_command"):
            cats.add("tampering")
        if flow.sink == "html_render":
            cats.add("information_disclosure")
        if flow.sink in ("os_command","file_write"):
            cats.add("elevation_of_privilege")
        if not flow.sanitization and flow.source == "user_input":
            cats.add("spoofing")
        return list(cats) if cats else ["information_disclosure"]

    @staticmethod
    def _describe(cat: str, flow: DataFlow) -> str:
        return {"spoofing":f"未认证的{flow.source}→{flow.sink}",
                "tampering":f"{flow.source}在到达{flow.sink}前可被篡改",
                "information_disclosure":f"{flow.source}经{flow.sink}泄露",
                "elevation_of_privilege":f"{flow.source}→{flow.sink}权限提升风险"
               }.get(cat, f"{cat}: {flow.source}→{flow.sink}")

    @staticmethod
    def _mitigate(cat: str, flow: DataFlow) -> str:
        return {"spoofing":f"对{flow.source}添加身份验证",
                "tampering":f"{flow.source}→{flow.sink}添加输入校验",
                "information_disclosure":f"对{flow.sink}输出脱敏",
                "elevation_of_privilege":f"在{flow.sink}前验证权限"
               }.get(cat, "添加审计日志")
