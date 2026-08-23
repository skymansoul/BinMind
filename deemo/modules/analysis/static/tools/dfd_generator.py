import logging
import time
import hashlib
from enum import Enum
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass, field

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class DFDNodeType(str, Enum):
    """DFD node type 分类"""
    EXTERNAL_ENTITY = "external_entity"
    PROCESS = "process"
    DATA_STORE = "data_store"
    DATA_FLOW = "data_flow"
    TRUST_BOUNDARY = "trust_boundary"

class FlowRiskLevel(str, Enum):
    """数据流 risk severity tier"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class DataFlowTrustZone(str, Enum):
    """数据流分析的信任区分"""
    UNTRUSTED = "untrusted"
    DMZ = "dmz"
    INTERNAL = "internal"
    RESTRICTED = "restricted"
    CONFIDENTIAL = "confidential"


@dataclass
class DFDNode:
    node_id: str
    name: str
    node_type: DFDNodeType
    trust_zone: DataFlowTrustZone = DataFlowTrustZone.INTERNAL
    description: str = ""
    is_boundary_crossing: bool = False
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DFDEdge:
    edge_id: str
    source_id: str
    target_id: str
    label: str = ""
    data_type: str = ""
    protocol: str = ""
    crosses_boundary: bool = False
    risk_level: FlowRiskLevel = FlowRiskLevel.LOW
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataFlowGraph:
    graph_id: str = ""
    title: str = ""
    nodes: List[DFDNode] = field(default_factory=list)
    edges: List[DFDEdge] = field(default_factory=list)
    trust_boundaries: List[str] = field(default_factory=list)
    high_risk_flows: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))


class DataFlowExtractor:
    """数据流 extractor, 提取 数据流s binary import analysis"""

    NETWORK_IMPORTS = {
        "send", "sendto", "sendmsg", "write", "writev",
        "recv", "recvfrom", "recvmsg", "read", "readv",
        "connect", "accept", "bind", "listen",
        "socket", "getsockname", "getpeername",
    }

    FILE_IMPORTS = {
        "open", "openat", "creat", "fopen", "freopen",
        "read", "fread", "write", "fwrite", "fputs", "fgets",
        "close", "fclose", "stat", "fstat",
    }

    IPC_IMPORTS = {
        "shmget", "shmat", "shmdt", "mq_open", "mq_send",
        "mq_receive", "pipe", "pipe2", "socketpair",
        "semget", "semop", "msgget", "msgsnd", "msgrcv",
    }

    CRYPTO_IMPORTS = {
        "EVP_EncryptInit", "EVP_DecryptInit", "AES_set_encrypt_key",
        "RSA_public_encrypt", "RSA_private_decrypt", "crypto_secretbox",
        "gcry_cipher_open", "CryptEncrypt", "CryptDecrypt",
    }

    def extract(self, binary_info: Dict[str, Any],
                function_list: List[Dict[str, Any]] = None) -> List[Tuple[str, str, str, Dict[str, Any]]]:
        """提取 数据流s binary import information"""
        flows: List[Tuple[str, str, str, Dict[str, Any]]] = []
        imports = binary_info.get("imports", [])

        net_funcs = [imp for imp in imports
                     if imp.get("name", "").split("@")[0] in self.NETWORK_IMPORTS]
        file_funcs = [imp for imp in imports
                      if imp.get("name", "").split("@")[0] in self.FILE_IMPORTS]
        ipc_funcs = [imp for imp in imports
                     if imp.get("name", "").split("@")[0] in self.IPC_IMPORTS]
        crypto_funcs = [imp for imp in imports
                        if any(c in imp.get("name", "") for c in self.CRYPTO_IMPORTS)]

        for nf in net_funcs:
            func_name = nf.get("name", "unknown").split("@")[0]
            if func_name in ("recv", "recvfrom", "recvmsg", "read", "accept"):
                flows.append((
                    "external_network",
                    f"func_{nf.get('caller_address', 'unknown')}",
                    "network_input",
                    {"import_name": func_name, "data_direction": "inbound",
                     "protocol": self._infer_protocol(func_name), "crosses_boundary": True},
                ))
            elif func_name in ("send", "sendto", "sendmsg", "write", "connect"):
                flows.append((
                    f"func_{nf.get('caller_address', 'unknown')}",
                    "external_network",
                    "network_output",
                    {"import_name": func_name, "data_direction": "outbound",
                     "protocol": self._infer_protocol(func_name), "crosses_boundary": True},
                ))

        for ff in file_funcs:
            func_name = ff.get("name", "unknown").split("@")[0]
            if func_name in ("read", "fread", "open", "fopen", "fgets"):
                flows.append((
                    "filesystem", f"func_{ff.get('caller_address', 'unknown')}",
                    "file_input",
                    {"import_name": func_name, "data_direction": "inbound",
                     "crosses_boundary": True},
                ))
            elif func_name in ("write", "fwrite", "fputs"):
                flows.append((
                    f"func_{ff.get('caller_address', 'unknown')}", "filesystem",
                    "file_output",
                    {"import_name": func_name, "data_direction": "outbound",
                     "crosses_boundary": True},
                ))

        for ipc in ipc_funcs:
            func_name = ipc.get("name", "unknown").split("@")[0]
            if func_name in ("mq_send", "msgsnd", "shmat", "write"):
                flows.append((
                    f"func_{ipc.get('caller_address', 'unknown')}",
                    f"ipc_{func_name}", "ipc_output",
                    {"import_name": func_name, "data_direction": "outbound"},
                ))
            elif func_name in ("mq_receive", "msgrcv", "read"):
                flows.append((
                    f"ipc_{func_name}", f"func_{ipc.get('caller_address', 'unknown')}",
                    "ipc_input",
                    {"import_name": func_name, "data_direction": "inbound"},
                ))

        for cf in crypto_funcs:
            func_name = cf.get("name", "unknown").split("@")[0]
            if "Encrypt" in func_name or "encrypt" in func_name:
                flows.append((
                    f"func_{cf.get('caller_address', 'unknown')}",
                    "encryption_layer", "encryption",
                    {"import_name": func_name, "crypto_operation": True,
                     "trust_zone": DataFlowTrustZone.CONFIDENTIAL.value},
                ))
            elif "Decrypt" in func_name or "decrypt" in func_name:
                flows.append((
                    "encryption_layer",
                    f"func_{cf.get('caller_address', 'unknown')}", "decryption",
                    {"import_name": func_name, "crypto_operation": True,
                     "trust_zone": DataFlowTrustZone.CONFIDENTIAL.value},
                ))

        return flows

    @staticmethod
    def _infer_protocol(func_name: str) -> str:
        """Infer transport 协议 function name"""
        mapping = {"send": "TCP/UDP", "recv": "TCP/UDP", "sendto": "UDP",
                   "recvfrom": "UDP", "sendmsg": "UDP", "recvmsg": "UDP",
                   "connect": "TCP", "accept": "TCP"}
        return mapping.get(func_name, "UNKNOWN")


class TrustBoundaryDetector:
    """信任边界检测器, 识别数据流中的跨区穿越"""

    def identify(self, flows: List[Tuple[str, str, str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
        boundaries: List[Dict[str, Any]] = []
        boundary_sources = {"network_input": DataFlowTrustZone.UNTRUSTED,
                            "file_input": DataFlowTrustZone.UNTRUSTED,
                            "network_output": DataFlowTrustZone.DMZ,
                            "file_output": DataFlowTrustZone.INTERNAL}

        for src, dst, flow_type, attrs in flows:
            if attrs.get("crosses_boundary"):
                boundaries.append({
                    "name": f"boundary_{src}_to_{dst}",
                    "source_zone": boundary_sources.get(flow_type, DataFlowTrustZone.UNTRUSTED).value,
                    "target_zone": DataFlowTrustZone.INTERNAL.value,
                    "flow_type": flow_type, "source": src, "target": dst,
                    "protocol": attrs.get("protocol", ""),
                })
            if attrs.get("crypto_operation"):
                boundaries.append({
                    "name": f"crypto_boundary_{src}_to_{dst}",
                    "source_zone": DataFlowTrustZone.INTERNAL.value,
                    "target_zone": DataFlowTrustZone.CONFIDENTIAL.value,
                    "flow_type": "encryption", "source": src, "target": dst,
                })

        seen = set()
        unique = []
        for b in boundaries:
            key = b["name"]
            if key not in seen:
                seen.add(key)
                unique.append(b)
        return unique


class DFDGraphBuilder:
    """DFD graph builder, assembles nodes/edges extracted flows"""

    def build(self, flows: List[Tuple[str, str, str, Dict[str, Any]]],
              boundaries: List[Dict[str, Any]],
              binary_name: str = "binary") -> DataFlowGraph:
        graph = DataFlowGraph(
            graph_id=hashlib.md5(str(flows).encode()).hexdigest()[:12],
            title=f"Data Flow Diagram, {binary_name}",
        )

        node_ids: Dict[str, str] = {}
        nodes: List[DFDNode] = []
        edges: List[DFDEdge] = []

        fixed = [
            ("external_network", "External Network", DFDNodeType.EXTERNAL_ENTITY, DataFlowTrustZone.UNTRUSTED),
            ("filesystem", "File System", DFDNodeType.DATA_STORE, DataFlowTrustZone.UNTRUSTED),
            ("encryption_layer", "Encryption Layer", DFDNodeType.PROCESS, DataFlowTrustZone.CONFIDENTIAL),
        ]
        for nid, name, ntype, zone in fixed:
            node_ids[nid] = nid
            nodes.append(DFDNode(node_id=nid, name=name, node_type=ntype, trust_zone=zone))

        for src, dst, flow_type, attrs in flows:
            if src not in node_ids:
                ntype = DFDNodeType.PROCESS if "func_" in src else DFDNodeType.DATA_STORE
                zone = DataFlowTrustZone.UNTRUSTED if "external" in src else DataFlowTrustZone.INTERNAL
                node_ids[src] = src
                nodes.append(DFDNode(
                    node_id=src, name=src.replace("func_", ""),
                    node_type=ntype, trust_zone=zone,
                    is_boundary_crossing=attrs.get("crosses_boundary", False),
                ))
            if dst not in node_ids:
                ntype = DFDNodeType.PROCESS if "func_" in dst else DFDNodeType.DATA_STORE
                zone = DataFlowTrustZone.UNTRUSTED if "external" in dst else DataFlowTrustZone.INTERNAL
                node_ids[dst] = dst
                nodes.append(DFDNode(
                    node_id=dst, name=dst.replace("func_", ""),
                    node_type=ntype, trust_zone=zone,
                    is_boundary_crossing=attrs.get("crosses_boundary", False),
                ))

            risk = self._assess_risk(flow_type, attrs)
            edge = DFDEdge(
                edge_id=f"edge_{len(edges):04d}",
                source_id=src, target_id=dst,
                label=flow_type,
                data_type=attrs.get("data_type", "data"),
                protocol=attrs.get("protocol", ""),
                crosses_boundary=attrs.get("crosses_boundary", False),
                risk_level=risk,
                attributes=attrs,
            )
            edges.append(edge)

        graph.nodes = nodes
        graph.edges = edges
        graph.trust_boundaries = [b["name"] for b in boundaries]
        graph.high_risk_flows = [e.edge_id for e in edges
                                  if e.risk_level in (FlowRiskLevel.CRITICAL, FlowRiskLevel.HIGH)]

        return graph

    @staticmethod
    def _assess_risk(flow_type: str, attrs: Dict[str, Any]) -> FlowRiskLevel:
        if flow_type == "network_input" and attrs.get("crosses_boundary"):
            return FlowRiskLevel.HIGH
        elif flow_type == "network_output" and attrs.get("crosses_boundary"):
            return FlowRiskLevel.MEDIUM
        elif attrs.get("crypto_operation"):
            return FlowRiskLevel.LOW
        elif flow_type in ("ipc_input", "ipc_output"):
            return FlowRiskLevel.MEDIUM
        elif flow_type in ("file_input", "file_output"):
            return FlowRiskLevel.MEDIUM
        return FlowRiskLevel.LOW


class MermaidRenderer:
    """Mermaid 图渲染器, 生成流程图与序列图"""

    @staticmethod
    def render_flowchart(graph: DataFlowGraph) -> str:
        lines = ["```mermaid", "graph TD", ""]
        zone_nodes: Dict[str, List[str]] = {}
        for node in graph.nodes:
            zone_nodes.setdefault(node.trust_zone.value, []).append(node.node_id)

        zone_styles = {
            "untrusted": "Untrusted Zone",
            "dmz": "DMZ",
            "internal": "Internal Zone",
            "restricted": "Restricted Zone",
            "confidential": "Confidential Zone",
        }

        for zone_name in ["untrusted", "dmz", "internal", "restricted", "confidential"]:
            if zone_name in zone_nodes:
                label = zone_styles.get(zone_name, zone_name.title())
                lines.append(f"    subgraph {zone_name}[\"{label}\"]")
                for nid in zone_nodes[zone_name]:
                    node = next((n for n in graph.nodes if n.node_id == nid), None)
                    if node:
                        shape = {"external_entity": "[", "process": "(", "data_store": "[(>", "data_flow": ">"}.get(
                            node.node_type, "[")
                        lines.append(f"        {_safe_id(nid)}{shape}\"{node.name}\"]")
                lines.append("    end")
                lines.append("")

        for edge in graph.edges:
            src = _safe_id(edge.source_id)
            tgt = _safe_id(edge.target_id)
            style = "==>" if edge.risk_level == FlowRiskLevel.HIGH else "-->"
            style = "-.->" if edge.risk_level == FlowRiskLevel.CRITICAL else style
            label = edge.label
            if edge.crosses_boundary:
                label += " [BND]"
            lines.append(f"    {src} {style}|{label}| {tgt}")

        lines.append("```")
        return "\n".join(lines)

    @staticmethod
    def render_sequence(flows: List[Tuple[str, str, str, Dict[str, Any]]],
                        title: str = "Data Flow Sequence") -> str:
        lines = ["```mermaid", "sequenceDiagram", f"    title {title}", ""]
        participants = set()
        for src, dst, *_ in flows:
            participants.add(src)
            participants.add(dst)
        for p in sorted(participants):
            alias = p.split("_", 1)[-1] if "_" in p else p
            lines.append(f"    participant {_safe_id(p)} as {alias}")
        lines.append("")
        for src, dst, flow_type, _ in flows:
            arrow = "->>" if "input" in flow_type else "-->"
            lines.append(f"    {_safe_id(src)} {arrow} {_safe_id(dst)}: {flow_type}")
        lines.append("```")
        return "\n".join(lines)


class GraphvizRenderer:
    """Graphviz DOT renderer, produces directed graph visualization"""

    @staticmethod
    def render(graph: DataFlowGraph) -> str:
        lines = [
            "digraph DFD {",
            f'    label="{graph.title}";',
            "    rankdir=LR;",
            "    node [shape=box, style=rounded];",
            "",
        ]
        for node in graph.nodes:
            shape = {"external_entity": "rectangle", "process": "ellipse",
                     "data_store": "cylinder", "trust_boundary": "dashed"}.get(
                node.node_type, "box")
            color = {"untrusted": "#ffaaaa", "dmz": "#ffddaa", "internal": "#aaffaa",
                     "restricted": "#aaaaff", "confidential": "#ffaaff"}.get(
                node.trust_zone.value, "#ffffff")
            lines.append(f'    {_dot_id(node.node_id)} [label="{node.name}", shape={shape}, fillcolor={color}, style=filled];')

        lines.append("")
        for edge in graph.edges:
            attrs = []
            if edge.crosses_boundary:
                attrs.extend(["color=red", "penwidth=2"])
            if edge.risk_level == FlowRiskLevel.CRITICAL:
                attrs.extend(["style=dashed", "color=darkred"])
            attr_str = ", ".join(attrs)
            lines.append(
                f'    {_dot_id(edge.source_id)} -> {_dot_id(edge.target_id)} '
                f'[label="{edge.label}"{", " + attr_str if attr_str else ""}];'
            )
        lines.append("}")
        return "\n".join(lines)


def _safe_id(node_id: str) -> str:
    """清理节点 ID 以兼容 Mermaid"""
    return node_id.replace(" ", "_").replace("-", "_").replace(".", "_").replace("@", "_")


def _dot_id(node_id: str) -> str:
    """清理节点 ID 以兼容 DOT"""
    return f'"{node_id}"'


class DFDGenerator(BaseAnalyzer):
    """数据流 diagram auto-generation analyzer, 提取 flows, identifies boundaries, 渲染 diagrams"""

    def __init__(self):
        super().__init__()
        self._extractor = DataFlowExtractor()
        self._boundary_detector = TrustBoundaryDetector()
        self._builder = DFDGraphBuilder()
        self._mermaid = MermaidRenderer()
        self._graphviz = GraphvizRenderer()
        self._graphs: List[DataFlowGraph] = []

    def analyze(self, **kwargs) -> Dict[str, Any]:
        command = kwargs.get("command", "extract_data_flows")
        try:
            handlers = {
                "extract_data_flows": self.extract_data_flows,
                "identify_trust_boundaries": self.identify_trust_boundaries,
                "generate_dfd_nodes": self.generate_dfd_nodes,
                "generate_dfd_edges": self.generate_dfd_edges,
                "render_as_mermaid": self.render_as_mermaid,
                "render_as_graphviz": self.render_as_graphviz,
                "identify_high_risk_flows": self.identify_high_risk_flows,
            }
            handler = handlers.get(command)
            if handler:
                return handler(**kwargs)
            return {"success": False, "error": f"Unknown command: {command}"}
        except Exception as e:
            logger.error("Analysis failed: %s", e)
            return {"success": False, "error": str(e)}

    def extract_data_flows(self, binary_info: Dict[str, Any] = None,
                           **kwargs) -> Dict[str, Any]:
        if not binary_info:
            return {"success": False, "error": "binary_info required"}
        flows = self._extractor.extract(binary_info)
        return {
            "success": True,
            "total_flows": len(flows),
            "flows": [{"source": s, "target": t, "type": ft, "attributes": a}
                      for s, t, ft, a in flows],
        }

    def identify_trust_boundaries(self, flows: List[Dict[str, Any]] = None,
                                   binary_info: Dict[str, Any] = None,
                                   **kwargs) -> Dict[str, Any]:
        if not flows and binary_info:
            raw = self._extractor.extract(binary_info)
            flows = [{"source": s, "target": t, **a} for s, t, _, a in raw]
        if not flows:
            return {"success": False, "error": "flows or binary_info required"}

        raw_flows = [(f["source"], f["target"], f.get("crosses_boundary", False) and "boundary" or "internal",
                      {k: v for k, v in f.items() if k not in ("source", "target")})
                     for f in flows]

        boundaries = self._boundary_detector.identify(raw_flows)
        return {"success": True, "total_boundaries": len(boundaries), "boundaries": boundaries}

    def generate_dfd_nodes(self, binary_info: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        if not binary_info:
            return {"success": False, "error": "binary_info required"}
        flows_raw = self._extractor.extract(binary_info)
        boundaries = self._boundary_detector.identify(flows_raw)
        graph = self._builder.build(flows_raw, boundaries, binary_info.get("name", "binary"))
        self._graphs.append(graph)
        return {
            "success": True, "total_nodes": len(graph.nodes),
            "nodes": [{"node_id": n.node_id, "name": n.name,
                        "type": n.node_type, "trust_zone": n.trust_zone.value}
                      for n in graph.nodes],
        }

    def generate_dfd_edges(self, binary_info: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        if not binary_info:
            return {"success": False, "error": "binary_info required"}
        flows_raw = self._extractor.extract(binary_info)
        boundaries = self._boundary_detector.identify(flows_raw)
        graph = self._builder.build(flows_raw, boundaries, binary_info.get("name", "binary"))
        self._graphs.append(graph)
        return {
            "success": True, "total_edges": len(graph.edges),
            "edges": [{"edge_id": e.edge_id, "source": e.source_id, "target": e.target_id,
                        "label": e.label, "risk_level": e.risk_level,
                        "crosses_boundary": e.crosses_boundary, "protocol": e.protocol}
                      for e in graph.edges],
        }

    def render_as_mermaid(self, binary_info: Dict[str, Any] = None,
                           render_type: str = "flowchart", **kwargs) -> Dict[str, Any]:
        if not binary_info:
            return {"success": False, "error": "binary_info required"}
        flows_raw = self._extractor.extract(binary_info)
        boundaries = self._boundary_detector.identify(flows_raw)
        graph = self._builder.build(flows_raw, boundaries, binary_info.get("name", "binary"))

        if render_type == "sequence":
            code = self._mermaid.render_sequence(flows_raw, graph.title)
        else:
            code = self._mermaid.render_flowchart(graph)

        return {"success": True, "render_type": render_type, "mermaid_code": code,
                "node_count": len(graph.nodes), "edge_count": len(graph.edges)}

    def render_as_graphviz(self, binary_info: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        if not binary_info:
            return {"success": False, "error": "binary_info required"}
        flows_raw = self._extractor.extract(binary_info)
        boundaries = self._boundary_detector.identify(flows_raw)
        graph = self._builder.build(flows_raw, boundaries, binary_info.get("name", "binary"))
        dot_code = self._graphviz.render(graph)
        return {"success": True, "graphviz_dot": dot_code,
                "node_count": len(graph.nodes), "edge_count": len(graph.edges)}

    def identify_high_risk_flows(self, binary_info: Dict[str, Any] = None,
                                  **kwargs) -> Dict[str, Any]:
        if not binary_info:
            return {"success": False, "error": "binary_info required"}
        flows_raw = self._extractor.extract(binary_info)
        boundaries = self._boundary_detector.identify(flows_raw)
        graph = self._builder.build(flows_raw, boundaries, binary_info.get("name", "binary"))
        high_risk = []
        for edge in graph.edges:
            if edge.risk_level in (FlowRiskLevel.CRITICAL, FlowRiskLevel.HIGH):
                high_risk.append({"edge_id": edge.edge_id, "source": edge.source_id,
                                  "target": edge.target_id, "label": edge.label,
                                  "risk_level": edge.risk_level,
                                  "crosses_boundary": edge.crosses_boundary})
        return {"success": True, "total_high_risk": len(high_risk), "high_risk_flows": high_risk}

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="DFDGenerator",
            type=AnalyzerType.UTILITY,
            version="1.0.0",
            description="Data flow diagram auto-generation: inter-function data flow extraction, trust boundary identification, Mermaid/Graphviz visualization, high-risk flow annotation",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["all"],
        )


__all__ = ["DFDGenerator"]

def _debug_print(*args, **kwargs):  # 调试残余, 未删除
    """环境变量设置时打印调试信息"""
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*args, **kwargs)
