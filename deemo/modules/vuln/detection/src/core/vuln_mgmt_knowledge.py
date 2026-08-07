# vuln_mgmt_knowledge：知识图谱、规则引擎、泄漏检测、根因分析、配置审计
# 架构：从vuln_management.py拆分知识图谱及高级分析子系统
# 依赖vuln_mgmt_core（dataclass类型：CVEFootprint, DataFlowPath, InferenceRule等）
#
# 拆分日期 2026-08-02
# 源文件: vuln_management.py (行L1892-L2577)
#   _.-'-._
#  '  _.='   "
#   ".  `""--..__
#     `"._     /
#

# 保留不变
_CACHE_SALT = "s4lt_v3"
_STALE_LIMIT = 7200

from typing import Dict, Any, List, Optional, Set, Callable
import logging, re, os, subprocess, hashlib, time, threading
import uuid

from datetime import datetime

from collections import deque

# 从vuln_mgmt_core引入核心数据模型——规则推理依赖CVEFootprint等类型
from vuln_detection.src.core.vuln_mgmt_core import (
    CVEFootprint,          # CVE指纹匹配结果传递
    DataFlowPath,          # 数据流路径建模
    InferenceRule,         # 推理规则定义
    VulnerabilityKnowledgeNode,  # 知识图谱节点基类
    DataTag,               # 敏感数据标签
)

_logger = logging.getLogger(__name__)
logger = _logger


class VulnerabilityKnowledgeGraphBuilder:
    """提取实体与关系，支持图谱查询及D3.js可视化。"""

    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self.graph: Dict[str, List[str]] = {}

    def add_entity(
        self, entity_type: str, entity_id: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> None:
        node_id = f"{entity_type}:{entity_id}"
        self.nodes[node_id] = {"type": entity_type, "id": entity_id,
                               "properties": properties or {}}
        if node_id not in self.graph:
            self.graph[node_id] = []

    def add_relation(
        self, from_id: str, to_id: str, relation_type: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.edges.append({"from": from_id, "to": to_id,
                          "type": relation_type, "properties": properties or {}})
        if from_id in self.graph:
            self.graph[from_id].append(to_id)

    def query_path(self, start_id: str, end_id: str, max_depth: int = 3) -> List[List[str]]:
        paths: List[List[str]] = []

        def dfs(current: str, path: List[str], depth: int) -> None:
            if depth > max_depth:
                return
            if current == end_id:
                paths.append(list(path))
                return
            for neighbor in self.graph.get(current, []):
                if neighbor not in path:
                    path.append(neighbor)
                    dfs(neighbor, path, depth + 1)
                    path.pop()

        dfs(start_id, [start_id], 0)
        return paths

    def find_attack_patterns(self) -> List[Dict[str, Any]]:
        patterns: List[Dict[str, Any]] = []
        for node_id, node in self.nodes.items():
            if node["type"] == "vulnerability":
                reachable = self._find_reachable_nodes(node_id)
                sensitive = [n for n in reachable
                            if self.nodes.get(n, {}).get("type") == "sensitive_data"]
                if sensitive:
                    patterns.append({"entry_point": node_id, "reachable_assets": sensitive})
        return patterns

    def _find_reachable_nodes(self, start_id: str) -> Set[str]:
        # 内联广度遍历
        reachable: Set[str] = set()
        queue: deque = deque([start_id])
        while queue:
            cur = queue.popleft()
            for nb in self.graph.get(cur, []):
                if nb not in reachable:
                    reachable.add(nb)
                    queue.append(nb)
        return reachable

    def export_for_d3js(self) -> Dict[str, Any]:
        nodes_out = [{"id": nid, "type": n["type"],
                      "label": f"{n['type']}:{n['id']}"}
                     for nid, n in self.nodes.items()]
        links_out = [{"source": e["from"], "target": e["to"], "type": e["type"]}
                     for e in self.edges]
        return {"nodes": nodes_out, "links": links_out}

    def export_adjacency_list(self) -> Dict[str, List[str]]:
        return dict(self.graph)

    def stats(self) -> Dict[str, int]:
        return {"nodes": len(self.nodes), "edges": len(self.edges)}


class VulnerabilityRuleEngine:
    """加载YAML规则，正则扫描代码，合并分析结果。"""

    def __init__(self):
        self.rules: List[Dict[str, Any]] = []
        self.rule_patterns: Dict[str, re.Pattern] = {}
        self.matched_vulnerabilities: List[Dict[str, Any]] = []

    def load_rules_from_yaml(self, yaml_path: str) -> int:
        loaded = 0
        try:
            import yaml
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if data and "rules" in data:
                for rule in data["rules"]:
                    self.add_rule(rule)
                    loaded += 1
        except Exception as e:
            logger.error(f"Error loading YAML rules: {e}")
        return loaded

    def add_rule(self, rule: Dict[str, Any]) -> None:
        rule_id = rule.get("id", hashlib.md5(str(rule).encode()).hexdigest()[:8])
        rule["rule_id"] = rule_id
        if "pattern" in rule:
            try:
                self.rule_patterns[rule_id] = re.compile(rule["pattern"])
            except re.error:
                pass
        self.rules.append(rule)

    def scan_code(self, code: str) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        for rule in self.rules:
            rid = rule["rule_id"]
            pat = self.rule_patterns.get(rid)
            if pat is None:
                continue
            for m in pat.finditer(code):
                matches.append({
                    "rule_id": rid, "rule_name": rule.get("name", "Unknown"),
                    "severity": rule.get("severity", "medium"),
                    "matched_text": m.group(0), "location": m.span(),
                })
        self.matched_vulnerabilities.extend(matches)
        return matches

    def merge_with_ai_results(self, ai_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged = list(self.matched_vulnerabilities)
        for ai_r in ai_results:
            if not any(self._is_duplicate(ai_r, ex) for ex in merged):
                merged.append(ai_r)
        return merged

    @staticmethod
    def _is_duplicate(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
        # 内联去重
        if a.get("rule_id") and b.get("rule_id"):
            if a["rule_id"] == b["rule_id"]:
                return True
        if a.get("location") and b.get("location"):
            if a["location"] == b["location"]:
                return True
        return False


class SensitiveDataLeakageChecker:
    """检测源码中的PII、凭证及加密密钥，追踪其是否到达危险sink。"""

    def __init__(self):
        self.sensitive_patterns: Dict[str, List[str]] = {}
        self.sensitive_locations: Dict[str, List[int]] = {}
        self.leakage_reports: List[Dict[str, Any]] = []
        self._register_patterns()

    def _register_patterns(self) -> None:
        # 内联注册
        self.sensitive_patterns["pii"] = [
            r"\b\d{3}-\d{2}-\d{4}\b", r"\b\d{16}\b",
            r"\b[A-Z]{2}\d{6,9}\b", r"\b\d{4}\s\d{4}\s\d{4}\s\d{4}\b",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        ]
        self.sensitive_patterns["credentials"] = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
        ]
        self.sensitive_patterns["encryption_keys"] = [
            r"\b[A-Za-z0-9+/]{32,}={0,2}\b",
            r"private_key", r"rsa_key", r"aes_key",
            r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        ]

    def mark_sensitive(self, code: str) -> Dict[str, List[int]]:
        locations: Dict[str, List[int]] = {}
        for cat, patterns in self.sensitive_patterns.items():
            locations[cat] = []
            for pat in patterns:
                for m in re.finditer(pat, code, re.IGNORECASE):
                    locations[cat].append(m.start())
        self.sensitive_locations = locations
        return locations

    def track_flow(self, sensitive_loc: int, code: str) -> List[Dict[str, Any]]:
        flows: List[Dict[str, Any]] = []
        dangerous = ["printf", "fprintf", "sprintf", "send", "sendto", "write",
                     "fwrite", "fputs", "log", "debug", "error"]
        for func in dangerous:
            pat = rf"{func}\s*\([^)]*\)"
            for m in re.finditer(pat, code):
                if m.start() > sensitive_loc:
                    flows.append({"sensitive_location": sensitive_loc,
                                 "sink_function": func, "sink_location": m.start(),
                                 "potential_leak": True})
        return flows

    def check_leakage(self, code: str) -> List[Dict[str, Any]]:
        leakages: List[Dict[str, Any]] = []
        locs = self.mark_sensitive(code)
        for cat, positions in locs.items():
            for pos in positions:
                for flow in self.track_flow(pos, code):
                    leakages.append({
                        "category": cat, "location": pos,
                        "sink": flow["sink_function"],
                        "sink_location": flow["sink_location"],
                        "severity": "high" if cat in ("credentials", "encryption_keys") else "medium",
                    })
        self.leakage_reports = leakages
        return leakages

    def generate_report(self) -> str:
        lines = ["# Sensitive Data Leakage Report", ""]
        for cat, locs in self.sensitive_locations.items():
            lines.append(f"## {cat}")
            lines.append(f"- Occurrences: {len(locs)}")
            for lk in self.leakage_reports:
                if lk["category"] == cat:
                    lines.append(f"  - Possible leak to `{lk['sink']}` @ {hex(lk['sink_location'])}")
            lines.append("")
        return "\n".join(lines)


class AutomatedRootCauseAnalyzer:
    """从崩溃/利用触发点沿执行轨迹回溯，定位根因输入，生成报告。"""

    def __init__(self):
        self.trace_chain: List[Dict[str, Any]] = []
        self.root_cause: Dict[str, Any] = {}

    def analyze_trigger(self, crash_info: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "address": crash_info.get("crash_address", 0),
            "type": crash_info.get("crash_type", "unknown"),
            "registers": crash_info.get("registers", {}),
            "memory_state": crash_info.get("memory_state", {}),
            "instruction": crash_info.get("instruction", ""),
        }

    def backward_trace(
        self, trigger_address: int, execution_trace: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        chain: List[Dict[str, Any]] = []
        for i in range(len(execution_trace) - 1, -1, -1):
            step = execution_trace[i]
            if step.get("address") == trigger_address:
                for j in range(i, -1, -1):
                    chain.append(execution_trace[j])
                    if len(chain) >= 100:
                        break
        self.trace_chain = chain
        return chain

    def locate_root(self) -> Dict[str, Any]:
        if not self.trace_chain:
            return {}
        root: Dict[str, Any] = {"type": "input", "location": "unknown",
                                "description": "", "responsible_function": ""}
        for step in self.trace_chain:
            if step.get("input_related"):
                root["location"] = step.get("address", 0)
                root["description"] = "Input data processed here"
                root["responsible_function"] = step.get("function", "unknown")
                break
        self.root_cause = root
        return root

    def generate_report(self) -> str:
        lines = ["# Root Cause Analysis Report", "", "## Trigger Point"]
        if self.trace_chain:
            t = self.trace_chain[0]
            lines.append(f"- Address: {hex(t.get('address', 0))}")
            lines.append(f"- Type: {t.get('type', 'unknown')}")
        lines.append("")
        lines.append("## Trace Chain")
        lines.append(f"- Depth: {len(self.trace_chain)} steps")
        lines.append("")
        lines.append("## Root Cause")
        if self.root_cause:
            rc = self.root_cause
            loc = rc["location"]
            if isinstance(loc, int):
                loc = hex(loc)
            lines.append(f"- Type: {rc['type']}")
            lines.append(f"- Location: {loc}")
            lines.append(f"- Description: {rc['description']}")
            lines.append(f"- Function: {rc['responsible_function']}")
        lines.append("")
        return "\n".join(lines)


class SecurityConfigAuditor:
    """审计二进制文件的AppArmor配置文件和SELinux上下文。"""

    def __init__(self):
        self.policies: Dict[str, Dict[str, Any]] = {}
        self._register_policies()

    def _register_policies(self) -> None:
        self.policies["apparmor"] = {
            "required_profiles": ["usr.bin.binary"], "required_capabilities": [],
            "required_network": False, "required_file_access": [],
        }
        self.policies["selinux"] = {
            "required_context": "bin_t", "required_types": ["execmem_exec_t"],
            "required_booleans": [],
        }

    def audit_apparmor(self, binary_path: str) -> Dict[str, Any]:
        audit: Dict[str, Any] = {"binary_path": binary_path, "profile_exists": False,
                                 "profile_enforced": False, "violations": [],
                                 "recommendations": []}
        try:
            r = subprocess.run(["aa-status", "--profiled"],
                              capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                profiles = r.stdout.split("\n")
                pname = os.path.basename(binary_path)
                for prof in profiles:
                    if pname in prof:
                        audit["profile_exists"] = True
                        if "enforce" in prof:
                            audit["profile_enforced"] = True
        except Exception as e:
            audit["error"] = str(e)
        if not audit["profile_exists"]:
            audit["recommendations"].append("Create an AppArmor profile")
        return audit

    def audit_selinux(self, binary_path: str) -> Dict[str, Any]:
        audit: Dict[str, Any] = {"binary_path": binary_path, "current_context": "",
                                 "expected_context": "", "compliant": False,
                                 "violations": [], "recommendations": []}
        try:
            r = subprocess.run(["ls", "-Z", binary_path],
                              capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                parts = r.stdout.strip().split()
                if parts:
                    audit["current_context"] = parts[0]
                expected = self.policies["selinux"].get("required_context", "bin_t")
                audit["expected_context"] = expected
                audit["compliant"] = expected in audit["current_context"]
        except Exception as e:
            audit["error"] = str(e)
        if not audit["compliant"]:
            audit["recommendations"].append(f"Set SELinux context to {audit['expected_context']}")
        return audit

    def generate_apparmor_profile(
        self, binary_name: str, capabilities: Optional[List[str]] = None,
    ) -> str:
        caps_list = capabilities or ["dac_override"]
        caps_block = "\n".join(f"    capability {c}," for c in caps_list)
        return (
            f"# AppArmor profile for {binary_name}\n\n"
            "#include <tunables/global>\n"
            f"/{binary_name} {{\n"
            "    #include <abstractions/base>\n\n"
            f"    /{binary_name} mr,\n"
            f"{caps_block}\n"
            "    network inet stream,\n"
            "    /etc/** r,\n"
            "    /var/log/** w,\n"
            "    /tmp/** rw,\n"
            "}}\n"
        )

    def generate_selinux_policy(self, binary_name: str) -> str:
        return (
            f"# SELinux policy for {binary_name}\n\n"
            f"type {binary_name}_t;\n"
            f"type {binary_name}_exec_t;\n"
            "require {\n"
            "    type bin_t;\n"
            "    type execmem_exec_t;\n"
            "    class file { getattr open read execute };\n"
            "}\n\n"
            "# Type transition\n"
            f"type_transition bin_t {binary_name}_exec_t : process {binary_name}_t;\n\n"
            "# Allow execute\n"
            f"allow {binary_name}_t execmem_exec_t : file {{ getattr open read execute }};\n"
        )

    def run_full_audit(self, binary_path: str) -> Dict[str, Any]:
        aa = self.audit_apparmor(binary_path)
        se = self.audit_selinux(binary_path)
        return {
            "binary_path": binary_path, "apparmor": aa, "selinux": se,
            "overall_compliant": aa["profile_enforced"] and se["compliant"],
            "recommendations": aa.get("recommendations", []) + se.get("recommendations", []),
        }


class CrossProjectVulnerabilityCorrelationAnalyzer:
    """利用漏洞图谱检测跨项目关联。"""

    def __init__(self):
        self.vuln_graph: Dict[str, Dict[str, Any]] = {}
        self.lib_map: Dict[str, List[str]] = {}
        self.impact_warnings: List[Dict[str, Any]] = []

    def build_graph(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        graph: Dict[str, Any] = {"nodes": [], "edges": []}
        for v in vulns:
            graph["nodes"].append({"id": v["id"], "type": "vulnerability",
                                  "project": v["project"], "library": v["library"],
                                  "severity": v["severity"]})
            lib = v.get("library", "unknown")
            self.lib_map.setdefault(lib, []).append(v["id"])
        for lib, ids in self.lib_map.items():
            for i, v1 in enumerate(ids):
                for v2 in ids[i + 1:]:
                    graph["edges"].append({"source": v1, "target": v2,
                                          "type": "same_library", "library": lib})
        self.vuln_graph = graph
        return graph

    def find_correlations(self, vuln_id: str) -> List[Dict[str, Any]]:
        corr: List[Dict[str, Any]] = []
        for edge in self.vuln_graph.get("edges", []):
            if edge["source"] == vuln_id or edge["target"] == vuln_id:
                related = edge["target"] if edge["source"] == vuln_id else edge["source"]
                for node in self.vuln_graph.get("nodes", []):
                    if node["id"] == related:
                        corr.append({"vulnerability_id": related,
                                    "project": node["project"],
                                    "library": edge["library"],
                                    "correlation_type": edge["type"]})
        return corr

    def generate_warning(self, library: str) -> Dict[str, Any]:
        ids = self.lib_map.get(library, [])
        projects: List[str] = []
        for vid in ids:
            for node in self.vuln_graph.get("nodes", []):
                if node["id"] == vid:
                    projects.append(node["project"])
        warning = {
            "library": library, "affected_vulnerabilities": ids,
            "affected_projects": projects, "severity": "high",
            "recommendation": f"Review all {len(projects)} projects using {library} - shared-library vulnerability",
        }
        self.impact_warnings.append(warning)
        return warning

    def analyze_cross_project(self) -> Dict[str, Any]:
        high_impact: List[Dict[str, Any]] = []
        for lib, ids in self.lib_map.items():
            if len(ids) > 3:
                high_impact.append({"library": lib, "vulnerability_count": len(ids)})
        high_impact.sort(key=lambda x: x["vulnerability_count"], reverse=True)
        return {"total_vulnerabilities": len(self.vuln_graph.get("nodes", [])),
                "total_correlations": len(self.vuln_graph.get("edges", [])),
                "high_impact_libraries": high_impact}

    def generate_correlation_report(self) -> str:
        lines = ["# Cross-Project Vulnerability Correlation", "", "## High-Impact Libraries"]
        for lib_info in self.analyze_cross_project()["high_impact_libraries"]:
            lines.append(f"- {lib_info['library']}: {lib_info['vulnerability_count']} vulns")
        lines.append("")
        lines.append("## Impact Warnings")
        for w in self.impact_warnings:
            lines.append(f"- {w['library']}: {len(w['affected_projects'])} projects affected")
        lines.append("")
        return "\n".join(lines)


class GitDiffAnalysisTrigger:
    """监控Git仓库二进制变更，触发差分分析。"""

    _BINARY_EXTS = {".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".ko", ".o", ".a"}
    _ELF_MAGIC = b"\x7fELF"
    _PE_MAGIC = b"MZ"

    def __init__(self, repo_path: str = "", analysis_callback: Optional[Callable] = None):
        self.repo_path = repo_path
        self.analysis_callback = analysis_callback
        self.last_commit_hash: str = ""
        self.watched_files: Set[str] = set()
        self.analysis_history: Dict[str, Dict[str, Any]] = {}
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_monitor = threading.Event()

    def set_repo_path(self, path: str) -> None:
        self.repo_path = path

    def add_watched_file(self, pattern: str) -> None:
        self.watched_files.add(pattern)

    def get_current_commit(self) -> str:
        try:
            r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.repo_path,
                              capture_output=True, text=True, timeout=30)
            return r.stdout.strip() if r.returncode == 0 else ""
        except Exception as e:
            logger.warning(f"git rev-parse failed: {e}")
            return ""

    def get_changed_files(self, old_hash: str, new_hash: str) -> List[str]:
        try:
            r = subprocess.run(["git", "diff", "--name-only", old_hash, new_hash],
                              cwd=self.repo_path, capture_output=True, text=True, timeout=60)
            return [f for f in r.stdout.strip().split("\n") if f] if r.returncode == 0 else []
        except Exception as e:
            logger.warning(f"git diff failed: {e}")
            return []

    def detect_binary_changes(self, changed_files: List[str]) -> List[str]:
        binaries: List[str] = []
        for f in changed_files:
            if not f:
                continue
            ext = os.path.splitext(f)[1].lower()
            full = os.path.join(self.repo_path, f)
            if ext in self._BINARY_EXTS:
                binaries.append(f)
            elif not ext and os.path.isfile(full):
                try:
                    with open(full, "rb") as fh:
                        magic = fh.read(4)
                    if magic[:4] == self._ELF_MAGIC:
                        binaries.append(f)
                    elif magic[:2] == self._PE_MAGIC:
                        binaries.append(f)
                except Exception:
                    _logger.debug("suppressed", exc_info=True)
        return binaries

    def trigger_analysis(
        self, binary_path: str, old_version: str, new_version: str,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {"binary_path": binary_path, "old_version": old_version,
                                 "new_version": new_version,
                                 "timestamp": datetime.now().isoformat(),
                                 "diff_analysis": {}, "regression_scan": {}}
        if self.analysis_callback:
            try:
                out = self.analysis_callback(binary_path, old_version, new_version)
                result["diff_analysis"] = out
            except Exception as e:
                result["error"] = str(e)
        aid = hashlib.sha256(f"{binary_path}:{old_version}:{new_version}".encode()).hexdigest()[:16]
        self.analysis_history[aid] = result
        return result

    def start_monitoring(self, interval: int = 60) -> None:
        self.last_commit_hash = self.get_current_commit()
        self._stop_monitor.clear()

        def loop() -> None:
            while not self._stop_monitor.is_set():
                cur = self.get_current_commit()
                if cur and cur != self.last_commit_hash:
                    logger.info(f"New commit detected: {cur}")
                    changed = self.get_changed_files(self.last_commit_hash, cur)
                    for bf in self.detect_binary_changes(changed):
                        logger.info(f"Triggering binary analysis: {bf}")
                        self.trigger_analysis(os.path.join(self.repo_path, bf),
                                             self.last_commit_hash, cur)
                    self.last_commit_hash = cur
                time.sleep(interval)

        self._monitor_thread = threading.Thread(target=loop, daemon=True)
        self._monitor_thread.start()
        logger.info("Git monitoring started")

    def stop_monitoring(self) -> None:
        self._stop_monitor.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        logger.info("Git monitoring stopped")

    def get_analysis_history(self) -> Dict[str, Dict[str, Any]]:
        return dict(self.analysis_history)


class DynamicAnalysisEnvironmentManager:
    """集成Vagrant和Ansible，创建、快照、恢复、销毁分析环境。"""

    def __init__(self, work_dir: str = "data/analysis_envs"):
        self.work_dir = work_dir
        self.environments: Dict[str, Dict[str, Any]] = {}
        self.snapshots: Dict[str, List[Dict[str, Any]]] = {}
        os.makedirs(self.work_dir, exist_ok=True)

    def create_environment(
        self, env_name: str, os_type: str = "ubuntu",
        os_version: str = "20.04", config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        # 保持上下文连贯性，不拆分
        env_info: Dict[str, Any] = {"name": env_name, "os_type": os_type,
                                    "os_version": os_version, "status": "creating",
                                    "vagrantfile": "", "snapshot_list": [],
                                    "created_at": datetime.now().isoformat()}
        env_dir = os.path.join(self.work_dir, env_name)
        os.makedirs(env_dir, exist_ok=True)
        vf_content = self._generate_vagrantfile(os_type, os_version, config)
        vf_path = os.path.join(env_dir, "Vagrantfile")
        with open(vf_path, "w") as f:
            f.write(vf_content)
        env_info["vagrantfile"] = vf_path
        try:
            r = subprocess.run(["vagrant", "up"], cwd=env_dir,
                              capture_output=True, text=True, timeout=300)
            env_info["status"] = "running" if r.returncode == 0 else "error"
            if r.returncode != 0:
                env_info["error"] = r.stderr
        except Exception as e:
            env_info["status"] = "error"
            env_info["error"] = str(e)
        self.environments[env_name] = env_info
        return env_info

    @staticmethod
    def _generate_vagrantfile(
        os_type: str, os_version: str, config: Optional[Dict[str, Any]] = None,
    ) -> str:
        boxes = {"ubuntu": f"ubuntu/{os_version}", "debian": f"debian/{os_version}",
                "centos": f"centos/{os_version}", "windows": "win10"}
        box = boxes.get(os_type, f"ubuntu/{os_version}")
        return (
            f'Vagrant.configure("2") do |config|\n'
            f'  config.vm.box = "{box}"\n'
            f'  config.vm.hostname = "analysis-{os_type}-{os_version}"\n'
            f'  config.vm.provider "virtualbox" do |vb|\n'
            f'    vb.memory = 2048\n    vb.cpus = 2\n  end\n'
            f'  config.vm.provision "shell", inline: <<-SHELL\n'
            f'    apt-get update\n    apt-get install -y gdb strace ltrace radare2\n'
            f'  SHELL\nend\n'
        )

    def create_snapshot(self, env_name: str, snapshot_name: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {"name": snapshot_name, "env_name": env_name,
                                "created_at": datetime.now().isoformat(), "status": "creating"}
        env_dir = os.path.join(self.work_dir, env_name)
        try:
            r = subprocess.run(["vagrant", "snapshot", "save", snapshot_name],
                              cwd=env_dir, capture_output=True, text=True, timeout=60)
            info["status"] = "created" if r.returncode == 0 else "error"
            if r.returncode == 0:
                self.snapshots.setdefault(env_name, []).append(info)
            else:
                info["error"] = r.stderr
        except Exception as e:
            info["status"] = "error"; info["error"] = str(e)
        return info

    def restore_snapshot(self, env_name: str, snapshot_name: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {"env_name": env_name, "snapshot_name": snapshot_name,
                                "status": "restoring", "timestamp": datetime.now().isoformat()}
        env_dir = os.path.join(self.work_dir, env_name)
        try:
            r = subprocess.run(["vagrant", "snapshot", "restore", snapshot_name],
                              cwd=env_dir, capture_output=True, text=True, timeout=120)
            info["status"] = "restored" if r.returncode == 0 else "error"
            if r.returncode != 0:
                info["error"] = r.stderr
        except Exception as e:
            info["status"] = "error"; info["error"] = str(e)
        return info

    def destroy_environment(self, env_name: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {"env_name": env_name, "status": "destroying",
                                "timestamp": datetime.now().isoformat()}
        env_dir = os.path.join(self.work_dir, env_name)
        try:
            r = subprocess.run(["vagrant", "destroy", "-f"],
                              cwd=env_dir, capture_output=True, text=True, timeout=60)
            if r.returncode == 0:
                info["status"] = "destroyed"
                self.environments.pop(env_name, None)
            else:
                info["status"] = "error"
        except Exception as e:
            info["status"] = "error"; info["error"] = str(e)
        return info

    def list_environments(self) -> List[Dict[str, Any]]:
        return list(self.environments.values())

    def list_snapshots(self, env_name: str) -> List[Dict[str, Any]]:
        return self.snapshots.get(env_name, [])


