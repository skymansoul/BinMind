"""Kubernetes 清单安全扫描器。RBAC + pod security + NetworkPolicy。

同时提供集群二进制风险的数据模型（ContainerInfo/BinaryRisk/ClusterScanResult）
与报告、保存、风险汇总接口，供上层审计流程消费。
"""

import json
import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import yaml

_log = logging.getLogger(__name__)


class ScanScope(Enum):
    """扫描范围。"""
    ALL = 'all'
    SPECIFIC = 'specific'
    LABEL = 'label'
    IMAGE = 'image'


class RiskLevel(Enum):
    """风险等级。"""
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'


@dataclass
class ContainerInfo:
    """容器信息。"""
    name: str
    image: str
    namespace: str = ''
    pod_name: str = ''
    container_id: str = ''
    status: str = ''
    ports: List[int] = field(default_factory=list)
    env_vars: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'image': self.image,
            'namespace': self.namespace,
            'pod_name': self.pod_name,
            'container_id': self.container_id,
            'status': self.status,
            'ports': list(self.ports),
            'env_vars': dict(self.env_vars),
        }


@dataclass
class BinaryRisk:
    """单二进制风险。"""
    binary_name: str
    binary_path: str
    risk_level: RiskLevel
    vulnerability_type: str
    description: str
    cve_id: Optional[str] = None
    remediation: str = ''
    container_name: str = ''
    pod_name: str = ''
    namespace: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'binary_name': self.binary_name,
            'binary_path': self.binary_path,
            'risk_level': self.risk_level.value,
            'vulnerability_type': self.vulnerability_type,
            'description': self.description,
            'cve_id': self.cve_id,
            'remediation': self.remediation,
            'container_name': self.container_name,
            'pod_name': self.pod_name,
            'namespace': self.namespace,
        }


@dataclass
class ClusterScanResult:
    """集群扫描结果。"""
    cluster_name: str
    scan_scope: ScanScope
    namespaces: List[str] = field(default_factory=list)
    containers: List[ContainerInfo] = field(default_factory=list)
    binary_risks: List[BinaryRisk] = field(default_factory=list)
    risk_summary: Dict[str, int] = field(default_factory=dict)
    scan_duration: float = 0.0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'cluster_name': self.cluster_name,
            'scan_scope': self.scan_scope.value,
            'namespaces': list(self.namespaces),
            'containers': [c.to_dict() for c in self.containers],
            'binary_risks': [r.to_dict() for r in self.binary_risks],
            'risk_summary': dict(self.risk_summary),
            'scan_duration': self.scan_duration,
            'errors': list(self.errors),
        }

# capability 黑名单
# 任一在受侵Pod中即大幅扩大攻击面——"容器逃逸入门包"
_DANGEROUS_CAPS = frozenset({
    "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE",
    "SYS_RAWIO", "DAC_OVERRIDE", "DAC_READ_SEARCH",
    "LINUX_IMMUTABLE", "NET_RAW", "IPC_LOCK", "BPF",
    "SYS_BOOT", "SYS_TIME", "PERFMON",
})

# RBAC 危险组合
# 每元组为 (verbs, resources, apiGroups) —— 三项均匹配即
# 构成提权路径，即使无字面"cluster-admin" ClusterRole名
_RBAC_ESCALATION_PATHS = [
    ({"*"}, {"*"}, {"*"}),
    ({"create", "update", "patch", "delete", "deletecollection"}, {"*"}, {"*"}),
    ({"*"}, {"secrets", "serviceaccounts"}, {"*"}),
    ({"escalate", "bind"}, {"roles", "clusterroles"}, {"rbac.authorization.k8s.io"}),
    ({"create"}, {"pods", "deployments", "daemonsets"}, {"*"}),
    # webhook控制 = MITM API server
    ({"create"}, {"validatingwebhookconfigurations", "mutatingwebhookconfigurations"},
     {"admissionregistration.k8s.io"}),
]


class Finding:
    def __init__(self, severity: str, title: str, resource: str, detail: str = ""):
        self.severity = severity  # LOW MEDIUM HIGH CRITICAL
        self.title = title
        self.resource = resource
        self.detail = detail

    def __repr__(self):
        return f"Finding({self.severity!r}, {self.title!r}, {self.resource!r})"


class ContainerImage:
    def __init__(self, name: str = "", tag: str = "latest", pull_policy: str = "IfNotPresent"):
        self.name = name
        self.tag = tag
        self.pull_policy = pull_policy


class K8sClusterScanner:
    """K8s YAML manifest 扫描 —— pod安全 + RBAC + NetworkPolicy缺口。

    设计说明: 扫描器对文档列表执行两遍遍历。第一遍收集全局上下文
    (NetworkPolicy覆盖、现有RBAC绑定)。第二遍执行逐资源扫描。
    比单遍多一次迭代但避免了复杂的跨文档依赖追踪。
    """

    def __init__(self, strict: bool = False, output_dir=None, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self._strict = strict
        self._findings: List[Finding] = []
        self.output_dir = output_dir
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

    def scan(self, cluster_spec: Any) -> List[Finding]:
        """接受文件路径(str)、预解析dict或dict列表"""
        self._findings = []

        if isinstance(cluster_spec, str):
            with open(cluster_spec, "r", encoding="utf-8") as fh:
                docs = list(yaml.safe_load_all(fh))
        elif isinstance(cluster_spec, dict):
            docs = [cluster_spec]
        elif isinstance(cluster_spec, list):
            docs = cluster_spec
        else:
            raise TypeError(f"Expected str/dict/list, got {type(cluster_spec)}")

        # 第1遍: 收集网络策略
        policies_found: list[str] = []
        for doc in docs:
            if doc is None:
                continue
            kind = (doc.get("kind") or "").lower()
            if kind == "networkpolicy":
                ns = doc.get("metadata", {}).get("namespace", "default")
                policies_found.append(ns)

        # 第2遍: 逐资源扫描
        for doc in docs:
            if doc is None:
                continue
            self._scan_document(doc)
            self._scan_rbac(doc)

        # 汇总: 无NetworkPolicy的命名空间
        scanned_namespaces: set[str] = set()
        for doc in docs:
            if doc is None:
                continue
            scanned_namespaces.add(
                doc.get("metadata", {}).get("namespace", "default")
            )

        for ns_name in scanned_namespaces:
            if ns_name not in policies_found and ns_name != "kube-system":
                self._add(
                    "MEDIUM",
                    "Namespace has no NetworkPolicy",
                    ns_name,
                    "All pod-to-pod traffic is allowed by default. "
                    "Deploy a default-deny ingress NetworkPolicy.",
                )

        return self._findings

# 文档分发

    def _scan_document(self, doc: Dict[str, Any]) -> None:
        kind = (doc.get("kind") or "").lower()
        meta = doc.get("metadata", {})
        res_name = meta.get("name", "unknown")

        if kind == "pod":
            self._scan_pod(doc, res_name)
        elif kind == "deployment":
            tmpl = doc.get("spec", {}).get("template", {})
            self._scan_pod(tmpl, res_name)
        elif kind == "daemonset":
            tmpl = doc.get("spec", {}).get("template", {})
            self._scan_pod(tmpl, res_name)
        elif kind == "statefulset":
            tmpl = doc.get("spec", {}).get("template", {})
            self._scan_pod(tmpl, res_name)
        elif kind in ("cronjob", "job"):
            job_spec = doc.get("spec", {}).get("jobTemplate", {}).get("spec", {})
            tmpl = job_spec.get("template", {})
            self._scan_pod(tmpl, res_name)

    def _scan_rbac(self, doc: Dict[str, Any]) -> None:
        """RBAC分析: 检测权限提升路径。

        逻辑: 对Role/ClusterRole中的每条规则，检查(verbs, resources, apiGroups)
        是否匹配任一已知危险组合。同时标记绑定到ServiceAccount的cluster-admin
        （经典"逃逸Pod"模式）。
        """
        kind = (doc.get("kind") or "").lower()
        meta = doc.get("metadata", {})
        res_name = meta.get("name", "unknown")

        if kind in ("clusterrole", "role"):
            rules = doc.get("rules", []) or []
            for rule in rules:
                verbs = set(rule.get("verbs", []))
                resources = set(rule.get("resources", []))
                api_groups = set(rule.get("apiGroups", []))

                for dverbs, dres, dapi in _RBAC_ESCALATION_PATHS:
                    v_ok = "*" in verbs or dverbs.issubset(verbs)
                    r_ok = "*" in resources or dres.issubset(resources)
                    a_ok = "*" in api_groups or dapi.issubset(api_groups)
                    if v_ok and r_ok and a_ok:
                        sev = "CRITICAL" if "*" in verbs else "HIGH"
                        self._add(
                            sev,
                            f"RBAC role '{res_name}' grants excessive permissions",
                            f"{kind}/{res_name}",
                            f"verbs={sorted(verbs)[:4]}, "
                            f"resources={sorted(resources)[:4]}, "
                            f"apiGroups={sorted(api_groups)[:4]}",
                        )
                        break  # 一个匹配即足够，避免重复

        if kind in ("clusterrolebinding", "rolebinding"):
            subjects = doc.get("subjects", []) or []
            role_ref = doc.get("roleRef", {}) or {}
            if role_ref.get("name") == "cluster-admin":
                sa_subs = [s for s in subjects if s.get("kind") == "ServiceAccount"]
                if sa_subs:
                    names = [s.get("name", "?") for s in sa_subs]
                    self._add(
                        "CRITICAL",
                        "cluster-admin bound to ServiceAccount",
                        f"binding/{res_name}",
                        f"SAs: {names} — grants full cluster control",
                    )

# pod 与容器扫描

    def _scan_pod(self, pod_spec: Dict[str, Any], owner: str) -> None:
        pod = pod_spec.get("spec", pod_spec)

        # host namespace 共享
        for flag in ("hostNetwork", "hostPID", "hostIPC"):
            if pod.get(flag):
                self._add("HIGH", f"Pod shares {flag} with host", owner)

        # hostPath 卷
        for vol in pod.get("volumes", []) or []:
            hp = vol.get("hostPath", {})
            if hp:
                self._add(
                    "MEDIUM",
                    "hostPath volume mounted",
                    owner,
                    f"volume={vol.get('name')} path={hp.get('path')}",
                )

        # 自动挂载 service account token
        sa_name = pod.get("serviceAccountName", "")
        auto_mount = pod.get("automountServiceAccountToken")
        if auto_mount is not False and sa_name:
            self._add(
                "MEDIUM",
                "ServiceAccount token auto-mounted",
                owner,
                f"SA={sa_name} — set automountServiceAccountToken: false",
            )

        # 扫描每个容器
        for c in pod.get("containers", []) or []:
            self._scan_container(c, owner)

    def _scan_container(self, c: Dict[str, Any], owner: str) -> None:
        cname = c.get("name", "unnamed")
        label = f"{owner}/{cname}"
        sec = c.get("securityContext", {}) or {}

        # 特权模式 —— near-root access
        if sec.get("privileged"):
            self._add("CRITICAL", "Privileged container", label)

        # allowPrivilegeEscalation: 未显式 false = 默认 true
        if sec.get("allowPrivilegeEscalation") is not False:
            self._add(
                "HIGH",
                "allowPrivilegeEscalation not explicitly false",
                label,
            )

        # 以 root 运行
        if sec.get("runAsNonRoot") is not True:
            self._add("MEDIUM", "Container may run as root", label)

        # 可写根文件系统
        if sec.get("readOnlyRootFilesystem") is not True:
            self._add("LOW", "Root filesystem is writable", label)

        # capabilities
        caps = sec.get("capabilities", {}) or {}
        for cap in caps.get("add", []) or []:
            if cap in _DANGEROUS_CAPS:
                self._add("HIGH", f"Dangerous capability added: {cap}", label)

        # image pull policy
        image_str = c.get("image", "")
        policy = c.get("imagePullPolicy", "")
        if not policy:
            self._add(
                "LOW",
                "imagePullPolicy not explicitly set",
                label,
                f"image={image_str}",
            )
        # latest 标签未使用 Always pull = 不可复现的构建风险
        if image_str.endswith(":latest") and policy != "Always":
            self._add(
                "LOW",
                "Latest tag without Always pull policy",
                label,
                f"image={image_str}",
            )

        # 资源限制
        limits = c.get("resources", {}).get("limits", {}) or {}
        requests = c.get("resources", {}).get("requests", {}) or {}
        if not limits or not requests:
            self._add(
                "MEDIUM",
                "Missing resource limits or requests",
                label,
                "Unbounded containers can starve other workloads",
            )

    def _add(self, severity: str, title: str, resource: str, detail: str = "") -> None:
        self._findings.append(Finding(severity, title, resource, detail))

    def _calculate_risk_summary(self, risks: List[BinaryRisk]) -> Dict[str, int]:
        """按风险等级统计二进制风险数量。"""
        summary = {'high': 0, 'medium': 0, 'low': 0, 'critical': 0}
        for r in risks:
            key = r.risk_level.value
            summary[key] = summary.get(key, 0) + 1
        return summary

    def generate_report(self, result: ClusterScanResult) -> str:
        """生成人类可读的扫描报告。"""
        lines = [
            f"Kubernetes Cluster Scan Report",
            f"================================",
            f"Cluster: {result.cluster_name}",
            f"Scope: {result.scan_scope.value}",
            f"Namespaces: {', '.join(result.namespaces)}",
            f"Scan Duration: {result.scan_duration:.1f}s",
            f"",
            f"Binary Risks:",
        ]
        if not result.binary_risks:
            lines.append("  (none)")
        for risk in result.binary_risks:
            lines.append(f"  [{risk.risk_level.value.upper()}] {risk.binary_name}")
            lines.append(f"      path: {risk.binary_path}")
            lines.append(f"      type: {risk.vulnerability_type}")
            lines.append(f"      description: {risk.description}")
            if risk.cve_id:
                lines.append(f"      cve: {risk.cve_id}")
            if risk.remediation:
                lines.append(f"      remediation: {risk.remediation}")
            lines.append(f"      container: {risk.container_name} ({risk.namespace}/{risk.pod_name})")
        return "\n".join(lines)

    def save_result(self, result: ClusterScanResult, name: str) -> str:
        """将扫描结果写入 JSON 文件，返回文件路径。"""
        out_dir = self.output_dir if getattr(self, 'output_dir', None) else '.'
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, f"{name}.json")
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(result.to_dict(), fh, ensure_ascii=False, indent=2)
        return path

    # 遗留别名 —— 旧代码调用 scan_cluster()
    scan_cluster = scan
