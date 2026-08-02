"""Kubernetes 清单安全扫描器。RBAC + pod security + NetworkPolicy。"""

import logging
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional
import yaml

_log = logging.getLogger(__name__)

# compat refs for older code that imports these
RiskLevel = None
ScanScope = None
BinaryRisk = None
ClusterScanResult = None

# ---- capability blocklist ----
# these are the "container escape starter pack" — any one of them in
# a compromised pod dramatically expands the attack surface
_DANGEROUS_CAPS = frozenset({
    "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE",
    "SYS_RAWIO", "DAC_OVERRIDE", "DAC_READ_SEARCH",
    "LINUX_IMMUTABLE", "NET_RAW", "IPC_LOCK", "BPF",
    "SYS_BOOT", "SYS_TIME", "PERFMON",
})

# ---- RBAC dangerous combinatorics ----
# each tuple is (verbs, resources, apiGroups) — if all three match a
# rule, it's effectively a privilege escalation path, even without
# the literal "cluster-admin" ClusterRole name
_RBAC_ESCALATION_PATHS = [
    ({"*"}, {"*"}, {"*"}),
    ({"create", "update", "patch", "delete", "deletecollection"}, {"*"}, {"*"}),
    ({"*"}, {"secrets", "serviceaccounts"}, {"*"}),
    ({"escalate", "bind"}, {"roles", "clusterroles"}, {"rbac.authorization.k8s.io"}),
    ({"create"}, {"pods", "deployments", "daemonsets"}, {"*"}),
    # webhook control = MITM the API server
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


class ContainerInfo:
    def __init__(self, name: str = ""):
        self.name = name
        self.images: List[ContainerImage] = []
        self.privileged = False
        self.allow_priv_esc = False
        self.read_only_root = False
        self.run_as_non_root = False
        self.capabilities: List[str] = []
        self.resources: Dict[str, Dict[str, str]] = {}
        self.host_ports: List[int] = []


class K8sClusterScanner:
    """K8s YAML manifest scanner — pod security + RBAC + NetworkPolicy gaps.

    Design note: the scanner does two passes over the doc list. First pass
    collects global context (NetworkPolicy coverage, existing RBAC bindings).
    Second pass does per-resource scanning. This is slightly slower (2x docs
    iteration) but avoids complex inter-document dependency tracking that
    would require a full-blown resource graph.
    """

    def __init__(self, strict: bool = False):
        self._strict = strict
        self._findings: List[Finding] = []

    def scan(self, cluster_spec: Any) -> List[Finding]:
        """accept file path (str), pre-parsed dict, or list of dicts"""
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

        # pass 1: collect network policies
        policies_found: list[str] = []
        for doc in docs:
            if doc is None:
                continue
            kind = (doc.get("kind") or "").lower()
            if kind == "networkpolicy":
                ns = doc.get("metadata", {}).get("namespace", "default")
                policies_found.append(ns)

        # pass 2: per-resource scanning
        for doc in docs:
            if doc is None:
                continue
            self._scan_document(doc)
            self._scan_rbac(doc)

        # aggregate: namespaces without NetworkPolicy
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

    # -- document dispatch --

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
        """RBAC analysis: detect privilege escalation paths.

        The logic: for each rule in a Role/ClusterRole, check whether
        (verbs, resources, apiGroups) matches any of the known-dangerous
        combinatorics. Also flags cluster-admin bound to ServiceAccount
        (the classic "escape pod" pattern).
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
                        break  # one match is enough, don't spam

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

    # -- pod & container scanning --

    def _scan_pod(self, pod_spec: Dict[str, Any], owner: str) -> None:
        pod = pod_spec.get("spec", pod_spec)

        # host namespace sharing
        for flag in ("hostNetwork", "hostPID", "hostIPC"):
            if pod.get(flag):
                self._add("HIGH", f"Pod shares {flag} with host", owner)

        # hostPath volumes
        for vol in pod.get("volumes", []) or []:
            hp = vol.get("hostPath", {})
            if hp:
                self._add(
                    "MEDIUM",
                    "hostPath volume mounted",
                    owner,
                    f"volume={vol.get('name')} path={hp.get('path')}",
                )

        # auto-mount service account token
        sa_name = pod.get("serviceAccountName", "")
        auto_mount = pod.get("automountServiceAccountToken")
        if auto_mount is not False and sa_name:
            self._add(
                "MEDIUM",
                "ServiceAccount token auto-mounted",
                owner,
                f"SA={sa_name} — set automountServiceAccountToken: false",
            )

        # scan each container
        for c in pod.get("containers", []) or []:
            self._scan_container(c, owner)

    def _scan_container(self, c: Dict[str, Any], owner: str) -> None:
        cname = c.get("name", "unnamed")
        label = f"{owner}/{cname}"
        sec = c.get("securityContext", {}) or {}

        # privileged mode — near-root access
        if sec.get("privileged"):
            self._add("CRITICAL", "Privileged container", label)

        # allowPrivilegeEscalation: not explicitly false = default true
        if sec.get("allowPrivilegeEscalation") is not False:
            self._add(
                "HIGH",
                "allowPrivilegeEscalation not explicitly false",
                label,
            )

        # running as root
        if sec.get("runAsNonRoot") is not True:
            self._add("MEDIUM", "Container may run as root", label)

        # writable root filesystem
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
        # latest tag without Always pull = non-reproducible build risk
        if image_str.endswith(":latest") and policy != "Always":
            self._add(
                "LOW",
                "Latest tag without Always pull policy",
                label,
                f"image={image_str}",
            )

        # resource limits
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

    # legacy alias — old code calls scan_cluster()
    scan_cluster = scan
