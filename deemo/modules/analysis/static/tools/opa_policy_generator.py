import logging, json
from typing import Dict, List, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

class PolicyType:
    NETWORK = "network"; POD_SECURITY = "pod_security"; RBAC = "rbac"
    IMAGE = "image"; SECRET = "secret"; RUNTIME = "runtime"

class PolicyRule:
    __slots__ = ('name', 'type', 'condition', 'action', 'description',)
    def __init__(self, name, policy_type, condition, action, description):
        self.name = name; self.type = policy_type; self.condition = condition
        self.action = action; self.description = description
    def to_dict(self) -> Dict[str, Any]:
        return {'name': self.name, 'type': self.type.value if hasattr(self.type, 'value') else str(self.type),
                'condition': self.condition, 'action': self.action, 'description': self.description}

class OPAPolicy:
    __slots__ = ('package_name', 'rules', 'imports', 'annotations',)
    def __init__(self, package_name, rules, imports, annotations):
        self.package_name = package_name; self.rules = rules
        self.imports = imports; self.annotations = annotations
    def to_dict(self) -> Dict[str, Any]:
        return {'package_name': self.package_name,
                'rules': [r.to_dict() for r in self.rules],
                'imports': self.imports, 'annotations': self.annotations}
    def generate_rego(self) -> str:
        lines = [f"package {self.package_name}", ""]
        for imp in self.imports: lines.append(f"import data.{imp}")
        lines.append("")
        for rule in self.rules:
            lines.append(f"# {rule.description}")
            lines.append(f"{rule.name} {{"); lines.append(f"  {rule.condition}")
            lines.append("}}"); lines.append("")
        return '\n'.join(lines)


class OPAPolicyGenerator:
    def __init__(self):
        self.default_imports = ["kubernetes", "policy"]

    def generate_pod_security_policy(self, vulnerabilities: List[Dict[str, Any]]) -> OPAPolicy:
        rules = []
        for vuln in vulnerabilities:
            if vuln.get('severity') == 'critical':
                rules.append(PolicyRule(
                    name=f"deny_critical_vuln_{vuln.get('id', 'unknown')}",
                    policy_type=PolicyType.POD_SECURITY,
                    condition=f"input.object.spec.containers[_].image == \"{vuln.get('image', '')}\"",
                    action="deny",
                    description=f"Deny pods using image with critical vulnerability: {vuln.get('id')}"))
        return OPAPolicy(package_name="k8s.pod_security", rules=rules,
                         imports=self.default_imports,
                         annotations={'title': 'Pod Security Policy',
                                      'description': 'Block pods with vulnerable images'})

    def generate_network_policy(self, high_risk_ips: List[str]) -> OPAPolicy:
        rules = []
        for ip in high_risk_ips:
            rules.append(PolicyRule(
                name=f"deny_high_risk_ip_{ip.replace('.', '_')}",
                policy_type=PolicyType.NETWORK,
                condition=f"input.request.object.spec.rules[_].to[_].ipBlock.cidr == \"{ip}/32\"",
                action="deny",
                description=f"Deny traffic to high-risk IP: {ip}"))
        return OPAPolicy(package_name="k8s.network", rules=rules,
                         imports=self.default_imports,
                         annotations={'title': 'Network Policy', 'description': 'Block high-risk IPs'})

    def generate_image_policy(self, vulnerable_images: List[str]) -> OPAPolicy:
        rules = []
        for image in vulnerable_images:
            rules.append(PolicyRule(
                name=f"deny_vulnerable_image_{image.replace('/', '_').replace(':', '_')}",
                policy_type=PolicyType.IMAGE,
                condition=f"input.request.object.spec.containers[_].image == \"{image}\"",
                action="deny", description=f"Deny vulnerable image: {image}"))
        return OPAPolicy(package_name="k8s.image", rules=rules,
                         imports=self.default_imports,
                         annotations={'title': 'Image Policy', 'description': 'Block vulnerable images'})

    def generate_rbac_policy(self, risky_permissions: List[str]) -> OPAPolicy:
        rules = []
        for permission in risky_permissions:
            rules.append(PolicyRule(
                name=f"deny_risky_permission_{permission.replace('-', '_')}",
                policy_type=PolicyType.RBAC,
                condition=f"input.request.object.rules[_].verbs[_] == \"{permission}\"",
                action="deny", description=f"Deny risky permission: {permission}"))
        return OPAPolicy(package_name="k8s.rbac", rules=rules,
                         imports=self.default_imports,
                         annotations={'title': 'RBAC Policy', 'description': 'Block risky permissions'})

    def generate_secret_policy(self, exposed_secrets: List[Dict[str, Any]]) -> OPAPolicy:
        rules = []
        for secret in exposed_secrets:
            key = secret.get('key', 'unknown').replace('.', '_')
            rules.append(PolicyRule(
                name=f"deny_secret_ref_{key}", policy_type=PolicyType.SECRET,
                condition=f"input.request.object.spec.containers[_].env[_].valueFrom.secretKeyRef.name == \"{key}\"",
                action="deny",
                description=f"Prevent pod from referencing exposed secret: {secret.get('key', 'unknown')}"))
        return OPAPolicy(package_name="k8s.secret", rules=rules,
                         imports=self.default_imports,
                         annotations={'title': 'Secret Access Policy',
                                      'description': 'Block mounting exposed secrets'})

# 运行时安全策略
    # 基于二进制分析发现（如检测到的危险系统调用）生成运行时策略

    def generate_runtime_policy(self, dangerous_calls: List[str]) -> OPAPolicy:
        rules = []
        for call_name in dangerous_calls:
            safe_name = call_name.replace('/', '_').replace('.', '_')
            rules.append(PolicyRule(
                name=f"block_syscall_{safe_name}",
                policy_type=PolicyType.RUNTIME,
                condition=f"input.request.object.spec.containers[_].securityContext.seccompProfile.type == \"RuntimeDefault\"",
                action="audit",
                description=f"Flag containers not using RuntimeDefault seccomp: potential {call_name} call"))
        return OPAPolicy(package_name="k8s.runtime_security", rules=rules,
                         imports=self.default_imports,
                         annotations={'title': 'Runtime Security Policy',
                                      'description': 'Enforce seccomp for dangerous syscalls'})

    def save_policy(self, policy: OPAPolicy, filepath: str) -> bool:
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(policy.generate_rego())
            logger.info(f"OPA policy saved to: {filepath}"); return True
        except Exception as e:
            logger.error(f"OPA policy save failed: {e}"); return False

    def save_policy_bundle(self, policies: List[OPAPolicy], output_dir: str) -> bool:
        try:
            os = __import__('os')
            os.makedirs(output_dir, exist_ok=True)
            manifest = {"revision": "v1"}
            with open(os.path.join(output_dir, ".manifest"), 'w') as f:
                json.dump(manifest, f)
            for policy in policies:
                fname = policy.package_name.replace('.', '_') + ".rego"
                self.save_policy(policy, os.path.join(output_dir, fname))
            return True
        except Exception as e:
            logger.error(f"Bundle save failed: {e}"); return False


def generate_opa_policy(policy_type: str, data: List[Dict[str, Any]]) -> OPAPolicy:
    generator = OPAPolicyGenerator()
    pt = policy_type.upper()
    if pt == "POD_SECURITY": return generator.generate_pod_security_policy(data)
    elif pt == "NETWORK": return generator.generate_network_policy([d.get('ip', '') for d in data])
    elif pt == "IMAGE": return generator.generate_image_policy([d.get('image', '') for d in data])
    elif pt == "RBAC": return generator.generate_rbac_policy([d.get('permission', '') for d in data])
    elif pt == "SECRET": return generator.generate_secret_policy(data)
    elif pt == "RUNTIME": return generator.generate_runtime_policy([d.get('syscall', '') for d in data])
    return OPAPolicy(package_name="k8s.default", rules=[], imports=[], annotations={})
