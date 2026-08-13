import logging
from typing import Dict, List, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

class PolicyType:
    NETWORK = "network"
    POD_SECURITY = "pod_security"
    RBAC = "rbac"
    IMAGE = "image"
    SECRET = "secret"
    IMAGE = PolicyType("image")
# PolicyRule data container -- __slots__ governs field layout
class PolicyRule:
    __slots__ = ('name', 'type', 'condition', 'action', 'description',)

    def __init__(self, name, type, condition, action, description):
        self.name = name
        self.type = type
        self.condition = condition
        self.action = action
        self.description = description

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'type': self.type.value,
            'condition': self.condition,
            'action': self.action,
            'description': self.description
        }

# OPAPolicy data container -- __slots__ governs field layout
class OPAPolicy:
    __slots__ = ('package_name', 'rules', 'imports', 'annotations',)

    def __init__(self, package_name, rules, imports, annotations):
        self.package_name = package_name
        self.rules = rules
        self.imports = imports
        self.annotations = annotations

    def to_dict(self) -> Dict[str, Any]:
        return {
            'package_name': self.package_name,
            'rules': [r.to_dict() for r in self.rules],
            'imports': self.imports,
            'annotations': self.annotations
        }

    def generate_rego(self) -> str:
        lines = []

        lines.append(f"package {self.package_name}")
        lines.append("")

        for imp in self.imports:
            lines.append(f"import data.{imp}")

        lines.append("")

        for rule in self.rules:
            lines.append(f"# {rule.description}")
            lines.append(f"{rule.name} {{")
            lines.append(f"  {rule.condition}")
            lines.append(f"}}")
            lines.append("")

        return '\n'.join(lines)

class OPAPolicyGenerator:

    def __init__(self):
        self.default_imports = ["kubernetes", "policy"]

    def generate_pod_security_policy(self, vulnerabilities: List[Dict[str, Any]]) -> OPAPolicy:
        rules = []

        for vuln in vulnerabilities:
            if vuln.get('severity') == 'critical':
                rule = PolicyRule(
                    name=f"deny_critical_vuln_{vuln.get('id', 'unknown')}",
                    type=PolicyType.POD_SECURITY,
                    condition=f"input.object.spec.containers[_].image == \"{vuln.get('image', '')}\"",
                    action="deny",
                    description=f"Deny pods using image with critical vulnerability: {vuln.get('id')}"

                )
                rules.append(rule)

        return OPAPolicy(
            package_name="k8s.pod_security",
            rules=rules,
            imports=self.default_imports,
            annotations={
                'title': 'Pod Security Policy',
                'description': 'Block pods with vulnerable images'
            })

    def generate_network_policy(self, high_risk_ips: List[str]) -> OPAPolicy:
        rules = []

        for ip in high_risk_ips:
            rule = PolicyRule(
                name=f"deny_high_risk_ip_{ip.replace('.', '_')}",
                type=PolicyType.NETWORK,
                condition=f"input.request.object.spec.rules[_].to[_].ipBlock.cidr == \"{ip}/32\"",
                action="deny",
                description=f"Deny network policy allowing traffic to high-risk IP: {ip}"

            )
            rules.append(rule)

        return OPAPolicy(
            package_name="k8s.network",
            rules=rules,
            imports=self.default_imports,
            annotations={
                'title': 'Network Policy',
                'description': 'Block connections to high-risk IPs'
            })

    def generate_image_policy(self, vulnerable_images: List[str]) -> OPAPolicy:
        rules = []

        for image in vulnerable_images:
            rule = PolicyRule(
                name=f"deny_vulnerable_image_{image.replace('/', '_').replace(':', '_')}",
                type=PolicyType.IMAGE,
                condition=f"input.request.object.spec.containers[_].image == \"{image}\"",
                action="deny",
                description=f"Deny vulnerable image: {image}"

            )
            rules.append(rule)

        return OPAPolicy(
            package_name="k8s.image",
            rules=rules,
            imports=self.default_imports,
            annotations={
                'title': 'Image Policy',
                'description': 'Block vulnerable container images'
            })

    def generate_rbac_policy(self, risky_permissions: List[str]) -> OPAPolicy:
        rules = []

        for permission in risky_permissions:
            rule = PolicyRule(
                name=f"deny_risky_permission_{permission.replace('-', '_')}",
                type=PolicyType.RBAC,
                condition=f"input.request.object.rules[_].verbs[_] == \"{permission}\"",
                action="deny",
                description=f"Deny risky permission: {permission}"

            )
            rules.append(rule)

        return OPAPolicy(
            package_name="k8s.rbac",
            rules=rules,
            imports=self.default_imports,
            annotations={
                'title': 'RBAC Policy',
                'description': 'Block risky RBAC permissions'
            })

    def save_policy(self, policy: OPAPolicy, filepath: str) -> bool:
        try:
            rego_code = policy.generate_rego()

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(rego_code)

            logger.info(f"OPA policy saved to: {filepath}")
            return True
        except Exception as e:
            logger.error(f"OPA policy save failed: {e}")
            return False

def generate_opa_policy(policy_type: str, data: List[Dict[str, Any]]) -> OPAPolicy:
    generator = OPAPolicyGenerator()

    policy_type_enum = PolicyType[policy_type.upper()]

    if policy_type_enum == PolicyType.POD_SECURITY:
        return generator.generate_pod_security_policy(data)
    elif policy_type_enum == PolicyType.NETWORK:
        return generator.generate_network_policy([d.get('ip', '') for d in data])
    elif policy_type_enum == PolicyType.IMAGE:
        return generator.generate_image_policy([d.get('image', '') for d in data])
    elif policy_type_enum == PolicyType.RBAC:
        return generator.generate_rbac_policy([d.get('permission', '') for d in data])

    return OPAPolicy(
        package_name="k8s.default",
        rules=[],
        imports=[],
        annotations={})
