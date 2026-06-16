"""
符号执行权限/能力模型违规检测模块

为Android Binder服务或seL4微内核建立capability模型，
符号探索是否存在低权限组件调用高权限接口的路径，发现权限提升。

Author: BinaryAnalysisPlatform
Version: 1.0.0
"""

import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple
from collections import defaultdict

from modules.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class CapabilityLevel(Enum):
    """权限级别枚举"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    SYSTEM = "system"


class IPCType(Enum):
    """IPC类型枚举"""
    BINDER = "binder"
    SEL4 = "sel4"
    RPC = "rpc"
    SIGNAL = "signal"


@dataclass
class Capability:
    """能力/权限定义"""
    name: str
    level: CapabilityLevel
    description: str = ""
    protected: bool = True


@dataclass
class Component:
    """组件定义"""
    name: str
    capabilities: Set[str] = field(default_factory=set)
    interfaces: List[str] = field(default_factory=list)
    permissions: Set[str] = field(default_factory=set)
    security_level: CapabilityLevel = CapabilityLevel.LOW


@dataclass
class IPCInterface:
    """IPC接口定义"""
    name: str
    provider: str
    required_capabilities: Set[str] = field(default_factory=set)
    exposed_capabilities: Set[str] = field(default_factory=set)
    ipc_type: IPCType = IPCType.BINDER


@dataclass
class PermissionViolation:
    """权限违规检测结果"""
    violation_type: str
    source_component: str
    target_interface: str
    missing_capabilities: Set[str]
    available_capabilities: Set[str]
    exploitability: float
    severity: str
    path: List[str] = field(default_factory=list)


@dataclass
class CapabilityGraph:
    """权限能力图"""
    nodes: Dict[str, Component] = field(default_factory=dict)
    edges: List[Tuple[str, str, Dict[str, Any]]] = field(default_factory=list)
    interfaces: Dict[str, IPCInterface] = field(default_factory=dict)
    capabilities: Dict[str, Capability] = field(default_factory=dict)


class CapabilityChecker(BaseAnalyzer):
    """
    符号执行权限/能力模型违规检测分析器
    
    核心功能：
    1. 构建Android Binder服务或seL4微内核的capability模型
    2. 符号探索调用路径
    3. 检测低权限组件调用高权限接口的路径
    4. 发现权限提升漏洞
    """
    
    def __init__(self):
        self.graph = CapabilityGraph()
        self.violations: List[PermissionViolation] = []
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行能力模型违规检测
        
        Args:
            **kwargs: 分析参数
                - binary_path: str - 目标二进制路径
                - ipc_type: str - IPC类型 'binder', 'sel4', 'rpc'
                - components: List[Dict] - 组件定义列表
                - interfaces: List[Dict] - 接口定义列表
                - capabilities: List[Dict] - 能力定义列表
        
        Returns:
            分析结果字典
        """
        binary_path = kwargs.get('binary_path', '')
        ipc_type = kwargs.get('ipc_type', 'binder')
        components = kwargs.get('components', [])
        interfaces = kwargs.get('interfaces', [])
        capabilities = kwargs.get('capabilities', [])
        
        if not binary_path:
            return {'success': False, 'error': '需要提供目标二进制路径'}
        
        # 构建能力模型
        self._build_capability_model(capabilities, components, interfaces)
        
        # 检测违规
        violations = self._detect_violations(ipc_type)
        
        return {
            'success': True,
            'violations': self._format_violations(violations),
            'summary': {
                'total_violations': len(violations),
                'critical_violations': sum(1 for v in violations if v.severity == 'Critical'),
                'high_violations': sum(1 for v in violations if v.severity == 'High'),
                'medium_violations': sum(1 for v in violations if v.severity == 'Medium')
            }
        }
    
    def _build_capability_model(
        self,
        capabilities_data: List[Dict[str, Any]],
        components_data: List[Dict[str, Any]],
        interfaces_data: List[Dict[str, Any]]
    ) -> None:
        """
        构建能力模型
        
        Args:
            capabilities_data: 能力定义数据
            components_data: 组件定义数据
            interfaces_data: 接口定义数据
        """
        logger.info("构建能力模型")
        
        # 加载能力定义
        for cap_data in capabilities_data:
            self.graph.capabilities[cap_data['name']] = Capability(
                name=cap_data['name'],
                level=CapabilityLevel(cap_data.get('level', 'low')),
                description=cap_data.get('description', ''),
                protected=cap_data.get('protected', True)
            )
        
        # 加载组件定义
        for comp_data in components_data:
            self.graph.nodes[comp_data['name']] = Component(
                name=comp_data['name'],
                capabilities=set(comp_data.get('capabilities', [])),
                interfaces=comp_data.get('interfaces', []),
                permissions=set(comp_data.get('permissions', [])),
                security_level=CapabilityLevel(comp_data.get('security_level', 'low'))
            )
        
        # 加载接口定义
        for iface_data in interfaces_data:
            self.graph.interfaces[iface_data['name']] = IPCInterface(
                name=iface_data['name'],
                provider=iface_data['provider'],
                required_capabilities=set(iface_data.get('required_capabilities', [])),
                exposed_capabilities=set(iface_data.get('exposed_capabilities', [])),
                ipc_type=IPCType(iface_data.get('ipc_type', 'binder'))
            )
        
        # 构建调用图边
        for comp_name, comp in self.graph.nodes.items():
            for iface_name in comp.interfaces:
                if iface_name in self.graph.interfaces:
                    iface = self.graph.interfaces[iface_name]
                    self.graph.edges.append((comp_name, iface.provider, {
                        'interface': iface_name,
                        'ipc_type': iface.ipc_type.value
                    }))
        
        logger.info(f"能力模型构建完成：{len(self.graph.nodes)} 个组件，{len(self.graph.interfaces)} 个接口")
    
    def _detect_violations(self, ipc_type: str) -> List[PermissionViolation]:
        """
        检测权限违规
        
        Args:
            ipc_type: IPC类型
        
        Returns:
            违规列表
        """
        logger.info(f"检测权限违规，IPC类型: {ipc_type}")
        
        violations = []
        
        for source_comp in self.graph.nodes.values():
            for iface_name in source_comp.interfaces:
                if iface_name not in self.graph.interfaces:
                    continue
                
                iface = self.graph.interfaces[iface_name]
                target_comp = self.graph.nodes.get(iface.provider)
                
                if not target_comp:
                    continue
                
                # 检查权限违规
                violation = self._check_capability_violation(source_comp, iface, target_comp)
                if violation:
                    violations.append(violation)
        
        # 检测权限提升路径
        escalation_paths = self._find_privilege_escalation_paths()
        violations.extend(escalation_paths)
        
        logger.info(f"检测完成，发现 {len(violations)} 个违规")
        
        return violations
    
    def _check_capability_violation(
        self,
        source: Component,
        iface: IPCInterface,
        target: Component
    ) -> Optional[PermissionViolation]:
        """
        检查单个调用是否存在权限违规
        
        Args:
            source: 源组件
            iface: 调用的接口
            target: 目标组件
        
        Returns:
            违规信息或None
        """
        # 检查调用者是否具备所需能力
        missing_caps = iface.required_capabilities - source.capabilities
        
        if not missing_caps:
            return None
        
        # 检查是否有能力提升
        source_level = source.security_level
        target_level = target.security_level
        
        has_escalation = target_level.value > source_level.value
        
        # 计算可利用性
        exploitability = self._calculate_exploitability(missing_caps, has_escalation)
        
        # 确定严重程度
        severity = self._determine_severity(missing_caps, has_escalation)
        
        return PermissionViolation(
            violation_type='capability_violation',
            source_component=source.name,
            target_interface=iface.name,
            missing_capabilities=missing_caps,
            available_capabilities=source.capabilities,
            exploitability=exploitability,
            severity=severity
        )
    
    def _find_privilege_escalation_paths(self) -> List[PermissionViolation]:
        """
        查找权限提升路径
        
        Returns:
            权限提升违规列表
        """
        violations = []
        
        # 使用BFS查找所有可能的调用路径
        for source_name, source_comp in self.graph.nodes.items():
            visited = set()
            queue = [(source_name, [source_name])]
            
            while queue:
                current_name, path = queue.pop(0)
                
                if current_name in visited:
                    continue
                visited.add(current_name)
                
                current_comp = self.graph.nodes.get(current_name)
                if not current_comp:
                    continue
                
                # 检查是否有能力提升
                for iface_name in current_comp.interfaces:
                    if iface_name not in self.graph.interfaces:
                        continue
                    
                    iface = self.graph.interfaces[iface_name]
                    target_name = iface.provider
                    target_comp = self.graph.nodes.get(target_name)
                    
                    if not target_comp:
                        continue
                    
                    # 检查是否存在权限提升
                    if target_comp.security_level.value > source_comp.security_level.value:
                        # 检查是否可以通过此接口获取新能力
                        gained_caps = iface.exposed_capabilities - source_comp.capabilities
                        
                        if gained_caps:
                            violations.append(PermissionViolation(
                                violation_type='privilege_escalation',
                                source_component=source_name,
                                target_interface=iface_name,
                                missing_capabilities=gained_caps,
                                available_capabilities=source_comp.capabilities,
                                exploitability=0.9,
                                severity='Critical',
                                path=path + [iface_name]
                            ))
                    
                    if target_name not in visited:
                        queue.append((target_name, path + [target_name]))
        
        return violations
    
    def _calculate_exploitability(
        self,
        missing_caps: Set[str],
        has_escalation: bool
    ) -> float:
        """
        计算可利用性评分
        
        Args:
            missing_caps: 缺失的能力集合
            has_escalation: 是否存在权限提升
        
        Returns:
            可利用性评分（0-1）
        """
        base_score = len(missing_caps) / 10.0
        
        if has_escalation:
            base_score += 0.5
        
        return min(1.0, base_score)
    
    def _determine_severity(
        self,
        missing_caps: Set[str],
        has_escalation: bool
    ) -> str:
        """
        确定违规严重程度
        
        Args:
            missing_caps: 缺失的能力集合
            has_escalation: 是否存在权限提升
        
        Returns:
            严重程度字符串
        """
        if has_escalation:
            return 'Critical'
        
        cap_levels = [self.graph.capabilities.get(cap) for cap in missing_caps]
        cap_levels = [c for c in cap_levels if c]
        
        if any(c.level == CapabilityLevel.SYSTEM for c in cap_levels):
            return 'Critical'
        
        if any(c.level == CapabilityLevel.HIGH for c in cap_levels):
            return 'High'
        
        if any(c.level == CapabilityLevel.MEDIUM for c in cap_levels):
            return 'Medium'
        
        return 'Low'
    
    def _format_violations(self, violations: List[PermissionViolation]) -> List[Dict[str, Any]]:
        """
        格式化违规结果
        
        Args:
            violations: 违规列表
        
        Returns:
            格式化后的违规列表
        """
        formatted = []
        for violation in violations:
            formatted.append({
                'type': violation.violation_type,
                'source_component': violation.source_component,
                'target_interface': violation.target_interface,
                'missing_capabilities': list(violation.missing_capabilities),
                'available_capabilities': list(violation.available_capabilities),
                'exploitability': violation.exploitability,
                'severity': violation.severity,
                'path': violation.path,
                'description': self._generate_description(violation)
            })
        return formatted
    
    def _generate_description(self, violation: PermissionViolation) -> str:
        """
        生成违规描述
        
        Args:
            violation: 违规信息
        
        Returns:
            描述字符串
        """
        if violation.violation_type == 'capability_violation':
            return f"组件 '{violation.source_component}' 调用接口 '{violation.target_interface}' " \
                   f"时缺少必要的能力: {', '.join(violation.missing_capabilities)}"
        else:
            path_str = ' -> '.join(violation.path) if violation.path else ''
            return f"发现权限提升路径: {violation.source_component} -> {violation.target_interface} " \
                   f"(路径: {path_str})，可获取能力: {', '.join(violation.missing_capabilities)}"
    
    def generate_exploit_scenario(self, violation: PermissionViolation) -> str:
        """
        生成漏洞利用场景描述
        
        Args:
            violation: 违规信息
        
        Returns:
            利用场景描述字符串
        """
        scenario = []
        scenario.append(f"【漏洞类型】{violation.violation_type}")
        scenario.append(f"【严重程度】{violation.severity}")
        scenario.append(f"【可利用性】{violation.exploitability:.1%}")
        scenario.append("")
        scenario.append("【利用场景】")
        scenario.append(f"  1. 攻击者控制低权限组件 '{violation.source_component}'")
        scenario.append(f"  2. 该组件可以调用接口 '{violation.target_interface}'")
        scenario.append(f"  3. 接口需要的能力: {', '.join(violation.missing_capabilities)}")
        scenario.append(f"  4. 组件当前拥有的能力: {', '.join(violation.available_capabilities)}")
        scenario.append("")
        scenario.append("【影响】")
        if violation.severity == 'Critical':
            scenario.append("  - 攻击者可以获取系统级权限")
            scenario.append("  - 可能导致完整的系统控制")
        elif violation.severity == 'High':
            scenario.append("  - 攻击者可以获取高级别权限")
            scenario.append("  - 可能绕过安全沙箱")
        
        return "\n".join(scenario)
    
    def generate_fix_recommendations(self, violation: PermissionViolation) -> List[str]:
        """
        生成修复建议
        
        Args:
            violation: 违规信息
        
        Returns:
            修复建议列表
        """
        recommendations = []
        
        if violation.violation_type == 'privilege_escalation':
            recommendations.append("限制接口的调用者范围，只允许授权组件调用")
            recommendations.append("增加调用者身份验证")
            recommendations.append("审查接口暴露的能力是否必要")
        
        recommendations.append("确保接口正确检查调用者的能力")
        recommendations.append("使用能力传递机制而非隐式提升")
        recommendations.append("记录所有能力提升操作用于审计")
        
        return recommendations
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="CapabilityChecker",
            type=AnalyzerType.VULNERABILITY_DETECTOR,
            version="1.0.0",
            description="符号执行权限/能力模型违规检测模块，检测Android Binder/seL4权限提升漏洞",
            author="BinaryAnalysisPlatform",
            dependencies=["collections"],
            supported_platforms=["arm", "arm64"]
        )


def check_capabilities(binary_path: str, **kwargs) -> Dict[str, Any]:
    """便捷函数：执行能力模型违规检测"""
    checker = CapabilityChecker()
    return checker.analyze(binary_path=binary_path, **kwargs)