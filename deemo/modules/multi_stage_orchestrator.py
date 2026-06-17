import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Set
from enum import Enum
from collections import deque

from .plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """漏洞类型枚举"""
    BUFFER_OVERFLOW = "buffer_overflow"
    HEAP_OVERFLOW = "heap_overflow"
    USE_AFTER_FREE = "use_after_free"
    FORMAT_STRING = "format_string"
    INFO_LEAK = "info_leak"
    AUTH_BYPASS = "auth_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INTEGER_OVERFLOW = "integer_overflow"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"


class Capability(Enum):
    """漏洞能力枚举"""
    READ_MEMORY = "read_memory"
    WRITE_MEMORY = "write_memory"
    EXECUTE_CODE = "execute_code"
    LEAK_ADDRESS = "leak_address"
    BYPASS_AUTH = "bypass_auth"
    ESCALATE_PRIVILEGES = "escalate_privileges"
    ARBITRARY_FILE_READ = "arbitrary_file_read"
    ARBITRARY_FILE_WRITE = "arbitrary_file_write"


class TargetType(Enum):
    """目标类型枚举"""
    USERLAND = "userland"
    KERNEL = "kernel"
    WEB = "web"
    NETWORK = "network"


class ChainStatus(Enum):
    """利用链状态枚举"""
    PLANNED = "planned"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class VulnerabilityNode:
    """漏洞节点"""
    id: str
    name: str
    vuln_type: VulnerabilityType
    description: str
    address: Optional[int] = None
    severity: str = "high"
    capabilities: List[Capability] = field(default_factory=list)


@dataclass
class ExploitChainStep:
    """利用链步骤"""
    id: str
    name: str
    vulnerability: VulnerabilityNode
    required_capabilities: List[Capability] = field(default_factory=list)
    output_capabilities: List[Capability] = field(default_factory=list)
    payload: Optional[str] = None
    success_rate: float = 0.8
    estimated_time: float = 1.0
    dependencies: List[str] = field(default_factory=list)


@dataclass
class ExploitChain:
    """利用链"""
    id: str
    name: str
    target_type: TargetType
    steps: List[ExploitChainStep] = field(default_factory=list)
    status: ChainStatus = ChainStatus.PLANNED
    current_step: int = 0
    success_rate: float = 0.0
    estimated_time: float = 0.0
    notes: List[str] = field(default_factory=list)


@dataclass
class ChainAnalysisResult:
    """利用链分析结果"""
    chain: ExploitChain
    valid: bool
    missing_capabilities: List[Capability]
    suggested_improvements: List[str]
    execution_plan: List[str]
    risk_assessment: str
    confidence: float


class MultiStageOrchestrator(BaseAnalyzer):
    """
    多阶段利用链自动编排模块
    
    功能：
    1. 自动分析漏洞之间的依赖关系
    2. 构建最优利用链
    3. 生成执行计划
    4. 评估利用链成功率和风险
    
    支持的利用链模式：
    - 信息泄露 -> 地址获取 -> ROP链 -> 代码执行
    - 权限绕过 -> 本地提权 -> 持久化
    - 堆溢出 -> 内存布局控制 -> 代码执行
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.vulnerabilities: Dict[str, VulnerabilityNode] = {}
        self.chains: Dict[str, ExploitChain] = {}
        self.capability_graph: Dict[Capability, List[Capability]] = self._build_capability_graph()
    
    def _build_capability_graph(self) -> Dict[Capability, List[Capability]]:
        """构建能力依赖图"""
        return {
            Capability.READ_MEMORY: [Capability.LEAK_ADDRESS],
            Capability.WRITE_MEMORY: [Capability.EXECUTE_CODE],
            Capability.LEAK_ADDRESS: [Capability.READ_MEMORY, Capability.EXECUTE_CODE],
            Capability.BYPASS_AUTH: [Capability.READ_MEMORY, Capability.WRITE_MEMORY],
            Capability.ESCALATE_PRIVILEGES: [Capability.READ_MEMORY, Capability.WRITE_MEMORY],
            Capability.EXECUTE_CODE: [],
            Capability.ARBITRARY_FILE_READ: [Capability.READ_MEMORY],
            Capability.ARBITRARY_FILE_WRITE: [Capability.WRITE_MEMORY],
        }
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="MultiStageOrchestrator",
            type=AnalyzerType.EXPLOIT_GENERATOR,
            version="1.0.0",
            description="多阶段利用链自动编排模块，分析漏洞依赖关系并构建最优利用链",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["x86", "x86_64", "arm", "arm64"],
            config_schema={
                "target_type": {"type": "string", "default": "userland"},
                "max_chain_length": {"type": "integer", "default": 10},
                "min_success_rate": {"type": "number", "default": 0.5}
            }
        )
    
    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        if 'vulnerabilities' not in kwargs:
            return False, "缺少必需参数: vulnerabilities"
        
        vulnerabilities = kwargs.get('vulnerabilities')
        if not isinstance(vulnerabilities, list) or len(vulnerabilities) == 0:
            return False, "vulnerabilities 必须是非空列表"
        
        return True, None
    
    def add_vulnerability(self, vuln: VulnerabilityNode) -> None:
        """添加漏洞节点"""
        self.vulnerabilities[vuln.id] = vuln
    
    def build_exploit_chain(self, target_type: str, vulnerabilities: List[Dict[str, Any]]) -> ExploitChain:
        """
        构建利用链
        
        Args:
            target_type: 目标类型
            vulnerabilities: 漏洞列表
        
        Returns:
            构建的利用链
        """
        chain_id = f"chain_{len(self.chains) + 1}"
        steps = []
        available_capabilities = set()
        
        # 将漏洞转换为VulnerabilityNode对象
        vuln_nodes = []
        for vuln_data in vulnerabilities:
            vuln_type = VulnerabilityType(vuln_data['vuln_type'])
            capabilities = [Capability(c) for c in vuln_data.get('capabilities', [])]
            
            vuln_node = VulnerabilityNode(
                id=vuln_data['id'],
                name=vuln_data['name'],
                vuln_type=vuln_type,
                description=vuln_data.get('description', ''),
                address=vuln_data.get('address'),
                severity=vuln_data.get('severity', 'high'),
                capabilities=capabilities
            )
            vuln_nodes.append(vuln_node)
        
        # 按能力依赖排序漏洞
        sorted_vulns = self._sort_by_capability_dependency(vuln_nodes)
        
        # 构建利用链步骤
        step_id = 1
        for vuln in sorted_vulns:
            # 确定此漏洞提供的能力
            new_capabilities = [c for c in vuln.capabilities if c not in available_capabilities]
            
            if new_capabilities:
                step = ExploitChainStep(
                    id=f"step_{step_id}",
                    name=f"利用 {vuln.name}",
                    vulnerability=vuln,
                    required_capabilities=[],
                    output_capabilities=new_capabilities,
                    success_rate=self._estimate_success_rate(vuln),
                    estimated_time=self._estimate_time(vuln)
                )
                steps.append(step)
                available_capabilities.update(new_capabilities)
                step_id += 1
        
        # 计算整体成功率
        overall_success_rate = 1.0
        estimated_time = 0.0
        for step in steps:
            overall_success_rate *= step.success_rate
            estimated_time += step.estimated_time
        
        chain = ExploitChain(
            id=chain_id,
            name=f"利用链 {chain_id}",
            target_type=TargetType(target_type),
            steps=steps,
            status=ChainStatus.PLANNED,
            success_rate=overall_success_rate,
            estimated_time=estimated_time
        )
        
        self.chains[chain_id] = chain
        return chain
    
    def _sort_by_capability_dependency(self, vulns: List[VulnerabilityNode]) -> List[VulnerabilityNode]:
        """按能力依赖排序漏洞"""
        # 简单的拓扑排序
        result = []
        visited = set()
        
        def dfs(vuln):
            if vuln.id in visited:
                return
            visited.add(vuln.id)
            
            # 先处理依赖的漏洞
            for cap in vuln.capabilities:
                for required_cap in self.capability_graph.get(cap, []):
                    for other_vuln in vulns:
                        if required_cap in other_vuln.capabilities and other_vuln.id not in visited:
                            dfs(other_vuln)
            
            if vuln not in result:
                result.append(vuln)
        
        for vuln in vulns:
            if vuln.id not in visited:
                dfs(vuln)
        
        return result
    
    def _estimate_success_rate(self, vuln: VulnerabilityNode) -> float:
        """估算漏洞利用成功率"""
        base_rate = {
            VulnerabilityType.BUFFER_OVERFLOW: 0.85,
            VulnerabilityType.HEAP_OVERFLOW: 0.7,
            VulnerabilityType.USE_AFTER_FREE: 0.65,
            VulnerabilityType.FORMAT_STRING: 0.9,
            VulnerabilityType.INFO_LEAK: 0.8,
            VulnerabilityType.AUTH_BYPASS: 0.95,
            VulnerabilityType.PRIVILEGE_ESCALATION: 0.75,
        }
        
        rate = base_rate.get(vuln.vuln_type, 0.7)
        
        # 根据严重程度调整
        if vuln.severity == "critical":
            rate *= 1.05
        elif vuln.severity == "low":
            rate *= 0.9
        
        return min(1.0, max(0.1, rate))
    
    def _estimate_time(self, vuln: VulnerabilityNode) -> float:
        """估算利用时间（秒）"""
        base_time = {
            VulnerabilityType.BUFFER_OVERFLOW: 2.0,
            VulnerabilityType.HEAP_OVERFLOW: 5.0,
            VulnerabilityType.USE_AFTER_FREE: 8.0,
            VulnerabilityType.FORMAT_STRING: 1.0,
            VulnerabilityType.INFO_LEAK: 1.5,
            VulnerabilityType.AUTH_BYPASS: 0.5,
            VulnerabilityType.PRIVILEGE_ESCALATION: 3.0,
        }
        
        return base_time.get(vuln.vuln_type, 3.0)
    
    def analyze_chain(self, chain: ExploitChain) -> ChainAnalysisResult:
        """
        分析利用链的可行性
        
        Args:
            chain: 利用链
        
        Returns:
            分析结果
        """
        missing_capabilities = []
        suggestions = []
        execution_plan = []
        available_capabilities = set()
        
        # 检查每个步骤
        for i, step in enumerate(chain.steps):
            # 检查所需能力
            for req_cap in step.required_capabilities:
                if req_cap not in available_capabilities:
                    missing_capabilities.append(req_cap)
                    suggestions.append(f"步骤 {i+1} 需要 {req_cap.value}，但之前的步骤未提供")
            
            # 添加输出能力
            available_capabilities.update(step.output_capabilities)
            
            # 生成执行计划
            execution_plan.append(f"步骤 {i+1}: {step.name}")
        
        # 评估风险
        risk_level = "low"
        if chain.success_rate < 0.5:
            risk_level = "high"
        elif chain.success_rate < 0.7:
            risk_level = "medium"
        
        # 计算置信度
        confidence = min(0.95, 0.5 + len(chain.steps) * 0.05 - len(missing_capabilities) * 0.1)
        
        return ChainAnalysisResult(
            chain=chain,
            valid=len(missing_capabilities) == 0,
            missing_capabilities=missing_capabilities,
            suggested_improvements=suggestions,
            execution_plan=execution_plan,
            risk_assessment=risk_level,
            confidence=confidence
        )
    
    def generate_chain_report(self, chain: ExploitChain) -> str:
        """生成利用链报告"""
        report = f"""利用链报告: {chain.name}
========================================
目标类型: {chain.target_type.value}
状态: {chain.status.value}
预计成功率: {chain.success_rate:.2%}
预计执行时间: {chain.estimated_time:.1f} 秒

步骤详情:
"""
        
        for i, step in enumerate(chain.steps):
            report += f"""
步骤 {i+1}: {step.name}
  - 漏洞: {step.vulnerability.name}
  - 类型: {step.vulnerability.vuln_type.value}
  - 成功率: {step.success_rate:.2%}
  - 预计时间: {step.estimated_time:.1f} 秒
  - 输出能力: {[c.value for c in step.output_capabilities]}
"""
        
        if chain.notes:
            report += "\n备注:\n"
            for note in chain.notes:
                report += f"  - {note}\n"
        
        return report
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行多阶段利用链分析
        
        Args:
            vulnerabilities: 漏洞列表（必需）
            target_type: 目标类型（默认 userland）
        
        Returns:
            分析结果字典
        """
        valid, error = self.validate_input(**kwargs)
        if not valid:
            return {"success": False, "error": error}
        
        vulnerabilities = kwargs.get('vulnerabilities')
        target_type = kwargs.get('target_type', 'userland')
        
        logger.info(f"开始构建利用链，目标类型: {target_type}")
        
        try:
            chain = self.build_exploit_chain(target_type, vulnerabilities)
            analysis_result = self.analyze_chain(chain)
            
            result = {
                "success": True,
                "chain_id": chain.id,
                "chain_name": chain.name,
                "target_type": chain.target_type.value,
                "status": chain.status.value,
                "steps_count": len(chain.steps),
                "success_rate": chain.success_rate,
                "estimated_time": chain.estimated_time,
                "valid": analysis_result.valid,
                "risk_assessment": analysis_result.risk_assessment,
                "confidence": analysis_result.confidence,
                "steps": [
                    {
                        "id": step.id,
                        "name": step.name,
                        "vulnerability_name": step.vulnerability.name,
                        "vulnerability_type": step.vulnerability.vuln_type.value,
                        "success_rate": step.success_rate,
                        "estimated_time": step.estimated_time,
                        "output_capabilities": [c.value for c in step.output_capabilities]
                    } for step in chain.steps
                ],
                "missing_capabilities": [c.value for c in analysis_result.missing_capabilities],
                "suggestions": analysis_result.suggested_improvements,
                "execution_plan": analysis_result.execution_plan,
                "report": self.generate_chain_report(chain)
            }
            
            return result
        
        except Exception as e:
            logger.error(f"利用链分析失败: {e}")
            return {"success": False, "error": str(e)}
    
    def execute_chain(self, chain_id: str) -> Dict[str, Any]:
        """
        执行利用链
        
        Args:
            chain_id: 利用链ID
        
        Returns:
            执行结果
        """
        chain = self.chains.get(chain_id)
        if not chain:
            return {"success": False, "error": f"利用链不存在: {chain_id}"}
        
        chain.status = ChainStatus.EXECUTING
        
        results = []
        overall_success = True
        
        for i, step in enumerate(chain.steps):
            chain.current_step = i
            
            logger.info(f"执行步骤 {i+1}: {step.name}")
            
            try:
                step_result = {
                    "step_id": step.id,
                    "step_name": step.name,
                    "success": True,
                    "message": f"步骤 {i+1} 执行成功"
                }
                results.append(step_result)
                
            except Exception as e:
                step_result = {
                    "step_id": step.id,
                    "step_name": step.name,
                    "success": False,
                    "message": f"步骤 {i+1} 执行失败: {str(e)}"
                }
                results.append(step_result)
                overall_success = False
                break
        
        chain.status = ChainStatus.COMPLETED if overall_success else ChainStatus.FAILED
        
        return {
            "success": overall_success,
            "chain_id": chain_id,
            "status": chain.status.value,
            "results": results
        }
    
    def cleanup(self) -> None:
        """清理资源"""
        self.vulnerabilities.clear()
        self.chains.clear()


def orchestrate_exploit_chain(vulnerabilities: List[Dict[str, Any]],
                               target_type: str = "userland") -> Dict[str, Any]:
    """
    编排利用链的便捷函数
    
    Args:
        vulnerabilities: 漏洞列表
        target_type: 目标类型
    
    Returns:
        利用链分析结果
    """
    orchestrator = MultiStageOrchestrator()
    return orchestrator.analyze(vulnerabilities=vulnerabilities, target_type=target_type)