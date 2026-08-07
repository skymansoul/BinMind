# 基于LLM智能体的二进制分析框架 — 多Agent协作完成端到端分析任务
# 依据: ClearAgent [Zotero: "Agentic Binary Analysis for Effective Vulnerability Detection"]
# Getting pwn'd by 智能 [Zotero: "Penetration Testing with Large Language Models"]
# 核心: 定义Agent角色(反汇编/漏洞发现/利用生成/报告) → 共享状态 → 迭代推理

from __future__ import annotations
import json
import time
import logging
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AgentRole(Enum):
    DISASSEMBLER = 'disassembler'       # 反汇编分析
    VULN_HUNTER = 'vuln_hunter'         # 漏洞发现
    EXPLOIT_CRAFTER = 'exploit_crafter' # 利用生成
    REPORT_COMPILER = 'report_compiler' # 报告汇总
    ORCHESTRATOR = 'orchestrator'       # 任务协调


@dataclass
class AgentObservation:
    """单个Agent的观察/发现"""
    role: AgentRole
    content: str
    confidence: float
    evidence: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)  # 代码地址/行号
    timestamp: float = 0.0

    def to_dict(self) -> dict:
        return {
            'role': self.role.value, 'content': self.content,
            'confidence': self.confidence, 'evidence': self.evidence,
            'references': self.references,
        }


@dataclass
class AgentState:
    """共享状态 — 各Agent通过它交换信息"""
    binary_path: str = ""
    target_functions: List[str] = field(default_factory=list)
    observations: List[AgentObservation] = field(default_factory=list)
    discovered_vulns: List[Dict] = field(default_factory=list)
    analysis_phase: str = "init"
    iteration: int = 0
    max_iterations: int = 10
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_observation(self, obs: AgentObservation):
        self.observations.append(obs)

    def get_observations_by_role(self, role: AgentRole) -> List[AgentObservation]:
        return [o for o in self.observations if o.role == role]

    def consensus_confidence(self) -> float:
        """多Agent共识置信度"""
        if not self.observations:
            return 0.0
        return sum(o.confidence for o in self.observations) / len(self.observations)


# Agent基类

class BaseAgent:
    """LLM Agent基类 — 每个Agent有独立的角色、提示模板和后端"""

    def __init__(self, role: AgentRole, llm_backend: Optional[Any] = None):
        self.role = role
        self.llm = llm_backend

    def observe(self, state: AgentState) -> AgentObservation:
        raise NotImplementedError

    def _build_prompt(self, state: AgentState) -> str:
        raise NotImplementedError


class DisassemblerAgent(BaseAgent):
    """反汇编分析Agent — 解析函数结构、调用关系、数据流"""

    def __init__(self, llm_backend=None):
        super().__init__(AgentRole.DISASSEMBLER, llm_backend)

    def observe(self, state: AgentState) -> AgentObservation:
        """分析目标函数的反汇编结构"""
        func_name = state.target_functions[0] if state.target_functions else "unknown"

        # 启发式分析 (无真实LLM时的回退)
        findings = []
        confidence = 0.0
        evidence = []

        # 模拟静态分析结果
        import_patterns = state.metadata.get('imports', [])
        if import_patterns:
            dangerous = [i for i in import_patterns if any(
                kw in i.lower() for kw in ['system', 'exec', 'popen', 'memcpy',
                                            'strcpy', 'gets', 'sprintf', 'malloc'])]
            if dangerous:
                findings.append(f"发现 {len(dangerous)} 个潜在危险导入: {', '.join(dangerous[:5])}")
                confidence = 0.7
                evidence = dangerous[:3]

        return AgentObservation(
            role=self.role,
            content='; '.join(findings) if findings else f"函数 {func_name} 的结构分析未发现明显异常",
            confidence=confidence,
            evidence=evidence,
            references=[func_name],
        )


class VulnHunterAgent(BaseAgent):
    """漏洞发现Agent — 模式匹配 + 约束推理"""

    VULN_PATTERNS = [
        ('buffer_overflow', ['memcpy', 'strcpy', 'gets', 'sprintf', 'strcat', 'scanf']),
        ('command_injection', ['system', 'popen', 'execve', 'ShellExecute']),
        ('format_string', ['printf', 'fprintf', 'sprintf', 'snprintf']),
        ('use_after_free', ['free', 'malloc', 'realloc']),
        ('integer_overflow', ['malloc', 'calloc', 'alloca', 'new']),
        ('path_traversal', ['fopen', 'open', 'CreateFile', 'access']),
        ('privilege_escalation', ['setuid', 'setgid', 'chmod', 'CreateProcessAsUser']),
    ]

    def __init__(self, llm_backend=None):
        super().__init__(AgentRole.VULN_HUNTER, llm_backend)

    def observe(self, state: AgentState) -> AgentObservation:
        prev = state.get_observations_by_role(AgentRole.DISASSEMBLER)
        imports = state.metadata.get('imports', [])
        pseudocode = state.metadata.get('pseudocode', '')

        findings = []
        evidence = []
        max_confidence = 0.0

        for vuln_type, keywords in self.VULN_PATTERNS:
            matched = [imp for imp in imports if any(kw in imp.lower() for kw in keywords)]
            if matched:
                findings.append(f"[{vuln_type}] 匹配到 {matched}")
                evidence.extend(matched)
                # 根据危险程度分配置信度
                if vuln_type in ('buffer_overflow', 'command_injection'):
                    max_confidence = max(max_confidence, 0.85)
                elif vuln_type == 'format_string':
                    max_confidence = max(max_confidence, 0.75)
                else:
                    max_confidence = max(max_confidence, 0.60)

        # 检查伪代码中的模式
        if pseudocode:
            for vuln_type, keywords in self.VULN_PATTERNS:
                for kw in keywords:
                    if kw.lower() in pseudocode.lower():
                        if vuln_type not in [f[0] for f in findings]:
                            findings.append(f"[{vuln_type}] 伪代码模式匹配")
                        max_confidence = max(max_confidence, 0.70)

        return AgentObservation(
            role=self.role,
            content='; '.join(findings) if findings else '未发现已知漏洞模式',
            confidence=max_confidence,
            evidence=evidence,
        )


class ExploitCrafterAgent(BaseAgent):
    """利用生成Agent — 基于漏洞发现构建PoC策略"""

    def __init__(self, llm_backend=None):
        super().__init__(AgentRole.EXPLOIT_CRAFTER, llm_backend)

    def observe(self, state: AgentState) -> AgentObservation:
        vuln_obs = state.get_observations_by_role(AgentRole.VULN_HUNTER)
        if not vuln_obs:
            return AgentObservation(
                role=self.role,
                content='无漏洞发现, 跳过利用生成',
                confidence=0.0,
            )

        vuln_content = ' '.join(o.content for o in vuln_obs)

        # 基于漏洞类型映射利用策略
        strategies = []
        if 'buffer_overflow' in vuln_content:
            strategies.append('栈缓冲区溢出 → ROP链构造 / ret2libc')
        if 'command_injection' in vuln_content:
            strategies.append('命令注入 → 反向shell payload')
        if 'format_string' in vuln_content:
            strategies.append('格式化字符串 → GOT覆写 / 信息泄露')
        if 'use_after_free' in vuln_content:
            strategies.append('UAF → 堆喷射 / vtable劫持')
        if 'integer_overflow' in vuln_content:
            strategies.append('整数溢出 → 堆/栈溢出触发')

        if not strategies:
            strategies.append('无明确利用路径, 建议先提升漏洞置信度')

        return AgentObservation(
            role=self.role,
            content='; '.join(strategies),
            confidence=0.5 if len(strategies) <= 1 else 0.65,
            evidence=strategies,
        )


class ReportCompilerAgent(BaseAgent):
    """报告生成Agent — 汇总所有发现"""

    def __init__(self, llm_backend=None):
        super().__init__(AgentRole.REPORT_COMPILER, llm_backend)

    def observe(self, state: AgentState) -> AgentObservation:
        parts = [f"# 二进制分析报告"]
        parts.append(f"## 目标: {state.binary_path}")
        parts.append(f"## 函数: {', '.join(state.target_functions[:5])}")
        parts.append(f"## 迭代次数: {state.iteration}")
        parts.append(f"## 共识置信度: {state.consensus_confidence():.2f}")
        parts.append("")

        for role in AgentRole:
            if role == AgentRole.ORCHESTRATOR:
                continue
            obs_list = state.get_observations_by_role(role)
            if obs_list:
                parts.append(f"### {role.value}")
                for o in obs_list:
                    parts.append(f"- [conf={o.confidence:.2f}] {o.content}")

        return AgentObservation(
            role=self.role,
            content='\n'.join(parts),
            confidence=state.consensus_confidence(),
        )


# 编排器

class BinaryAnalysisOrchestrator:
    """多Agent协调器 — ClearAgent风格的任务编排

    工作流: Disassembler → VulnHunter → ExploitCrafter → ReportCompiler
    每轮迭代共享状态, Agent间通过observations交换信息
    """

    def __init__(self, llm_backend=None, max_iterations: int = 5):
        self.agents: Dict[AgentRole, BaseAgent] = {
            AgentRole.DISASSEMBLER: DisassemblerAgent(llm_backend),
            AgentRole.VULN_HUNTER: VulnHunterAgent(llm_backend),
            AgentRole.EXPLOIT_CRAFTER: ExploitCrafterAgent(llm_backend),
            AgentRole.REPORT_COMPILER: ReportCompilerAgent(llm_backend),
        }
        self.max_iters = max_iterations

    def analyze(self, binary_path: str, target_functions: List[str],
                **metadata) -> AgentState:
        """执行完整的Agent协作分析"""
        state = AgentState(
            binary_path=binary_path,
            target_functions=target_functions,
            max_iterations=self.max_iters,
            metadata=metadata,
        )

        pipeline = [
            AgentRole.DISASSEMBLER,
            AgentRole.VULN_HUNTER,
            AgentRole.EXPLOIT_CRAFTER,
            AgentRole.REPORT_COMPILER,
        ]

        for iteration in range(self.max_iters):
            state.iteration = iteration + 1
            state.analysis_phase = f"round_{iteration}"

            for role in pipeline:
                agent = self.agents[role]
                obs = agent.observe(state)
                obs.timestamp = time.time()
                state.add_observation(obs)

            # 收敛检查: 高置信度或稳定状态
            if state.consensus_confidence() > 0.85:
                state.analysis_phase = "converged"
                break

        return state

    def add_custom_agent(self, role_name: str, agent: BaseAgent):
        """注册自定义Agent"""
        self.agents[AgentRole(role_name)] = agent


def create_binary_analysis_agent() -> BinaryAnalysisOrchestrator:
    return BinaryAnalysisOrchestrator()
