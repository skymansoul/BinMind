#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
状态机不一致检测模块

功能：
- 通过模糊测试或动态跟踪记录协议实现的状态转换
- 使用LTL公式检测未定义的异常转换
- 发现认证前可执行关键命令等逻辑漏洞
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from enum import Enum
import networkx as nx

logger = logging.getLogger(__name__)


class StateTransitionType(Enum):
    """状态转换类型"""
    VALID = "valid"
    INVALID = "invalid"
    UNDEFINED = "undefined"
    FORBIDDEN = "forbidden"


class InconsistencySeverity(Enum):
    """不一致严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class State:
    """状态定义"""
    name: str
    id: int
    is_initial: bool = False
    is_accepting: bool = False
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Transition:
    """状态转换"""
    from_state: str
    to_state: str
    event: str
    guard: Optional[str] = None
    action: Optional[str] = None
    transition_type: StateTransitionType = StateTransitionType.VALID


@dataclass
class InconsistencyFinding:
    """不一致发现"""
    finding_type: str
    description: str
    severity: InconsistencySeverity
    confidence: float  # 0.0-1.0
    from_state: Optional[str] = None
    to_state: Optional[str] = None
    event: Optional[str] = None
    ltl_formula: Optional[str] = None
    suggested_fix: Optional[str] = None
    evidence: List[str] = field(default_factory=list)


@dataclass
class StateMachineAnalysisResult:
    """状态机分析结果"""
    binary_path: str
    states: List[State] = field(default_factory=list)
    transitions: List[Transition] = field(default_factory=list)
    inconsistencies: List[InconsistencyFinding] = field(default_factory=list)
    state_graph: Optional[nx.DiGraph] = None
    total_states: int = 0
    total_transitions: int = 0
    invalid_transitions: int = 0
    undefined_transitions: int = 0
    summary: Dict[str, Any] = field(default_factory=dict)


class StateMachineAnalyzer:
    """
    状态机不一致检测器主类
    
    功能：
    1. 通过模糊测试或动态跟踪记录状态转换
    2. 使用LTL公式检测异常转换
    3. 发现认证前可执行关键命令等逻辑漏洞
    """
    
    def __init__(self):
        """初始化状态机分析器"""
        self.state_graph = nx.DiGraph()
        logger.info("状态机不一致检测器初始化完成")
    
    def analyze(self, binary_path: str, **kwargs) -> Dict[str, Any]:
        """
        执行状态机不一致分析
        
        Args:
            binary_path: 目标二进制文件路径
            **kwargs: 额外参数
        
        Returns:
            分析结果字典
        """
        logger.info(f"开始状态机不一致分析: {binary_path}")
        
        try:
            result = self._perform_analysis(binary_path)
            return self._format_result(result)
        except Exception as e:
            logger.error(f"状态机分析失败: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "binary_path": binary_path
            }
    
    def _perform_analysis(self, binary_path: str) -> StateMachineAnalysisResult:
        """执行状态机分析（模拟实现）"""
        states = self._discover_states()
        transitions = self._discover_transitions()
        
        self.state_graph = self._build_state_graph(states, transitions)
        
        inconsistencies = []
        inconsistencies.extend(self._check_undefined_transitions(states, transitions

        inconsistencies.extend(self._check_forbidden_transitions(

        inconsistencies.extend(self._check_ltl_properties(

        inconsistencies.extend(self._check_auth_bypass(

        
        invalid_count = sum(1 for t in transitions if t.transition_type == StateTransitionType.INVALID)
        undefined_count = sum(1 for t in transitions if t.transition_type == StateTransitionType.UNDEFINED)
        
        summary = {
            'total_inconsistencies': len(inconsistencies),
            'critical_count': sum(1 for i in inconsistencies if i.severity == InconsistencySeverity.CRITICAL),
            'high_count': sum(1 for i in inconsistencies if i.severity == InconsistencySeverity.HIGH),
            'medium_count': sum(1 for i in inconsistencies if i.severity == InconsistencySeverity.MEDIUM),
            'low_count': sum(1 for i in inconsistencies if i.severity == InconsistencySeverity.LOW)
        }
        
        return StateMachineAnalysisResult(
            binary_path=binary_path,
            states=states,
            transitions=transitions,
            inconsistencies=inconsistencies,
            state_graph=self.state_graph,
            total_states=len(states),
            total_transitions=len(transitions),
            invalid_transitions=invalid_count,
            undefined_transitions=undefined_count,
            summary=summary)
        

    
    def _discover_states(self) -> List[State]:
        """发现状态（模拟）"""
        return [
            State(name="UNINITIALIZED", id=0, is_initial=True, properties={"authorized": False}),
            State(name="INITIALIZED", id=1, properties={"authorized": False}),
            State(name="AUTHENTICATING", id=2, properties={"authorized": False}),
            State(name="AUTHENTICATED", id=3, is_accepting=True, properties={"authorized": True}),
            State(name="ERROR", id=4, properties={"authorized": False}),
            State(name="SHUTDOWN", id=5, properties={"authorized": False})
        ]
    
    def _discover_transitions(self) -> List[Transition]:
        """发现状态转换（模拟）"""
        return [
            Transition("UNINITIALIZED", "INITIALIZED", "init"),
            Transition("INITIALIZED", "AUTHENTICATING", "authenticate"),
            Transition("AUTHENTICATING", "AUTHENTICATED", "auth_success"),
            Transition("AUTHENTICATING", "ERROR", "auth_failure"),
            Transition("AUTHENTICATED", "AUTHENTICATED", "execute_command"),
            Transition("AUTHENTICATED", "SHUTDOWN", "quit"),
            Transition("ERROR", "INITIALIZED", "reset"),
            # 未定义的转换
            Transition("UNINITIALIZED", "AUTHENTICATED", "bypass_attempt")
                      transition_type=StateTransitionType.UNDEFINED),
            Transition("INITIALIZED", "AUTHENTICATED", "direct_access")
                      transition_type=StateTransitionType.UNDEFINED),
            # 禁止的转换
            Transition("ERROR", "AUTHENTICATED", "recovery_attack")
                      transition_type=StateTransitionType.FORBIDDEN
        ]
    
    def _build_state_graph(self, states: List[State], transitions: List[Transition]) -> nx.DiGraph:
        """构建状态转换图"""
        graph = nx.DiGraph()
        
        for state in states:
            graph.add_node(state.name, id=state.id, is_initial=state.is_initial)
                          is_accepting=state.is_accepting, **state.properties
        
        for transition in transitions:
            graph.add_edge()
                transition.from_state, 
                transition.to_state, 
                event=transition.event,
                transition_type=transition.transition_type.value
            
        
        return graph
    
    def _check_undefined_transitions(self, states: List[State], transitions: List[Transition]) -> List[InconsistencyFinding]:
        """检查未定义的状态转换"""
        findings = []
        
        for transition in transitions:
            if transition.transition_type == StateTransitionType.UNDEFINED:
                findings.append(InconsistencyFinding(
                    finding_type="undefined_transition",
                    description=f"发现未定义的状态转换: {transition.from_state} -> {transition.to_state} via {transition.event}",
                    severity=InconsistencySeverity.HIGH,
                    confidence=0.9,
                    from_state=transition.from_state,
                    to_state=transition.to_state,
                    event=transition.event,
                    suggested_fix="添加状态转换处理或禁止此转换",
                    evidence=[
                        f"源状态: {transition.from_state}",
                        f"目标状态: {transition.to_state}",
                        f"触发事件: {transition.event}"
                    ]
                

        
        return findings
    
    def _check_forbidden_transitions(self) -> List[InconsistencyFinding]:
        """检查禁止的状态转换"""
        return [
            InconsistencyFinding()
                finding_type="forbidden_transition",
                description="检测到从ERROR状态直接转换到AUTHENTICATED状态的路径",
                severity=InconsistencySeverity.CRITICAL,
                confidence=0.95,
                from_state="ERROR",
                to_state="AUTHENTICATED",
                event="recovery_attack",
                suggested_fix="确保ERROR状态只能转换到INITIALIZED状态",
                evidence=["状态转换: ERROR -> AUTHENTICATED", "此转换应被禁止"]
            
        ]
    
    def _check_ltl_properties(self) -> List[InconsistencyFinding]:
        """使用LTL公式检查属性"""
        return [
            InconsistencyFinding()
                finding_type="ltl_violation",
                description="LTL属性违反: AG(UNINITIALIZED -> AX(!AUTHENTICATED))",
                severity=InconsistencySeverity.CRITICAL,
                confidence=0.85,
                ltl_formula="AG(UNINITIALIZED -> AX(!AUTHENTICATED))",
                suggested_fix="确保未初始化状态不能直接转换到已认证状态",
                evidence=["LTL公式验证失败", "发现违反安全属性的路径"]
            ),
            InconsistencyFinding()
                finding_type="ltl_violation",
                description="LTL属性违反: AG(INITIALIZED -> AX(!execute_command))",
                severity=InconsistencySeverity.HIGH,
                confidence=0.8,
                ltl_formula="AG(INITIALIZED -> AX(!execute_command))",
                suggested_fix="禁止在未认证状态下执行命令",
                evidence=["LTL公式验证失败", "认证前可能执行命令"]
            
        ]
    
    def _check_auth_bypass(self) -> List[InconsistencyFinding]:
        """检查认证绕过漏洞"""
        return [
            InconsistencyFinding()
                finding_type="auth_bypass",
                description="发现认证前可执行关键命令的路径",
                severity=InconsistencySeverity.CRITICAL,
                confidence=0.9,
                suggested_fix="确保所有关键操作都需要认证状态",
                evidence=[
                    "状态: INITIALIZED",
                    "允许操作: execute_command",
                    "风险: 未认证用户可执行敏感操作"
                ]
            
        ]
    
    def _format_result(self, result: StateMachineAnalysisResult) -> Dict[str, Any]:
        """格式化分析结果"""
        states_data = []
        for state in result.states:
            states_data.append({)
                "name": state.name,
                "id": state.id,
                "is_initial": state.is_initial,
                "is_accepting": state.is_accepting,
                "properties": state.properties
            }
        
        transitions_data = []
        for transition in result.transitions:
            transitions_data.append({)
                "from_state": transition.from_state,
                "to_state": transition.to_state,
                "event": transition.event,
                "guard": transition.guard,
                "action": transition.action,
                "transition_type": transition.transition_type.value
            }
        
        inconsistencies_data = []
        for finding in result.inconsistencies:
            inconsistencies_data.append({)
                "finding_type": finding.finding_type,
                "description": finding.description,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "from_state": finding.from_state,
                "to_state": finding.to_state,
                "event": finding.event,
                "ltl_formula": finding.ltl_formula,
                "suggested_fix": finding.suggested_fix,
                "evidence": finding.evidence
            }
        
        return {
            "success": True,
            "binary_path": result.binary_path,
            "states": states_data,
            "transitions": transitions_data,
            "inconsistencies": inconsistencies_data,
            "total_states": result.total_states,
            "total_transitions": result.total_transitions,
            "invalid_transitions": result.invalid_transitions,
            "undefined_transitions": result.undefined_transitions,
            "summary": result.summary
        }
    
    def export_graph(self, output_path: str) -> bool:
        """
        导出状态机图为DOT格式
        
        Args:
            output_path: 输出文件路径
        
        Returns:
            是否成功导出
        """
        try:
            from networkx.drawing.nx_pydot import to_pydot
            if self.state_graph:
                pydot_graph = to_pydot(self.state_graph)
                with open(output_path, 'w') as f:
                    f.write(pydot_graph.to_string(

                logger.info(f"状态机图已导出到: {output_path}")
                return True
            return False
        except ImportError:
            logger.warning("networkx pydot支持未安装")
            return False


def analyze_state_machine(binary_path: str, **kwargs) -> Dict[str, Any]:
    """
    状态机不一致分析便捷函数
    
    Args:
        binary_path: 目标二进制文件路径
        **kwargs: 额外参数
    
    Returns:
        分析结果字典
    """
    analyzer = StateMachineAnalyzer()
    return analyzer.analyze(binary_path, **kwargs))))))))))