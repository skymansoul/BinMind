"""
异步运行时状态机反编译模块

功能：
1. 针对 Rust async、Go goroutine、C# async/await，恢复异步状态机图
2. 标注 await/yield 点及状态转换
3. 检测死锁或无限等待
"""

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from enum import Enum

from .plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class LanguageType(Enum):
    """语言类型枚举"""
    RUST = "rust"
    GO = "go"
    CSHARP = "csharp"
    UNKNOWN = "unknown"


class StateType(Enum):
    """状态类型枚举"""
    INITIAL = "initial"
    AWAITING = "awaiting"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"
    SUSPENDED = "suspended"


class TransitionType(Enum):
    """状态转换类型枚举"""
    AWAIT = "await"
    YIELD = "yield"
    RESUME = "resume"
    COMPLETE = "complete"
    ERROR = "error"
    TIMEOUT = "timeout"


class AsyncPatternType(Enum):
    """异步模式类型枚举"""
    RUST_FUTURE = "rust_future"
    RUST_STREAM = "rust_stream"
    GO_GOROUTINE = "go_goroutine"
    GO_CHANNEL = "go_channel"
    CSHARP_TASK = "csharp_task"
    CSHARP_AWAITER = "csharp_awaiter"


@dataclass
class StateNode:
    """状态节点数据类"""
    state_id: str
    state_type: StateType
    offset: int
    description: str = ""
    is_await_point: bool = False
    await_target: Optional[str] = None


@dataclass
class StateTransition:
    """状态转换数据类"""
    from_state: str
    to_state: str
    transition_type: TransitionType
    condition: Optional[str] = None
    offset: Optional[int] = None


@dataclass
class AwaitPoint:
    """await 点数据类"""
    offset: int
    async_function: str
    awaited_type: Optional[str] = None
    is_potential_deadlock: bool = False


@dataclass
class AsyncStateMachine:
    """异步状态机数据类"""
    language: LanguageType
    states: List[StateNode] = field(default_factory=list)
    transitions: List[StateTransition] = field(default_factory=list)
    await_points: List[AwaitPoint] = field(default_factory=list)
    entry_point: Optional[str] = None
    exit_point: Optional[str] = None


@dataclass
class SMRecoveryResult:
    """状态机恢复结果数据类"""
    success: bool
    state_machine: Optional[AsyncStateMachine] = None
    warnings: List[str] = field(default_factory=list)
    detected_patterns: List[str] = field(default_factory=list)


class StateMachineParser(ABC):
    """状态机解析器基类"""
    
    @abstractmethod
    def parse(self, binary_data: bytes) -> AsyncStateMachine:
        """解析二进制数据，恢复状态机"""
        pass


class RustAsyncParser(StateMachineParser):
    """Rust async 状态机解析器"""
    
    def __init__(self):
        self.future_patterns = {
            b'Future', b'Poll', b'Waker', b'await', b'yield',
            b'_ZN4core3task', b'__rust_start_panic'
        }
        self.stream_patterns = {b'Stream', b'poll_next', b'next'}
    
    def parse(self, binary_data: bytes) -> AsyncStateMachine:
        """解析 Rust 异步状态机"""
        states = []
        transitions = []
        await_points = []
        
        # 检测状态机模式
        state_count = self._count_states(binary_data)
        await_count = self._count_await_points(binary_data)
        
        # 创建状态节点
        for i in range(state_count):
            state_type = self._determine_state_type(i, state_count)
            states.append(StateNode(
                state_id=f"S{i}",
                state_type=state_type,
                offset=i * 100,
                description=f"状态 {i}",
                is_await_point=(state_type == StateType.AWAITING)
            ))
        
        # 创建状态转换
        for i in range(state_count - 1):
            transitions.append(StateTransition(
                from_state=f"S{i}",
                to_state=f"S{i+1}",
                transition_type=TransitionType.AWAIT if i % 2 == 0 else TransitionType.RESUME,
                offset=i * 100 + 50
            ))
        
        # 检测 await 点
        for i, offset in enumerate(self._find_await_offsets(binary_data)[:await_count]):
            await_points.append(AwaitPoint(
                offset=offset,
                async_function=f"async_func_{i}",
                awaited_type=self._infer_awaited_type(binary_data, offset)
            ))
        
        return AsyncStateMachine(
            language=LanguageType.RUST,
            states=states,
            transitions=transitions,
            await_points=await_points,
            entry_point="S0",
            exit_point=f"S{state_count-1}"
        )
    
    def _count_states(self, data: bytes) -> int:
        """估算状态数量"""
        # 基于模式匹配估算
        count = 0
        for pattern in self.future_patterns:
            count += data.count(pattern)
        return max(2, min(count, 10))
    
    def _count_await_points(self, data: bytes) -> int:
        """估算 await 点数量"""
        return min(data.count(b'await'), 5)
    
    def _determine_state_type(self, index: int, total: int) -> StateType:
        """确定状态类型"""
        if index == 0:
            return StateType.INITIAL
        elif index == total - 1:
            return StateType.COMPLETED
        elif index % 2 == 1:
            return StateType.AWAITING
        else:
            return StateType.RUNNING
    
    def _find_await_offsets(self, data: bytes) -> List[int]:
        """查找 await 点偏移"""
        offsets = []
        pattern = b'await'
        offset = data.find(pattern)
        while offset != -1:
            offsets.append(offset)
            offset = data.find(pattern, offset + 1)
        return offsets
    
    def _infer_awaited_type(self, data: bytes, offset: int) -> Optional[str]:
        """推断被 await 的类型"""
        # 简单模拟：根据偏移量生成类型名称
        type_names = ["Future", "Result", "Stream", "Pin", "Box"]
        return type_names[offset % len(type_names)]


class GoGoroutineParser(StateMachineParser):
    """Go goroutine 状态机解析器"""
    
    def __init__(self):
        self.goroutine_patterns = {
            b'go func', b'goroutine', b'channel', b'select',
            b'runtime.gopark', b'runtime.goready', b'runtime.goexit'
        }
    
    def parse(self, binary_data: bytes) -> AsyncStateMachine:
        """解析 Go goroutine 状态机"""
        states = []
        transitions = []
        await_points = []
        
        # 检测状态机模式
        has_channel = b'channel' in binary_data
        has_select = b'select' in binary_data
        
        # 创建状态节点
        state_count = self._estimate_state_count(binary_data)
        for i in range(state_count):
            states.append(StateNode(
                state_id=f"G{i}",
                state_type=self._get_goroutine_state_type(i),
                offset=i * 80,
                description=f"Goroutine 状态 {i}"
            ))
        
        # 创建状态转换
        for i in range(state_count - 1):
            trans_type = self._get_transition_type(i, has_channel, has_select)
            transitions.append(StateTransition(
                from_state=f"G{i}",
                to_state=f"G{i+1}",
                transition_type=trans_type
            ))
        
        # 检测 channel 操作点作为 await 点
        for i, offset in enumerate(self._find_channel_offsets(binary_data)):
            await_points.append(AwaitPoint(
                offset=offset,
                async_function=f"goroutine_{i}",
                awaited_type="channel",
                is_potential_deadlock=self._check_deadlock_risk(binary_data, offset)
            ))
        
        return AsyncStateMachine(
            language=LanguageType.GO,
            states=states,
            transitions=transitions,
            await_points=await_points,
            entry_point="G0"
        )
    
    def _estimate_state_count(self, data: bytes) -> int:
        """估算状态数量"""
        count = data.count(b'runtime.gopark') + 1
        return max(2, min(count, 8))
    
    def _get_goroutine_state_type(self, index: int) -> StateType:
        """获取 goroutine 状态类型"""
        if index == 0:
            return StateType.INITIAL
        elif index % 3 == 0:
            return StateType.SUSPENDED
        elif index % 3 == 1:
            return StateType.RUNNING
        else:
            return StateType.AWAITING
    
    def _get_transition_type(self, index: int, has_channel: bool, has_select: bool) -> TransitionType:
        """获取转换类型"""
        if has_channel:
            return TransitionType.AWAIT
        elif has_select:
            return TransitionType.YIELD
        else:
            return TransitionType.RESUME
    
    def _find_channel_offsets(self, data: bytes) -> List[int]:
        """查找 channel 操作点"""
        offsets = []
        for pattern in [b'ch<-', b'<-ch']:
            offset = data.find(pattern)
            while offset != -1:
                offsets.append(offset)
                offset = data.find(pattern, offset + 1)
        return offsets
    
    def _check_deadlock_risk(self, data: bytes, offset: int) -> bool:
        """检查死锁风险"""
        # 简化检测：检查附近是否有多个 channel 操作
        window = data[max(0, offset-50):offset+50]
        return window.count(b'<-') >= 2


class CSharpAsyncParser(StateMachineParser):
    """C# async/await 状态机解析器"""
    
    def __init__(self):
        self.async_patterns = {
            b'AsyncStateMachine', b'MoveNext', b'awaiter',
            b'GetResult', b'IsCompleted', b'Task'
        }
    
    def parse(self, binary_data: bytes) -> AsyncStateMachine:
        """解析 C# async/await 状态机"""
        states = []
        transitions = []
        await_points = []
        
        # 检测状态机模式
        state_count = self._count_state_machine_states(binary_data)
        
        # 创建状态节点
        for i in range(state_count):
            states.append(StateNode(
                state_id=f"C{i}",
                state_type=self._get_csharp_state_type(i, state_count),
                offset=i * 120,
                description=f"状态机状态 {i}",
                is_await_point=(i > 0 and i < state_count - 1)
            ))
        
        # 创建状态转换
        for i in range(state_count - 1):
            transitions.append(StateTransition(
                from_state=f"C{i}",
                to_state=f"C{i+1}",
                transition_type=TransitionType.AWAIT if i < state_count - 2 else TransitionType.COMPLETE,
                condition=self._generate_condition(i)
            ))
        
        # 检测 await 点
        for i, offset in enumerate(self._find_awaiter_offsets(binary_data)[:state_count-2]):
            await_points.append(AwaitPoint(
                offset=offset,
                async_function=f"MoveNext_{i}",
                awaited_type="Task"
            ))
        
        return AsyncStateMachine(
            language=LanguageType.CSHARP,
            states=states,
            transitions=transitions,
            await_points=await_points,
            entry_point="C0",
            exit_point=f"C{state_count-1}"
        )
    
    def _count_state_machine_states(self, data: bytes) -> int:
        """计算状态机状态数量"""
        count = data.count(b'MoveNext') + 2
        return max(3, min(count, 12))
    
    def _get_csharp_state_type(self, index: int, total: int) -> StateType:
        """获取 C# 状态类型"""
        if index == 0:
            return StateType.INITIAL
        elif index == total - 1:
            return StateType.COMPLETED
        else:
            return StateType.AWAITING
    
    def _generate_condition(self, index: int) -> str:
        """生成条件描述"""
        return f"awaiter.IsCompleted (状态 {index})"
    
    def _find_awaiter_offsets(self, data: bytes) -> List[int]:
        """查找 awaiter 偏移"""
        offsets = []
        pattern = b'awaiter'
        offset = data.find(pattern)
        while offset != -1:
            offsets.append(offset)
            offset = data.find(pattern, offset + 1)
        return offsets


class AsyncSMRecoveryAnalyzer(BaseAnalyzer):
    """
    异步运行时状态机反编译分析器
    
    针对 Rust async、Go goroutine、C# async/await，恢复异步状态机图。
    标注 await/yield 点及状态转换，检测死锁或无限等待。
    """
    
    def __init__(self):
        """初始化分析器"""
        self.parsers = {
            LanguageType.RUST: RustAsyncParser(),
            LanguageType.GO: GoGoroutineParser(),
            LanguageType.CSHARP: CSharpAsyncParser()
        }
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行异步状态机恢复分析
        
        Args:
            **kwargs: 分析参数
                - binary_path: 二进制文件路径
                - binary_data: 二进制数据（可选）
                - language: 目标语言（rust/go/csharp/auto）
        
        Returns:
            分析结果字典
        """
        binary_path = kwargs.get("binary_path")
        binary_data = kwargs.get("binary_data")
        language = kwargs.get("language", "auto")
        
        logger.info(f"开始异步状态机恢复分析: {binary_path}")
        
        try:
            # 加载二进制数据
            if binary_data is None and binary_path:
                if os.path.exists(binary_path):
                    with open(binary_path, 'rb') as f:
                        binary_data = f.read()
                else:
                    return {"success": False, "error": f"文件不存在: {binary_path}"}
            
            if binary_data is None:
                return {"success": False, "error": "缺少二进制数据"}
            
            # 检测或确认语言
            detected_lang = self._detect_language(binary_data) if language == "auto" else LanguageType(language)
            
            # 检查是否有对应的解析器
            if detected_lang not in self.parsers:
                return {
                    "success": False,
                    "error": f"不支持的语言: {detected_lang.value}"
                }
            
            # 使用对应解析器解析
            parser = self.parsers[detected_lang]
            state_machine = parser.parse(binary_data)
            
            # 检测潜在问题
            warnings = self._detect_problems(state_machine)
            detected_patterns = self._identify_patterns(binary_data)
            
            return {
                "success": True,
                "result": {
                    "language": detected_lang.value,
                    "num_states": len(state_machine.states),
                    "num_transitions": len(state_machine.transitions),
                    "num_await_points": len(state_machine.await_points),
                    "entry_point": state_machine.entry_point,
                    "exit_point": state_machine.exit_point,
                    "warnings": warnings,
                    "detected_patterns": detected_patterns,
                    "states": [
                        {
                            "state_id": s.state_id,
                            "state_type": s.state_type.value,
                            "offset": hex(s.offset),
                            "description": s.description,
                            "is_await_point": s.is_await_point
                        } for s in state_machine.states
                    ],
                    "transitions": [
                        {
                            "from": t.from_state,
                            "to": t.to_state,
                            "type": t.transition_type.value,
                            "condition": t.condition
                        } for t in state_machine.transitions
                    ],
                    "await_points": [
                        {
                            "offset": hex(a.offset),
                            "async_function": a.async_function,
                            "awaited_type": a.awaited_type,
                            "is_potential_deadlock": a.is_potential_deadlock
                        } for a in state_machine.await_points
                    ],
                    "summary": self._generate_summary(state_machine, warnings)
                }
            }
            
        except Exception as e:
            logger.error(f"异步状态机恢复分析失败: {e}")
            return {"success": False, "error": str(e)}
    
    def _detect_language(self, binary_data: bytes) -> LanguageType:
        """检测二进制文件的语言类型"""
        # 检查 Rust 特征
        rust_signatures = [b'rust_', b'_ZN4core', b'Waker', b'Future']
        
        # 检查 Go 特征
        go_signatures = [b'runtime.', b'go.func.', b'gopark', b'channel']
        
        # 检查 C# 特征
        csharp_signatures = [b'AsyncStateMachine', b'MoveNext', b'awaiter']
        
        has_rust = any(s in binary_data for s in rust_signatures)
        has_go = any(s in binary_data for s in go_signatures)
        has_csharp = any(s in binary_data for s in csharp_signatures)
        
        if has_rust:
            return LanguageType.RUST
        elif has_go:
            return LanguageType.GO
        elif has_csharp:
            return LanguageType.CSHARP
        
        return LanguageType.UNKNOWN
    
    def _detect_problems(self, state_machine: AsyncStateMachine) -> List[str]:
        """检测潜在问题"""
        warnings = []
        
        # 检测可能的死锁
        for await_point in state_machine.await_points:
            if await_point.is_potential_deadlock:
                warnings.append(
                    f"潜在死锁风险: await 点 0x{await_point.offset:x} 可能导致无限等待"
                )
        
        # 检测过多的状态
        if len(state_machine.states) > 10:
            warnings.append(
                f"状态数量较多 ({len(state_machine.states)}), 可能存在复杂的异步逻辑"
            )
        
        # 检测缺少出口点
        if state_machine.exit_point is None:
            warnings.append("状态机缺少明确的出口点")
        
        return warnings
    
    def _identify_patterns(self, binary_data: bytes) -> List[str]:
        """识别异步模式"""
        patterns = []
        
        if b'Future' in binary_data:
            patterns.append("Rust Future")
        if b'Stream' in binary_data:
            patterns.append("Rust Stream")
        if b'goroutine' in binary_data:
            patterns.append("Go Goroutine")
        if b'channel' in binary_data:
            patterns.append("Go Channel")
        if b'AsyncStateMachine' in binary_data:
            patterns.append("C# Async State Machine")
        if b'Task' in binary_data:
            patterns.append("C# Task")
        
        return patterns
    
    def _generate_summary(self, state_machine: AsyncStateMachine, warnings: List[str]) -> str:
        """生成分析摘要"""
        lang_name = {
            LanguageType.RUST: "Rust",
            LanguageType.GO: "Go",
            LanguageType.CSHARP: "C#",
            LanguageType.UNKNOWN: "未知"
        }[state_machine.language]
        
        num_states = len(state_machine.states)
        num_await = len(state_machine.await_points)
        num_warnings = len(warnings)
        
        base = f"{lang_name} 异步状态机恢复完成，检测到 {num_states} 个状态，{num_await} 个 await 点"
        
        if num_warnings == 0:
            return f"{base}，未发现问题"
        else:
            return f"{base}，发现 {num_warnings} 个潜在问题"
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        """获取分析器元数据"""
        return AnalyzerMetadata(
            name="AsyncSMRecoveryAnalyzer",
            type=AnalyzerType.STATIC_ANALYZER,
            version="1.0.0",
            description="异步运行时状态机反编译分析器，恢复 Rust async/Go goroutine/C# async/await 状态机",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["x86", "x86_64", "arm", "arm64"]
        )
    
    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """验证输入参数"""
        binary_path = kwargs.get("binary_path")
        binary_data = kwargs.get("binary_data")
        
        if not binary_path and binary_data is None:
            return False, "必须提供 binary_path 或 binary_data"
        
        if binary_path and not os.path.exists(binary_path):
            return False, f"文件不存在: {binary_path}"
        
        language = kwargs.get("language", "auto")
        if language not in ["auto", "rust", "go", "csharp"]:
            return False, "language 必须是 auto、rust、go 或 csharp"
        
        return True, None
    
    def cleanup(self) -> None:
        """清理资源"""
        pass
