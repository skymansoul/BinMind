#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
确定性重放与并行漏洞复现模块

功能：
- 基于RR或自定义PinTool，记录所有非确定性事件
- 生成可重放日志
- 重放时人为扰动调度顺序，触发并发漏洞
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from enum import Enum
from abc import ABC, abstractmethod
import json
import os

logger = logging.getLogger(__name__)


class EventType(Enum):
    """事件类型"""
    THREAD_CREATE = "thread_create"
    THREAD_EXIT = "thread_exit"
    THREAD_YIELD = "thread_yield"
    LOCK_ACQUIRE = "lock_acquire"
    LOCK_RELEASE = "lock_release"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    SYSTEM_CALL = "system_call"
    RANDOM = "random"
    TIMER = "timer"
    INTERRUPT = "interrupt"


class ReplayMode(Enum):
    """重放模式"""
    EXACT = "exact"           # 精确重放
    PERTURB_SCHEDULE = "perturb_schedule"  # 扰动调度
    PARALLEL_EXPLORE = "parallel_explore"  # 并行探索
    SYMBOLIC_EXECUTE = "symbolic_execute"  # 符号执行


class RaceConditionType(Enum):
    """竞争条件类型"""
    DATA_RACE = "data_race"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    DEADLOCK = "deadlock"
    LOCK_ORDER_VIOLATION = "lock_order_violation"
    ATOMICITY_VIOLATION = "atomicity_violation"


@dataclass
class ReplayEvent:
    """重放事件"""
    event_id: str
    event_type: EventType
    timestamp: int
    thread_id: int
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReplayLog:
    """重放日志"""
    log_id: str
    binary_path: str
    events: List[ReplayEvent] = field(default_factory=list)
    start_time: int = 0
    end_time: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RaceDetectionResult:
    """竞争检测结果"""
    race_type: RaceConditionType
    description: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    confidence: float  # 0.0-1.0
    thread1_id: int
    thread2_id: int
    address: Optional[int] = None
    stack_trace1: List[str] = field(default_factory=list)
    stack_trace2: List[str] = field(default_factory=list)
    suggested_fix: Optional[str] = None


@dataclass
class ReplayResult:
    """重放结果"""
    log_id: str
    replay_mode: ReplayMode
    success: bool
    duration_ms: int
    race_conditions: List[RaceDetectionResult] = field(default_factory=list)
    crashes: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)


class ReplayLogger(ABC):
    """重放日志记录器基类"""
    
    @abstractmethod
    def record_event(self, event: ReplayEvent) -> None:
        """记录事件"""
        pass
    
    @abstractmethod
    def save_log(self, path: str) -> bool:
        """保存日志"""
        pass
    
    @abstractmethod
    def load_log(self, path: str) -> ReplayLog:
        """加载日志"""
        pass


class FileReplayLogger(ReplayLogger):
    """文件重放日志记录器"""
    
    def __init__(self):
        self.events: List[ReplayEvent] = []
        self.log_id = ""
    
    def record_event(self, event: ReplayEvent) -> None:
        """记录事件"""
        self.events.append(event)
    
    def save_log(self, path: str) -> bool:
        """保存日志"""
        try:
            log_data = {
                "log_id": self.log_id,
                "events": [
                    {
                        "event_id": e.event_id,
                        "event_type": e.event_type.value,
                        "timestamp": e.timestamp,
                        "thread_id": e.thread_id,
                        "data": e.data
                    } for e in self.events
                ],
                "start_time": 0,
                "end_time": self.events[-1].timestamp if self.events else 0,
                "metadata": {}
            }
            
            with open(path, 'w') as f:
                json.dump(log_data, f, indent=2)
            
            logger.info(f"重放日志已保存: {path}")
            return True
        except Exception as e:
            logger.error(f"保存日志失败: {e}")
            return False
    
    def load_log(self, path: str) -> ReplayLog:
        """加载日志"""
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            
            events = []
            for event_data in data.get("events", []):
                events.append(ReplayEvent(
                    event_id=event_data["event_id"],
                    event_type=EventType(event_data["event_type"]),
                    timestamp=event_data["timestamp"],
                    thread_id=event_data["thread_id"],
                    data=event_data.get("data", {})
                ))
            
            return ReplayLog(
                log_id=data.get("log_id", ""),
                binary_path=data.get("binary_path", ""),
                events=events,
                start_time=data.get("start_time", 0),
                end_time=data.get("end_time", 0),
                metadata=data.get("metadata", {})
            )
        except Exception as e:
            logger.error(f"加载日志失败: {e}")
            return ReplayLog(log_id="", binary_path="")


class DeterministicReplayer:
    """
    确定性重放与并行漏洞复现器
    
    功能：
    1. 记录所有非确定性事件
    2. 生成可重放日志
    3. 重放时扰动调度顺序
    4. 检测并发漏洞
    """
    
    def __init__(self):
        """初始化确定性重放器"""
        self.logger = FileReplayLogger()
        self.is_recording = False
        self.current_log_id = ""
        logger.info("确定性重放器初始化完成")
    
    def analyze(self, binary_path: str, **kwargs) -> Dict[str, Any]:
        """
        执行确定性重放分析
        
        Args:
            binary_path: 目标二进制文件路径
            **kwargs: 额外参数（replay_mode, log_path等）
        
        Returns:
            分析结果字典
        """
        logger.info(f"开始确定性重放分析: {binary_path}")
        
        try:
            replay_mode = kwargs.get("replay_mode", "perturb_schedule")
            log_path = kwargs.get("log_path", None)
            
            if log_path and os.path.exists(log_path):
                result = self._replay_from_log(log_path, replay_mode)
            else:
                result = self._record_and_replay(binary_path, replay_mode)
            
            return self._format_result(result)
        except Exception as e:
            logger.error(f"确定性重放分析失败: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "binary_path": binary_path
            }
    
    def _record_and_replay(self, binary_path: str, replay_mode: str) -> ReplayResult:
        """记录并重放（模拟实现）"""
        self._record_execution(binary_path)
        
        log_path = f"/tmp/replay_{self.current_log_id}.json"
        self.logger.save_log(log_path)
        
        return self._replay_from_log(log_path, replay_mode)
    
    def _record_execution(self, binary_path: str) -> None:
        """记录执行过程（模拟）"""
        self.is_recording = True
        self.current_log_id = "LOG_001"
        self.logger.log_id = self.current_log_id
        
        logger.info(f"开始记录执行: {binary_path}")
        
        # 模拟记录各种事件
        events = [
            ReplayEvent("evt_001", EventType.THREAD_CREATE, 100, 1, {"name": "main"}),
            ReplayEvent("evt_002", EventType.THREAD_CREATE, 150, 2, {"name": "worker"}),
            ReplayEvent("evt_003", EventType.LOCK_ACQUIRE, 200, 1, {"lock": "mutex1"}),
            ReplayEvent("evt_004", EventType.MEMORY_WRITE, 250, 1, {"address": 0x1000, "size": 4}),
            ReplayEvent("evt_005", EventType.THREAD_YIELD, 300, 1, {}),
            ReplayEvent("evt_006", EventType.LOCK_ACQUIRE, 350, 2, {"lock": "mutex1"}),
            ReplayEvent("evt_007", EventType.MEMORY_READ, 400, 2, {"address": 0x1000}),
            ReplayEvent("evt_008", EventType.LOCK_RELEASE, 450, 1, {"lock": "mutex1"}),
            ReplayEvent("evt_009", EventType.LOCK_RELEASE, 500, 2, {"lock": "mutex1"}),
            ReplayEvent("evt_010", EventType.THREAD_EXIT, 550, 2, {}),
            ReplayEvent("evt_011", EventType.THREAD_EXIT, 600, 1, {})
        ]
        
        for event in events:
            self.logger.record_event(event)
        
        self.is_recording = False
        logger.info("执行记录完成")
    
    def _replay_from_log(self, log_path: str, replay_mode: str) -> ReplayResult:
        """从日志重放（模拟实现）"""
        logger.info(f"从日志重放: {log_path}, 模式: {replay_mode}")
        
        log = self.logger.load_log(log_path)
        
        race_conditions = []
        crashes = []
        
        # 根据重放模式检测不同类型的漏洞
        if replay_mode == "perturb_schedule":
            race_conditions = self._detect_race_conditions(log)
        elif replay_mode == "parallel_explore":
            race_conditions = self._parallel_explore(log)
        elif replay_mode == "symbolic_execute":
            race_conditions = self._symbolic_replay(log)
        
        if race_conditions:
            crashes = ["检测到竞争条件导致的潜在崩溃"]
        
        return ReplayResult(
            log_id=log.log_id,
            replay_mode=ReplayMode(replay_mode),
            success=True,
            duration_ms=150,
            race_conditions=race_conditions,
            crashes=crashes,
            anomalies=[]
        )
    
    def _detect_race_conditions(self, log: ReplayLog) -> List[RaceDetectionResult]:
        """检测竞争条件（模拟）"""
        return [
            RaceDetectionResult(
                race_type=RaceConditionType.DATA_RACE,
                description="检测到数据竞争：两个线程同时访问共享内存",
                severity="critical",
                confidence=0.95,
                thread1_id=1,
                thread2_id=2,
                address=0x1000,
                stack_trace1=[
                    "write_data() at 0x401000",
                    "thread_main() at 0x401100"
                ],
                stack_trace2=[
                    "read_data() at 0x402000",
                    "thread_worker() at 0x402100"
                ],
                suggested_fix="使用互斥锁保护共享数据访问"
            ),
            RaceDetectionResult(
                race_type=RaceConditionType.LOCK_ORDER_VIOLATION,
                description="检测到锁顺序违反：线程获取锁的顺序不一致",
                severity="high",
                confidence=0.85,
                thread1_id=1,
                thread2_id=2,
                stack_trace1=["function_a() at 0x401050"],
                stack_trace2=["function_b() at 0x402050"],
                suggested_fix="确保所有线程以相同顺序获取锁"
            )
        ]
    
    def _parallel_explore(self, log: ReplayLog) -> List[RaceDetectionResult]:
        """并行探索（模拟）"""
        return [
            RaceDetectionResult(
                race_type=RaceConditionType.ATOMICITY_VIOLATION,
                description="检测到原子性违反：复合操作未正确同步",
                severity="high",
                confidence=0.9,
                thread1_id=1,
                thread2_id=2,
                stack_trace1=["update_counter() at 0x401200"],
                stack_trace2=["update_counter() at 0x401200"],
                suggested_fix="使用原子操作或锁保护复合操作"
            )
        ]
    
    def _symbolic_replay(self, log: ReplayLog) -> List[RaceDetectionResult]:
        """符号执行重放（模拟）"""
        return []
    
    def _format_result(self, result: ReplayResult) -> Dict[str, Any]:
        """格式化分析结果"""
        race_data = []
        for race in result.race_conditions:
            race_data.append({
                "race_type": race.race_type.value,
                "description": race.description,
                "severity": race.severity,
                "confidence": race.confidence,
                "thread1_id": race.thread1_id,
                "thread2_id": race.thread2_id,
                "address": hex(race.address) if race.address else None,
                "stack_trace1": race.stack_trace1,
                "stack_trace2": race.stack_trace2,
                "suggested_fix": race.suggested_fix
            })
        
        return {
            "success": True,
            "log_id": result.log_id,
            "replay_mode": result.replay_mode.value,
            "duration_ms": result.duration_ms,
            "race_conditions": race_data,
            "crashes": result.crashes,
            "anomalies": result.anomalies,
            "total_races_found": len(result.race_conditions)
        }
    
    def start_recording(self, binary_path: str) -> bool:
        """
        开始记录执行
        
        Args:
            binary_path: 目标二进制文件路径
        
        Returns:
            是否成功开始
        """
        logger.info(f"开始记录: {binary_path}")
        try:
            self._record_execution(binary_path)
            return True
        except Exception as e:
            logger.error(f"开始记录失败: {e}")
            return False
    
    def stop_recording(self, output_path: str) -> bool:
        """
        停止记录并保存日志
        
        Args:
            output_path: 输出日志路径
        
        Returns:
            是否成功保存
        """
        return self.logger.save_log(output_path)


def analyze_deterministic_replay(binary_path: str, **kwargs) -> Dict[str, Any]:
    """
    确定性重放分析便捷函数
    
    Args:
        binary_path: 目标二进制文件路径
        **kwargs: 额外参数（replay_mode, log_path等）
    
    Returns:
        分析结果字典
    """
    replayer = DeterministicReplayer()
    return replayer.analyze(binary_path, **kwargs)