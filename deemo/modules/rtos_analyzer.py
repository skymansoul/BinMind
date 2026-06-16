"""
RTOS 分析模块

针对 FreeRTOS、ThreadX 等实时操作系统，识别任务、队列、ISR，检测任务间竞争和优先级反转。

Author: Binary Vulnerability Analysis Platform
Version: 1.0.0
"""

import logging
import os
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Set

from modules.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class RTOSVendor(Enum):
    """RTOS 厂商枚举"""
    FREERTOS = "freertos"
    THREADX = "threadx"
    NUTTX = "nuttx"
    MICRIUM = "micrium"
    UCOS = "ucos"
    UNKNOWN = "unknown"


class TaskPriority(Enum):
    """任务优先级枚举"""
    IDLE = "idle"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    REALTIME = "realtime"


@dataclass
class RTOSConfig:
    """RTOS 配置信息"""
    vendor: RTOSVendor
    version: Optional[str] = None
    config_items: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RTOSStack:
    """任务栈信息"""
    start_addr: int
    end_addr: int
    size: int
    watermark: Optional[int] = None


@dataclass
class RTOSTask:
    """任务信息"""
    name: str
    function_addr: int
    priority: int
    stack: RTOSStack
    state: str
    handle: Optional[int] = None
    tcb_addr: Optional[int] = None


@dataclass
class RTOSQueue:
    """队列信息"""
    name: Optional[str]
    handle: int
    base_addr: int
    length: int
    item_size: int
    waiting_tasks: List[int] = field(default_factory=list)


@dataclass
class RTOSMutex:
    """互斥锁信息"""
    name: Optional[str]
    handle: int
    holder_task: Optional[int] = None
    priority_ceiling: Optional[int] = None


@dataclass
class RTOSISR:
    """中断服务程序信息"""
    name: Optional[str]
    vector_addr: int
    handler_addr: int
    priority: int
    uses_fpu: bool = False


@dataclass
class RTOSAnalysisResult:
    """RTOS 分析结果"""
    rtos_config: RTOSConfig
    tasks: List[RTOSTask]
    queues: List[RTOSQueue]
    mutexes: List[RTOSMutex]
    isrs: List[RTOSISR]
    issues: List['RTOSIssue']
    warnings: List[str]


@dataclass
class RTOSIssue:
    """RTOS 问题报告"""
    type: str
    severity: str
    description: str
    affected_tasks: List[str] = field(default_factory=list)
    address: Optional[int] = None


class RTOSAnalyzer(BaseAnalyzer):
    """
    RTOS 分析器基类
    
    支持多种 RTOS 的统一分析接口
    """
    
    def __init__(self):
        self.binary_data: bytes = b""
        self.binary_path: str = ""
        self.rtos_config: Optional[RTOSConfig] = None
        self.tasks: List[RTOSTask] = []
        self.queues: List[RTOSQueue] = []
        self.mutexes: List[RTOSMutex] = []
        self.isrs: List[RTOSISR] = []
        self.issues: List[RTOSIssue] = []
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行 RTOS 分析
        
        Args:
            **kwargs: 分析参数，必须包含 'binary_path'
            
        Returns:
            分析结果字典
        """
        self.binary_path = kwargs.get("binary_path", "")
        if not self.binary_path:
            return {"success": False, "error": "binary_path 是必需参数"}
        
        if not os.path.exists(self.binary_path):
            return {"success": False, "error": f"文件不存在: {self.binary_path}"}
        
        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()
            
            # 识别 RTOS 类型
            vendor = self._identify_rtos_vendor()
            self.rtos_config = RTOSConfig(vendor=vendor)
            
            # 提取任务信息
            self._extract_tasks()
            
            # 提取队列信息
            self._extract_queues()
            
            # 提取互斥锁信息
            self._extract_mutexes()
            
            # 提取 ISR 信息
            self._extract_isrs()
            
            # 检测问题
            self._detect_issues()
            
            result = RTOSAnalysisResult(
                rtos_config=self.rtos_config,
                tasks=self.tasks,
                queues=self.queues,
                mutexes=self.mutexes,
                isrs=self.isrs,
                issues=self.issues,
                warnings=[]
            )
            
            return {
                "success": True,
                "result": {
                    "rtos_vendor": self.rtos_config.vendor.value,
                    "task_count": len(self.tasks),
                    "queue_count": len(self.queues),
                    "mutex_count": len(self.mutexes),
                    "isr_count": len(self.isrs),
                    "issue_count": len(self.issues),
                    "tasks": [self._task_to_dict(t) for t in self.tasks],
                    "queues": [self._queue_to_dict(q) for q in self.queues],
                    "mutexes": [self._mutex_to_dict(m) for m in self.mutexes],
                    "isrs": [self._isr_to_dict(i) for i in self.isrs],
                    "issues": [self._issue_to_dict(i) for i in self.issues]
                }
            }
        except Exception as e:
            logger.error(f"RTOS 分析失败: {e}")
            return {"success": False, "error": str(e)}
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="RTOSAnalyzer",
            type=AnalyzerType.STATIC_ANALYZER,
            version="1.0.0",
            description="RTOS 分析器，识别任务、队列、ISR，检测任务间竞争和优先级反转",
            author="BinaryAnalysisPlatform",
            supported_platforms=["arm", "arm64", "riscv"]
        )
    
    def _identify_rtos_vendor(self) -> RTOSVendor:
        """识别 RTOS 厂商"""
        data = self.binary_data
        
        # FreeRTOS 特征
        free_rtos_signatures = [
            b"FreeRTOS",
            b"vTaskStartScheduler",
            b"xQueueSend",
            b"xSemaphoreTake",
            b"pvPortMalloc"
        ]
        
        # ThreadX 特征
        threadx_signatures = [
            b"TX_THREAD",
            b"tx_thread_create",
            b"tx_queue_send",
            b"tx_mutex_get"
        ]
        
        # NuttX 特征
        nuttx_signatures = [
            b"NuttX",
            b"sched_task_create",
            b"sem_wait"
        ]
        
        # Micrium 特征
        micrium_signatures = [
            b"uC/OS",
            b"OSTaskCreate",
            b"OSMutexCreate"
        ]
        
        if any(sig in data for sig in free_rtos_signatures):
            return RTOSVendor.FREERTOS
        elif any(sig in data for sig in threadx_signatures):
            return RTOSVendor.THREADX
        elif any(sig in data for sig in nuttx_signatures):
            return RTOSVendor.NUTTX
        elif any(sig in data for sig in micrium_signatures):
            return RTOSVendor.MICRIUM
        
        return RTOSVendor.UNKNOWN
    
    def _extract_tasks(self) -> None:
        """提取任务信息"""
        if self.rtos_config.vendor == RTOSVendor.FREERTOS:
            self._extract_freertos_tasks()
        elif self.rtos_config.vendor == RTOSVendor.THREADX:
            self._extract_threadx_tasks()
        else:
            self._generic_task_extraction()
    
    def _extract_freertos_tasks(self) -> None:
        """提取 FreeRTOS 任务"""
        # FreeRTOS TCB 结构特征
        # typedef struct tskTaskControlBlock {
        #     volatile StackType_t *pxTopOfStack;
        #     ListItem_t xStateListItem;
        #     ListItem_t xEventListItem;
        #     UBaseType_t uxPriority;
        #     StackType_t *pxStack;
        #     char pcTaskName[ configMAX_TASK_NAME_LEN ];
        #     ...
        # }
        
        # 搜索任务名称字符串
        import re
        # 查找类似 "TaskName" 后跟空字符的模式
        task_pattern = re.compile(rb'([A-Za-z_][A-Za-z0-9_]{2,31})\x00')
        matches = task_pattern.findall(self.binary_data)
        
        for match in matches[:20]:  # 最多提取20个任务
            try:
                task_name = match.decode('ascii')
                # 排除明显不是任务名的字符串
                if len(task_name) < 3 or len(task_name) > 32:
                    continue
                if task_name.lower() in ['malloc', 'free', 'memcpy', 'printf']:
                    continue
                
                addr = self.binary_data.find(match)
                self.tasks.append(RTOSTask(
                    name=task_name,
                    function_addr=0,
                    priority=1,
                    stack=RTOSStack(start_addr=0, end_addr=0, size=0),
                    state="unknown",
                    tcb_addr=addr
                ))
            except:
                continue
    
    def _extract_threadx_tasks(self) -> None:
        """提取 ThreadX 任务"""
        # ThreadX 任务结构不同，使用类似的启发式方法
        import re
        task_pattern = re.compile(rb'([A-Za-z_][A-Za-z0-9_]{2,31})\x00')
        matches = task_pattern.findall(self.binary_data)
        
        for match in matches[:20]:
            try:
                task_name = match.decode('ascii')
                if len(task_name) < 3 or len(task_name) > 32:
                    continue
                
                self.tasks.append(RTOSTask(
                    name=task_name,
                    function_addr=0,
                    priority=1,
                    stack=RTOSStack(start_addr=0, end_addr=0, size=0),
                    state="unknown"
                ))
            except:
                continue
    
    def _generic_task_extraction(self) -> None:
        """通用任务提取"""
        import re
        task_pattern = re.compile(rb'(Task[A-Z][a-zA-Z0-9_]*|_[a-z]+_task)\x00')
        matches = task_pattern.findall(self.binary_data)
        
        for match in matches[:20]:
            try:
                task_name = match.decode('ascii')
                self.tasks.append(RTOSTask(
                    name=task_name,
                    function_addr=0,
                    priority=1,
                    stack=RTOSStack(start_addr=0, end_addr=0, size=0),
                    state="unknown"
                ))
            except:
                continue
    
    def _extract_queues(self) -> None:
        """提取队列信息"""
        import re
        queue_pattern = re.compile(rb'(Queue[A-Z][a-zA-Z0-9_]*|_[a-z]+_queue)\x00')
        matches = queue_pattern.findall(self.binary_data)
        
        for match in matches[:10]:
            try:
                queue_name = match.decode('ascii')
                self.queues.append(RTOSQueue(
                    name=queue_name,
                    handle=0,
                    base_addr=0,
                    length=0,
                    item_size=0
                ))
            except:
                continue
    
    def _extract_mutexes(self) -> None:
        """提取互斥锁信息"""
        import re
        mutex_pattern = re.compile(rb'(Mutex[A-Z][a-zA-Z0-9_]*|_[a-z]+_mutex)\x00')
        matches = mutex_pattern.findall(self.binary_data)
        
        for match in matches[:10]:
            try:
                mutex_name = match.decode('ascii')
                self.mutexes.append(RTOSMutex(
                    name=mutex_name,
                    handle=0
                ))
            except:
                continue
    
    def _extract_isrs(self) -> None:
        """提取 ISR 信息"""
        import re
        isr_pattern = re.compile(rb'(ISR[A-Z][a-zA-Z0-9_]*|_[a-z]+_isr|IRQ_)\x00')
        matches = isr_pattern.findall(self.binary_data)
        
        for match in matches[:10]:
            try:
                isr_name = match.decode('ascii')
                self.isrs.append(RTOSISR(
                    name=isr_name,
                    vector_addr=0,
                    handler_addr=0,
                    priority=0
                ))
            except:
                continue
    
    def _detect_issues(self) -> None:
        """检测 RTOS 相关问题"""
        self._detect_priority_inversion()
        self._detect_task_competition()
        self._detect_stack_overflow_risk()
    
    def _detect_priority_inversion(self) -> None:
        """检测优先级反转问题"""
        if len(self.tasks) >= 2:
            # 检查是否存在低优先级任务持有高优先级任务需要的锁
            for mutex in self.mutexes:
                if mutex.holder_task is not None:
                    for task in self.tasks:
                        if task.priority > 0 and mutex.holder_task != task.handle:
                            self.issues.append(RTOSIssue(
                                type="priority_inversion",
                                severity="high",
                                description=f"可能存在优先级反转: 低优先级任务持有互斥锁 {mutex.name}",
                                affected_tasks=[task.name] if task.name else []
                            ))
    
    def _detect_task_competition(self) -> None:
        """检测任务间竞争条件"""
        if len(self.queues) > 0:
            for queue in self.queues:
                if len(queue.waiting_tasks) > 1:
                    self.issues.append(RTOSIssue(
                        type="task_competition",
                        severity="medium",
                        description=f"多个任务等待同一队列: {queue.name}",
                        affected_tasks=[f"Task {t}" for t in queue.waiting_tasks]
                    ))
    
    def _detect_stack_overflow_risk(self) -> None:
        """检测栈溢出风险"""
        for task in self.tasks:
            if task.stack.size > 0 and task.stack.size < 512:
                self.issues.append(RTOSIssue(
                    type="stack_overflow_risk",
                    severity="medium",
                    description=f"任务 {task.name} 栈大小过小 ({task.stack.size} bytes)",
                    affected_tasks=[task.name]
                ))
    
    def _task_to_dict(self, task: RTOSTask) -> Dict[str, Any]:
        """任务转字典"""
        return {
            "name": task.name,
            "function_addr": hex(task.function_addr),
            "priority": task.priority,
            "stack": {
                "start_addr": hex(task.stack.start_addr),
                "end_addr": hex(task.stack.end_addr),
                "size": task.stack.size
            },
            "state": task.state,
            "handle": hex(task.handle) if task.handle else None,
            "tcb_addr": hex(task.tcb_addr) if task.tcb_addr else None
        }
    
    def _queue_to_dict(self, queue: RTOSQueue) -> Dict[str, Any]:
        """队列转字典"""
        return {
            "name": queue.name,
            "handle": hex(queue.handle),
            "base_addr": hex(queue.base_addr),
            "length": queue.length,
            "item_size": queue.item_size,
            "waiting_task_count": len(queue.waiting_tasks)
        }
    
    def _mutex_to_dict(self, mutex: RTOSMutex) -> Dict[str, Any]:
        """互斥锁转字典"""
        return {
            "name": mutex.name,
            "handle": hex(mutex.handle),
            "has_holder": mutex.holder_task is not None,
            "priority_ceiling": mutex.priority_ceiling
        }
    
    def _isr_to_dict(self, isr: RTOSISR) -> Dict[str, Any]:
        """ISR转字典"""
        return {
            "name": isr.name,
            "vector_addr": hex(isr.vector_addr),
            "handler_addr": hex(isr.handler_addr),
            "priority": isr.priority,
            "uses_fpu": isr.uses_fpu
        }
    
    def _issue_to_dict(self, issue: RTOSIssue) -> Dict[str, Any]:
        """问题转字典"""
        return {
            "type": issue.type,
            "severity": issue.severity,
            "description": issue.description,
            "affected_tasks": issue.affected_tasks,
            "address": hex(issue.address) if issue.address else None
        }


# 便捷函数
def analyze_rtos(binary_path: str) -> Dict[str, Any]:
    """
    分析 RTOS 固件
    
    Args:
        binary_path: 固件文件路径
    
    Returns:
        分析结果
    """
    analyzer = RTOSAnalyzer()
    return analyzer.analyze(binary_path=binary_path)
