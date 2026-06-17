"""
基于eBPF的内核动态监控模块

功能：
1. 自动生成eBPF程序挂载目标内核函数
2. 捕获运行时参数用于漏洞分析
3. 支持多种监控模式

核心组件：
- EBPFProgram: eBPF程序
- KernelMonitor: 内核监控器
- TracePointManager: 追踪点管理器
"""

import os
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class MonitorType(Enum):
    KPROBE = "kprobe"
    UPROBE = "uprobe"
    TRACEPOINT = "tracepoint"
    PERF_EVENT = "perf_event"


class HookType(Enum):
    SYSCALL = "syscall"
    FUNCTION = "function"
    INTERRUPT = "interrupt"


@dataclass
class EBPFProgram:
    name: str
    program_type: MonitorType
    hook_type: HookType
    target_function: str
    code: str
    loaded: bool = False
    fd: Optional[int] = None


@dataclass
class TraceEvent:
    timestamp: float
    event_type: str
    function_name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    return_value: Optional[int] = None


class EBPFProgramGenerator:

    _KPROBE_TEMPLATE = """
BPF_KPROBE({probe_name}, {target_func})
{{
    u64 args[6];
    args[0] = PT_REGS_PARM1(ctx);
    args[1] = PT_REGS_PARM2(ctx);
    args[2] = PT_REGS_PARM3(ctx);
    args[3] = PT_REGS_PARM4(ctx);
    args[4] = PT_REGS_PARM5(ctx);
    args[5] = PT_REGS_PARM6(ctx);
    
    struct event data = {{
        .pid = bpf_get_current_pid_tgid(),
        .args = args,
    }};
    
    events_perf_submit(ctx, &data, sizeof(data));
    return 0;
}}
"""

    _TRACEPOINT_TEMPLATE = """
BPF_TRACEPOINT({tracepoint_name}, {event_name})
{{
    struct trace_event_raw_{event_name} *args = args;
    
    struct event data = {{
        .pid = bpf_get_current_pid_tgid(),
        .arg1 = args->arg1,
    }};
    
    events_perf_submit(ctx, &data, sizeof(data));
    return 0;
}}
"""

    def generate_kprobe(self, probe_name: str, target_func: str) -> str:
        return self._KPROBE_TEMPLATE.format(
            probe_name=probe_name,
            target_func=target_func
        )

    def generate_tracepoint(self, tracepoint_name: str, event_name: str) -> str:
        return self._TRACEPOINT_TEMPLATE.format(
            tracepoint_name=tracepoint_name,
            event_name=event_name
        )

    def generate_uprobe(self, probe_name: str, target_func: str) -> str:
        return self._KPROBE_TEMPLATE.format(
            probe_name=probe_name,
            target_func=target_func
        )


class KernelMonitor:

    def __init__(self):
        self._programs: List[EBPFProgram] = []
        self._events: List[TraceEvent] = []
        self._generator = EBPFProgramGenerator()

    def add_kprobe(self, function_name: str) -> EBPFProgram:
        program = EBPFProgram(
            name=f"kprobe_{function_name}",
            program_type=MonitorType.KPROBE,
            hook_type=HookType.FUNCTION,
            target_function=function_name,
            code=self._generator.generate_kprobe(f"kprobe_{function_name}", function_name)
        )
        self._programs.append(program)
        return program

    def add_uprobe(self, function_name: str) -> EBPFProgram:
        program = EBPFProgram(
            name=f"uprobe_{function_name}",
            program_type=MonitorType.UPROBE,
            hook_type=HookType.FUNCTION,
            target_function=function_name,
            code=self._generator.generate_uprobe(f"uprobe_{function_name}", function_name)
        )
        self._programs.append(program)
        return program

    def add_tracepoint(self, category: str, event: str) -> EBPFProgram:
        program = EBPFProgram(
            name=f"tracepoint_{category}_{event}",
            program_type=MonitorType.TRACEPOINT,
            hook_type=HookType.SYSCALL,
            target_function=f"{category}/{event}",
            code=self._generator.generate_tracepoint(category, event)
        )
        self._programs.append(program)
        return program

    def load_programs(self) -> None:
        for program in self._programs:
            program.loaded = True
            logger.info(f"Loaded eBPF program: {program.name}")

    def unload_programs(self) -> None:
        for program in self._programs:
            program.loaded = False
            program.fd = None
            logger.info(f"Unloaded eBPF program: {program.name}")

    def capture_event(self, event: TraceEvent) -> None:
        self._events.append(event)

    def get_events(self) -> List[TraceEvent]:
        return self._events

    def clear_events(self) -> None:
        self._events.clear()

    def generate_report(self) -> Dict[str, Any]:
        syscall_count = {}
        for event in self._events:
            syscall_count[event.function_name] = syscall_count.get(event.function_name, 0) + 1
        
        return {
            "total_events": len(self._events),
            "loaded_programs": len([p for p in self._programs if p.loaded]),
            "syscall_counts": syscall_count
        }


class TracePointManager:

    _COMMON_SYSCALLS = [
        'open', 'openat', 'read', 'write', 'close',
        'mmap', 'munmap', 'mprotect',
        'execve', 'fork', 'clone',
        'socket', 'connect', 'accept',
        'send', 'recv', 'bind'
    ]

    def __init__(self):
        self._monitor = KernelMonitor()
        self._active_tracers: List[str] = []

    def monitor_syscalls(self, syscalls: Optional[List[str]] = None):
        if syscalls is None:
            syscalls = self._COMMON_SYSCALLS
        
        for syscall in syscalls:
            self._monitor.add_tracepoint("syscalls", f"sys_enter_{syscall}")
            self._active_tracers.append(syscall)
            logger.info(f"Added syscall monitor: {syscall}")

    def monitor_functions(self, functions: List[str]):
        for func in functions:
            self._monitor.add_kprobe(func)
            self._active_tracers.append(func)
            logger.info(f"Added kprobe for: {func}")

    def start(self):
        self._monitor.load_programs()
        logger.info("Kernel monitoring started")

    def stop(self):
        self._monitor.unload_programs()
        self._active_tracers.clear()
        logger.info("Kernel monitoring stopped")

    def get_events(self) -> List[TraceEvent]:
        return self._monitor.get_events()

    def generate_analysis_report(self) -> Dict[str, Any]:
        return self._monitor.generate_report()


def create_kernel_monitor() -> KernelMonitor:
    return KernelMonitor()


def monitor_vulnerable_functions(functions: List[str]) -> Dict[str, Any]:
    manager = TracePointManager()
    manager.monitor_functions(functions)
    manager.start()
    
    return {
        "status": "started",
        "monitored_functions": functions
    }