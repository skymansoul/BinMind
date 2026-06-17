import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class TracePoint(Enum):
    SYSCALL_ENTER = "syscall_enter"
    SYSCALL_EXIT = "syscall_exit"
    FUNCTION_ENTER = "function_enter"
    FUNCTION_EXIT = "function_exit"
    KPROBE = "kprobe"
    UPROBE = "uprobe"
    TRACEPOINT = "tracepoint"


@dataclass
class eBPFProgram:
    name: str
    type: TracePoint
    attach_point: str
    code: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    return_type: str = "int"

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'type': self.type.value,
            'attach_point': self.attach_point,
            'code': self.code,
            'arguments': self.arguments,
            'return_type': self.return_type
        }


@dataclass
class TraceData:
    timestamp: int
    pid: int
    tid: int
    function: str
    arguments: Dict[str, Any]
    return_value: Optional[int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'pid': self.pid,
            'tid': self.tid,
            'function': self.function,
            'arguments': self.arguments,
            'return_value': self.return_value
        }


@dataclass
class TraceResult:
    programs: List[eBPFProgram]
    trace_data: List[TraceData]
    summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'programs': [p.to_dict() for p in self.programs],
            'trace_data': [t.to_dict() for t in self.trace_data],
            'summary': self.summary
        }


class EbpfDynamicTracer:
    
    def __init__(self):
        self.syscall_probes = {
            'open': 'sys_open',
            'read': 'sys_read',
            'write': 'sys_write',
            'close': 'sys_close',
            'socket': 'sys_socket',
            'connect': 'sys_connect',
            'execve': 'sys_execve',
            'mmap': 'sys_mmap',
            'mprotect': 'sys_mprotect'
        }
    
    def create_programs(self, targets: List[str]) -> List[eBPFProgram]:
        programs = []
        
        for target in targets:
            if target in self.syscall_probes:
                program = self._create_syscall_probe(target)
                programs.append(program)
            else:
                program = self._create_kprobe(target)
                programs.append(program)
        
        return programs
    
    def _create_syscall_probe(self, syscall_name: str) -> eBPFProgram:
        code = f"""
SEC("tracepoint/syscalls/sys_enter_{syscall_name}")
int trace_sys_enter_{syscall_name}(struct trace_event_raw_sys_enter *ctx) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    bpf_printk("syscall_{syscall_name} enter: pid=%d, tid=%d", pid, tid);
    
    return 0;
}}
"""
        
        return eBPFProgram(
            name=f"trace_{syscall_name}",
            type=TracePoint.SYSCALL_ENTER,
            attach_point=f"syscalls/sys_enter_{syscall_name}",
            code=code.strip(),
            arguments={'syscall': syscall_name},
            return_type='int')
        

    
    def _create_kprobe(self, function_name: str) -> eBPFProgram:
        code = f"""
SEC("kprobe/{function_name}")
int kprobe_{function_name}(struct pt_regs *ctx) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    bpf_printk("kprobe_{function_name}: pid=%d", pid);
    
    return 0;
}}
"""
        
        return eBPFProgram(
            name=f"kprobe_{function_name}",
            type=TracePoint.KPROBE,
            attach_point=function_name,
            code=code.strip(),
            arguments={'function': function_name},
            return_type='int')
        

    
    def generate_bpf_code(self, programs: List[eBPFProgram]) -> str:
        parts = []
        
        parts.append("#include <vmlinux.h>")
        parts.append("#include <bpf/bpf_helpers.h>")
        parts.append("#include <bpf/bpf_tracing.h>")
        parts.append("")
        
        for program in programs:
            parts.append(program.code)
        
        parts.append("char _license[] SEC(\"license\") = \"GPL\";")
        
        return '\n'.join(parts)
    
    def save_bpf_file(self, programs: List[eBPFProgram], filepath: str) -> bool:
        try:
            code = self.generate_bpf_code(programs)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(code)
            
            logger.info(f"eBPF 代码已保存到: {filepath}")
            return True
        except Exception as e:
            logger.error(f"保存 eBPF 文件失败: {e}")
            return False
    
    def analyze_trace_data(self, trace_log: List[Dict[str, Any]]) -> TraceResult:
        programs = []
        trace_data = []
        
        for entry in trace_log:
            trace_entry = TraceData()
                timestamp=entry.get('timestamp', 0),
                pid=entry.get('pid', 0),
                tid=entry.get('tid', 0),
                function=entry.get('function', ''),
                arguments=entry.get('arguments', {}),
                return_value=entry.get('return_value')
            
            trace_data.append(trace_entry)
        
        summary = {
            'total_entries': len(trace_data),
            'unique_functions': len(set(t.function for t in trace_data)),
            'unique_pids': len(set(t.pid for t in trace_data

        }
        
        return TraceResult(
            programs=programs,
            trace_data=trace_data,
            summary=summary)
        



def create_ebpf_programs(targets: List[str]) -> List[eBPFProgram]:
    tracer = EbpfDynamicTracer()
    return tracer))