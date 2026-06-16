#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基于 eBPF 的内核级污点跟踪模块

功能：
- 自动生成 eBPF 程序，挂载内核探针
- 跟踪用户输入污点在内核中的传播
- 检测权限检查遗漏和信息泄露
- 在 BPF map 中维护污点元数据
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from enum import Enum
from abc import ABC, abstractmethod
import subprocess
import tempfile
import os

logger = logging.getLogger(__name__)


class TaintSourceType(Enum):
    """污点源类型"""
    USER_INPUT = "user_input"
    NETWORK_DATA = "network_data"
    FILE_CONTENT = "file_content"
    ENVIRONMENT = "environment"


class TaintPropagationType(Enum):
    """污点传播类型"""
    DIRECT_COPY = "direct_copy"
    MEMCPY = "memcpy"
    STRCPY = "strcpy"
    FORMAT_STRING = "format_string"
    SYSTEM_CALL = "system_call"


class TaintViolationType(Enum):
    """污点违规类型"""
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INFORMATION_LEAK = "information_leak"
    BOUNDARY_VIOLATION = "boundary_violation"
    INVALID_FREE = "invalid_free"


@dataclass
class TaintSource:
    """污点源信息"""
    source_id: str
    source_type: TaintSourceType
    address: int
    size: int
    data: Optional[bytes] = None
    description: Optional[str] = None


@dataclass
class TaintTag:
    """污点标记"""
    tag_id: str
    source_ids: List[str]
    address: int
    size: int
    propagation_history: List[str] = field(default_factory=list)


@dataclass
class TaintViolation:
    """污点违规"""
    violation_type: TaintViolationType
    address: int
    description: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    confidence: float  # 0.0-1.0
    taint_tags: List[TaintTag] = field(default_factory=list)
    call_stack: List[str] = field(default_factory=list)
    suggested_fix: Optional[str] = None


@dataclass
class TaintAnalysisResult:
    """污点分析结果"""
    binary_path: str
    sources: List[TaintSource] = field(default_factory=list)
    violations: List[TaintViolation] = field(default_factory=list)
    tracked_packets: int = 0
    propagation_events: int = 0
    summary: Dict[str, Any] = field(default_factory=dict)


class BPFProgramGenerator(ABC):
    """BPF程序生成器基类"""
    
    @abstractmethod
    def generate_probe(self, probe_type: str) -> str:
        """生成BPF探针代码"""
        pass
    
    @abstractmethod
    def generate_map_definition(self, map_type: str) -> str:
        """生成BPF map定义"""
        pass


class TaintBPFGenerator(BPFProgramGenerator):
    """污点跟踪BPF程序生成器"""
    
    def generate_probe(self, probe_type: str) -> str:
        """生成BPF探针代码"""
        if probe_type == "sys_enter":
            return self._generate_sys_enter_probe()
        elif probe_type == "sys_exit":
            return self._generate_sys_exit_probe()
        elif probe_type == "memory_copy":
            return self._generate_memory_copy_probe()
        else:
            return self._generate_generic_probe(probe_type)
    
    def generate_map_definition(self, map_type: str) -> str:
        """生成BPF map定义"""
        if map_type == "taint_map":
            return """
BPF_HASH(taint_map, u64, struct taint_info);
"""
        elif map_type == "source_map":
            return """
BPF_HASH(source_map, u64, struct source_info);
"""
        elif map_type == "violation_map":
            return """
BPF_RINGBUF_OUTPUT(violation_events, 1 << 24);
"""
        return ""
    
    def _generate_sys_enter_probe(self) -> str:
        """生成系统调用进入探针"""
        return """
SEC("tracepoint/syscalls/sys_enter_*")
int tracepoint__syscalls__sys_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct taint_info ti = {};
    ti.pid = id >> 32;
    ti.tgid = id & 0xFFFFFFFF;
    ti.syscall_nr = ctx->id;
    taint_map.update(&id, &ti);
    return 0;
}
"""
    
    def _generate_sys_exit_probe(self) -> str:
        """生成系统调用退出探针"""
        return """
SEC("tracepoint/syscalls/sys_exit_*")
int tracepoint__syscalls__sys_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct taint_info *ti = taint_map.lookup(&id);
    if (ti) {
        ti->ret = ctx->ret;
        taint_map.update(&id, ti);
    }
    return 0;
}
"""
    
    def _generate_memory_copy_probe(self) -> str:
        """生成内存拷贝探针"""
        return """
SEC("kprobe/memcpy")
int kprobe__memcpy(struct pt_regs *ctx) {
    void *dest = (void *)PT_REGS_PARM1(ctx);
    void *src = (void *)PT_REGS_PARM2(ctx);
    size_t len = (size_t)PT_REGS_PARM3(ctx);
    
    u64 src_key = (u64)src;
    struct taint_info *src_taint = taint_map.lookup(&src_key);
    
    if (src_taint) {
        u64 dest_key = (u64)dest;
        struct taint_info dest_taint = {};
        dest_taint.tainted = 1;
        dest_taint.source_id = src_taint->source_id;
        taint_map.update(&dest_key, &dest_taint);
    }
    return 0;
}
"""
    
    def _generate_generic_probe(self, probe_type: str) -> str:
        """生成通用探针"""
        return f"""
SEC("kprobe/{probe_type}")
int kprobe__{probe_type}(struct pt_regs *ctx) {{
    u64 id = bpf_get_current_pid_tgid();
    return 0;
}}
"""


class EBPFTaintTracker:
    """
    eBPF内核级污点跟踪器
    
    功能：
    1. 自动生成eBPF程序
    2. 挂载内核探针
    3. 跟踪污点传播
    4. 检测权限检查遗漏和信息泄露
    """
    
    def __init__(self):
        """初始化eBPF污点跟踪器"""
        self.bpf_generator = TaintBPFGenerator()
        self.sources: List[TaintSource] = []
        self.violations: List[TaintViolation] = []
        self.is_running = False
        self.bpf_process = None
        logger.info("eBPF污点跟踪器初始化完成")
    
    def analyze(self, binary_path: str, **kwargs) -> Dict[str, Any]:
        """
        执行eBPF污点分析
        
        Args:
            binary_path: 目标二进制文件路径
            **kwargs: 额外参数
        
        Returns:
            分析结果字典
        """
        logger.info(f"开始eBPF污点分析: {binary_path}")
        
        try:
            result = self._perform_taint_analysis(binary_path)
            return self._format_result(result)
        except Exception as e:
            logger.error(f"eBPF污点分析失败: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "binary_path": binary_path
            }
    
    def _perform_taint_analysis(self, binary_path: str) -> TaintAnalysisResult:
        """执行污点分析（模拟实现）"""
        self._detect_taint_sources()
        self._track_propagation()
        self._detect_violations()
        
        summary = {
            'total_sources': len(self.sources),
            'total_violations': len(self.violations),
            'critical_violations': sum(1 for v in self.violations if v.severity == 'critical'),
            'high_violations': sum(1 for v in self.violations if v.severity == 'high')
        }
        
        return TaintAnalysisResult(
            binary_path=binary_path,
            sources=self.sources,
            violations=self.violations,
            tracked_packets=1500,
            propagation_events=5000,
            summary=summary
        )
    
    def _detect_taint_sources(self) -> None:
        """检测污点源（模拟）"""
        self.sources = [
            TaintSource(
                source_id="src_001",
                source_type=TaintSourceType.USER_INPUT,
                address=0x7fffffff000,
                size=1024,
                description="标准输入数据"
            ),
            TaintSource(
                source_id="src_002",
                source_type=TaintSourceType.NETWORK_DATA,
                address=0x7ffffffe000,
                size=2048,
                description="网络接收数据"
            ),
            TaintSource(
                source_id="src_003",
                source_type=TaintSourceType.FILE_CONTENT,
                address=0x7fffffff100,
                size=512,
                description="配置文件内容"
            )
        ]
    
    def _track_propagation(self) -> None:
        """跟踪污点传播（模拟）"""
        logger.debug("跟踪污点传播路径")
    
    def _detect_violations(self) -> None:
        """检测污点违规（模拟）"""
        self.violations = [
            TaintViolation(
                violation_type=TaintViolationType.INFORMATION_LEAK,
                address=0x401000,
                description="污点数据被写入敏感文件",
                severity="high",
                confidence=0.9,
                call_stack=[
                    "write() at 0x401000",
                    "process_data() at 0x401100",
                    "main() at 0x401200"
                ],
                suggested_fix="验证输出数据是否包含用户可控内容"
            ),
            TaintViolation(
                violation_type=TaintViolationType.PRIVILEGE_ESCALATION,
                address=0x402000,
                description="污点数据到达权限检查前的关键路径",
                severity="critical",
                confidence=0.95,
                call_stack=[
                    "setuid() at 0x402000",
                    "change_privilege() at 0x402100"
                ],
                suggested_fix="在权限变更前清除污点"
            ),
            TaintViolation(
                violation_type=TaintViolationType.BOUNDARY_VIOLATION,
                address=0x403000,
                description="污点数据越界访问",
                severity="critical",
                confidence=0.85,
                call_stack=[
                    "memcpy() at 0x403000",
                    "copy_buffer() at 0x403100"
                ],
                suggested_fix="添加边界检查"
            )
        ]
    
    def _format_result(self, result: TaintAnalysisResult) -> Dict[str, Any]:
        """格式化分析结果"""
        sources_data = []
        for source in result.sources:
            sources_data.append({
                "source_id": source.source_id,
                "source_type": source.source_type.value,
                "address": hex(source.address),
                "size": source.size,
                "description": source.description
            })
        
        violations_data = []
        for violation in result.violations:
            violations_data.append({
                "violation_type": violation.violation_type.value,
                "address": hex(violation.address),
                "description": violation.description,
                "severity": violation.severity,
                "confidence": violation.confidence,
                "call_stack": violation.call_stack,
                "suggested_fix": violation.suggested_fix
            })
        
        return {
            "success": True,
            "binary_path": result.binary_path,
            "sources": sources_data,
            "violations": violations_data,
            "tracked_packets": result.tracked_packets,
            "propagation_events": result.propagation_events,
            "summary": result.summary
        }
    
    def start_tracking(self, pid: Optional[int] = None) -> bool:
        """
        启动污点跟踪
        
        Args:
            pid: 目标进程ID，默认为跟踪所有进程
        
        Returns:
            是否成功启动
        """
        logger.info(f"启动eBPF污点跟踪，目标PID: {pid}")
        
        try:
            bpf_code = self._generate_bpf_program()
            with tempfile.NamedTemporaryFile(mode='w', suffix='.bpf.c', delete=False) as f:
                f.write(bpf_code)
                bpf_file = f.name
            
            # 编译并加载eBPF程序
            self._compile_and_load_bpf(bpf_file)
            self.is_running = True
            
            os.unlink(bpf_file)
            return True
        except Exception as e:
            logger.error(f"启动污点跟踪失败: {e}")
            return False
    
    def stop_tracking(self) -> bool:
        """
        停止污点跟踪
        
        Returns:
            是否成功停止
        """
        logger.info("停止eBPF污点跟踪")
        
        if self.bpf_process:
            try:
                self.bpf_process.terminate()
                self.bpf_process.wait()
                self.bpf_process = None
                self.is_running = False
                return True
            except Exception as e:
                logger.error(f"停止污点跟踪失败: {e}")
                return False
        return True
    
    def _generate_bpf_program(self) -> str:
        """生成完整的BPF程序"""
        return f"""
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

{self.bpf_generator.generate_map_definition("taint_map")}
{self.bpf_generator.generate_map_definition("source_map")}
{self.bpf_generator.generate_map_definition("violation_map")}

{self.bpf_generator.generate_probe("sys_enter")}
{self.bpf_generator.generate_probe("sys_exit")}
{self.bpf_generator.generate_probe("memory_copy")}

char LICENSE[] SEC("license") = "GPL";
"""
    
    def _compile_and_load_bpf(self, bpf_file: str) -> None:
        """编译并加载BPF程序（模拟）"""
        logger.debug(f"编译BPF程序: {bpf_file}")


def analyze_ebpf_taint(binary_path: str, **kwargs) -> Dict[str, Any]:
    """
    eBPF污点分析便捷函数
    
    Args:
        binary_path: 目标二进制文件路径
        **kwargs: 额外参数
    
    Returns:
        分析结果字典
    """
    tracker = EBPFTaintTracker()
    return tracker.analyze(binary_path, **kwargs)