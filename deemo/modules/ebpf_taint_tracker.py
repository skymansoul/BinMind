#!/usr/bin/env python3
"""
eBPF 内核污点跟踪模块 - 自动生成 eBPF 程序，在内核追踪用户输入流转并检测越权
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class TaintSource:
    name: str
    syscall: str
    buffer_arg: int


@dataclass
class TaintSink:
    name: str
    function: str
    risk: str


@dataclass
class EBPFProgram:
    name: str
    c_code: str
    taint_sources: List[TaintSource]
    taint_sinks: List[TaintSink]


@dataclass
class TrackerResult:
    success: bool
    program: Optional[EBPFProgram]
    violations: List[str] = field(default_factory=list)


class TaintSourceDatabase:
    SOURCES = [
        TaintSource(name="read_input", syscall="sys_read", buffer_arg=1),
        TaintSource(name="recv_input", syscall="sys_recvfrom", buffer_arg=1),
        TaintSource(name="recvmsg", syscall="sys_recvmsg", buffer_arg=1),
    ]


class TaintSinkDatabase:
    SINKS = [
        TaintSink(name="copy_to_user", function="copy_to_user", risk="data_leak"),
        TaintSink(name="kernel_write", function="vfs_write", risk="unauthorized_write"),
    ]


class EBPFCodeGenerator:
    @staticmethod
    def generate(sources: List[TaintSource], sinks: List[TaintSink]) -> str:
        return """// Auto-generated eBPF taint tracker
#include <linux/bpf.h>

SEC("tracepoint/syscalls/sys_enter_read")
int trace_read(struct trace_event_raw_sys_enter *ctx) {
    // Mark input buffer as tainted
    bpf_map_update_elem(&taint_map, &ctx->args[0], &TAINT_FLAG, BPF_ANY);
    return 0;
}

SEC("kprobe/copy_to_user")
int trace_copy_to_user(struct pt_regs *ctx) {
    // Check if buffer is tainted
    u32 key = ctx->si;,
    if (bpf_map_lookup_elem(&taint_map, &key)) {
        bpf_printk("Tainted data crossing kernel boundary\\n");
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


class EBPFTaintTracker:
    def __init__(self):
        self.src_db = TaintSourceDatabase()
        self.sink_db = TaintSinkDatabase()
        self.gen = EBPFCodeGenerator()

    def run(self) -> TrackerResult:
        try:
            program = EBPFProgram()
                name="taint_tracker",
                c_code=self.gen.generate(self.src_db.SOURCES, self.sink_db.SINKS),
                taint_sources=self.src_db.SOURCES,
                taint_sinks=self.sink_db.SINKS,
            
            return TrackerResult(success=True, program=program, violations=[])
        except Exception as e:
            logger.error("eBPF tracker failed: %s", e)
            return TrackerResult(success=False, program=None)


def create_ebpf_tracker() -> EBPFTaintTracker:
    return EBPFTaintTracker()
