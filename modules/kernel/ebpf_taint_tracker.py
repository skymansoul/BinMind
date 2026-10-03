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
    """生成 eBPF C 代码 — 根据污点源/汇配置动态生成"""

    @staticmethod
    def generate(sources: List[TaintSource], sinks: List[TaintSink]) -> str:
        """生成完整的 eBPF 污点追踪程序"""
        source_hooks = []
        for src in sources:
            source_hooks.append(
                f'SEC("tracepoint/syscalls/sys_enter_{src.name}")',
            )
            source_hooks.append(
                f'int trace_{src.name}(struct trace_event_raw_sys_enter *ctx) {{'
            )
            source_hooks.append(
                f'    u32 key = (u32)ctx->args[{src.buffer_arg}];'
            )
            source_hooks.append(
                '    u32 val = TAINT_FLAG;'
            )
            source_hooks.append(
                '    bpf_map_update_elem(&taint_map, &key, &val, BPF_ANY);'
            )
            source_hooks.append(
                '    return 0;'
            )
            source_hooks.append('}')

        sink_hooks = []
        for sink in sinks:
            sink_hooks.append(
                f'SEC("kprobe/{sink.function}")',
            )
            sink_hooks.append(
                f'int check_{sink.name}(struct pt_regs *ctx) {{'
            )
            sink_hooks.append(
                '    u32 key = (u32)PT_REGS_PARM1(ctx);'
            )
            sink_hooks.append(
                '    u32 *val = bpf_map_lookup_elem(&taint_map, &key);'
            )
            sink_hooks.append(
                '    if (val && (*val & TAINT_FLAG)) {'
            )
            sink_hooks.append(
                f'        bpf_printk("ALERT: tainted data at {sink.name}");'
            )
            sink_hooks.append(
                '    }'
            )
            sink_hooks.append(
                '    return 0;'
            )
            sink_hooks.append('}')

        return f"""// Auto-generated eBPF taint tracker
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TAINT_FLAG 0xDEADBEEF

struct {{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u32);
}} taint_map SEC(".maps");

{chr(10).join(source_hooks)}

{chr(10).join(sink_hooks)}

char _license[] SEC("license") = "GPL";
"""


class BCCLoader:
    """BCC 加载器 — 编译并加载 eBPF 程序到内核"""

    @staticmethod
    def load_and_verify(c_code: str) -> Dict[str, Any]:
        """尝试使用 BCC 编译验证 eBPF 程序"""
        try:
            from bcc import BPF
            bpf = BPF(text=c_code)
            funcs = []
            for sym in bpf.load_funcs(BPF.SCHED_CLS):
                funcs.append(sym)
            return {
                'bcc_available': True,
                'compiled': True,
                'functions': funcs,
                'error': None,
            }
        except ImportError:
            return {
                'bcc_available': False,
                'compiled': False,
                'functions': [],
                'error': 'BCC not installed — pip install bcc',
            }
        except Exception as e:
            return {
                'bcc_available': True,
                'compiled': False,
                'functions': [],
                'error': str(e),
            }


class EBPFTaintTracker:
    def __init__(self):
        self.src_db = TaintSourceDatabase()
        self.sink_db = TaintSinkDatabase()
        self.gen = EBPFCodeGenerator()

    def run(self, verify: bool = False) -> TrackerResult:
        try:
            c_code = self.gen.generate(
                self.src_db.SOURCES, self.sink_db.SINKS
            )
            program = EBPFProgram(
                name="taint_tracker",
                c_code=c_code,
                taint_sources=self.src_db.SOURCES,
                taint_sinks=self.sink_db.SINKS,
            )
            violations = []
            if verify:
                result = BCCLoader.load_and_verify(c_code)
                if result.get('error'):
                    violations.append(f"BCC verify: {result['error']}")
                elif result.get('compiled'):
                    logger.info("eBPF 程序编译验证通过")
            return TrackerResult(
                success=True, program=program, violations=violations
            )
        except Exception as e:
            logger.error("eBPF tracker failed: %s", e)
            return TrackerResult(success=False, program=None)


def create_ebpf_tracker() -> EBPFTaintTracker:
    return EBPFTaintTracker()
