# 自动化崩溃分诊管道 — 端到端: 去重→符号化→最小化提示→可利用性→报告
#
# 核心问题:
#   triage_reporter.py 创建 TriageEntry 但需手动填入每个字段。
#   crash_dedup.py 用栈哈希分组但仅去重不做分诊。
#   exploit_primitive.py 评估可利用性但不生成报告。
#   各模块独立运行——缺少将它们串联为端到端管道的编排层。
#
#   工业界最佳实践 定义7阶段管道:
#     Fuzzer→存储→符号化→归一化→去重→最小化→验证→报告
#   本模块实现的是"分析层"管道: 去重→分类→可利用性→报告,
#   假设符号化和存储已由外部工具完成。
#
# 管道阶段:
#   Stage 1: 去重 — 按栈哈希+崩溃类型分组
#   Stage 2: 分类 — 按可利用原语类别分组 (EP_WRITE_WHAT_WHERE等)
#   Stage 3: 评分 — ESA + 严重度 + 频率的综合优先级
#   Stage 4: 报告 — 生成结构化Markdown/JSON报告
#
# 文献:
#   ECHO — 在线去重反馈到fuzzing循环;
#     本项目取其管道集成的思想
#   Beefed.ai Fuzzing-as-a-Service — 7阶段自动化管道

from __future__ import annotations

import hashlib
import json
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

# 桥接多个现有模块:
#   exploit_primitive.py: _quick_primitive_classify() 内部实现简化版
#     利用原语分类, 调用方可替换为 ExploitPrimitiveClassifier.assess()
#   crash_dedup.py: _stage_dedup() 内部做栈哈希分组,
#     调用方可替换为 crash_dedup.deduplicate_crashes()
#   triage_reporter.py: TriageReport 格式与 TriageEntry 兼容,
#     可通过 to_triage_reporter() 桥接


class TriageStage(str, Enum):
    DEDUP = "dedup"
    CLASSIFY = "classify"
    SCORE = "score"
    REPORT = "report"


class Priority(str, Enum):
    CRITICAL = "P0_critical"
    HIGH = "P1_high"
    MEDIUM = "P2_medium"
    LOW = "P3_low"


@dataclass
class CrashInput:
    """管道输入——一个崩溃的基本信息"""
    crash_id: str = ""
    # 崩溃元数据
    signal: int = 0
    signal_name: str = "UNKNOWN"
    crash_pc: int = 0
    fault_addr: int = 0
    crash_type: str = "unknown"
    # 栈回溯
    stack_frames: List[str] = field(default_factory=list)
    stack_hash: str = ""
    # 输入
    input_data: bytes = b""
    input_size: int = 0
    # 寄存器状态 (可选)
    registers: Dict[str, int] = field(default_factory=dict)
    reg_taint: Dict[str, Set[int]] = field(default_factory=dict)
    # 缓解措施
    has_stack_canary: bool = True
    has_nx: bool = True
    has_pie: bool = True
    # 发现元数据
    discovery_time: float = 0.0
    fuzzer_name: str = ""


@dataclass
class TriageReport:
    """分诊管道输出的完整报告"""
    report_id: str = ""
    # 统计
    total_crashes: int = 0
    unique_crashes: int = 0
    # 按优先级分组
    by_priority: Dict[str, List[Dict[str, Any]]] = field(
        default_factory=lambda: defaultdict(list))
    # Top-N 最高优先级崩溃
    top_findings: List[Dict[str, Any]] = field(default_factory=list)
    # 摘要
    generated_at: float = 0.0
    pipeline_duration_s: float = 0.0
    markdown_report: str = ""
    json_report: str = ""


class AutoTriagePipeline:
    """端到端自动化分诊管道。

    典型用法:
        pipe = AutoTriagePipeline()
        crashes = [CrashInput(...), ...]
        report = pipe.run(crashes)
        print(report.markdown_report)
    """

    def __init__(self):
        self._dedup_groups: Dict[str, List[CrashInput]] = {}

    def run(self, crashes: List[CrashInput]) -> TriageReport:
        """主入口: 运行完整的分诊管道"""
        t0 = time.perf_counter()

        # Stage 1: 去重
        groups = self._stage_dedup(crashes)

        # Stage 2: 分类+可利用性评估
        classified = self._stage_classify(groups)

        # Stage 3: 综合评分+优先级
        scored = self._stage_score(classified)

        # Stage 4: 生成报告
        report = self._stage_report(scored, len(crashes), len(groups),
                                     time.perf_counter() - t0)
        return report

    def _stage_dedup(self, crashes: List[CrashInput]
                      ) -> Dict[str, List[CrashInput]]:
        """Stage 1: 哈希去重——按栈哈希+崩溃类型"""
        groups: Dict[str, List[CrashInput]] = defaultdict(list)
        for c in crashes:
            if not c.stack_hash:
                frames = ''.join(c.stack_frames[:5])
                c.stack_hash = hashlib.sha256(
                    f"{frames}:{c.signal}:{c.crash_type}".encode()
                ).hexdigest()[:16]
            groups[c.stack_hash].append(c)
        self._dedup_groups = groups
        return groups

    def _stage_classify(self, groups: Dict[str, List[CrashInput]]
                         ) -> List[Dict[str, Any]]:
        """Stage 2: 崩溃分类——利用原语 + 严重度初步判定"""
        classified: List[Dict[str, Any]] = []

        for stack_hash, crashes in groups.items():
            rep = crashes[0]  # 代表样本
            info: Dict[str, Any] = {
                'stack_hash': stack_hash,
                'count': len(crashes),
                'crash_type': rep.crash_type,
                'crash_pc': f'{rep.crash_pc:#x}',
                'fault_addr': f'{rep.fault_addr:#x}',
                'signal': rep.signal_name,
                'stack_top3': rep.stack_frames[:3],
                'min_input_size': min(c.input_size for c in crashes),
                'max_input_size': max(c.input_size for c in crashes),
            }

            # 利用原语快速判定
            info['exploit_primitive'] = self._quick_primitive_classify(rep)
            info['severity'] = self._quick_severity(rep)

            classified.append(info)

        return classified

    def _stage_score(self, classified: List[Dict[str, Any]]
                      ) -> List[Dict[str, Any]]:
        """Stage 3: 综合评分——频率×严重度×可利用性"""
        for info in classified:
            freq_score = min(1.0, math.log1p(info['count']) / 10.0)
            sev_map = {'critical': 1.0, 'high': 0.7, 'medium': 0.4, 'low': 0.1}
            sev_score = sev_map.get(info.get('severity', 'low'), 0.1)
            prim_map = {
                'write_what_where': 1.0, 'rip_control': 0.9,
                'stack_pivot': 0.7, 'arbitrary_read': 0.5,
                'heap_manipulation': 0.4, 'info_leak': 0.2, 'none': 0.05,
            }
            prim_score = prim_map.get(
                info.get('exploit_primitive', 'none'), 0.1)

            info['priority_score'] = round(
                0.4 * sev_score + 0.35 * prim_score + 0.25 * freq_score, 3)

            if info['priority_score'] >= 0.7:
                info['priority'] = Priority.CRITICAL.value
            elif info['priority_score'] >= 0.4:
                info['priority'] = Priority.HIGH.value
            elif info['priority_score'] >= 0.2:
                info['priority'] = Priority.MEDIUM.value
            else:
                info['priority'] = Priority.LOW.value

        classified.sort(key=lambda x: -x['priority_score'])
        return classified

    def _stage_report(self, scored: List[Dict[str, Any]],
                       total: int, unique: int,
                       duration: float) -> TriageReport:
        """Stage 4: 生成结构化报告"""
        report = TriageReport(
            report_id=hashlib.sha256(
                str(time.time()).encode()).hexdigest()[:12],
            total_crashes=total,
            unique_crashes=unique,
            generated_at=time.time(),
            pipeline_duration_s=duration,
        )

        for info in scored:
            pri = info.get('priority', Priority.LOW.value)
            report.by_priority[pri].append(info)

        report.top_findings = scored[:10]

        report.markdown_report = self._render_markdown(report, scored)
        report.json_report = json.dumps({
            'report_id': report.report_id,
            'total_crashes': total,
            'unique_crashes': unique,
            'findings': scored[:20],
        }, indent=2, default=str)

        return report

    @staticmethod
    def _quick_primitive_classify(crash: CrashInput) -> str:
        """快速利用原语分类——基于崩溃信号+寄存器污点的启发式"""
        if crash.signal_name == 'SIGSEGV':
            rip_tainted = bool(crash.reg_taint.get('rip', set()))
            if rip_tainted and crash.fault_addr != 0:
                return 'write_what_where'
            if rip_tainted:
                return 'rip_control'
            if crash.reg_taint.get('rsp', set()):
                return 'stack_pivot'
            return 'rip_control'
        if crash.signal_name == 'SIGABRT':
            return 'heap_manipulation'
        if crash.signal_name == 'SIGBUS':
            return 'info_leak'
        return 'none'

    @staticmethod
    def _quick_severity(crash: CrashInput) -> str:
        sev = crash.crash_type.lower()
        if any(k in sev for k in ('overflow', 'uaf', 'double free')):
            return 'critical'
        if any(k in sev for k in ('null', 'assert', 'abort')):
            return 'medium'
        return 'high'

    @staticmethod
    def _render_markdown(report: TriageReport,
                          scored: List[Dict[str, Any]]) -> str:
        import math as _m
        lines = [
            "# 崩溃分诊报告",
            f"- ID: `{report.report_id}`",
            f"- 总崩溃: {report.total_crashes}",
            f"- 唯一崩溃: {report.unique_crashes} ({report.total_crashes - report.unique_crashes} 重复)",
            f"- 耗时: {report.pipeline_duration_s:.1f}s",
            "",
            "## 优先级分布",
        ]
        for pri in [Priority.CRITICAL, Priority.HIGH, Priority.MEDIUM, Priority.LOW]:
            count = len(report.by_priority.get(pri.value, []))
            lines.append(f"- **{pri.value}**: {count}")

        lines += ["", "## Top 发现"]
        for i, info in enumerate(scored[:10]):
            lines.append(
                f"### {i+1}. [{info.get('priority', '?')}] "
                f"{info.get('crash_type', '?')} ({info['count']}×)")
            lines.append(f"- 原语: {info.get('exploit_primitive', '?')}")
            lines.append(f"- PC: {info.get('crash_pc', '?')}")
            lines.append(f"- 栈顶: {', '.join(info.get('stack_top3', [])[:3])}")
            lines.append(f"- 评分: {info.get('priority_score', 0):.3f}")
        return "\n".join(lines)


def quick_triage(crashes: List[CrashInput]) -> TriageReport:
    """便捷入口: 一键分诊"""
    pipe = AutoTriagePipeline()
    return pipe.run(crashes)
