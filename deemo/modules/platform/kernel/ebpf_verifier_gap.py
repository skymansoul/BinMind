# 2026-08-01
# eBPF 验证器拒绝诊断差距分析器
# 参考:
#   "Characterizing and Bridging the Diagnostic Gap in eBPF Verifier Rejections"
#    (arXiv 2607.02748, Jul 2026)
#    发现: Linux eBPF verifier 的拒绝消息中 42% 缺乏可操作的诊断信息,
#    平均调试时间 3.7 小时; 提出 GAPFIX 框架自动补充诊断上下文
#   "A Flow-Sensitive Refinement Type System for Verifying eBPF Programs"
#    (ACM POPL 2025) — 精化类型系统提高验证精度
#   "Heimdall: Formally Verified Automated Migration of Legacy eBPF Programs to Rust"
#    (arXiv 2605.25411, May 2026) — 形式化迁移工具

import os
import re
import logging
from dataclasses import dataclass, field
from typing import Optional
from collections import Counter

logger = logging.getLogger(__name__)

# ── 已知的 eBPF verifier 拒绝错误类别 (来自 arXiv 2607.02748 的分类学) ──
# 每条包含: 正则匹配 verifier 输出的模式 → 人类可读解释 + 修复建议
_VERIFIER_ERROR_TYPES: list[dict] = [
    {
        "id": "E001",
        "pattern": re.compile(r"invalid access to (packet|map value|stack|ctx).*R(\d+)"),
        "title": "无效内存访问",
        "category": "memory_safety",
        "severity": "Error",
        "fix_hint": "检查寄存器 R{grp2} 是否在访问前经过了 bounds check (r < size)",
    },
    {
        "id": "E002",
        "pattern": re.compile(r"R(\d+) unbounded memory access"),
        "title": "无边界内存访问",
        "category": "memory_safety",
        "severity": "Error",
        "fix_hint": "在 load/store 前添加 if (offset + sizeof(data) <= ctx->data_end) 检查",
    },
    {
        "id": "E003",
        "pattern": re.compile(r"math between map_value pointer and register with unbounded min value"),
        "title": "指针算术无界范围",
        "category": "pointer_arithmetic",
        "severity": "Error",
        "fix_hint": "使用有界循环变量或添加 __builtin_expect 提示验证器",
    },
    {
        "id": "E004",
        "pattern": re.compile(r"back-edge from insn (\d+) to (\d+)"),
        "title": "回边 (循环) 检测",
        "category": "control_flow",
        "severity": "Error",
        "fix_hint": f"确保循环次数有上界; 使用 #pragma unroll 或 bounded loop pattern",
    },
    {
        "id": "E005",
        "pattern": re.compile(r"invalid (bpf helper|function) call"),
        "title": "无效的 BPF helper 调用",
        "category": "helper_call",
        "severity": "Error",
        "fix_hint": "验证 helper 函数的参数类型是否匹配; 检查是否在允许的 BPF 程序类型中",
    },
    {
        "id": "E006",
        "pattern": re.compile(r"cannot write into.*map"),
        "title": "只读 map 写入",
        "category": "map_access",
        "severity": "Error",
        "fix_hint": "将 BPF_MAP 标志从 BPF_RDONLY 改为 BPF_RDWR",
    },
    {
        "id": "E007",
        "pattern": re.compile(r"R(\d+) (min value is negative|max value is beyond)"),
        "title": "寄存器值超出合法范围",
        "category": "value_range",
        "severity": "Error",
        "fix_hint": "在操作前添加 signed/unsigned bounds check; 使用 BPF_REG_{grp1} 的已知范围约束",
    },
    {
        "id": "E008",
        "pattern": re.compile(r"program too large.*(\d+) instructions"),
        "title": "程序过大",
        "category": "complexity_limit",
        "severity": "Error",
        "fix_hint": "当前指令数 {grp1} 超过限制; 拆分 BPF 程序为多个 tail call",
    },
    {
        "id": "E009",
        "pattern": re.compile(r"stack limit exceeded|too many stack"),
        "title": "栈溢出",
        "category": "complexity_limit",
        "severity": "Error",
        "fix_hint": "将大局部变量移入 BPF map; 栈帧上限 512 字节",
    },
    {
        "id": "E010",
        "pattern": re.compile(r"processed (\d+) insns.*complexity limit"),
        "title": "验证复杂度超限",
        "category": "complexity_limit",
        "severity": "Error",
        "fix_hint": "简化控制流; 使用 __attribute__((always_inline)) 减少调用深度",
    },
]


@dataclass
class VerifierGapFinding:
    gap_id: str
    category: str
    severity: str
    title: str = ""
    verifier_message: str = ""
    diagnostic_quality: str = "poor"  # poor / fair / actionable
    fix_suggestion: str = ""
    affected_register: str = ""
    confidence: float = 0.0
    reference: str = ""


class EbpfVerifierGapAnalyzer:
    """eBPF 验证器诊断差距分析器 (arXiv 2607.02748)。

    输入: Linux eBPF verifier 的输出日志 (bpftool prog load 的 stderr)
    输出: 每条拒绝错误的结构化诊断 + 可操作的修复建议

    方法:
    1. 解析 verifier 输出中的错误行
    2. 匹配已知错误模式 → 分类
    3. 评估诊断质量 (GAPFIX 框架): poor / fair / actionable
    4. 生成包含寄存器状态上下文的修复建议
    """

    def __init__(self, verifier_log: str = "", log_path: str = ""):
        self._log = verifier_log
        if log_path and os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                self._log = f.read()

    def analyze(self) -> list[VerifierGapFinding]:
        if not self._log:
            return []
        res: list[VerifierGapFinding] = []
        for line in self._log.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue
            for rule in _VERIFIER_ERROR_TYPES:
                m = rule["pattern"].search(stripped)
                if m:
                    fix = rule["fix_hint"]
                    # 替换占位符 {grp1}, {grp2}
                    for gi in range(1, len(m.groups()) + 1):
                        try:
                            val = m.group(gi) or ""
                            fix = fix.replace(f"{{grp{gi}}}", val)
                        except IndexError:
                            break
                    dq = self._assess_diagnostic_quality(stripped, rule)
                    res.append(VerifierGapFinding(
                        gap_id=rule["id"],
                        category=rule["category"],
                        severity=rule["severity"],
                        title=rule["title"],
                        verifier_message=stripped[:200],
                        diagnostic_quality=dq,
                        fix_suggestion=fix,
                        affected_register=m.group(1) if m.lastindex and m.lastindex >= 1 else "",
                        confidence=0.90,
                        reference="arXiv 2607.02748"
                    ))
        dq_counts = Counter(f.diagnostic_quality for f in res)
        logger.info("eBPF verifier gap analysis: %d findings (poor=%d, fair=%d, actionable=%d)",
                    len(res),
                    dq_counts.get("poor", 0),
                    dq_counts.get("fair", 0),
                    dq_counts.get("actionable", 0))
        return res

    def _assess_diagnostic_quality(self, message: str,
                                    rule: dict) -> str:
        """评估 verifier 错误消息的诊断质量。

        标准 (来自 GAPFIX 论文 Section 3.2):
        - actionable: 消息明确指出具体寄存器和修复方向
        - fair: 消息指出问题类型但缺少具体数值
        - poor: 仅报告拒绝，无任何上下文
        """
        has_register_info = bool(re.search(r'R\d+', message))
        has_value_range = bool(re.search(r'(min|max)\s+value\s+is', message))
        has_instruction_ref = bool(re.search(r'insn\s+\d+', message))
        if has_register_info and has_value_range:
            return "actionable"
        if has_register_info or has_instruction_ref:
            return "fair"
        return "poor"

    def generate_fix_report(self, findings: list[VerifierGapFinding] | None = None
                            ) -> str:
        """生成 Markdown 格式的修复建议报告。"""
        findings = findings or self.analyze()
        lines = ["# eBPF Verifier Diagnostic Gap Report",
                 f"Total findings: {len(findings)}",
                 ""]
        by_cat = defaultdict(list)
        for f in findings:
            by_cat[f.category].append(f)
        for cat, cat_findings in sorted(by_cat.items()):
            lines.append(f"## {cat} ({len(cat_findings)} issues)")
            for f in cat_findings[:5]:
                lines.append(f"- **{f.gap_id}**: {f.title}")
                lines.append(f"  - Diagnostic quality: {f.diagnostic_quality}")
                lines.append(f"  - Fix: {f.fix_suggestion}")
                if f.affected_register:
                    lines.append(f"  - Register: R{f.affected_register}")
            lines.append("")
        return "\n".join(lines)

    def summary_stats(self, findings: list[VerifierGapFinding] | None = None) -> dict:
        findings = findings or self.analyze()
        dq = Counter(f.diagnostic_quality for f in findings)
        total = len(findings) or 1
        return {
            "total_errors": total,
            "actionable_rate": round(dq.get("actionable", 0) / total, 2),
            "fair_rate": round(dq.get("fair", 0) / total, 2),
            "poor_rate": round(dq.get("poor", 0) / total, 2),
            "categories": dict(Counter(f.category for f in findings)),
        }


def analyze_verifier_gaps(verifier_log: str = "", log_path: str = ""
                          ) -> list[VerifierGapFinding]:
    analyzer = EbpfVerifierGapAnalyzer(
        verifier_log=verifier_log, log_path=log_path)
    return analyzer.analyze()
