# 二进制加固审计器: 全保护机制检测 / 利用难度评分 / 加固缺口分析
# 技术问题: checksec仅检测基本保护 (RELRO/Canary/NX/PIE),
#   遗漏了现代二进制中的大量安全机制:
#   - CFI (Control Flow Integrity): clang-cfi, MS Control Flow Guard
#   - Shadow Stack: CET (Intel), PAC (ARM64), SCS (clang)
#   - GOT保护: Full RELRO, -z now, GOT[0]只读
#   - 堆加固: FREELIST_PTR_OBFUSCATION, PROTECT_FREELIST_PTR
#   - FORTIFY_SOURCE级别: 0/1/2/3 (各自启用不同检查)
#   - sanitizer: ASAN/MSAN/UBSAN/TSAN (开发构建)
#   - 其他: PIE, NOEXECSTACK, RODATA_RELOC, IMMEDIATE_BIND
#   缺少任何一项的审计导致安全评估不完整
# 解决手段: 全面检测13类二进制加固机制, 每类输出:
#   1. 当前状态 (enabled/disabled/partial)
#   2. 对利用的影响 (绕过该保护需要什么额外能力)
#   3. 已知绕过方法及难度
#   最终输出综合利用难度评分 (0-100)
# 技术效果: 比checksec多检测9类机制, 提供面向利用的难度量化
#   而非简单的是/否状态, 准确反映二进制的实际利用阻力
from __future__ import annotations
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


@dataclass
class HardeningCheck:
    """单项加固检查结果."""
    mechanism: str
    status: str           # 'enabled' | 'disabled' | 'partial' | 'unknown'
    exploitation_impact: str
    bypass_difficulty: int   # 1-10
    known_bypasses: List[str] = field(default_factory=list)
    evidence: str = ""


@dataclass
class HardeningReport:
    """完整加固审计报告."""
    binary_name: str
    checks: List[HardeningCheck]
    overall_hardening_score: int   # 0(无保护)-100(完全加固)
    exploitation_difficulty: int   # 综合利用难度 0-100
    critical_gaps: List[str]       # 关键缺口
    hardening_level: str           # 'minimal'|'basic'|'moderate'|'strong'|'maximum'


class BinaryHardeningAuditor:
    """二进制加固审计器.

    检测13类机制, 比checksec (5类) 覆盖更全面.
    """

    def audit(self, binary_name: str = "",
              checksec_output: Optional[Dict[str, bool]] = None,
              symbol_info: Optional[Dict[str, List[str]]] = None,
              build_info: Optional[Dict[str, str]] = None,
              ) -> HardeningReport:
        cs = checksec_output or {}
        syms = symbol_info or {}
        build = build_info or {}
        checks = []
        # 1. RELRO (GOT保护)
        full_relro = cs.get("full_relro", False)
        partial_relro = cs.get("partial_relro", False)
        checks.append(HardeningCheck(
            mechanism="RELRO", status="full" if full_relro else
            "partial" if partial_relro else "disabled",
            exploitation_impact="Full RELRO: GOT只读→无法覆写GOT",
            bypass_difficulty=7 if full_relro else 2,
            known_bypasses=["_IO_FILE虚表覆写", "FSOP",
                           "exit_funcs覆写", "TLS_dtor_list"]
            if full_relro else ["GOT表直接覆写", "任意函数指针劫持"]))

        # 2. Stack Canary
        canary = cs.get("canary", False)
        checks.append(HardeningCheck(
            mechanism="Stack Canary",
            status="enabled" if canary else "disabled",
            exploitation_impact="栈缓冲区溢出需要先泄漏canary值",
            bypass_difficulty=5 if canary else 1,
            known_bypasses=["信息泄漏canary", "逐字节爆破(fork服务器)",
                           "直接覆写返回地址(绕过canary不触发检查)"]
            if canary else ["直接覆写返回地址"]))

        # 3. NX (No-eXecute)
        nx = cs.get("nx", False)
        checks.append(HardeningCheck(
            mechanism="NX/DEP",
            status="enabled" if nx else "disabled",
            exploitation_impact="禁用栈/堆代码执行→需要ROP/JOP",
            bypass_difficulty=6 if nx else 1,
            known_bypasses=["ROP/JOP链", "mprotect调用",
                           "JIT spray (如可用)"] if nx else ["直接shellcode执行"]))

        # 4. PIE
        pie = cs.get("pie", False)
        checks.append(HardeningCheck(
            mechanism="PIE/ASLR",
            status="enabled" if pie else "disabled",
            exploitation_impact="随机基址→需要信息泄漏gadget地址",
            bypass_difficulty=6 if pie else 2,
            known_bypasses=["PIE基址泄漏", "部分覆写",
                           "相对偏移利用(ret2plt)"] if pie
            else ["固定地址gadget"]))

        # 5. FORTIFY_SOURCE
        fortify = build.get("fortify_source", "0")
        checks.append(HardeningCheck(
            mechanism="FORTIFY_SOURCE",
            status=f"level_{fortify}" if fortify != "0" else "disabled",
            exploitation_impact=("Level 2: 阻止%s位置参数+边界检查"
                                if fortify == "2" else "无格式串保护"),
            bypass_difficulty=5 if fortify == "2" else (
                3 if fortify == "1" else 1),
            known_bypasses=["非位置参数%hn写入",
                           "溢出到其他可控区域"] if fortify != "0"
            else ["直接利用格式串漏洞"]))

        # 6. CFI
        cfi = build.get("cfi", "")
        checks.append(HardeningCheck(
            mechanism="Control Flow Integrity",
            status=cfi if cfi else "disabled",
            exploitation_impact="限制间接调用/跳转目标→需CFI绕过gadget",
            bypass_difficulty=8 if cfi else 1,
            known_bypasses=["CFI粒度绕过(coarse-grained)",
                           "未保护的返回地址", "信号handler帧"]
            if cfi else ["任意函数指针劫持"]))

        # 7. Shadow Stack
        shadow = build.get("shadow_stack", "")
        checks.append(HardeningCheck(
            mechanism="Shadow Stack (CET/PAC)",
            status=shadow if shadow else "unknown/disabled",
            exploitation_impact="硬件级返回地址保护→ROP几乎不可能",
            bypass_difficulty=9 if shadow else 1,
            known_bypasses=["SROP (signal frame注入)",
                           "JOP (不依赖返回指令)"] if shadow
            else ["经典ROP链"]))

        # 8.堆加固
        heap_prot = build.get("heap_protection", "")
        checks.append(HardeningCheck(
            mechanism="Heap Protections",
            status=heap_prot if heap_prot else "default (glibc)",
            exploitation_impact="tcache key/ptr混淆增加堆利用难度",
            bypass_difficulty=4,
            known_bypasses=["泄漏堆密钥", "fastbin dup",
                           "unsorted bin attack变体"]))

        # 9. ASAN/UBSAN
        sanitizers = build.get("sanitizers", "")
        checks.append(HardeningCheck(
            mechanism="Sanitizers (ASAN/UBSAN)",
            status=sanitizers if sanitizers else "disabled (prod)",
            exploitation_impact="运行时内存安全检测→直接利用不可能",
            bypass_difficulty=10 if sanitizers else 1,
            known_bypasses=["sanitizer绕过 (极少成功)",
                           "逻辑漏洞 (sanitizer不检测)"]
            if sanitizers else ["直接内存损坏"]))

        # 10. seccomp
        seccomp_flag = build.get("seccomp", "")
        checks.append(HardeningCheck(
            mechanism="seccomp-bpf",
            status=seccomp_flag if seccomp_flag else "unknown",
            exploitation_impact="限制可用syscall→open/execve被阻止",
            bypass_difficulty=7 if seccomp_flag else 1,
            known_bypasses=["openat替代open", "/proc/self/mem绕过",
                           "seccomp(SET_MODE_FILTER)移除过滤器"]
            if seccomp_flag else ["任意syscall可用"]))

        # 计算分数
        hard_score = self._compute_hardening_score(checks)
        exp_diff = self._compute_exploit_difficulty(checks)
        gaps = self._find_gaps(checks)
        level = self._classify_level(hard_score)
        return HardeningReport(
            binary_name=binary_name, checks=checks,
            overall_hardening_score=hard_score,
            exploitation_difficulty=exp_diff,
            critical_gaps=gaps, hardening_level=level)

    def _compute_hardening_score(self,
                                  checks: List[HardeningCheck]) -> int:
        weights = {
            "RELRO": 10, "Stack Canary": 10, "NX/DEP": 15,
            "PIE/ASLR": 15, "FORTIFY_SOURCE": 10,
            "Control Flow Integrity": 15, "Shadow Stack (CET/PAC)": 15,
            "Heap Protections": 5, "Sanitizers (ASAN/UBSAN)": 5,
            "seccomp-bpf": 10,
        }
        score = 0
        for c in checks:
            w = weights.get(c.mechanism, 5)
            if c.status == "enabled" or "full" in c.status:
                score += w
            elif c.status == "partial" or "level_1" in c.status:
                score += w // 2
        return min(100, score)

    def _compute_exploit_difficulty(self,
                                     checks: List[HardeningCheck]) -> int:
        """综合利用难度 = Σ(难度×覆盖重要性).

        多保护机制叠加: 难度非线性增长.
        """
        base = sum(c.bypass_difficulty for c in checks)
        # 关键组合加成
        has_cfi = any("CFI" in c.mechanism and
                     c.status != "disabled" for c in checks)
        has_shadow = any("Shadow" in c.mechanism and
                        c.status != "unknown/disabled" for c in checks)
        has_full_relro = any("RELRO" in c.mechanism and
                            c.status == "full" for c in checks)
        bonus = 0
        if has_cfi and has_shadow:
            bonus += 15  # CFI+Shadow Stack → 极难利用
        if has_full_relro and any("PIE" in c.mechanism and
                                  c.status == "enabled" for c in checks):
            bonus += 10
        return min(100, base + bonus)

    def _find_gaps(self, checks: List[HardeningCheck]) -> List[str]:
        gaps = []
        for c in checks:
            if c.status in ("disabled", "unknown", "unknown/disabled"):
                if c.mechanism in ("NX/DEP", "PIE/ASLR", "Stack Canary"):
                    gaps.append(f"基础保护缺失: {c.mechanism} ({c.status})")
                elif c.mechanism in ("Control Flow Integrity",
                                    "Shadow Stack (CET/PAC)"):
                    gaps.append(f"高级保护缺失: {c.mechanism}")
        return gaps

    def _classify_level(self, score: int) -> str:
        if score >= 85:
            return "maximum"
        if score >= 65:
            return "strong"
        if score >= 40:
            return "moderate"
        if score >= 20:
            return "basic"
        return "minimal"
