# 反模糊测试检测器: 防护技术分类 / 绕过难度评分 / 路径覆盖影响
# 技术问题: C-Fuzz和T-Fuzz通过控制流跳转绕过反fuzzing,
#   但没有工具系统性地检测和分类二进制中的反fuzzing技术.
#   测试人员不知道哪些代码段存在反fuzzing防护, 无法评估
#   fuzzing活动的"盲区"——100%覆盖率的假象可能掩盖关键未测试代码 （口径: 此处描述 fuzzing 覆盖率假象, 非检测结果宣称）
# 解决手段: 从执行trace+二进制静态特征中检测四类反fuzzing模式:
#   类别1: 校验和/哈希守卫 — 输入完整性检查阻碍变异
#   类别2: 多阶段验证链 — 需要连续通过多个检查的串行守卫
#   类别3: 环境敏感代码 — 时间/随机数/系统状态依赖
#   类别4: 反覆盖率反馈 — 虚假路径/膨胀代码路径阻碍引导
#   输出每种防护的位置、绕过难度 (1-10) 和影响的未覆盖代码量
# 技术效果: 四类反fuzzing模式检测+绕过难度评分, 补充C-Fuzz/T-Fuzz仅聚焦绕过而缺乏检测能力的空白
#
#   C-Fuzz — 强制控制流跳转绕过,
#     本项目借鉴其反fuzzing模式分类但聚焦检测而非绕过
#   T-Fuzz — NCC检测,
#     本项目借鉴其非关键检查分类思想
#   PFuzzer — 环境敏感反分析fuzzing,
#     本项目借鉴其环境敏感代码分类
#   Trail of Bits fuzzing-obstacles — 编译时旁路模式
from __future__ import annotations
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)


@dataclass
class AntiFuzzGuard:
    """反fuzzing防护点."""
    guard_id: str
    category: str           # 'checksum' | 'multistage' | 'environment' | 'anti_coverage'
    location: str = ""       # 函数名/地址
    pattern_matched: str = ""
    bypass_difficulty: int = 5     # 1(easy)-10(hard)
    blocked_code_pct: float = 0.0   # 被此防护阻挡的代码覆盖率损失
    suggested_bypass: str = ""
    evidence_lines: List[str] = field(default_factory=list)


class AntiFuzzingDetector:
    """反模糊测试检测主引擎.

    从二进制trace或源码中识别四种反fuzzing防护:
      checksum: 输入数据的完整性校验 (CRC32, MD5, SHA, HMAC)
      multistage: 多个串行检查, 任一步失败即退出
      environment: gettimeofday, rand(), /dev/urandom等环境依赖
      anti_coverage: 虚假路径分支, 膨胀CFG阻碍覆盖率引导
    """

    _CHECKSUM_PATTERNS = [
        (r'(?:crc32|CRC32|checksum|crc_check)', 'CRC32 check', 4),
        (r'(?:md5|MD5|MD5_Init|MD5_Update|MD5_Final)', 'MD5 hash check', 7),
        (r'(?:SHA256|SHA1|SHA512|sha256|sha1|sha512|EVP_Digest)',
         'SHA hash check', 8),
        (r'(?:HMAC|hmac|CMAC|AES_CMAC)', 'HMAC/CMAC auth', 9),
        (r'(?:verify_sign|VerifySig|RSA_verify|ECDSA_verify)',
         'crypto signature', 10),
    ]
    _MULTISTAGE_PATTERNS = [
        (r'if\s*\(\s*!\s*\w+\s*\).*return.*if\s*\(\s*!\s*\w+\s*\).*return',
         'serial guard clauses', 5),
        (r'(?:validate|check|verify)_\w+\s*\(.*\)\s*\{.*'
         r'(?:validate|check|verify)_\w+\s*\(.*\)\s*\{',
         'chained validators', 6),
    ]
    _ENV_PATTERNS = [
        (r'(?:gettimeofday|clock_gettime|time\(|GetTickCount)', 'time check', 3),
        (r'(?:rand\(|random\(|srand\(|srandom\(|rand_s)', 'PRNG check', 4),
        (r'(?:/dev/urandom|/dev/random|CryptGenRandom|RtlGenRandom)',
         'crypto PRNG check', 7),
        (r'(?:getenv\(|GetEnvironmentVariable|secure_getenv)',
         'environment check', 3),
        (r'(?:ptrace|PTRACE_TRACEME|is_debugger_present|CheckRemoteDebugger)',
         'anti-debug', 6),
    ]
    _ANTI_COV_PATTERNS = [
        (r'(?:__attribute__\s*\(\s*\(\s*noinline\s*\)\s*\)|'
         r'__declspec\s*\(\s*noinline\s*\))', 'noinline barrier', 2),
        (r'if\s*\(\s*\w+\s*==\s*0x[0-9a-fA-F]{8,}\)',
         'magic constant gate', 5),
        (r'(?:signal|sigaction)\s*\(.*SIG(?:SEGV|ILL|BUS|FPE)',
         'signal handler trap', 6),
    ]

    def detect_from_source(self, source_lines: List[str],
                           file_path: str = "") -> List[AntiFuzzGuard]:
        code = "\n".join(source_lines)
        guards: List[AntiFuzzGuard] = []
        guards.extend(self._scan_category(code, file_path, "checksum",
                        self._CHECKSUM_PATTERNS, source_lines))
        guards.extend(self._scan_category(code, file_path, "multistage",
                        self._MULTISTAGE_PATTERNS, source_lines))
        guards.extend(self._scan_category(code, file_path, "environment",
                        self._ENV_PATTERNS, source_lines))
        guards.extend(self._scan_category(code, file_path, "anti_coverage",
                        self._ANTI_COV_PATTERNS, source_lines))
        for g in guards:
            g.guard_id = f"{file_path}:{g.category}:{hash(g.pattern_matched) & 0xFFFF:04x}"
        return guards

    def detect_from_trace(self, trace_lines: List[str]
                          ) -> List[AntiFuzzGuard]:
        """从执行trace中检测反fuzzing热点.

        trace格式: 每行一条执行的基本块地址或函数调用.
        """
        guards = []
        func_counts = defaultdict(int)
        error_labels = defaultdict(int)
        for line in trace_lines:
            # 统计函数调用频率
            m = re.search(r'(\w+)\s*\(', line)
            if m:
                func_counts[m.group(1)] += 1
            # 检测提前退出模式: return -1 / goto error_cleanup
            if re.search(r'(?:return\s+-1|goto\s+\w+_err|goto\s+cleanup)',
                        line):
                for m2 in re.finditer(r'(\w+)', line):
                    error_labels[m2.group(1)] += 1
        # 高频率错误退出→可能存在多重验证
        for label, count in error_labels.items():
            if count > 3 and "err" in label.lower():
                guards.append(AntiFuzzGuard(
                    guard_id=f"trace:{label}", category="multistage",
                    location=label, pattern_matched=f"error exit x{count}",
                    bypass_difficulty=5,
                    blocked_code_pct=min(count * 5.0, 50.0),
                    suggested_bypass="对该错误标签的所有goto目标进行NOP替换"))
        return guards

    def _scan_category(self, code: str, file_path: str, category: str,
                       patterns: List[Tuple[str, str, int]],
                       lines: List[str]) -> List[AntiFuzzGuard]:
        guards = []
        for pattern, desc, difficulty in patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_no = code[:match.start()].count('\n') + 1
                # 提取证据行 (匹配行及上下文)
                ev_start = max(0, line_no - 2)
                ev_end = min(len(lines), line_no + 1)
                evidence = [f"L{i+1}: {lines[i].rstrip()[:80]}"
                           for i in range(ev_start, ev_end)]
                # 估算影响: 防护之后的代码量/总代码量
                pct_after = (len(lines) - line_no) / max(len(lines), 1) * 100
                bypass = self._suggest_bypass(category, desc)
                guards.append(AntiFuzzGuard(
                    guard_id="", category=category,
                    location=f"{file_path}:{line_no}",
                    pattern_matched=desc,
                    bypass_difficulty=difficulty,
                    blocked_code_pct=round(pct_after, 1),
                    suggested_bypass=bypass,
                    evidence_lines=evidence))
        return guards

    def _suggest_bypass(self, category: str, desc: str) -> str:
        tips = {
            "checksum": ("编译时定义FUZZING_BUILD_MODE宏, 将校验分支条件反转; "
                        "或对校验函数使用LD_PRELOAD拦截返回固定值"),
            "multistage": ("使用T-Fuzz策略: 对中间检查的cmp/jne指令NOP化, "
                          "使多阶段验证退化为单阶段"),
            "environment": ("对时间函数使用faketime/fakeclock LD_PRELOAD; "
                           "对PRNG使用固定种子或libfuzzer的FuzzedDataProvider"),
            "anti_coverage": ("使用C-Fuzz策略: 强制控制流跳转到深度路径; "
                             "或使用AFL_POST_LIBRARY进行覆盖率反馈修复"),
        }
        return tips.get(category, "通用: 条件编译+必要时代码变换")

    def summary(self, guards: List[AntiFuzzGuard]) -> Dict:
        cats = defaultdict(int)
        total_blocked = 0.0
        max_diff = 0
        for g in guards:
            cats[g.category] += 1
            total_blocked = max(total_blocked, g.blocked_code_pct)
            max_diff = max(max_diff, g.bypass_difficulty)
        return {
            "total_guards": len(guards),
            "by_category": dict(cats),
            "max_blocked_pct": round(total_blocked, 1),
            "hardest_bypass": max_diff,
            "overall_assessment": (
                "critical" if max_diff >= 8 else
                "significant" if max_diff >= 5 else
                "moderate" if guards else "none"),
        }
