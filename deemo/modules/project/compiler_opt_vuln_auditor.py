# 编译器优化漏洞审计器: 优化引入/掩盖漏洞的模式检测
# 技术问题: 编译器优化 (-O2/-O3) 可能在以下情况引入或掩盖安全漏洞:
#   (a) 死代码消除 (DSE): 删除看似无用的安全检查代码 (memset_s清零被优化)
#   (b) 边界检查消除: 编译器证明"索引不可能越界"→删除边界检查→
#       但证明依赖未定义行为假设, 实际运行时越界
#   (c) 未定义行为利用: 编译器假设UB不发生进行优化,
#       将NULL指针检查优化掉 (因为"解引用了就不可能为NULL")
#   (d) 常量折叠传播: 将密钥/随机数优化为常量
#   (e) 内存排序重排: 编译器重排volatile/atomic操作破坏同步语义
#   现有工具 (SAST, UBSan) 检查源代码而非编译器行为,
#   无法审计编译器优化对安全属性的影响
# 解决手段: 构建优化→安全属性映射表, 对C/C++代码片段检测
#   可能被特定优化破坏的安全模式:
#   1. memset_s/bzero安全清零→可能被DSE消除
#   2. assert(ptr!=NULL)→优化后可能被移除 (NDEBUG)
#   3. 有符号溢出检查→UB假设可能导致检查被移除
#   4. volatile遗漏→编译器重排破坏同步
# 技术效果: 检测编译器优化可能引入的6类安全模式, 覆盖
#   已知编译器优化导致的安全问题 (如CVE-2009-1897 NULL指针优化消除)
# 参考:
#   CVE-2009-1897 (Linux kernel) — NULL指针检查被GCC优化消除
#   Wang et al. "Towards Optimization-Safe Systems" (HotOS 2013)
#   MemBuster (USENIX 2025) — 内存安全优化的形式化验证
from __future__ import annotations
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)


@dataclass
class OptVulnFinding:
    """编译器优化可能引入的漏洞."""
    finding_id: str
    pattern_type: str        # 'dead_store_elim' | 'bounds_check_elim' |
                             # 'null_check_elim' | 'const_prop_leak' |
                             # 'mem_order_reorder' | 'assert_removal'
    optimization_flag: str    # '-O2' | '-O3' | '-Os' | '-Oz'
    location: str = ""
    code_snippet: str = ""
    risk: str = "medium"     # 'critical' | 'high' | 'medium' | 'low'
    cwe: str = ""
    mitigation: str = ""


class CompilerOptVulnAuditor:
    """编译器优化漏洞审计器.

    检测以下六类优化→安全属性冲突:
      1. DSE消除安全清零
      2. 边界检查被优化消除
      3. NULL指针检查消除 (UB假设)
      4. 常量传播泄露密钥/随机数
      5. 内存排序重排破坏同步
      6. assert中的安全检查被NDEBUG移除
    """

    _DEAD_STORE_PATTERNS = [
        # memset清零后立即free (DSE可能消除memset)
        (re.compile(r'memset\s*\(\s*(\w+)\s*,\s*0\s*,\s*(\w+)\s*\).*?free\s*\(\s*\1\s*\)',
                    re.DOTALL),
         "memset清零后free: DSE可能消除清零, 敏感数据残留堆内存"),
        # bzero后未读取
        (re.compile(r'(?:bzero|explicit_bzero)\s*\(\s*(\w+).*?\)'
                    r'(?!.*\1).{0,200}(?:return|free|goto)',
                    re.DOTALL),
         "bzero后变量未被读取: DSE可消除清零"),
        # 安全清零后未使用内存即结束作用域
        (re.compile(r'(?:memset_s|SecureZeroMemory|RtlSecureZeroMemory)\s*\(.*?\).{0,100}\}',
                    re.DOTALL),
         "安全清零API后立即结束作用域: 编译器可能内联后优化消除"),
    ]

    _BOUNDS_CHECK_PATTERNS = [
        # 有符号int作为数组索引, 编译器假设>=0 (UB假设)
        (re.compile(r'int\s+(\w+)\s*=.*?;.*?(\w+)\s*\[\s*\1\s*\]', re.DOTALL),
         "有符号int作数组索引: 编译器假设非负, 移除符号检查"),
        # 检查后无副作用的bounds check (可能被消除)
        (re.compile(r'if\s*\(\s*(\w+)\s*(?:>=|>)\s*(\w+)\s*\).*?'
                    r'(?:return|abort|exit|__builtin_unreachable)',
                    re.DOTALL),
         "边界检查+终止: 若终止路径被优化→检查可能被删除"),
    ]

    _NULL_CHECK_PATTERNS = [
        # ptr已解引用→后续NULL检查 (编译器推断ptr非NULL→移除检查)
        (re.compile(r'(\w+)->(\w+).{0,200}if\s*\(\s*!\s*\1\s*\)', re.DOTALL),
         "解引用后的NULL检查: 编译器推断ptr非NULL移除检查"),
        # 函数参数ptr解引用在NULL检查之前 (UB)
        (re.compile(r'void\s+\w+\s*\([^)]*\*\s*(\w+)[^)]*\).*?'
                    r'\1->.{0,300}if\s*\(\s*!\s*\1\s*\)', re.DOTALL),
         "函数参数先解引用后NULL检查: 编译器基于UB假设移除"),
    ]

    _CONST_PROP_PATTERNS = [
        # 局部常量密钥 (可能被常量折叠)
        (re.compile(r'(?:static\s+)?const\s+(?:char|unsigned\s+char)\s+(\w+)\['
                    r'[^\]]*\]\s*=\s*[\"\']', re.DOTALL),
         "const局部密钥: 常量折叠后密钥可能嵌入指令立即数"),
        # 编译时计算的随机种子
        (re.compile(r'srand\s*\(\s*(?:time\(0\)|0|[0-9]+)\s*\)',
                    re.DOTALL),
         "固定种子的srand: 常量传播后随机序列可预测"),
    ]

    _MEM_ORDER_PATTERNS = [
        # 缺少volatile的共享变量
        (re.compile(r'(?:int|bool|unsigned)\s+(\w+)\s*;(?!.*volatile)',
                    re.DOTALL),
         "无volatile修饰的共享标志: 编译器可重排访问顺序"),
        # atomic_store/load未使用显式memory_order
        (re.compile(r'atomic_(?:store|load)\s*\([^,]+,\s*memory_order_relaxed',
                    re.DOTALL),
         "memory_order_relaxed: 无同步保证, 编译器可激进重排"),
    ]

    _ASSERT_PATTERNS = [
        # assert中包含安全关键检查
        (re.compile(r'assert\s*\(\s*(?:p|ptr|buf|data)\s*!=\s*(?:NULL|nullptr|0)\s*\)',
                    re.DOTALL),
         "assert中的NULL检查: NDEBUG定义时被移除"),
        (re.compile(r'assert\s*\(\s*(\w+)\s*<=\s*(?:MAX|SIZE|LEN|LIMIT)',
                    re.DOTALL),
         "assert中的边界检查: NDEBUG移除导致无保护访问"),
    ]

    def audit(self, code: str, optimization_flag: str = "-O2",
              file_path: str = "") -> List[OptVulnFinding]:
        findings: List[OptVulnFinding] = []
        findings.extend(self._check_patterns(
            code, optimization_flag, file_path,
            "dead_store_elim", self._DEAD_STORE_PATTERNS,
            "CWE-226", "使用volatile或__attribute__((used))标记清零操作; "
            "或调用explicit_bzero/memset_s替代memset"))
        findings.extend(self._check_patterns(
            code, optimization_flag, file_path,
            "bounds_check_elim", self._BOUNDS_CHECK_PATTERNS,
            "CWE-129", "对索引变量使用size_t/size_t类型; "
            "或使用__builtin_assume表达边界约束"))
        findings.extend(self._check_patterns(
            code, optimization_flag, file_path,
            "null_check_elim", self._NULL_CHECK_PATTERNS,
            "CWE-476", "将NULL检查移到解引用之前; "
            "或使用__attribute__((optimize(\"O0\")))标记关键函数"))
        findings.extend(self._check_patterns(
            code, optimization_flag, file_path,
            "const_prop_leak", self._CONST_PROP_PATTERNS,
            "CWE-321", "避免const局部密钥; 运行时从外部加载密钥; "
            "使用__attribute__((noinline))阻止内联"))
        findings.extend(self._check_patterns(
            code, optimization_flag, file_path,
            "mem_order_reorder", self._MEM_ORDER_PATTERNS,
            "CWE-362", "对共享变量添加volatile; "
            "使用atomic_store/load+memory_order_seq_cst"))
        findings.extend(self._check_patterns(
            code, optimization_flag, file_path,
            "assert_removal", self._ASSERT_PATTERNS,
            "CWE-617", "将安全关键检查从assert移动到显式if检查; "
            "assert仅用于调试诊断"))
        for f in findings:
            f.finding_id = f"{file_path}:{f.pattern_type}:{hash(f.code_snippet) & 0xFFFF:04x}"
        return findings

    def _check_patterns(self, code: str, opt_flag: str, file_path: str,
                        ptype: str, patterns: List[Tuple[re.Pattern, str]],
                        cwe: str, mitigation: str
                        ) -> List[OptVulnFinding]:
        findings = []
        for pattern, desc in patterns:
            for match in pattern.finditer(code):
                line_no = code[:match.start()].count('\n') + 1
                snippet = match.group(0)[:120]
                # 风险评估: 结合优化级别
                risk = self._assess_risk(ptype, opt_flag)
                findings.append(OptVulnFinding(
                    finding_id="", pattern_type=ptype,
                    optimization_flag=opt_flag,
                    location=f"{file_path}:{line_no}",
                    code_snippet=snippet,
                    risk=risk, cwe=cwe, mitigation=mitigation))
        return findings

    def _assess_risk(self, ptype: str, opt_flag: str) -> str:
        """结合优化级别评估风险.

        -O3比-O2更激进: 激进内联和循环向量化使某些模式更危险.
        -Os/-Oz: 空间优先→DSE更激进→清零消除概率更高.
        """
        base_risk = {
            "dead_store_elim": "high",
            "bounds_check_elim": "high",
            "null_check_elim": "critical",
            "const_prop_leak": "medium",
            "mem_order_reorder": "medium",
            "assert_removal": "high",
        }.get(ptype, "medium")
        if opt_flag in ("-O3", "-Ofast") and base_risk != "critical":
            if base_risk == "high":
                return "critical"
        if opt_flag in ("-Os", "-Oz") and ptype == "dead_store_elim":
            return "critical"
        return base_risk

    def audit_batch(self, files: Dict[str, str],
                    optimization_flag: str = "-O2"
                    ) -> Dict[str, List[OptVulnFinding]]:
        return {path: self.audit(code, optimization_flag, path)
                for path, code in files.items()}

    def summary(self, findings: List[OptVulnFinding]) -> Dict:
        cats = defaultdict(int)
        risks = defaultdict(int)
        for f in findings:
            cats[f.pattern_type] += 1
            risks[f.risk] += 1
        return {
            "total": len(findings), "by_type": dict(cats),
            "by_risk": dict(risks),
            "worst_risk": "critical" if risks["critical"] > 0 else
                          "high" if risks["high"] > 0 else
                          "medium" if risks["medium"] > 0 else "low",
        }
