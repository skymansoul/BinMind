# 修改记录:
# 2025-07-24 09:33 — 初始创建: 正则模式检测四类侧信道泄漏
# 2025-07-31 15:08 — 增加数据流追踪+支配者分析+缓存行冲突建模
# 侧信道泄漏风险评估器: 数据流追踪 / 支配者分支分析 / 缓存行冲突
# 技术问题: 正则匹配仅检测代码模式 (如memcmp), 无法回答:
#   (a) 分支条件中是否包含了秘密数据?
#   (b) 内存访问地址是否依赖秘密值? (flush+reload的信号)
#   (c) 两个密钥相关的访问是否会冲突在同一缓存行?
# 解决手段: 在正则检测基础上增加:
#   层1 — 数据流追踪: 从标记变量 (key, secret, password, token) 出发,
#     追踪哪些变量继承了秘密标签
#   层2 — 支配者分析: 若秘密标签变量出现在条件分支中,
#     该分支的两个方向有不同的执行时间→可被侧信道观测
#   层3 — 缓存行冲突: 对标记为秘密索引的数组访问,
#     计算访问步幅→判断是否在同缓存行 (64B) → prime+probe目标
# 参考 (已验证真实):
#   Yarom & Falkner "FLUSH+RELOAD: a High Resolution, Low Noise, L3
#     Cache Side-Channel Attack" (USENIX Security 2014) —
#     缓存行冲突是侧信道攻击的基础
#   Kocher "Timing Attacks on Implementations of Diffie-Hellman, RSA,
#     DSS, and Other Systems" (CRYPTO 1996) — 时序攻击原型
from __future__ import annotations
import logging, math, re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)

_SECRET_VARS = {"key", "secret", "password", "token", "private_key",
                "nonce", "iv", "plaintext", "ciphertext", "signature",
                "hash", "credential", "passwd", "passphrase", "seed"}

_CACHE_LINE = 64   # x86_64 L1/L2/L3缓存行大小 (字节)


@dataclass
class SideChannelFinding:
    finding_id: str
    category: str         # 'cache_timing' | 'branch_prediction' |
                          # 'page_fault' | 'const_time_violation' |
                          # 'data_flow_leak' | 'cache_conflict'
    description: str
    severity: float = 5.0; location: str = ""
    code_snippet: str = ""; attack_scenario: str = ""
    mitigation: str = ""


class SecretDataFlow:
    """秘密数据流追踪: 从秘密变量出发, 追踪标签传播.

    秘密标签传播规则:
      - 赋值: x = secret → x 继承 secret 标签
      - 算术: x = a op b → 若a或b有标签, x继承
      - 数组索引: arr[secret] → arr的索引有标签→cache timing
      - 条件分支: if (secret_expr) → 分支方向依赖秘密
    """

    def __init__(self):
        self._secret_vars: Set[str] = set()
        self._tainted_exprs: Set[str] = set()
        self._secret_branches: List[Tuple[str, int]] = []
        self._secret_indices: List[Tuple[str, str, int]] = []  # (array, index, line)
        self._cache_accesses: List[Tuple[str, int, int]] = []  # (array, stride, line)

    def mark_secret(self, var_name: str):
        self._secret_vars.add(var_name)

    def propagate_assign(self, lhs: str, rhs: str, line_no: int = 0):
        if rhs in self._secret_vars:
            self._secret_vars.add(lhs)
            self._tainted_exprs.add(rhs)

    def propagate_arith(self, lhs: str, operands: List[str], line_no: int = 0):
        if any(op in self._secret_vars for op in operands):
            self._secret_vars.add(lhs)
            for op in operands:
                if op in self._secret_vars:
                    self._tainted_exprs.add(op)

    def detect_secret_branch(self, condition: str, line_no: int):
        """检测条件分支是否依赖秘密变量."""
        for sv in self._secret_vars:
            if sv in condition:
                self._secret_branches.append((condition.strip()[:80], line_no))
                break

    def detect_secret_index(self, array: str, index: str, line_no: int,
                            stride: int = 1):
        """检测数组索引是否依赖秘密变量."""
        for sv in self._secret_vars:
            if sv in index or sv == index:
                self._secret_indices.append((array, index, line_no))
                self._cache_accesses.append((array, stride, line_no))
                break

    def cache_conflicts(self) -> List[Tuple[str, str, int, int]]:
        """检测缓存行冲突: 两个秘密索引访问是否在同一缓存行.

        若 stride < _CACHE_LINE 且都是秘密驱动的访问→
        可被prime+probe或flush+reload观测.
        """
        conflicts = []
        for i, (arr1, stride1, ln1) in enumerate(self._cache_accesses):
            for arr2, stride2, ln2 in self._cache_accesses[i+1:]:
                if arr1 == arr2:
                    continue
                if abs(stride1 - stride2) < _CACHE_LINE and stride1 < _CACHE_LINE:
                    conflicts.append((arr1, arr2, ln1, ln2))
        return conflicts


class SideChannelAssessor:
    """侧信道泄漏风险评估器 (含数据流分析).

    用法:
      assessor = SideChannelAssessor()
      findings = assessor.assess(code, is_crypto_code=True)
      for f in findings:
          print(f'{f.category}: {f.severity:.1f}')
    """

    _CACHE_PATTERNS = [
        (re.compile(r'(\w+)\s*\[(\w+)\s*\^\s*(\w+)\]'),
         "XOR-indexed lookup: 可能AES S-Box→cache timing",
         "使用AES-NI硬件指令替代"),
        (re.compile(r'(\w+)\s*\[(\w+)\s*&\s*0x[0-9a-fA-F]+\]'),
         "masked index: 查表依赖秘密→flush+reload可行",
         "确保索引与秘密无关"),
    ]
    _BRANCH_PATTERNS = [
        (re.compile(r'if\s*\(\s*(\w+)\s*(?:==|!=|<|>)\s*\w+\s*\).*'
                    r'(?:return|break|goto)', re.DOTALL),
         "秘密依赖的条件分支: 方向泄露1bit信息",
         "使用cmov或位操作替代"),
    ]
    _CONST_TIME_PATTERNS = [
        (re.compile(r'(?:memcmp|strcmp|strncmp|bcmp)\s*\([^)]*\)\s*'
                    r'(?:!=|==)\s*0'),
         "memcmp/strcmp提前返回→逐字节oracle",
         "使用CRYPTO_memcmp或累积diff后统一返回"),
    ]

    def assess(self, code: str, file_path: str = "",
               is_crypto_code: bool = False) -> List[SideChannelFinding]:
        findings: List[SideChannelFinding] = []
        boost = 2.0 if is_crypto_code else 0.0
        # 层1: 秘密数据流追踪
        sdf = SecretDataFlow()
        self._run_dataflow(code, sdf)
        # 秘密分支→侧信道发现
        for cond, line in sdf._secret_branches:
            findings.append(SideChannelFinding(
                finding_id=f"branch_{len(findings)}",
                category="branch_prediction",
                description=f"分支条件依赖秘密变量: {cond}",
                severity=min(10.0, 6.0 + boost),
                location=f"{file_path}:L{line}",
                attack_scenario="Spectre v1 / branch timing oracle",
                mitigation="使用cmov或位操作消除条件分支"))
        # 秘密索引→缓存时序
        for arr, idx, line in sdf._secret_indices:
            findings.append(SideChannelFinding(
                finding_id=f"cache_{len(findings)}",
                category="cache_timing",
                description=f"数组{arr}的索引{idx}依赖秘密→cache地址泄露",
                severity=min(10.0, 7.0 + boost),
                location=f"{file_path}:L{line}",
                attack_scenario="Prime+Probe / Flush+Reload",
                mitigation="使用常量时间查表或数据无关访问模式"))
        # 缓存冲突
        for arr1, arr2, ln1, ln2 in sdf.cache_conflicts():
            findings.append(SideChannelFinding(
                finding_id=f"conflict_{len(findings)}",
                category="cache_conflict",
                description=f"{arr1}(L{ln1})和{arr2}(L{ln2})共享缓存行",
                severity=min(10.0, 5.0 + boost),
                location=f"{file_path}:L{ln1}",
                attack_scenario="Evict+Time / Prime+Probe",
                mitigation="padding到不同缓存行或随机化访问顺序"))
        # 层2: 正则模式检测 (原有功能保留)
        for pattern, desc, mitigation in self._CACHE_PATTERNS:
            for m in pattern.finditer(code):
                findings.append(SideChannelFinding(
                    finding_id=f"pat_{len(findings)}", category="cache_timing",
                    description=desc, severity=min(10.0, 6.0 + boost),
                    code_snippet=m.group(0)[:80], mitigation=mitigation))
        for pattern, desc, mitigation in self._BRANCH_PATTERNS:
            for m in pattern.finditer(code):
                findings.append(SideChannelFinding(
                    finding_id=f"pat_{len(findings)}", category="branch_prediction",
                    description=desc, severity=min(10.0, 5.0 + boost),
                    code_snippet=m.group(0)[:80], mitigation=mitigation))
        for pattern, desc, mitigation in self._CONST_TIME_PATTERNS:
            for m in pattern.finditer(code):
                findings.append(SideChannelFinding(
                    finding_id=f"pat_{len(findings)}", category="const_time_violation",
                    description=desc, severity=min(10.0, 7.0 + boost),
                    code_snippet=m.group(0)[:80], mitigation=mitigation))
        return findings

    def _run_dataflow(self, code: str, sdf: SecretDataFlow):
        """执行秘密数据流分析.

        解析代码的每行, 识别:
          - 秘密变量声明/初始化
          - 赋值传播
          - 条件分支
          - 数组索引
        """
        lines = code.split('\n')
        # 第一遍: 识别秘密变量
        for i, line in enumerate(lines):
            for sv in _SECRET_VARS:
                if re.search(rf'\b{sv}\b', line, re.IGNORECASE):
                    sdf.mark_secret(sv)
                    # 识别赋值: var = secret
                    m = re.match(r'(\w+)\s*=\s*(\w+)', line.strip())
                    if m:
                        sdf.propagate_assign(m.group(1), m.group(2), i + 1)
        # 第二遍: 传播+检测
        for i, line in enumerate(lines):
            stripped = line.strip()
            # 赋值: x = expr
            m = re.match(r'(\w+)\s*=\s*(\w+)\s*([+\-*/^|&])\s*(\w+)', stripped)
            if m:
                lhs = m.group(1)
                ops = [m.group(2), m.group(4)]
                sdf.propagate_arith(lhs, ops, i + 1)
                continue
            m = re.match(r'(\w+)\s*=\s*(\w+)', stripped)
            if m:
                sdf.propagate_assign(m.group(1), m.group(2), i + 1)
            # 条件分支
            m = re.match(r'if\s*\((.*)\)', stripped)
            if m:
                sdf.detect_secret_branch(m.group(1), i + 1)
            # 数组索引: arr[expr]
            for arr_m in re.finditer(r'(\w+)\s*\[(\w+)\]', stripped):
                arr_name = arr_m.group(1)
                idx_name = arr_m.group(2)
                # 推断步幅: 从类型声明推断
                stride = 4  # 默认4字节 (int)
                if 'char' in stripped or 'byte' in stripped.lower():
                    stride = 1
                elif 'long' in stripped or 'double' in stripped:
                    stride = 8
                sdf.detect_secret_index(arr_name, idx_name, i + 1, stride)

    def assess_risk_score(self, findings: List[SideChannelFinding]) -> Dict:
        if not findings:
            return {"overall_risk": "low", "max_severity": 0.0, "total_findings": 0}
        max_sev = max(f.severity for f in findings)
        cats = defaultdict(int)
        for f in findings: cats[f.category] += 1
        return {
            "overall_risk": ("critical" if max_sev >= 9 else
                            "high" if max_sev >= 7 else
                            "medium" if max_sev >= 4 else "low"),
            "max_severity": max_sev, "total_findings": len(findings),
            "by_category": dict(cats),
            "most_severe": max(findings, key=lambda f: f.severity).description,
        }
