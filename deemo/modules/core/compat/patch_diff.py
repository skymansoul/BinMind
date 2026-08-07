# 安全补丁差分分析 — 1-day 漏洞检测与利用原语推断
# ReSyn — 符号恢复与程序逻辑交叉验证在补丁分析中的应用
# FirmNamer — 固件逆向中的多模态语义匹配策略
# "Enhancing Vulnerability Detection via AST-Based Patch Decomposition"
# — AST 层级补丁分解与安全影响评估

import re as _re
import hashlib as _hl
import difflib as _dl

# 补丁类型分类
# 从 diff hunks 推断补丁的安全性质
# 基于修改模式而非关键词匹配 — 后者易被 commit message 误导


def classify_patch_type(added_lines: list[str], removed_lines: list[str],
                        context_func_name: str = '') -> str:
    # 基于代码变更模式的安全补丁分类。
    # 返回: bounds_check | integer_overflow | use_after_free | format_string
    #       | race_condition | input_validation | error_handling | refactor | unknown
    added_text = '\n'.join(added_lines)
    rm_text = '\n'.join(removed_lines)

    # 边界检查模式
    bounds_patterns = [
        r'if\s*\(.*>=\s*(?:size|len|count|max)',
        r'if\s*\(.*<=\s*(?:size|len|count|max)',
        r'if\s*\(.*==\s*NULL', r'if\s*\(.*!=\s*NULL',
        r'if\s*\(.*>\s*(?:0x[0-9a-fA-F]+|\d+)\)',
        r'BUG_ON\s*\(', r'WARN_ON\s*\(',
    ]
    for pat in bounds_patterns:
        if _re.search(pat, added_text) and not _re.search(pat, rm_text):
            return 'bounds_check'

    # 整数溢出: 新增 size_t 检查或乘法溢出保护
    if _re.search(r'(?:size_t|uint(?:32|64)_t|unsigned\s+(?:int|long))\s+\w+\s*=', added_text):
        if _re.search(r'if\s*\([^)]*(?:\*|overflow|wrap)', added_text):
            return 'integer_overflow'

    # UAF: free 后置 NULL
    if _re.search(r'(?:kfree|free|delete)\s*\(', added_text):
        after_free = added_text[added_text.find('free'):]
        if _re.search(r'=\s*NULL|=\s*nullptr', after_free):
            return 'use_after_free'

    # 格式字符串: va_list 或格式参数
    if _re.search(r'va_list|va_start|va_end|vsnprintf', added_text):
        return 'format_string'

    # 竞态条件: 锁操作
    if _re.search(r'(?:mutex_lock|spin_lock|rwlock|down_read|up_read)', added_text):
        return 'race_condition'

    # 输入验证: 新增对用户可控数据的检查
    if _re.search(r'copy_from_user|__copy_from_user|memcpy.*user', context_func_name):
        return 'input_validation'

    # 错误处理: 新增 goto 错误标签或 return -E*
    if _re.search(r'goto\s+\w+_err|return\s+-E\w+', added_text):
        if not _re.search(r'goto\s+\w+_err|return\s+-E\w+', rm_text):
            return 'error_handling'

    # 无实质变更
    if added_lines == removed_lines:
        return 'refactor'

    return 'unknown'


# 语义级补丁差分
# 超越逐行 diff — 比较修改前后函数的控制流和数据流变化
# Nguyen et al. 的 AST 层级分解


def compute_semantic_diff(before_cfg: dict, after_cfg: dict) -> dict:
    """比较补丁前后 CFG 的语义差异。
    before_cfg/after_cfg: {block_addr: {'instructions': [...], 'successors': [...]}}

    返回:
    {
        'added_blocks': int,        # 新增基本块数
        'removed_blocks': int,      # 删除基本块数
        'changed_blocks': int,      # 修改基本块数（指令变更但地址未变）
        'added_edges': int,         # 新增控制流边的数量
        'removed_edges': int,
        'complexity_delta': float,  # 圈复杂度变化 (正=增加)
        'security_impact': str,     # none|low|medium|high|critical
    }"""
    before_addrs = set(before_cfg.keys())
    after_addrs = set(after_cfg.keys())

    added = after_addrs - before_addrs
    removed = before_addrs - after_addrs
    common = before_addrs & after_addrs

    # 基本块变化
    changed = 0
    for addr in common:
        b_insns = before_cfg[addr].get('instructions', [])
        a_insns = after_cfg[addr].get('instructions', [])
        if b_insns != a_insns:
            changed += 1

    # 边变化
    before_edges = set()
    after_edges = set()
    for addr, info in before_cfg.items():
        for succ in info.get('successors', []):
            before_edges.add((addr, succ))
    for addr, info in after_cfg.items():
        for succ in info.get('successors', []):
            after_edges.add((addr, succ))

    added_edges = len(after_edges - before_edges)
    removed_edges = len(before_edges - after_edges)

    # 圈复杂度近似: edges - nodes + 2
    def cyclomatic(cfg):
        nodes = len(cfg)
        edges = sum(len(info.get('successors', [])) for info in cfg.values())
        return edges - nodes + 2

    cc_before = cyclomatic(before_cfg)
    cc_after = cyclomatic(after_cfg)

    # 安全影响评估
    impact = _assess_security_impact(len(added), len(removed), changed,
                                      added_edges, removed_edges,
                                      cc_after - cc_before)

    return {
        'added_blocks': len(added),
        'removed_blocks': len(removed),
        'changed_blocks': changed,
        'added_edges': added_edges,
        'removed_edges': removed_edges,
        'complexity_delta': round(cc_after - cc_before, 2),
        'security_impact': impact,
    }


def _assess_security_impact(n_added: int, n_removed: int, n_changed: int,
                             n_added_edges: int, n_removed_edges: int,
                             cc_delta: float) -> str:
    """基于代码变更量评估安全影响等级。
    新增边界检查（复杂度略微增加 + 新增块）→ high
    大量代码重构（复杂度大幅变化）→ low (很可能仅是重构)
    少量变更（1-3 块变化）→ 视边变化而定。"""
    if n_added == 0 and n_removed == 0 and n_changed <= 2:
        return 'low'  # 微调
    if n_added <= 3 and n_changed <= 1 and cc_delta > 0 and cc_delta < 5:
        return 'high'  # 典型的漏洞修复：小范围增加检查
    if n_added + n_removed >= 10:
        return 'low'  # 大规模重写 → 很可能是重构
    if n_added_edges >= 3 or n_removed_edges >= 3:
        return 'medium'  # 控制流调整
    return 'medium'


# 相似函数匹配 (用于找到补丁影响的未打补丁版本)
# ReSyn 的符号交叉验证 — 将函数级匹配从语法提升到语义

def find_vulnerable_clone(patched_func_insns: list[tuple[str, str]],
                           candidate_pool: dict[str, list[tuple[str, str]]],
                           min_similarity: float = 0.65) -> list[dict]:
    """在候选池中搜索与已修复函数相似的未修复版本。
    使用归一化指令序列的 Jaccard 相似度。

    candidate_pool: {func_identifier: [(mnemonic, operands), ...]}

    返回匹配列表，按相似度降序排列。低于 min_similarity 的结果被过滤。"""
    def normalize(insns):
        normed = set()
        for mnem, ops in insns:
            n = _re.sub(r'0x[0-9a-fA-F]+', 'IMM', ops)
            n = _re.sub(r'-?\d+', 'IMM', n)
            normed.add(f'{mnem} {n}')
        return normed

    patched_set = normalize(patched_func_insns)

    matches = []
    for func_id, insns in candidate_pool.items():
        cand_set = normalize(insns)
        inter = len(patched_set & cand_set)
        union = len(patched_set | cand_set)
        jaccard = inter / union if union > 0 else 0.0

        if jaccard >= min_similarity:
            matches.append({
                'function_id': func_id,
                'similarity': round(jaccard, 3),
                'shared_instructions': inter,
                'total_unique': union,
            })

    matches.sort(key=lambda m: -m['similarity'])
    return matches


# Xref 引导的补丁影响分析
# 补丁修改的函数可能被多处调用 — 修复一个点但遗漏其他调用点
# FirmNamer 的多模态语义匹配 — 跨编译单元的全局符号关联

def patch_impact_analysis(patched_func_name: str,
                           callers: dict[str, list[str]],
                           callees: dict[str, list[str]]) -> dict:
    """分析补丁的影响面: 哪些上游调用者可能也受影响。
    返回 callers → patched_function 的传递闭包 (2 跳以内)。"""
    # 直达调用者 (1-hop)
    direct_callers = set()
    for caller, targets in callees.items():
        if patched_func_name in targets:
            direct_callers.add(caller)

    # 间接调用者 (2-hop)
    indirect_callers = set()
    for dc in direct_callers:
        for caller, targets in callees.items():
            if dc in targets and caller != patched_func_name:
                indirect_callers.add(caller)

    return {
        'patched_function': patched_func_name,
        'direct_callers': sorted(direct_callers),
        'indirect_callers': sorted(indirect_callers - direct_callers),
        'total_affected_call_sites': len(direct_callers) + len(indirect_callers - direct_callers),
        'risk_level': 'high' if len(direct_callers) >= 5 else (
            'medium' if len(direct_callers) >= 2 else 'low'),
    }


# Commit Message 解析
# 从 git log 或 CVE 公告中提取安全相关信息
# 基于 CVE/NVD 描述的结构化解析模式

_CVE_PATTERN = _re.compile(r'CVE-\d{4}-\d{4,}', _re.IGNORECASE)
_SECURITY_KEYWORDS = frozenset({
    'overflow', 'injection', 'bypass', 'escalation', 'disclosure',
    'corruption', 'null pointer', 'race condition', 'use after free',
    'double free', 'out of bounds', 'arbitrary code', 'denial of service',
    'privilege escalation', 'information leak', 'memory leak',
    'authentication bypass', 'remote code execution', 'rce',
})


def parse_security_commit(message: str) -> dict:
    """从 commit message 中提取安全相关信息。
    识别 CVE 编号、漏洞类型、影响范围。"""
    cves = _CVE_PATTERN.findall(message)
    msg_lower = message.lower()

    vuln_types = []
    for kw in _SECURITY_KEYWORDS:
        if kw in msg_lower:
            vuln_types.append(kw)

    # 严重度推断
    if any(t in msg_lower for t in ('remote code execution', 'rce', 'arbitrary code')):
        severity = 'critical'
    elif any(t in msg_lower for t in ('privilege escalation', 'escalation', 'bypass')):
        severity = 'high'
    elif any(t in msg_lower for t in ('denial of service', 'dos', 'memory leak')):
        severity = 'medium'
    elif vuln_types:
        severity = 'medium'
    else:
        severity = 'low'

    return {
        'cve_ids': cves,
        'vulnerability_types': vuln_types,
        'severity': severity,
        'has_security_implication': len(vuln_types) > 0 or len(cves) > 0,
    }


# 补丁差分行级匹配 (LCS-based)
# 最长公共子序列 → 识别补丁的实质变更 vs 格式化变更
# 忽略空白行、注释变更和仅缩进调整的行

def diff_essential_changes(before_lines: list[str], after_lines: list[str]) -> dict:
    """提取补丁中的实质性变更（忽略空白/注释/缩进变更）。
    返回实质增删行的索引和内容。"""
    # 预处理: 去除空白和纯注释行
    def essential(lines):
        result = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue
            if stripped.startswith('#') and 'define' not in stripped:
                continue
            result.append(_re.sub(r'\s+', ' ', stripped))
        return result

    b_ess = essential(before_lines)
    a_ess = essential(after_lines)

    # 使用 difflib 的 SequenceMatcher
    matcher = _dl.SequenceMatcher(None, b_ess, a_ess)
    opcodes = matcher.get_opcodes()

    essential_added = []
    essential_removed = []
    for tag, i1, i2, j1, j2 in opcodes:
        if tag == 'insert':
            essential_added.extend(a_ess[j1:j2])
        elif tag == 'delete':
            essential_removed.extend(b_ess[i1:i2])
        elif tag == 'replace':
            essential_removed.extend(b_ess[i1:i2])
            essential_added.extend(a_ess[j1:j2])

    return {
        'total_before_lines': len(before_lines),
        'total_after_lines': len(after_lines),
        'essential_removed': essential_removed,
        'essential_added': essential_added,
        'noise_ratio': 1.0 - (len(essential_added) + len(essential_removed)) /
                       max(len(before_lines) + len(after_lines), 1),
    }
