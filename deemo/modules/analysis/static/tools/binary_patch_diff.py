# 二进制补丁差异分析 - 通过函数级多特征指纹匹配定位patch引入/移除/修改的函数
# 设计思路：四阶段渐进式匹配(名称→mnemonic hash→mnemonic profile→模糊匹配)，安全相关性标记
# 权衡：不做基本块级控制流图同构匹配(BinDiff策略)，用助记符分布+哈希在速度vs精度间取平衡

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Set
from collections import defaultdict
import re
import math


@dataclass
class FuncProfile:
    name: str
    address: int
    mnemonic_hash: str
    mnemonics: List[str]
    basic_block_count: int
    instruction_count: int
    call_targets: List[str]


@dataclass
class FunctionDiff:
    func_a: FuncProfile
    func_b: FuncProfile
    similarity: float
    match_method: str
    changes: List[str]


@dataclass
class PatchDiffResult:
    matched: List[FunctionDiff]
    added: List[FuncProfile]
    removed: List[FuncProfile]
    modified: List[FunctionDiff]
    security_relevant: List[FunctionDiff]
    section_hashes: Dict[str, Tuple[str, str]]


# 安全敏感函数关键字
_SECURITY_KEYWORDS = [
    'crypt', 'encrypt', 'decrypt', 'cipher', 'aes', 'rsa', 'hash',
    'auth', 'login', 'password', 'credential', 'token', 'session',
    'permission', 'privilege', 'capability', 'access_control', 'acl',
    'verify', 'validate', 'sanitize', 'escape', 'filter', 'check',
    'sign', 'signature', 'certificate', 'ssl', 'tls', 'pki',
    'seccomp', 'sandbox', 'chroot', 'setuid', 'setgid', 'capset',
    'rand', 'random', 'entropy', 'rng',
    'key', 'secret', 'private', 'sensitive',
    'protect', 'guard', 'canary', 'nx', 'aslr',
]

# //// 指令助记符抽取 ////
# CPU指令助记符正则 - 提取纯指令部分，剥离操作数
_INSN_RE = re.compile(r'^\s*([a-zA-Z][a-zA-Z0-9]*)')


def extract_mnemonics(asm_lines: List[str]) -> List[str]:
    """从汇编行中提取纯助记符(小写)，过滤标签/伪指令"""
    _result = []
    for _ln in asm_lines:
        _s = _ln.strip()
        # 跳过空行、标签、注释行
        if not _s or _s.startswith(';') or _s.startswith('#') or _s.startswith('.'):
            continue
        if _s.endswith(':'):
            continue
        _m = _INSN_RE.match(_s)
        if _m:
            _result.append(_m.group(1).lower())
    return _result


# mnemonic哈希
def compute_mnemonic_hash(mnemonics: List[str]) -> str:
    """助记符序列的SHA256 - 严格匹配用，不抗指令重排"""
    _joined = '|'.join(mnemonics)
    return hashlib.sha256(_joined.encode('utf-8', errors='replace')).hexdigest()


# //// mnemonic频次向量 ////
def build_mnemonic_profile(mnemonics: List[str]) -> Dict[str, float]:
    """构建助记符频率分布(normalized unit vector)"""
    if not mnemonics:
        return {}
    _counter: Dict[str, int] = {}
    for _m in mnemonics:
        _counter[_m] = _counter.get(_m, 0) + 1
    # 标准化 unit vector
    _mag = math.sqrt(sum(v * v for v in _counter.values()))
    if _mag == 0:
        return {}
    return {_k: _v / _mag for _k, _v in _counter.items()}


# 余弦相似度
def cosine_similarity(vec1: Dict[str, float], vec2: Dict[str, float]) -> float:
    """归一化词频向量的余弦相似度 - 1.0=完全相同, 0.0=正交"""
    if not vec1 or not vec2:
        return 0.0
    _all_keys = set(vec1.keys()) | set(vec2.keys())
    _dot = sum(vec1.get(k, 0.0) * vec2.get(k, 0.0) for k in _all_keys)
    # 注意: vec1/vec2已经归一化, _dot就是余弦相似度
    return _dot


# //// 第一轮: 名称匹配 ////
def match_by_name(funcs_a: List[FuncProfile], funcs_b: List[FuncProfile]) -> Tuple[List[FunctionDiff], List[FuncProfile], List[FuncProfile]]:
    """按函数名精确匹配 — 最可靠的匹配方式"""
    _matched = []
    _b_by_name: Dict[str, FuncProfile] = {f.name: f for f in funcs_b}
    _unmatched_b_names = set(_b_by_name.keys())

    _unmatched_a = []
    for _fa in funcs_a:
        if _fa.name in _b_by_name:
            _fb = _b_by_name[_fa.name]
            _unmatched_b_names.discard(_fa.name)
            _diff = FunctionDiff(
                func_a=_fa, func_b=_fb,
                similarity=1.0,
                match_method='name',
                changes=detect_changes_between(_fa, _fb)
            )
            _matched.append(_diff)
        else:
            _unmatched_a.append(_fa)

    _unmatched_b = [f for f in funcs_b if f.name in _unmatched_b_names]
    return _matched, _unmatched_a, _unmatched_b


# //// 第二轮: mnemonic哈希匹配 ////
def match_by_hash(unmatched_a: List[FuncProfile], unmatched_b: List[FuncProfile]) -> Tuple[List[FunctionDiff], List[FuncProfile], List[FuncProfile]]:
    """助记符序列哈希匹配 — 高度相似函数的快速定位"""
    _matched = []
    _b_by_hash: Dict[str, List[FuncProfile]] = {}
    for _fb in unmatched_b:
        _b_by_hash.setdefault(_fb.mnemonic_hash, []).append(_fb)

    _still_a = []
    _used_b_indices: Set[int] = set()

    for _fa in unmatched_a:
        _candidates = _b_by_hash.get(_fa.mnemonic_hash, [])
        if _candidates:
            # 取第一个未使用的候选
            for _fb in _candidates:
                _b_idx = unmatched_b.index(_fb)
                if _b_idx not in _used_b_indices:
                    _used_b_indices.add(_b_idx)
                    _matched.append(FunctionDiff(
                        func_a=_fa, func_b=_fb,
                        similarity=1.0,
                        match_method='mnemonic_hash',
                        changes=detect_changes_between(_fa, _fb)
                    ))
                    break
            else:
                _still_a.append(_fa)
        else:
            _still_a.append(_fa)

    _still_b = [unmatched_b[i] for i in range(len(unmatched_b)) if i not in _used_b_indices]
    return _matched, _still_a, _still_b


# //// 第三轮: profile余弦相似度 ////
def match_by_profile(unmatched_a: List[FuncProfile], unmatched_b: List[FuncProfile],
                     threshold: float = 0.8) -> Tuple[List[FunctionDiff], List[FuncProfile], List[FuncProfile]]:
    """基于助记符频率分布的余弦相似度匹配 — 处理部分修改/重编译的函数"""
    _matched = []
    _used_b: Set[int] = set()

    # 预计算所有B函数的profile向量
    _b_profiles = [(i, build_mnemonic_profile(fb.mnemonics), fb) for i, fb in enumerate(unmatched_b)]

    _still_a = []
    for _fa in unmatched_a:
        _fa_profile = build_mnemonic_profile(_fa.mnemonics)
        _best_score = 0.0
        _best_idx = -1
        _best_fb = None

        for _bi, _bprof, _fb in _b_profiles:
            if _bi in _used_b:
                continue
            _sim = cosine_similarity(_fa_profile, _bprof)
            if _sim > _best_score:
                _best_score = _sim
                _best_idx = _bi
                _best_fb = _fb

        if _best_score >= threshold and _best_fb:
            _used_b.add(_best_idx)
            _matched.append(FunctionDiff(
                func_a=_fa, func_b=_best_fb,
                similarity=_best_score,
                match_method='mnemonic_profile',
                changes=detect_changes_between(_fa, _best_fb)
            ))
        else:
            _still_a.append(_fa)

    _still_b = [unmatched_b[i] for i in range(len(unmatched_b)) if i not in _used_b]
    return _matched, _still_a, _still_b


# 变更检测
def detect_changes_between(fa: FuncProfile, fb: FuncProfile) -> List[str]:
    """比较两个匹配的函数，列出所有观察到的差异"""
    _changes = []

    # 指令数量差异
    if fa.instruction_count != fb.instruction_count:
        _diff = fb.instruction_count - fa.instruction_count
        _dir = '+' if _diff > 0 else ''
        _changes.append(f"instruction_count: {fa.instruction_count} → {fb.instruction_count} ({_dir}{_diff})")

    # 基本块数量差异
    if fa.basic_block_count != fb.basic_block_count:
        _diff_bb = fb.basic_block_count - fa.basic_block_count
        _dir_bb = '+' if _diff_bb > 0 else ''
        _changes.append(f"basic_blocks: {fa.basic_block_count} → {fb.basic_block_count} ({_dir_bb}{_diff_bb})")

    # 助记符差异: 新增+移除
    _set_a = set(fa.mnemonics)
    _set_b = set(fb.mnemonics)
    _added_mn = _set_b - _set_a
    _removed_mn = _set_a - _set_b
    if _added_mn:
        _changes.append(f"added_mnemonics: {sorted(_added_mn)[:5]}{'...' if len(_added_mn) > 5 else ''}")
    if _removed_mn:
        _changes.append(f"removed_mnemonics: {sorted(_removed_mn)[:5]}{'...' if len(_removed_mn) > 5 else ''}")

    # 调用目标差异
    _ct_a = set(fa.call_targets)
    _ct_b = set(fb.call_targets)
    _added_ct = _ct_b - _ct_a
    _removed_ct = _ct_a - _ct_b
    if _added_ct:
        _changes.append(f"added_calls: {sorted(_added_ct)[:3]}{'...' if len(_added_ct) > 3 else ''}")
    if _removed_ct:
        _changes.append(f"removed_calls: {sorted(_removed_ct)[:3]}{'...' if len(_removed_ct) > 3 else ''}")

    # 助记符序列长度变化率
    if fa.mnemonics and fb.mnemonics:
        _len_change = abs(len(fb.mnemonics) - len(fa.mnemonics)) / max(len(fa.mnemonics), 1)
        if _len_change > 0.1:
            _changes.append(f"mnemonic_length_change: {_len_change:.1%}")

    return _changes


def detect_changes(matched: List[FunctionDiff]) -> List[FunctionDiff]:
    """对已匹配列表做批量变更检测(原地更新)"""
    for _d in matched:
        _d.changes = detect_changes_between(_d.func_a, _d.func_b)
    return matched


# 安全相关性标记
_SR_PATTERN = re.compile(
    r'|'.join(_SECURITY_KEYWORDS),
    re.IGNORECASE
)


def is_security_relevant(func_name: str) -> bool:
    """判断函数是否与安全相关 - 基于关键字模式匹配"""
    if not func_name:
        return False
    return bool(_SR_PATTERN.search(func_name))


# //// 段哈希 ////
def section_hash(data: bytes) -> str:
    """二进制数据的SHA256摘要"""
    return hashlib.sha256(data).hexdigest()


# 完整diff 流水线
def diff_binaries(bin_a_data: bytes, bin_b_data: bytes,
                  funcs_a: List[FuncProfile], funcs_b: List[FuncProfile]) -> PatchDiffResult:
    """四阶段渐进式匹配pipeline → 最终diff结果"""
    # 计算段级哈希
    _sec_hashes = {
        'full_binary': (section_hash(bin_a_data), section_hash(bin_b_data)),
    }

    # 阶段1: 名称精确匹配
    _m1, _ua1, _ub1 = match_by_name(funcs_a, funcs_b)

    # 阶段2: mnemonic哈希匹配
    _m2, _ua2, _ub2 = match_by_hash(_ua1, _ub1)

    # 阶段3: profile余弦相似度
    _m3, _ua3, _ub3 = match_by_profile(_ua2, _ub2, threshold=0.8)

    # 汇总
    _all_matched = _m1 + _m2 + _m3
    _added = _ub3     # B有A没有 → 新增
    _removed = _ua3   # A有B没有 → 移除

    # 分类: 精确匹配 vs 有修改 (similarity < 1.0)
    _modified = [_d for _d in _all_matched if _d.similarity < 1.0 or len(_d.changes) > 0]

    # 安全相关过滤
    _sec_rel = [_d for _d in _all_matched
                if is_security_relevant(_d.func_a.name) or is_security_relevant(_d.func_b.name)]

    return PatchDiffResult(
        matched=_all_matched,
        added=_added,
        removed=_removed,
        modified=_modified,
        security_relevant=_sec_rel,
        section_hashes=_sec_hashes,
    )


# //// 函数名提取 ////
def _parse_function_names(asm_text: str) -> List[str]:
    """从反汇编文本中提取函数名"""
    _names = []
    _func_re = re.compile(r'^([a-zA-Z_][a-zA-Z0-9_.]*):\s*$', re.MULTILINE)
    for _m in _func_re.finditer(asm_text):
        _names.append(_m.group(1))
    return _names
