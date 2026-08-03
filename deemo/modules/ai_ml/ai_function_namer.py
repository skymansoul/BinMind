#!/usr/bin/env python3
# Heuristic function naming from decompiled code — identifies common patterns and assigns
# descriptive names based on API calls, string references, structural signatures,
# n‑gram similarity propagation, and entropy‑aware 栈‑string 检测.
# N‑gram similarity‑based name propagation (CLAP‑style contrastive matching),
# Shannon熵栈字符串评分, 多证据贝叶斯融合置信度.

import logging as _logging
import re as _re
from collections import defaultdict as _defaultdict
from collections import Counter as _Counter
from math import log as _log, sqrt as _sqrt

__dbg = _logging.getLogger(__name__)

# ── N‑gram 指纹种子 — 多项式滚动哈希用 ─────────────────────────────────
_NGRAM_SEEDS = (1931, 2137, 31337)
_NGRAM_N = 3
_SIMILARITY_PROPAGATE_THRESHOLD = 0.65  # Jaccard ≥ 此值则传播名称

# Pattern database: (regex, name_框架, confidence)
_API_PATTERNS = [
    (_re.compile(r'\b(malloc|calloc|realloc|free)\s*\('), "memory_{}", 0.85),
    (_re.compile(r'\b(fopen|fclose|fread|fwrite|fprintf|fscanf)\s*\('), "file_{}", 0.85),
    (_re.compile(r'\b(socket|bind|listen|accept|connect|send|recv)\s*\('), "network_{}", 0.85),
    (_re.compile(r'\b(CreateFile[A-Z]?|ReadFile|WriteFile|CloseHandle)\s*\('), "win32_file_{}", 0.85),
    (_re.compile(r'\b(RegOpenKey|RegQueryValue|RegSetValue|RegCloseKey)\s*\('), "registry_{}", 0.85),
    (_re.compile(r'\b(CreateThread|_beginthread|pthread_create)\s*\('), "thread_{}", 0.80),
    (_re.compile(r'\b(CreateProcess|execve?|system|popen|WinExec)\s*\('), "process_{}", 0.85),
    (_re.compile(r'\b(LoadLibrary|GetProcAddress|dlopen|dlsym)\s*\('), "dynamic_load_{}", 0.80),
    (_re.compile(r'\b(strcpy|strcat|sprintf|memcpy|memmove|memset)\s*\('), "string_{}", 0.75),
    (_re.compile(r'\b(crypt|encrypt|decrypt|hash|AES|RSA|SHA|MD5)\s*\('), "crypto_{}", 0.85),
    (_re.compile(r'\b(VirtualAlloc|VirtualProtect|mprotect)\s*\('), "memory_protect_{}", 0.80),
    (_re.compile(r'\b(base64_|b64_|xor_|rot\d+|caesar)\s*\('), "encode_{}", 0.75),
    (_re.compile(r'\b(main|WinMain|DllMain|_start)\s*\('), "{}", 0.90),
    (_re.compile(r'\b(ServiceMain|RegisterServiceCtrlHandler)\s*\('), "service_{}", 0.85),
    (_re.compile(r'\b(CoInitialize|CoCreateInstance|CoUninitialize)\s*\('), "com_{}", 0.85),
    (_re.compile(r'\b(HttpSendRequest|URLDownloadToFile|WinHttp)\s*\('), "http_{}", 0.85),
]

_STRUCTURAL_PATTERNS = [
    (_re.compile(r'(?:while|for)\s*\([^)]*str[^)]*\)'), "string_loop", 0.55),
    (_re.compile(r'(?:while|for)\s*\([^)]*(?:buf|ptr|data)[^)]*\)'), "buffer_loop", 0.50),
    (_re.compile(r'switch\s*\([^)]*(?:cmd|opcode|type|msg)[^)]*\)'), "dispatch_{}", 0.65),
    (_re.compile(r'if\s*\([^)]*(?:error|fail|!=\s*0)[^)]*\)'), "validate_{}", 0.45),
    (_re.compile(r'__try|__except|try\s*\{'), "exception_handler", 0.60),
    (_re.compile(r'(?:base64|hex|hexlify|unhexlify|encode|decode)\s*\('), "codec_{}", 0.70),
]

# Anti-pattern words for filtering bad names
_FILTER_WORDS = {
    'sub_', 'unknown_', 'unnamed_', 'dummy_', 'nullsub_',
}

# ── 汇编助记符归一化 — 压缩操作码空间提升 n‑gram 碰撞精度 ──────────
_OPCODE_NORMALIZE = dict(
    [('mov', 'mov'), ('movzx', 'mov'), ('movsx', 'mov'), ('movsxd', 'mov'),
     ('lea', 'lea'),
     ('add', 'alu'), ('sub', 'alu'), ('imul', 'alu'), ('xor', 'alu'),
     ('and', 'alu'), ('or', 'alu'), ('shl', 'alu'), ('shr', 'alu'),
     ('sar', 'alu'), ('neg', 'alu'), ('inc', 'alu'), ('dec', 'alu'),
     ('not', 'alu'), ('mul', 'alu'), ('div', 'alu'), ('idiv', 'alu'),
     ('call', 'call'), ('jmp', 'jmp'),
     ('je', 'jcc'), ('jne', 'jcc'), ('jz', 'jcc'), ('jnz', 'jcc'),
     ('jl', 'jcc'), ('jg', 'jcc'), ('jle', 'jcc'), ('jge', 'jcc'),
     ('ja', 'jcc'), ('jb', 'jcc'), ('jae', 'jcc'), ('jbe', 'jcc'),
     ('js', 'jcc'), ('jns', 'jcc'), ('jo', 'jcc'), ('jno', 'jcc'),
     ('push', 'stack'), ('pop', 'stack'),
     ('ret', 'ret'), ('retn', 'ret'),
     ('cmp', 'cmp'), ('test', 'cmp')]
)


def _tokenize_for_ngrams(code_snippet):
    """伪 C 分解为标准化 token 流 — 剥离字面量噪音，归一化标识符。"""
    if code_snippet is None:
        return []
    # 剥离注释与字符串常量中可变部分
    stripped = _re.sub(
        r'//.*?$|/\*.*?\*/', ' ',
        code_snippet, flags=_re.DOTALL | _re.MULTILINE)
    stripped = _re.sub(r'"[^"]*"', '"..."', stripped)
    stripped = _re.sub(r"'[^']*'", "'x'", stripped)
    # 标识符归一化：函数指针/变量名 → 操作码类别
    stripped = _re.sub(
        r'\b[a-zA-Z_]\w*\b',
        lambda m: _OPCODE_NORMALIZE.get(m.group(0), 'IDENT'),
        stripped)
    token_seq = _re.findall(r'[a-zA-Z_]+|\d+|.', stripped)
    return token_seq


def _ngram_fingerprint(token_seq, n=_NGRAM_N):
    """多项式滚动哈希 n‑gram 指纹 — O(n) 单趟，三重桶降低假阳性。

    CLAP 核心思想：将函数体表示为向量哈希集合，
    通过 Jaccard 相似度检索历史中已命名的相近函数。
    """
    if len(token_seq) < n:
        return frozenset()
    sketch = set()
    window_hash = 0
    prime = _NGRAM_SEEDS[0]
    mod_mersenne = (1 << 31) - 1
    # prime^(n-1) mod mod
    power = 1
    ki = 0
    while ki < n - 1:
        power = (power * prime) % mod_mersenne
        ki += 1
    ti = 0
    while ti < len(token_seq):
        t_val = hash(token_seq[ti]) & 0x7FFFFFFF
        window_hash = (window_hash * prime + t_val) % mod_mersenne
        if ti >= n - 1:
            # 三桶注入：对抗单一桶冲突
            b1 = window_hash % 1021
            b2 = (window_hash * _NGRAM_SEEDS[1]) % 2039
            b3 = (window_hash ^ _NGRAM_SEEDS[2]) % 4093
            sketch.update((b1, b2, b3))
            oldest = ti - n + 1
            oldest_val = hash(token_seq[oldest]) & 0x7FFFFFFF
            window_hash = (window_hash - oldest_val * power) % mod_mersenne
        ti += 1
    return frozenset(sketch)


def _similarity_jaccard(fp_a, fp_b):
    """两个 MinHash 草图间的 Jaccard 相似度估计。"""
    if fp_a is None or fp_b is None:
        return 0.0
    la, lb = len(fp_a), len(fp_b)
    if la == 0 or lb == 0:
        return 0.0
    inter_size = len(fp_a & fp_b)
    union_size = la + lb - inter_size
    return inter_size / union_size if union_size > 0 else 0.0


# ── Shannon 熵驱动栈字符串检测 — 区分布局常量与真实混淆字符串 ──────────
def _compute_byte_entropy(byte_vals):
    """对单字节序列计算 Shannon 熵。混淆字符串通常 ≥ 3.5 bits，全零布局 < 1.0。"""
    if byte_vals is None or len(byte_vals) == 0:
        return 0.0, 0.0
    freq = _Counter(byte_vals)
    total = len(byte_vals)
    entropy_accum = 0.0
    for cnt in freq.values():
        if cnt > 0:
            p = cnt / total
            entropy_accum -= p * _log(p, 2)

    # 可打印 ASCII 比例（0x20–0x7E）
    printable_hits = 0
    bi = 0
    while bi < len(byte_vals):
        if 0x20 <= byte_vals[bi] <= 0x7E:
            printable_hits += 1
        bi += 1
    printable_ratio = printable_hits / total
    return entropy_accum, printable_ratio


def _extract_stack_byte_values(code):
    """扫描伪 C 中栈偏移赋值的立即数，仅提取 [0,255] 范围的字节值。"""
    if code is None:
        return []
    imm_re = _re.compile(
        r'(?:\[[^\]]*\]|\*\s*\([^)]+\))\s*=\s*(0x[0-9a-fA-F]+|\d+)')
    raw_matches = imm_re.findall(code)
    byte_buf = []
    mi = 0
    while mi < len(raw_matches):
        token = raw_matches[mi]
        val = int(token, 16 if token.lower().startswith('0x') else 10)
        # 截断到字节
        byte_buf.append(val & 0xFF)
        mi += 1
    return byte_buf


def _detect_stack_string(code):
    """熵增强栈字符串检测 — 回归布尔兼容旧接口，内部使用熵评分。

    纯常量初始化表（熵<1.5）不再误报为混淆字符串。
    """
    if code is None:
        return False

    stack_pats = [
        _re.compile(r'\[[^\]]*\+\s*(?:0x[0-9a-fA-F]+|\d+)\]\s*=\s*(?:0x[0-9a-fA-F]+|\d+)'),
        _re.compile(r'\*\s*\(\s*\w+\s*\+\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)\s*=\s*(?:0x[0-9a-fA-F]+|\d+)'),
    ]
    match_total = 0
    pi = 0
    while pi < len(stack_pats):
        match_total += len(stack_pats[pi].findall(code))
        pi += 1

    if match_total < 3:
        return False

    byte_vals = _extract_stack_byte_values(code)
    if len(byte_vals) < 4:
        return False

    entropy, printable_ratio = _compute_byte_entropy(byte_vals)

    # 决策面：
    # 高熵 + 高可打印 → 混淆字符串
    # 低熵 + 低可打印 → 表初始化（忽略）
    # 中等区间 → 宽松通过
    if entropy > 3.5 and printable_ratio > 0.3:
        return True
    if entropy > 2.0 and printable_ratio > 0.5:
        return True
    # 极低熵：全零/常量初始化，噪声
    if entropy < 1.2:
        return False
    # 边缘：字节数很多（≥16）且有中等多样性
    return entropy > 2.5 and len(byte_vals) >= 12


def _detect_stack_string_confidence(code):
    """返回 (is_obfuscated: bool, confidence: float) 用于证据融合。"""
    if code is None:
        return False, 0.0

    stack_pats = [
        _re.compile(r'\[[^\]]*\+\s*(?:0x[0-9a-fA-F]+|\d+)\]\s*=\s*(?:0x[0-9a-fA-F]+|\d+)'),
        _re.compile(r'\*\s*\(\s*\w+\s*\+\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)\s*=\s*(?:0x[0-9a-fA-F]+|\d+)'),
    ]
    match_total = 0
    pi = 0
    while pi < len(stack_pats):
        match_total += len(stack_pats[pi].findall(code))
        pi += 1

    if match_total < 3:
        return False, 0.0

    byte_vals = _extract_stack_byte_values(code)
    if len(byte_vals) < 4:
        return False, 0.0

    entropy, printable_ratio = _compute_byte_entropy(byte_vals)

    # 综合置信度：高熵 + 高可打印 → 强信号
    if entropy > 3.5 and printable_ratio > 0.3:
        conf = 0.55 + (entropy - 3.5) * 0.10 + printable_ratio * 0.18
        return True, min(conf, 0.92)
    elif entropy > 2.0 and printable_ratio > 0.5:
        conf = 0.40 + (entropy - 2.0) * 0.08 + printable_ratio * 0.10
        return True, min(conf, 0.65)
    elif entropy < 1.2:
        return False, 0.0
    # 边缘情形
    if entropy > 2.5 and len(byte_vals) >= 12:
        return True, min(0.35 + entropy * 0.06, 0.55)
    return False, 0.0


def _extract_api_name(code, patterns):
    """Extract the most likely API group from a decompiled code snippet."""
    if code is None or len(code) == 0:
        return None, 0.0
    best_match = None
    best_conf = 0.0
    pi = 0
    while pi < len(patterns):
        pat, template, base_conf = patterns[pi]
        m = pat.search(code)
        if m:
            api = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
            conf = base_conf
            # Bonus for multiple matches
            all_matches = pat.findall(code)
            if len(all_matches) > 1:
                conf = min(conf + 0.05, 0.98)
            if conf > best_conf:
                best_match = (template, api, conf)
                best_conf = conf
        pi += 1
    return best_match, best_conf


def _extract_string_hints(strings):
    """推断字符串引用的功能意图 — 返回 [(name, conf), ...] 或 None。

    多证据融合时需要 top‑N 而非单一最佳值，
    因此返回列表而非 (best_name, best_conf) 元组。
    """
    if strings is None or len(strings) == 0:
        return None

    hints = _defaultdict(float)
    si = 0
    while si < len(strings):
        s = strings[si].lower()
        if 'error' in s or 'fail' in s:
            hints['error_handler'] += 0.3
        if 'success' in s or 'ok' in s:
            hints['success_handler'] += 0.2
        if 'init' in s or 'startup' in s:
            hints['init'] += 0.3
        if 'cleanup' in s or 'destroy' in s or 'release' in s:
            hints['cleanup'] += 0.3
        if 'config' in s or 'setting' in s or 'option' in s:
            hints['config'] += 0.25
        if 'log' in s or 'debug' in s or 'trace' in s:
            hints['logger'] += 0.25
        if 'parse' in s or 'decode' in s or 'deserialize' in s:
            hints['parser'] += 0.3
        if 'serialize' in s or 'encode' in s or 'pack' in s:
            hints['serializer'] += 0.3
        if 'http' in s or 'url' in s:
            hints['http_handler'] += 0.3
        if 'json' in s or 'xml' in s:
            hints['data_parser'] += 0.25
        si += 1

    if not hints:
        return None
    # 取 top‑N 用于多证据融合
    ranked = sorted(hints.items(), key=lambda x: x[1], reverse=True)
    aggregator = [(name, min(conf, 0.8)) for name, conf in ranked[:3]]
    return aggregator


def _infer_indirect_call_target(code, imports):
    """Attempt to resolve indirect call targets (vtable / callback patterns)."""
    if code is None or imports is None:
        return None, 0.0

    # Look for offset-from-base call patterns
    offset_pattern = _re.compile(r'call\s+.*\[.*\+\s*(0x[0-9a-fA-F]+|\d+)\]')
    matches = offset_pattern.findall(code)
    if len(matches) >= 2:
        return "vtable_dispatch", 0.55

    # Look for function pointer patterns
    fp_pattern = _re.compile(r'\(\*\w+\)\s*\(')
    if fp_pattern.search(code):
        return "callback_dispatcher", 0.50

    # Compare against import table for wrapper 检测
    i = 0
    while i < len(imports):
        imp = imports[i]
        if imp in code:
            return f"wrap_{imp}", 0.60
        i += 1
    return None, 0.0


# ── 多证据贝叶斯融合 ─────────────────────────────────────────────────
def _bayesian_fuse(candidates):
    """将候选 (name, confidence, source) 列表融合为加权共识。

    BLens 风格多模态融合：每个 evidence source 看作独立观测，
    使用 Dempster-Shafer 简化的加权置信度合并：
        fused_conf = 1 - prod_i (1 - w_i * conf_i)
    其中 w_i 是 source 先验可靠度。
    """
    if candidates is None or len(candidates) == 0:
        return None, 0.0

    # source prior weights — API 匹配 > 字符串 > 结构 > 栈检测 > 间接调用
    _SOURCE_WEIGHTS = {
        'api_pattern': 0.90,
        'string_inference': 0.65,
        'structural_pattern': 0.50,
        'stack_string': 0.45,
        'indirect_call': 0.40,
        'ngram_propagate': 0.55,
        'complexity_fallback': 0.20,
        'size_fallback': 0.15,
        'fallback': 0.10,
    }

    # 按名称 cluster：同名的取最高置信度后加权
    name_clusters = {}
    ci = 0
    while ci < len(candidates):
        cname, cconf, csource = candidates[ci]
        w = _SOURCE_WEIGHTS.get(csource, 0.35)
        weighted = cconf * w
        if cname not in name_clusters or weighted > name_clusters[cname][1]:
            name_clusters[cname] = (cconf, weighted, csource)
        ci += 1

    # 对每个候选应用独立观测融合
    fused_name = None
    fused_conf = 0.0
    product_term = 1.0
    all_names = list(name_clusters.keys())
    ni = 0
    while ni < len(all_names):
        cname = all_names[ni]
        cconf, weighted, csrc = name_clusters[cname]
        product_term *= (1.0 - weighted)
        # 取最高加权置信度的名称
        if weighted > fused_conf:
            fused_conf = weighted
            fused_name = cname
        ni += 1

    # 独立源融合修正
    bayesian_conf = 1.0 - product_term
    bayesian_conf = bayesian_conf if bayesian_conf >= 0.0 else 0.0
    bayesian_conf = bayesian_conf if bayesian_conf <= 0.98 else 0.98

    return fused_name, max(fused_conf, bayesian_conf)


class FunctionNamer:
    """Heuristic binary function renamer using API usage, strings, structural cues,
    n‑gram similarity propagation, and entropy‑aware stack‑string detection."""

    __slots__ = ('m_history', 'm_min_conf', '_fingerprint_cache')

    def __init__(self, min_confidence=0.45):
        self.m_history = {}
        self.m_min_conf = min_confidence
        self._fingerprint_cache = {}  # addr → frozenset fingerprint

    # ── N‑gram 相似度名称传播 — CLAP 风格跨函数对比 ─────────────────
    def _propagate_name_by_similarity(self, code, addr=None):
        """在历史命名中检索最相似函数，若 Jaccard ≥ 阈值则传播其名称。

        核心洞见（来自 CLAP 跨模态对比）：函数体 token‑n‑gram 集合
        如果与已命名函数高度重叠，其语义标签大概率可迁移。
        """
        if code is None or len(self.m_history) == 0:
            return None, 0.0

        query_tokens = _tokenize_for_ngrams(code)
        query_fp = _ngram_fingerprint(query_tokens)

        # 可选：缓存查询指纹
        if addr is not None:
            self._fingerprint_cache[addr] = query_fp

        best_similarity = 0.0
        best_name = None
        best_hist_conf = 0.0

        hist_items = list(self.m_history.items())
        hi = 0
        while hi < len(hist_items):
            hist_addr, hist_result = hist_items[hi]
            hist_name = hist_result.get('name')
            hist_conf = hist_result.get('confidence', 0.0)
            if hist_name is None:
                hi += 1
                continue

            # 从缓存或重新计算指纹
            hist_fp = self._fingerprint_cache.get(hist_addr)
            if hist_fp is None:
                hist_code = hist_result.get('_code_snapshot')
                if hist_code is None:
                    hi += 1
                    continue
                hist_tokens = _tokenize_for_ngrams(hist_code)
                hist_fp = _ngram_fingerprint(hist_tokens)
                self._fingerprint_cache[hist_addr] = hist_fp

            sim = _similarity_jaccard(query_fp, hist_fp)
            if sim > best_similarity:
                best_similarity = sim
                best_name = hist_name
                best_hist_conf = hist_conf
            hi += 1

        if best_similarity >= _SIMILARITY_PROPAGATE_THRESHOLD and best_name is not None:
            # 传播置信度 = 相似度 × 源置信度 × 衰减因子
            propagated_conf = best_similarity * best_hist_conf * 0.85
            _Filtered = any(best_name.startswith(w) for w in _FILTER_WORDS)
            if _Filtered:
                return None, 0.0
            return best_name, min(propagated_conf, 0.85)
        return None, 0.0

    def name_function_fn(self, decompiled_code, strings=None, imports=None, addr=None):
        """Propose a descriptive name for a decompiled function.

        Args:
            decompiled_code: string of pseudo-C / decompiled code.
            strings: list of referenced string literals.
            imports: list of imported function names.
            addr: function address (for history/dedup).

        Returns:
            dict with 'name', 'confidence', 'reason', 'method'.
        """
        if decompiled_code is None or len(decompiled_code.strip()) == 0:
            return {'name': 'empty_function', 'confidence': 0.3,
                    'reason': 'empty body', 'method': 'default'}

        code = decompiled_code
        str_list = strings if strings else []
        imp_list = imports if imports else []

        # ── 多证据收集阶段（不提前返回） ──────────────────────────
        evidence_candidates = []

        # 1. API-based naming
        api_match, api_conf = _extract_api_name(code, _API_PATTERNS)
        if api_match is not None:
            template, api, base_conf = api_match
            api_name = template.format(api) if '{}' in template else template
            str_hints_list = _extract_string_hints(str_list)
            if str_hints_list is not None:
                str_bonus = str_hints_list[0][1] * 0.1
            else:
                str_bonus = 0.0
            api_final_conf = min(api_conf + str_bonus, 0.98)
            evidence_candidates.append((api_name, api_final_conf, 'api_pattern'))
            # 强 API 证据：早退仍可行（兼容性），但也收集完后续合并
            # 保留旧版行为：高置信度 API 匹配直接返回
            if api_final_conf >= 0.85:
                return {'name': api_name, 'confidence': api_final_conf,
                        'reason': f"API pattern: {api}", 'method': 'api_pattern'}

        # 2. String-based 推理 (multi-hint)
        str_hints_list = _extract_string_hints(str_list)
        if str_hints_list is not None:
            shi = 0
            while shi < len(str_hints_list):
                sh_name, sh_conf = str_hints_list[shi]
                if sh_conf >= 0.20:
                    evidence_candidates.append(
                        (sh_name, sh_conf, 'string_inference'))
                shi += 1

        # 3. Structural pattern matching
        structural, struct_conf = _extract_api_name(code, _STRUCTURAL_PATTERNS)
        if structural is not None:
            s_template, s_matched, s_base_conf = structural
            s_name = s_template.format(s_matched) if '{}' in s_template else s_template
            evidence_candidates.append((s_name, struct_conf, 'structural_pattern'))

        # 4. Stack string 检测 (entropy-enhanced)
        is_obfuscated, obf_conf = _detect_stack_string_confidence(code)
        if is_obfuscated and obf_conf >= 0.35:
            evidence_candidates.append(
                ('obfuscated_string_builder', obf_conf, 'stack_string'))

        # 5. Indirect call target 推理
        indirect, ind_conf = _infer_indirect_call_target(code, imp_list)
        if indirect is not None and ind_conf >= 0.40:
            evidence_candidates.append((indirect, ind_conf, 'indirect_call'))

        # 6. N-gram similarity propagation (CLAP-style)
        propagated_name, prop_conf = self._propagate_name_by_similarity(code, addr)
        if propagated_name is not None and prop_conf >= 0.35:
            evidence_candidates.append(
                (propagated_name, prop_conf, 'ngram_propagate'))

        # 7. Complexity/size 回退 evidence
        bb_count = code.count('goto') + code.count('if (')
        if bb_count >= 10:
            evidence_candidates.append(
                ('complex_dispatcher', 0.35, 'complexity_fallback'))
        elif len(code) < 50:
            evidence_candidates.append(
                ('small_helper', 0.25, 'size_fallback'))
        else:
            fallback_label = f'func_{addr:x}' if addr else 'unknown_function'
            evidence_candidates.append(
                (fallback_label, 0.15, 'fallback'))

        # ── 多证据贝叶斯融合 ──────────────────────────────────────
        fused_result = _bayesian_fuse(evidence_candidates)
        if fused_result is not None and fused_result[0] is not None:
            fused_name, fused_conf = fused_result
            name_valid = not any(fused_name.startswith(w) for w in _FILTER_WORDS)
            if name_valid and fused_conf >= self.m_min_conf:
                # 存储代码快照以便后续相似度传播
                if addr is not None:
                    self.m_history[addr] = {
                        'name': fused_name,
                        'confidence': fused_conf,
                        'reason': 'multi-evidence fusion',
                        'method': 'bayesian_fusion',
                        '_code_snapshot': code,
                    }
                return {'name': fused_name, 'confidence': fused_conf,
                        'reason': 'multi-evidence fusion', 'method': 'bayesian_fusion'}

        # 最保守回退：取最高置信度单项
        if evidence_candidates:
            best_candidate = max(evidence_candidates, key=lambda x: x[1])
            best_name = best_candidate[0]
            best_conf = best_candidate[1]
            best_source = best_candidate[2]
            if addr is not None:
                self.m_history[addr] = {
                    'name': best_name,
                    'confidence': best_conf,
                    'reason': f'best single: {best_source}',
                    'method': best_source,
                    '_code_snapshot': code,
                }
            return {'name': best_name, 'confidence': best_conf,
                    'reason': f'best single: {best_source}', 'method': best_source}

        # 绝对无法识别
        return {'name': f'func_{addr:x}' if addr else 'unknown_function',
                'confidence': 0.15, 'reason': 'no distinguishing features',
                'method': 'fallback'}

    def batch_name_fn(self, functions, min_confidence=None):
        """Name multiple functions, returning a dict mapping addr -> name dict.

        Args:
            functions: list of dicts with 'code', 'strings', 'imports', 'addr'.
            min_confidence: override instance threshold.
        """
        threshold = min_confidence if min_confidence is not None else self.m_min_conf
        results = {}
        fi = 0
        while fi < len(functions):
            f = functions[fi]
            addr = f.get('addr', fi)
            result = self.name_function_fn(
                decompiled_code=f.get('code', ''),
                strings=f.get('strings', []),
                imports=f.get('imports', []),
                addr=addr)
            if result['confidence'] >= threshold:
                results[addr] = result
                # history 已由 name_function_fn 写入（含代码快照）
                if addr not in self.m_history:
                    self.m_history[addr] = result
            fi += 1
        return results

    def get_history_fn(self):
        """返回历史记录（不含内部代码快照的浅拷贝）。"""
        clean = {}
        hi_key, hi_val = None, None
        hi_iter = iter(self.m_history.items())
        while True:
            try:
                nxt = next(hi_iter)
                hi_key, hi_val = nxt[0], nxt[1]
                clean[hi_key] = {
                    k: v for k, v in hi_val.items()
                    if not k.startswith('_')}
            except StopIteration:
                break
        return clean

    def clear_history_fn(self):
        self.m_history.clear()
        self._fingerprint_cache.clear()


def create_function_namer(min_confidence=0.45):
    return FunctionNamer(min_confidence=min_confidence)
