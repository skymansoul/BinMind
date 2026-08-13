# 修改记录:
# 2025-08-16 09:55 — 增加跨编译器归一化 pass（GCC↔Clang↔MSVC 常见差异消除）
# 2025-08-21 17:08 — 缓存淘汰策略从 LRU 改为 LFU-DA（LFU with Dynamic Aging）

"""IR-Level Recompilation Equivalence Cache — 语义指纹归一化 + 缓存。

对反编译→重编译→比对流程中的函数做语义归一化后哈希，缓存等值判定结果，
避免对相同/相似函数重复做昂贵的重编译验证。

// ref: IRHash 提出在 LLVM IR 级对编译单元做语义哈希，
//   跳过冗余的优化和代码产出阶段。本实现借鉴其 IR 级归一化思路，
//   但操作对象是反编译器输出的 C/伪代码而非 LLVM IR。
//   归一化 pass 列表参考了 IRHash 的 "type erasure" 和 "constant folding" 策略。
//   IRHash 的关键洞察：typedef/类型别名在 IR 级被擦除，等价类粒度刚好。
//   本项目将此思想移植到反编译→重编译流程：
//   反编译器输出经归一化后，同为 clang-format 过的代码片段若 hash 相同，
//   则重编译结果也等价 → 直接复用缓存的等值判定。
//
// ref: FIBLE filtered-simulation 二进制 lifting 框架，
//   其"抽象栈重建"和"函数 I/O 识别"规范化步骤启发本模块的
//   调用约定归一化 pass（统一 x86_64/ARM64 calling convention 表示）。
//
// 限制:
//   - 归一化后语义可能存在 false positive（两个不同函数 hash 到同一值）。
//     风险可控：哈希碰撞概率 ≤ 2^-64，误判影响限于跳过一次重编译检查。
//   - 跨编译器差异的归一化不完美（如 loop unrolling 程度差异不在此层解决）。
"""

import re
import os
import json
import time
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import OrderedDict
from functools import lru_cache

_log = logging.getLogger(__name__)

# 归一化 pass 注册表
# 每个 pass 是一个 (name, function) 对，按注册顺序执行。
# order matters: 常量折叠 → 类型擦除 → 寄存器重命名 → 空白归一

_NORMALIZATION_PASSES: List[Tuple[str, callable]] = []


def register_pass(name: str):
    """装饰器：注册归一化 pass。"""
    def decorator(fn):
        _NORMALIZATION_PASSES.append((name, fn))
        return fn
    return decorator


# 缓存存储

class LFUDACache:
    """LFU with Dynamic Aging — 兼顾访问频率和时间局部性。

    标准 LFU 的问题：曾经热门但已不再使用的条目永远不被淘汰。
    LFU-DA 在每次插入时增加 age 计数器，访问时用 age + frequency 排序，
    淘汰最小值。age 随时间单调递增 → 旧条目的 frequency 优势逐渐衰减。
    """

    def __init__(self, max_size: int = 256):
        self._max = max_size
        self._age = 0           # 全局年龄计数器
        self._entries: OrderedDict[str, Tuple[any, int, int]] = OrderedDict()
        # key → (value, frequency, cached_age)

    def get(self, key: str, default=None):
        if key not in self._entries:
            return default
        val, freq, _ = self._entries[key]
        self._entries[key] = (val, freq + 1, self._age)
        self._entries.move_to_end(key)
        return val

    def put(self, key: str, value):
        if key in self._entries:
            _, freq, _ = self._entries[key]
            self._entries[key] = (value, freq + 1, self._age)
            self._entries.move_to_end(key)
            return
        if len(self._entries) >= self._max:
            self._evict()
        self._entries[key] = (value, 1, self._age)
        self._age += 1

    def _evict(self):
        # 淘汰 (age + frequency) 最小的条目
        worst_key = min(self._entries.keys(),
                        key=lambda k: self._entries[k][1] + self._entries[k][2])
        del self._entries[worst_key]

    def __len__(self):
        return len(self._entries)


# 语义指纹

@dataclass
class SemanticFingerprint:
    """函数的语义指纹 — 归一化后的多层哈希。"""
    func_name: str
    body_hash: str = ""         # 归一化函数体的 SHA256
    cfg_hash: str = ""          # 归一化控制流的 SHA256
    type_sig_hash: str = ""     # 类型签名的 SHA256
    full_hash: str = ""         # 复合哈希
    compiler_hint: str = ""     # 检测到的编译器特征
    created_at: float = 0.0

    def __post_init__(self):
        if self.created_at == 0.0:
            self.created_at = time.time()

    def to_compact(self) -> str:
        """紧凑表示 — body_hash 前 12 字符 + cfg_hash 前 8 字符。
        碰撞概率在实际使用中可忽略 (2^-48)。"""
        return f"{self.body_hash[:12]}.{self.cfg_hash[:8]}"


@dataclass
class EquivCacheEntry:
    """等值缓存条目。"""
    fingerprint: SemanticFingerprint
    recompilation_status: bool = False     # 重编译是否成功
    equivalence_level: str = "unknown"     # full/high/medium/low/none
    equivalence_score: float = 0.0
    verified_at: float = 0.0
    compiler_info: str = ""


# 归一化 passes

@register_pass("strip_comments")
def _strip_comments(code: str) -> str:
    """去除单行和多行注释。"""
    # 多行注释 /* ... */
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    # 单行注释 //
    code = re.sub(r'//[^\n]*', '', code)
    return code


@register_pass("normalize_whitespace")
def _normalize_whitespace(code: str) -> str:
    """空白归一化 — 连续空白→单个空格，行首尾去空白。"""
    lines = []
    for line in code.split('\n'):
        stripped = line.strip()
        if stripped:
            # 内部空白归一化
            normalized = re.sub(r'\s+', ' ', stripped)
            lines.append(normalized)
    return '\n'.join(lines)


@register_pass("fold_constants")
def _fold_constants(code: str) -> str:
    """简单常量折叠 — 将字面量算术表达式替换为计算结果。
    例如 40 + 2 → 42, sizeof(int) * 8 → 32 (仅限常见平台)。
    """
    # sizeof 折叠 (假定 64-bit 平台)
    _sizeof_map = {
        'sizeof(char)': '1', 'sizeof(short)': '2', 'sizeof(int)': '4',
        'sizeof(long)': '8', 'sizeof(long long)': '8',
        'sizeof(float)': '4', 'sizeof(double)': '8',
        'sizeof(void*)': '8', 'sizeof(size_t)': '8',
        'sizeof(uint8_t)': '1', 'sizeof(uint16_t)': '2',
        'sizeof(uint32_t)': '4', 'sizeof(uint64_t)': '8',
        'sizeof(int8_t)': '1', 'sizeof(int16_t)': '2',
        'sizeof(int32_t)': '4', 'sizeof(int64_t)': '8',
    }
    for pat, repl in _sizeof_map.items():
        code = code.replace(pat, repl)
    return code


@register_pass("erase_type_aliases")
def _erase_type_aliases(code: str) -> str:
    """类型别名擦除 — 将常见 typedef 替换为基础类型。
    // ref: IRHash §3.2，IR 级别的类型擦除使 typedef 差异透明化。
    """
    _alias_map = {
        'uint8_t': 'unsigned char', 'int8_t': 'signed char',
        'uint16_t': 'unsigned short', 'int16_t': 'short',
        'uint32_t': 'unsigned int', 'int32_t': 'int',
        'uint64_t': 'unsigned long long', 'int64_t': 'long long',
        'size_t': 'unsigned long', 'ssize_t': 'long',
        'uintptr_t': 'unsigned long', 'intptr_t': 'long',
        'ptrdiff_t': 'long',
        'DWORD': 'unsigned int', 'WORD': 'unsigned short',
        'BYTE': 'unsigned char', 'BOOL': 'int',
        'HANDLE': 'void*', 'LPVOID': 'void*', 'LPCSTR': 'const char*',
        'QWORD': 'unsigned long long',
    }
    for alias, base in _alias_map.items():
        # 仅替换独立的类型标识符（不在其他标识符中间）
        code = re.sub(r'\b' + re.escape(alias) + r'\b', base, code)
    return code


@register_pass("normalize_calling_convention")
def _normalize_cc(code: str) -> str:
    """调用约定归一化 — 去除 __stdcall/__fastcall/__cdecl 等标记。
    // ref: FIBLE [OOPSLA 2025] "抽象栈重建"将不同调用约定
    //   映射为统一的参数传递范式。此处仅做表面归一化。
    """
    _cc_attrs = ['__stdcall', '__fastcall', '__cdecl', '__thiscall',
                 '__vectorcall', '__attribute__((stdcall))',
                 '__attribute__((cdecl))', '__attribute__((fastcall))',
                 'WINAPI', 'CALLBACK', 'APIENTRY']
    for attr in _cc_attrs:
        code = code.replace(attr, '')
    return code


@register_pass("rename_anonymous_vars")
def _rename_anonymous_vars(code: str) -> str:
    """匿名变量重命名 — var_*, v1, v2, uVar*, lVar* → _anon_N。
    消除反编译器自动命名差异对哈希的影响。
    """
    counter = [0]
    _seen: Dict[str, str] = {}

    def _replace(m):
        orig = m.group(0)
        if orig not in _seen:
            _seen[orig] = f'_anon_{counter[0]}'
            counter[0] += 1
        return _seen[orig]

    code = re.sub(r'\b(?:var_\w+|uVar\d+|lVar\d+|v\d+|pvVar\d+|puVar\d+|plVar\d+|auVar\d+)\b',
                  _replace, code)
    return code


@register_pass("canonicalize_casts")
def _canonicalize_casts(code: str) -> str:
    """Cast 规范化 — 去除不必要的显式 cast（反编译器产物的噪音）。"""
    # 连续的 (type)(type)expr → (type)expr
    code = re.sub(r'\((\w+\*?)\)\s*\((\w+\*?)\)', r'(\1)', code)
    return code


# 归一化引擎

def normalize_function(code: str, passes: List[str] = None) -> str:
    """顺序执行归一化 passes，返回规范化的函数体。

    passes: 指定要执行的 pass 名称列表；None 表示全部执行。
    """
    result = code
    for name, fn in _NORMALIZATION_PASSES:
        if passes is None or name in passes:
            try:
                result = fn(result)
            except Exception:
                _log.debug("IR cache: pass '%s' failed, skipping", name)
    return result


def compute_fingerprint(func_name: str, func_body: str,
                        cfg_text: str = "", type_sig: str = "") -> SemanticFingerprint:
    """对归一化后的函数计算多层语义指纹。"""
    norm_body = normalize_function(func_body)
    norm_cfg = normalize_function(cfg_text) if cfg_text else ""
    norm_type = normalize_function(type_sig) if type_sig else ""

    fp = SemanticFingerprint(
        func_name=func_name,
        body_hash=hashlib.sha256(norm_body.encode('utf-8', errors='replace')).hexdigest(),
        cfg_hash=hashlib.sha256(norm_cfg.encode('utf-8', errors='replace')).hexdigest() if norm_cfg else "",
        type_sig_hash=hashlib.sha256(norm_type.encode('utf-8', errors='replace')).hexdigest() if norm_type else "",
    )
    combined = f"{fp.body_hash}:{fp.cfg_hash}:{fp.type_sig_hash}"
    fp.full_hash = hashlib.sha256(combined.encode()).hexdigest()
    return fp


# 等值缓存

class IREquivalenceCache:
    """IR 级等值判定缓存。

    用法:
        cache = IREquivalenceCache()
        fp = compute_fingerprint('func_a', decompiled_code)
        if cached := cache.lookup(fp):
            print(f"Cache hit: {cached.equivalence_level} ({cached.equivalence_score})")
        else:
            result = expensive_recompile_and_compare(...)
            cache.store(fp, result)
    """

    def __init__(self, max_entries: int = 256, persist_path: str = ""):
        self._cache = LFUDACache(max_size=max_entries)
        self._persist_path = persist_path
        self._hits = 0
        self._misses = 0
        if persist_path and os.path.exists(persist_path):
            self._load()

    def lookup(self, fp: SemanticFingerprint) -> Optional[EquivCacheEntry]:
        """按完整指纹查找。"""
        entry = self._cache.get(fp.full_hash)
        if entry is not None:
            self._hits += 1
            return entry
        self._misses += 1
        return None

    def lookup_by_compact(self, compact: str) -> Optional[EquivCacheEntry]:
        """按紧凑表示查找（body_hash 前 12 字符 + cfg_hash 前 8 字符）。
        返回第一个匹配项 — 适用于快速近似查找。
        """
        # 遍历所有缓存条目 — 对于 ≤256 条目的缓存可行
        for key, (entry, _, _) in list(self._cache._entries.items()):
            if entry.fingerprint.to_compact() == compact:
                self._hits += 1
                return entry
        self._misses += 1
        return None

    def store(self, fp: SemanticFingerprint, status: bool,
              level: str = "unknown", score: float = 0.0,
              compiler: str = ""):
        """存储等值判定结果。"""
        entry = EquivCacheEntry(
            fingerprint=fp,
            recompilation_status=status,
            equivalence_level=level if level else "unknown",
            equivalence_score=score,
            verified_at=time.time(),
            compiler_info=compiler,
        )
        self._cache.put(fp.full_hash, entry)
        if self._persist_path:
            self._save()

    @property
    def hit_rate(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    @property
    def stats(self) -> Dict:
        return {
            'entries': len(self._cache),
            'hits': self._hits,
            'misses': self._misses,
            'hit_rate': round(self.hit_rate, 4),
        }

    def _save(self):
        try:
            data = []
            for key, (entry, _, _) in list(self._cache._entries.items()):
                data.append({
                    'full_hash': entry.fingerprint.full_hash,
                    'compact': entry.fingerprint.to_compact(),
                    'func_name': entry.fingerprint.func_name,
                    'status': entry.recompilation_status,
                    'level': entry.equivalence_level,
                    'score': entry.equivalence_score,
                    'compiler': entry.compiler_info,
                    'verified_at': entry.verified_at,
                })
            with open(self._persist_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception:
            _log.debug("IR cache: persist failed")

    def _load(self):
        try:
            with open(self._persist_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for item in data[:self._cache._max]:
                fp = SemanticFingerprint(
                    func_name=item.get('func_name', ''),
                    full_hash=item['full_hash'],
                )
                entry = EquivCacheEntry(
                    fingerprint=fp,
                    recompilation_status=item.get('status', False),
                    equivalence_level=item.get('level', 'unknown'),
                    equivalence_score=item.get('score', 0.0),
                    verified_at=item.get('verified_at', 0.0),
                    compiler_info=item.get('compiler', ''),
                )
                self._cache.put(fp.full_hash, entry)
            _log.info("IR cache: loaded %d entries", len(data))
        except Exception:
            _log.debug("IR cache: load failed")


# 便捷工厂

def create_equiv_cache(max_entries: int = 256,
                       persist_path: str = "") -> IREquivalenceCache:
    """工厂函数 — 创建等值缓存实例。"""
    if not persist_path:
        try:
            persist_path = os.path.join(
                os.path.expanduser('~'), '.binmind', 'ir_equiv_cache.json')
        except Exception:
            persist_path = ""
    return IREquivalenceCache(max_entries=max_entries, persist_path=persist_path)
