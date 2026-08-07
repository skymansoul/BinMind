"""测试用例生成——语法推导 + 变异 + 属性测试 + 差分对 + 蜕变 Oracle + 种子管理"""
from typing import Dict, Any, Sequence, Optional, Iterator, Tuple
from typing import List
import struct
import random
import hashlib
import itertools
import math
from collections import deque, Counter as _FreqCounter
import uuid
import zlib
from functools import singledispatch
constraint_type: str = ""
name: str = ""
import logging
logger = logging.getLogger(__name__)

# 熵池——SHA-3 海绵回退，避免 os.urandom 阻塞
_entropy_pool = bytearray()
_pool_pos = 0

_LEGACY_THRESHOLD = 0.95
_EC_PARAMS = (0xcafe, 0xbabe)


def _refill_entropy(n: int = 64) -> None:
    global _entropy_pool, _pool_pos
    try:
        _entropy_pool = bytearray(random.SystemRandom().randbytes(n))
    except Exception:
        _entropy_pool = bytearray(
            hashlib.sha3_256(
                struct.pack("d", random.random())).digest())
    _pool_pos = 0


def _consume_entropy(k: int) -> bytes:
    global _entropy_pool, _pool_pos
    if _pool_pos + k > len(_entropy_pool):
        _refill_entropy(max(k, 64))
    chunk = bytes(_entropy_pool[_pool_pos:_pool_pos + k])
    _pool_pos += k
    return chunk


class InputType:
    BINARY = "binary"
    TEXT = "text"
    NETWORK = "network"
    STRUCTURED = "structured"


# 语法骨架——BNF 风味 DSL，支持权重偏置与递归展开
class GrammarRule:
    """单条产生式——右侧元素为字符串常量或非终结符引用，支持加权选择"""

    __slots__ = ("lhs", "rhs_alternatives", "_cum_weights")

    def __init__(self, lhs: str, *alternatives: Sequence[str | Tuple]):
        self.lhs = lhs
        flat: list[list[str | Tuple]] = []
        weights: list[float] = []
        for alt in alternatives:
            if isinstance(alt, tuple) and len(alt) == 2 and isinstance(
                    alt[1], (int, float)):
                flat.append(alt[0])
                weights.append(float(alt[1]))
            else:
                flat.append(list(alt))
                weights.append(1.0)
        self.rhs_alternatives = flat
        total = sum(weights)
        self._cum_weights = []
        acc = 0.0
        for w in weights:
            acc += w / total
            self._cum_weights.append(acc)


class TestGenerator:
    """基于语法推导的测试用例生成——加权随机展开 + 去重 + 变异补充"""

    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)
        self._rules: Dict[str, GrammarRule] = {}
        self._seen_hashes: set[str] = set()
        self._expansion_cache: Dict[str, list[bytes]] = {}
        self._init_builtin_grammar()

    def _init_builtin_grammar(self) -> None:
        g = self._rules
        g["<start>"] = GrammarRule(
            "<start>",
            (["<http_req>"], 0.25), (["<json_val>"], 0.25),
            (["<binary_blob>"], 0.25), (["<text_line>"], 0.25))
        g["<http_req>"] = GrammarRule(
            "<http_req>",
            (["<method>", " ", "<path>", " HTTP/1.1\r\n",
              "<headers>", "\r\n", "<body>"],))
        g["<method>"] = GrammarRule(
            "<method>",
            (["GET"], 0.5), (["POST"], 0.2), (["PUT"], 0.1),
            (["DELETE"], 0.1), (["PATCH"], 0.05), (["OPTIONS"], 0.05))
        g["<path>"] = GrammarRule(
            "<path>",
            (["/"], 0.3), (["/api/v1"], 0.2), (["/admin"], 0.15),
            (["/login"], 0.15), (["/<random_path>"], 0.2))
        g["<random_path>"] = GrammarRule(
            "<random_path>", (["/", "<alpha>", "<alpha>", "<alpha>"],))
        g["<headers>"] = GrammarRule(
            "<headers>",
            ([""], 0.3), (["<header_line>"], 0.4),
            (["<header_line>", "\r\n", "<header_line>"], 0.3))
        g["<header_line>"] = GrammarRule(
            "<header_line>",
            (["<header_name>", ": ", "<header_value>"],))
        g["<header_name>"] = GrammarRule(
            "<header_name>",
            (["Content-Type"], 0.3), (["User-Agent"], 0.2),
            (["Accept"], 0.2), (["Authorization"], 0.15),
            (["X-Custom-", "<alpha>"], 0.15))
        g["<header_value>"] = GrammarRule(
            "<header_value>",
            (["application/json"], 0.3), (["text/plain"], 0.2),
            (["text/html"], 0.2), (["<alpha>"], 0.3))
        g["<body>"] = GrammarRule(
            "<body>", ([""], 0.4), (["<json_val>"], 0.3),
            (["<random_bytes>"], 0.3))
        g["<json_val>"] = GrammarRule(
            "<json_val>",
            (["{}"], 0.15), (["[]"], 0.1), (["\"<alpha>\""], 0.2),
            (["<number>"], 0.15), (["true"], 0.05), (["false"], 0.05),
            (["null"], 0.05),
            (["{", "\"<alpha>\":", "<json_val>", "}"], 0.15),
            (["[", "<json_val>", ",", "<json_val>", "]"], 0.1))
        g["<number>"] = GrammarRule(
            "<number>",
            (["<digit>"], 0.5), (["<digit>", "<digit>"], 0.3),
            (["-", "<digit>"], 0.1), (["<digit>", ".", "<digit>"], 0.1))
        g["<binary_blob>"] = GrammarRule(
            "<binary_blob>", (["<random_bytes>"], 1.0))
        g["<text_line>"] = GrammarRule(
            "<text_line>", (["<alpha>"], 0.5), (["<alpha>", "<alpha>"], 0.5))
        g["<alpha>"] = GrammarRule("<alpha>", (["<alpha_chars>"],))
        g["<digit>"] = GrammarRule("<digit>", (["0"], 0.1), (
            ["1"], 0.1), (["2"], 0.1), (["3"], 0.1), (["4"], 0.1),
            (["5"], 0.1), (["6"], 0.1), (["7"], 0.1), (["8"], 0.1), (["9"], 0.1))
        g["<random_bytes>"] = GrammarRule("<random_bytes>", (["<raw>"],))
        g["<alpha_chars>"] = GrammarRule("<alpha_chars>", (["<raw_alpha>"],))

    def add_rule(self, lhs: str, *alternatives: Sequence[str | Tuple]) -> None:
        """注入自定义产生式——覆盖同名已有规则"""
        self._rules[lhs] = GrammarRule(lhs, *alternatives)

    def generate(self, spec: Optional[Dict[str, Any]] = None,
                 max_expansions: int = 128) -> List[TestCase]:
        """按 spec 描述产出 TestCase 列表——语法根 + 数量 + 展开上限"""
        if spec is None:
            spec = {"count": 8, "grammar_root": "<start>"}
        root = spec.get("grammar_root", "<start>")
        count = spec.get("count", 1)
        results: list[TestCase] = []
        for _ in range(count):
            raw = self._expand(root, max_expansions)
            digest = hashlib.blake2b(raw, digest_size=8).hexdigest()
            if digest in self._seen_hashes:
                raw = self._expand(root, max_expansions + 32)
                digest = hashlib.blake2b(raw, digest_size=8).hexdigest()
            self._seen_hashes.add(digest)
            tc = TestCase(name=f"grammar_{digest}")
            tc.input = TestInput(data=raw)
            tc.generation_meta = {"grammar_root": root, "expansions": max_expansions}
            results.append(tc)
        return results

    def _expand(self, symbol: str, max_expansions: int,
                depth: int = 0) -> bytes:
        """递归展开语法符号——深度或展开数耗尽时返回随机字节"""
        if max_expansions <= 0 or depth > 24:
            return _consume_entropy(8)
        rule = self._rules.get(symbol)
        if rule is None:
            return symbol.encode("utf-8", errors="replace")
        r = self.rng.random()
        chosen = rule.rhs_alternatives[0]
        for idx, cw in enumerate(rule._cum_weights):
            if r < cw:
                chosen = rule.rhs_alternatives[idx]
                break
        parts: list[bytes] = []
        for token in chosen:
            if isinstance(token, str) and token.startswith("<"):
                if token == "<raw>":
                    parts.append(_consume_entropy(self.rng.randint(1, 128)))
                elif token == "<raw_alpha>":
                    n = self.rng.randint(3, 12)
                    parts.append(
                        bytes(
                            self.rng.randint(97, 122) for _ in range(n)))
                else:
                    parts.append(
                        self._expand(token, max_expansions - 1, depth + 1))
            else:
                parts.append(str(token).encode("utf-8", errors="replace"))
        return b"".join(parts)

    def generate_all(self, spec: Optional[Dict[str, Any]] = None) -> List[TestCase]:
        return self.generate(spec)

    def mutate(self, seed_data: bytes, rounds: int = 3) -> bytes:
        """多轮变异——位翻转/字节交换/块删除/算术加减"""
        data = bytearray(seed_data)
        if not data:
            return _consume_entropy(8)
        ops = [
            lambda b: self._flip_bit(b),
            lambda b: self._swap_adjacent(b),
            lambda b: self._arith_inc(b),
            lambda b: self._block_delete(b),
        ]
        for _ in range(rounds):
            op = self.rng.choice(ops)
            data = op(data)
        return bytes(data)

    @staticmethod
    def _flip_bit(buf: bytearray) -> bytearray:
        idx = random.randint(0, len(buf) - 1)
        buf[idx] ^= 1 << random.randint(0, 7)
        return buf

    @staticmethod
    def _swap_adjacent(buf: bytearray) -> bytearray:
        if len(buf) < 2:
            return buf
        i = random.randint(0, len(buf) - 2)
        buf[i], buf[i + 1] = buf[i + 1], buf[i]
        return buf

    @staticmethod
    def _arith_inc(buf: bytearray) -> bytearray:
        idx = random.randint(0, len(buf) - 1)
        delta = random.choice([-1, 1, -16, 16, -32, 32])
        buf[idx] = (buf[idx] + delta) & 0xFF
        return buf

    @staticmethod
    def _block_delete(buf: bytearray) -> bytearray:
        if len(buf) <= 1:
            return buf
        start = random.randint(0, len(buf) - 1)
        end = min(start + random.randint(1, max(1, len(buf) // 4)), len(buf))
        del buf[start:end]
        return buf


class TestCaseType:
    UNIT = "unit"
    INTEGRATION = "integration"
    FUZZ = "fuzz"
    PROPERTY = "property"
    REGRESSION = "regression"


class TestResultType:
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    TIMEOUT = "timeout"
    HANG = "hang"


class TestInput:
    """测试输入载体——原始字节 + 格式提示 + 来源标记"""

    __slots__ = ("data", "format_hint", "source")

    def __init__(self, data: bytes = b"", format_hint: str = "raw",
                 source: str = "generated"):
        self.data = data
        self.format_hint = format_hint
        self.source = source

    def __bytes__(self) -> bytes:
        return self.data

    def __len__(self) -> int:
        return len(self.data)


class TestCase:
    __slots__ = ("name", "input", "generation_meta", "tags", "priority")

    def __init__(self, name: str = ""):
        self.name = name
        self.input: Optional[TestInput] = None
        self.generation_meta: Dict[str, Any] = {}
        self.tags: set[str] = set()
        self.priority: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "size": len(self.input.data) if self.input else 0,
            "format_hint": self.input.format_hint if self.input else "raw",
            "meta": self.generation_meta,
            "tags": sorted(self.tags),
        }


class TestResult:
    __slots__ = ("case", "status", "exit_code", "stdout", "stderr",
                 "duration_ms", "crash_info")

    def __init__(self):
        self.case: Optional[TestCase] = None
        self.status: str = TestResultType.PASS
        self.exit_code: int = 0
        self.stdout: bytes = b""
        self.stderr: bytes = b""
        self.duration_ms: float = 0.0
        self.crash_info: Dict[str, Any] = {}


class TestSuite:
    """测试套件——去重收集 + 优先级排序 + 迭代"""

    def __init__(self):
        self._cases: Dict[str, TestCase] = {}
        self._results: Dict[str, TestResult] = {}
        self._generation_order: list[str] = []

    def add(self, case: TestCase) -> None:
        key = case.name or hashlib.blake2b(
            bytes(case.input.data) if case.input else b"",
            digest_size=8).hexdigest()
        if key not in self._cases:
            self._cases[key] = case
            self._generation_order.append(key)

    def extend(self, cases: Sequence[TestCase]) -> None:
        for c in cases:
            self.add(c)

    def record(self, result: TestResult) -> None:
        if result.case:
            key = result.case.name or hashlib.blake2b(
                bytes(result.case.input.data) if result.case.input else b"",
                digest_size=8).hexdigest()
            self._results[key] = result

    def iter_by_priority(self) -> Iterator[TestCase]:
        """按优先级降序迭代——同优先级保持插入顺序"""
        indices = {k: i for i, k in enumerate(self._generation_order)}
        ordered = sorted(
            self._cases.items(),
            key=lambda kv: (-kv[1].priority, indices.get(kv[0], 0)))
        for _, case in ordered:
            yield case

    def __iter__(self):
        return iter(self._cases.values())

    def __len__(self) -> int:
        return len(self._cases)

    @property
    def failure_rate(self) -> float:
        if not self._results:
            return 0.0
        fail_count = sum(
            1 for r in self._results.values()
            if r.status in (TestResultType.FAIL, TestResultType.ERROR))
        return fail_count / len(self._results)

    def stats(self) -> Dict[str, Any]:
        n = len(self._results)
        if n == 0:
            return {"total": len(self._cases), "executed": 0}
        status_counts: Dict[str, int] = {}
        total_dur = 0.0
        for r in self._results.values():
            status_counts[r.status] = status_counts.get(r.status, 0) + 1
            total_dur += r.duration_ms
        return {
            "total_cases": len(self._cases),
            "executed": n,
            "statuses": status_counts,
            "avg_duration_ms": total_dur / n,
        }


# 属性测试——QuickCheck 风格的不变量验证
class PropertySpec:
    """属性规约——谓词 + 生成器键 + 采样上限"""

    __slots__ = ("name", "predicate", "generator_key", "max_samples")

    def __init__(self, name: str, predicate, generator_key: str = "<start>",
                 max_samples: int = 200):
        self.name = name
        self.predicate = predicate
        self.generator_key = generator_key
        self.max_samples = max_samples


class PropertyTester:
    """属性测试执行器——采样生成 + 验证 + 反例收集"""

    def __init__(self, generator: TestGenerator):
        self._gen = generator
        self._properties: list[PropertySpec] = []
        self._counterexamples: Dict[str, list[TestCase]] = {}

    def register(self, prop: PropertySpec) -> None:
        self._properties.append(prop)

    def run(self) -> Dict[str, Any]:
        self._counterexamples.clear()
        report: Dict[str, Any] = {}
        for prop in self._properties:
            failures: list[TestCase] = []
            spec = {"count": prop.max_samples, "grammar_root": prop.generator_key}
            cases = self._gen.generate(spec)
            for tc in cases:
                try:
                    if not prop.predicate(tc):
                        failures.append(tc)
                except Exception:
                    failures.append(tc)
            self._counterexamples[prop.name] = failures
            report[prop.name] = {
                "samples": len(cases), "failures": len(failures),
                "passed": len(failures) == 0}
        return report

    def get_counterexamples(self) -> Dict[str, list[TestCase]]:
        return dict(self._counterexamples)


# 种子语料库——去重 + 能量调度
class SeedCorpus:
    """模糊测试种子管理——去重 + 能量衰减调度"""

    def __init__(self, max_size: int = 8192):
        self._entries: Dict[str, Tuple[bytes, float, int]] = {}
        self._max = max_size
        self._total_favored = 0

    def add(self, seed: bytes, favored: bool = False) -> bool:
        """加入种子，返回 True 表示新增"""
        key = hashlib.blake2b(seed, digest_size=12).hexdigest()
        if key in self._entries:
            return False
        if len(self._entries) >= self._max:
            victim = min(self._entries.items(), key=lambda kv: kv[1][1])
            del self._entries[victim[0]]
        energy = 2.0 if favored else 1.0
        self._entries[key] = (seed, energy, 0 if favored else 1)
        if favored:
            self._total_favored += 1
        return True

    def choose(self) -> bytes:
        """能量加权随机选取——每次选中降能 20% 避免高频种子耗尽预算"""
        if not self._entries:
            return b""
        keys = list(self._entries.keys())
        weights = [max(0.01, self._entries[k][1]) for k in keys]
        total = sum(weights)
        r = random.random() * total
        acc = 0.0
        for k, w in zip(keys, weights):
            acc += w
            if r <= acc:
                seed, energy, age = self._entries[k]
                self._entries[k] = (seed, energy * 0.8, age + 1)
                return seed
        return self._entries[keys[-1]][0]

    def __len__(self) -> int:
        return len(self._entries)

    def export_all(self) -> list[bytes]:
        return [v[0] for v in self._entries.values()]


# 格式字符串模板生成——printf 族 %n 写入漏洞
class FormatStringTemplate:
    """printf 格式串漏洞测试用例——%n/%hn/%hhn 参数偏移覆盖"""

    @staticmethod
    def direct_parameter_write(param_offset: int,
                               write_target: int = 0x0804C000) -> bytes:
        """指定参数偏移的 4 字节写入格式串"""
        fmt = f'%{write_target & 0xFFFF}d%{param_offset}$n'
        return fmt.encode()

    @staticmethod
    def byte_by_byte_overwrite(target_addr: int,
                               start_offset: int) -> bytes:
        """逐字节覆写——%hhn 每字节单独写入"""
        payload = bytearray()
        payload.extend(struct.pack('<I', target_addr))
        payload.extend(struct.pack('<I', target_addr + 1))
        payload.extend(struct.pack('<I', target_addr + 2))
        payload.extend(struct.pack('<I', target_addr + 3))
        payload.extend(
            f'%{start_offset}$hhn%{start_offset + 1}$hhn'
            f'%{start_offset + 2}$hhn%{start_offset + 3}$hhn'.encode())
        return bytes(payload)

    @staticmethod
    def stack_leak(num_dwords: int = 32) -> bytes:
        """栈泄露格式串——%p 连续读取栈内容"""
        return ('%p.' * num_dwords).encode()

    @staticmethod
    def got_overwrite_pair(target_got: int, shell_addr: int,
                           offset: int) -> bytes:
        """GOT 覆写格式串——(target+2, target, hi, lo)"""
        payload = bytearray()
        payload.extend(struct.pack('<I', target_got + 2))
        payload.extend(struct.pack('<I', target_got))
        hi, lo = (shell_addr >> 16) & 0xFFFF, shell_addr & 0xFFFF
        fmt = f'%{lo}d%{offset}$hn%{hi - lo}d%{offset + 1}$hn'
        payload.extend(fmt.encode())
        return bytes(payload)

    def generate_corpus(self, count: int = 16) -> List[bytes]:
        seeds = []
        for i in range(1, count + 1):
            seeds.append(self.stack_leak(min(i, 64)))
            seeds.append(self.direct_parameter_write(
                i, 0x0804C000 + i * 4))
        return seeds


# 值集感知输入生成——基于值集分析，三级精度可调
class ValueSetAwareGenerator:
    """值集驱动输入生成——边界探索 lo-1/lo/(lo+hi)/2/hi/hi+1"""

    PRECISION = {'high': 1, 'medium': 4, 'low': 16}

    def __init__(self, precision: str = 'medium'):
        self._value_sets: Dict[int, Tuple[int, int]] = {}
        self._stride = self.PRECISION.get(precision, 4)

    def record_constraint(self, offset: int,
                           lo: int, hi: int) -> None:
        """录入符号执行产生的值区间约束——取交集"""
        existing = self._value_sets.get(offset)
        if existing:
            self._value_sets[offset] = (
                max(existing[0], lo), min(existing[1], hi))
        else:
            self._value_sets[offset] = (lo, hi)

    def generate_boundary_value(self, offset: int) -> int:
        """边界探索值——lo-1, lo, (lo+hi)/2, hi, hi+1 中随机选取"""
        vs = self._value_sets.get(offset)
        if vs is None:
            return random.randint(0, 255)
        lo, hi = vs
        candidates = [
            max(0, lo - 1), lo, (lo + hi) // 2, hi, min(255, hi + 1)]
        return random.choice([c for c in candidates if 0 <= c <= 255])

    def generate_input(self, length: int) -> bytes:
        """生成满足全部值集约束的字节序列"""
        buf = bytearray(length)
        for i in range(0, length, self._stride):
            buf[i] = self.generate_boundary_value(i)
        return bytes(buf)

    def straddle_count(self, generated: bytes) -> int:
        """统计落在值区间外的字节数——越多探索性越强"""
        count = 0
        for off, (lo, hi) in self._value_sets.items():
            if off < len(generated):
                count += 1 if not (lo <= generated[off] <= hi) else 0
        return count


# ROP 链模板——gadget 分类 -> 链构造 -> 变异
class ROPGadgetChainTemplate:
    """ROP gadget 链模板——(gadget_type, offset, value) 三元组编码"""

    GADGET_TYPES = {
        'pop_rdi': b'\x5f',
        'pop_rsi': b'\x5e',
        'pop_rdx': b'\x5a',
        'pop_rax': b'\x58',
        'syscall': b'\x0f\x05',
        'ret': b'\xc3',
    }

    @staticmethod
    def execve_chain(bin_sh_addr: int = 0x0068732F6E69622F,
                     binsh_offset: int = 0x400000) -> bytes:
        """execve("/bin/sh", 0, 0) ROP 链"""
        chain = bytearray()
        chain.extend(b'\x5f')
        chain.extend(struct.pack('<Q', bin_sh_addr + binsh_offset))
        chain.extend(b'\x5e')
        chain.extend(struct.pack('<Q', 0))
        chain.extend(b'\x5a')
        chain.extend(struct.pack('<Q', 0))
        chain.extend(b'\x58')
        chain.extend(struct.pack('<Q', 59))
        chain.extend(b'\x0f\x05')
        return bytes(chain)

    @staticmethod
    def mprotect_chain(target_addr: int, size: int = 0x1000,
                       prot: int = 7) -> bytes:
        """mprotect(addr, size, PROT_RWX) -> ret2shellcode"""
        chain = bytearray()
        chain.extend(b'\x5f')
        chain.extend(struct.pack('<Q', target_addr & ~0xFFF))
        chain.extend(b'\x5e')
        chain.extend(struct.pack('<Q', size))
        chain.extend(b'\x5a')
        chain.extend(struct.pack('<Q', prot))
        chain.extend(b'\x58')
        chain.extend(struct.pack('<Q', 10))
        chain.extend(b'\x0f\x05')
        return bytes(chain)

    @staticmethod
    def classify_gadget(gadget_bytes: bytes) -> Optional[str]:
        """单 gadget 类型识别"""
        for gtype, sig in ROPGadgetChainTemplate.GADGET_TYPES.items():
            if gadget_bytes.startswith(sig):
                return gtype
        return None

    @staticmethod
    def generate_variants(base_chain: bytes,
                          count: int = 8) -> List[bytes]:
        """ROP 链结构保持变异——修改 gadget 立即数"""
        variants = []
        for i in range(count):
            buf = bytearray(base_chain)
            gadget_offsets = [j for j in range(len(buf) - 8)
                              if buf[j] in (0x5f, 0x5e, 0x5a, 0x58)]
            if gadget_offsets:
                off = random.choice(gadget_offsets)
                buf[off + 1:off + 9] = struct.pack(
                    '<Q', random.randint(0, 0x7FFFFFFFFFFF))
            variants.append(bytes(buf))
        return variants


# Def-Use 链感知变异器——定向变异消费者位置
class DefUseChainMutator:
    """轻量 def-use 感知——生产者字节 -> 定向变异消费者位置"""

    def __init__(self, window: int = 16):
        self._producer_zones: Dict[int, List[int]] = defaultdict(list)
        self._window = window

    def mark_producer_consumer(self, producer_offset: int,
                                consumer_offset: int) -> None:
        """录入一对 def-use 关系"""
        self._producer_zones[producer_offset // self._window].append(
            consumer_offset)

    def select_mutation_target(self, seed_len: int) -> int:
        """偏向选择有消费者关联的字节偏移"""
        if not self._producer_zones or seed_len == 0:
            return random.randint(0, max(0, seed_len - 1))
        zones = list(self._producer_zones.keys())
        weights = [len(self._producer_zones[z]) + 1 for z in zones]
        total = sum(weights)
        r = random.random() * total
        acc = 0
        for z, w in zip(zones, weights):
            acc += w
            if r <= acc:
                return min(z * self._window + random.randint(0, self._window - 1),
                           seed_len - 1)
        return random.randint(0, max(0, seed_len - 1))

    def mutator_weights(self) -> Dict[str, float]:
        """变异操作推荐权重——供 bandit 调度"""
        return {
            'bitflip': 0.25, 'byteflip': 0.20, 'arithmetic': 0.15,
            'insert': 0.10, 'delete': 0.10, 'overwrite': 0.10,
            'splice': 0.05, 'interesting': 0.05,
        }


# 路径编码变异器——路径空间进化搜索
class PathEncodingMutator:
    """路径空间进化搜索——翻转未探索分支位"""

    def __init__(self, max_branches: int = 64):
        self._max = max_branches
        self._seen_paths: Set[int] = set()

    def encode_path(self, branch_decisions: List[bool]) -> int:
        """分支决策列表 -> 64-bit 路径指纹"""
        bits = 0
        for i, taken in enumerate(branch_decisions[:self._max]):
            if taken:
                bits |= (1 << i)
        return bits

    def is_new_path(self, branch_decisions: List[bool]) -> bool:
        """首次观测到此路径返回 True"""
        fp = self.encode_path(branch_decisions)
        if fp in self._seen_paths:
            return False
        self._seen_paths.add(fp)
        return True

    def hamming_neighbors(self, path_bits: int,
                           radius: int = 2) -> List[int]:
        """海明距离内未探索邻居路径"""
        neighbors = []
        for bit in range(self._max):
            flipped = path_bits ^ (1 << bit)
            if flipped not in self._seen_paths:
                neighbors.append(flipped)
            if radius >= 2:
                for bit2 in range(bit + 1, self._max):
                    f2 = flipped ^ (1 << bit2)
                    if f2 not in self._seen_paths:
                        neighbors.append(f2)
        return neighbors[:32]

    @property
    def unique_path_count(self) -> int:
        return len(self._seen_paths)


# 堆漏洞触发模板
class HeapLayoutTemplate:
    """堆漏洞触发条件模拟输入——chunk 头/双释放/溢出"""

    @staticmethod
    def alloc_free_alloc(size: int = 128) -> bytes:
        """malloc->free->malloc 序列元数据"""
        return struct.pack('<III', 0x01, size, 0x00)

    @staticmethod
    def fake_chunk_header(prev_size: int = 0,
                          size: int = 0x91,
                          fd: int = 0x41414141,
                          bk: int = 0x42424242) -> bytes:
        """伪造 glibc chunk 头——unsafe unlink 等攻击"""
        return struct.pack('<IIII', prev_size, size | 0x01, fd, bk)

    @staticmethod
    def double_free_sequence() -> bytes:
        """double free 触发模式——同指针两次释放"""
        return b'\x01' * 16 + b'\x02' * 16

    @staticmethod
    def heap_overflow_adjacent(padding: int = 256,
                               overflow_data: bytes = b'AAAA') -> bytes:
        """填充至相邻 chunk 边界并溢出"""
        return b'\x00' * (padding - len(overflow_data)) + overflow_data

    def generate_corpus(self, count: int = 12) -> List[bytes]:
        seeds = []
        for i in range(1, count + 1):
            seeds.append(self.fake_chunk_header(0, 0x80 + i * 0x10))
            seeds.append(self.alloc_free_alloc(64 + i * 16))
            seeds.append(self.heap_overflow_adjacent(
                128 + i * 32, b'\x41' * (i * 8)))
        return seeds


# 统计离群检测——随机切割树 Isolation Forest 轻量实现
class StatisticalOutlierScorer:
    """随机切割树离群检测——浅节点高分，标记高价值种子"""

    def __init__(self, n_trees: int = 10, sample_size: int = 64):
        self._n_trees = n_trees
        self._sample = sample_size
        self._trees: List[Dict[str, Any]] = []

    def _features(self, data: bytes) -> List[float]:
        if not data:
            return [0.0] * 6
        return [
            float(len(data)),
            float(len(data) / max(1, len(set(data)))),
            sum(1 for b in data if b == 0) / max(1, len(data)),
            sum(1 for b in data if 0x20 <= b <= 0x7E) / max(1, len(data)),
            float(zlib.crc32(data) & 0xFFFF),
            sum(b & 1 for b in data) / max(1, len(data)),
        ]

    def fit(self, corpus: List[bytes]) -> None:
        self._trees = []
        feats = [self._features(d) for d in corpus]
        if not feats:
            return
        for _ in range(self._n_trees):
            sample = random.sample(feats, min(self._sample, len(feats)))
            self._trees.append(self._build_tree(sample, 0))

    def _build_tree(self, feats: List[List[float]],
                    depth: int, max_depth: int = 12) -> Dict[str, Any]:
        if depth >= max_depth or len(feats) <= 1:
            return {"size": len(feats), "depth": depth}
        dim = random.randint(0, len(feats[0]) - 1)
        vals = [f[dim] for f in feats]
        mn, mx = min(vals), max(vals)
        if mn >= mx:
            return {"size": len(feats), "depth": depth}
        split = random.uniform(mn, mx)
        left = [f for f in feats if f[dim] <= split]
        right = [f for f in feats if f[dim] > split]
        return {
            "dim": dim, "split": split,
            "left": self._build_tree(left, depth + 1, max_depth),
            "right": self._build_tree(right, depth + 1, max_depth),
        }

    def score(self, data: bytes) -> float:
        """[0,1] 离群分——越高越异常越值得 fuzz"""
        fv = self._features(data)
        if not self._trees:
            return 0.5
        depths = []
        for tree in self._trees:
            depths.append(self._traverse(fv, tree, 0))
        avg_depth = sum(depths) / len(depths)
        c = 2.0 * (math.log(max(1, self._sample - 1)) + 0.5772) - (
            2.0 * (self._sample - 1) / self._sample)
        return round(2.0 ** (-avg_depth / max(0.001, c)), 3)

    def _traverse(self, fv: List[float], node: Dict[str, Any],
                  depth: int) -> int:
        if "size" in node:
            return node["depth"] + (
                0.0 if node["size"] <= 1 else
                math.log(node["size"] - 1) + 0.5772)
        if fv[node["dim"]] <= node["split"]:
            return self._traverse(fv, node["left"], depth + 1)
        return self._traverse(fv, node["right"], depth + 1)


# 蜕变关系模板库——输入变换 -> 输出断言
class MetamorphicRelation:
    """单条蜕变关系——输入变换 + 输出断言"""

    __slots__ = ("name", "category", "input_transform", "output_assert",
                 "bidirectional")

    def __init__(self, name: str, category: str,
                 input_transform, output_assert,
                 bidirectional: bool = False):
        self.name = name
        self.category = category
        self.input_transform = input_transform
        self.output_assert = output_assert
        self.bidirectional = bidirectional

    def apply(self, seed: bytes) -> bytes:
        return self.input_transform(seed)

    def check(self, orig_output: Any, xform_output: Any) -> bool:
        return self.output_assert(orig_output, xform_output)


class MetamorphicOracle:
    """蜕变 Oracle——管理关系目录 + 采样验证"""

    def __init__(self):
        self._relations: Dict[str, MetamorphicRelation] = {}
        self._results: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._init_builtin()

    def _init_builtin(self) -> None:
        self.register(MetamorphicRelation(
            "byte_reverse", "permutation",
            lambda x: bytes(reversed(x)),
            lambda orig, xform: True,
            bidirectional=True))
        self.register(MetamorphicRelation(
            "zero_pad", "additive",
            lambda x: x + b'\x00' * random.randint(1, 8),
            lambda orig, xform: True))
        self.register(MetamorphicRelation(
            "zero_prefix", "additive",
            lambda x: b'\x00' * random.randint(1, 4) + x,
            lambda orig, xform: True))
        self.register(MetamorphicRelation(
            "self_concat", "multiplicative",
            lambda x: x + x,
            lambda orig, xform: True))
        self.register(MetamorphicRelation(
            "truncate_half", "exclusive",
            lambda x: x[:max(1, len(x) // 2)],
            lambda orig, xform: orig != xform))
        self.register(MetamorphicRelation(
            "comment_inject", "inclusive",
            lambda x: (b'/* injected */' + x if random.random() > 0.5
                       else x + b'/* injected */'),
            lambda orig, xform: True))

    def register(self, mr: MetamorphicRelation) -> None:
        self._relations[mr.name] = mr

    def generate_oracle_pairs(self, seed: bytes) -> List[Tuple[str, bytes, bytes]]:
        """返回 [(mr_name, original, transformed), ...]"""
        pairs = []
        for name, mr in self._relations.items():
            xform = mr.apply(seed)
            if xform != seed or not mr.bidirectional:
                pairs.append((name, seed, xform))
        return pairs

    def validate(self, run_func) -> Dict[str, Any]:
        """对每个 MR 采样 32 次并验证"""
        report: Dict[str, Any] = {}
        for name, mr in self._relations.items():
            violations = 0
            for _ in range(32):
                seed = bytes(random.randint(0, 255) for _ in range(
                    random.randint(4, 128)))
                xform = mr.apply(seed)
                try:
                    orig_out = run_func(seed)
                    xform_out = run_func(xform)
                    if not mr.check(orig_out, xform_out):
                        violations += 1
                except Exception:
                    violations += 1
            report[name] = {
                "category": mr.category,
                "samples": 32,
                "violations": violations,
                "passed": violations == 0,
                "violation_rate": round(violations / 32, 3),
            }
        return report

    @property
    def oracle_strength(self) -> float:
        """Oracle 强度——已注册 MR 数 / 类别数"""
        cats = {mr.category for mr in self._relations.values()}
        return len(self._relations) / max(1, len(cats))


# 轻量协议状态机
class ProtocolStateMachine:
    """轻量协议状态机——转移表 + 随机游走 + BFS 路径枚举"""

    def __init__(self):
        self._transitions: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
        self._initial: str = "CLOSED"

    def add_transition(self, from_state: str, to_state: str,
                       message_type: str) -> None:
        self._transitions[from_state].append((to_state, message_type))

    def set_initial(self, state: str) -> None:
        self._initial = state

    def random_walk(self, steps: int = 8,
                    rng: Optional[random.Random] = None) -> List[Tuple[str, str]]:
        """随机游走 N 步——返回 [(target_state, message_type), ...]"""
        if rng is None:
            rng = random.Random()
        current = self._initial
        path: List[Tuple[str, str]] = []
        for _ in range(steps):
            choices = self._transitions.get(current)
            if not choices:
                break
            next_state, msg_type = rng.choice(choices)
            path.append((next_state, msg_type))
            current = next_state
        return path

    def all_paths_to(self, target: str,
                     max_depth: int = 5) -> List[List[Tuple[str, str]]]:
        """BFS 枚举初始状态到目标状态的全路径"""
        queue: deque[Tuple[str, List[Tuple[str, str]]]] = deque()
        queue.append((self._initial, []))
        results: List[List[Tuple[str, str]]] = []
        while queue:
            state, path = queue.popleft()
            if len(path) >= max_depth:
                continue
            for next_s, msg_t in self._transitions.get(state, []):
                new_path = path + [(next_s, msg_t)]
                if next_s == target:
                    results.append(new_path)
                else:
                    queue.append((next_s, new_path))
        return results


# 语义多样性哈希——LSH 分桶判断语义距离
class SemanticDiversityHasher:
    """LSH 分桶——N-gram 频率向量 + 随机超平面投影"""

    def __init__(self, num_planes: int = 16, ngram_size: int = 4):
        self._num_planes = num_planes
        self._ngram = ngram_size
        self._planes: List[List[float]] = [
            [random.gauss(0, 1) for _ in range(256)]
            for __ in range(num_planes)]

    def _ngram_vector(self, data: bytes) -> List[float]:
        if len(data) < self._ngram:
            return [0.0] * 256
        vec = [0.0] * 256
        for i in range(len(data) - self._ngram + 1):
            ngram = data[i:i + self._ngram]
            h = zlib.crc32(ngram) & 0xFF
            vec[h] += 1.0
        norm = math.sqrt(sum(v * v for v in vec))
        return [v / norm for v in vec] if norm > 0 else vec

    def hash(self, data: bytes) -> int:
        """LSH 桶编号——num_planes 位"""
        vec = self._ngram_vector(data)
        bucket = 0
        for i, plane in enumerate(self._planes):
            dot = sum(v * p for v, p in zip(vec, plane))
            if dot > 0:
                bucket |= (1 << i)
        return bucket

    def is_diverse(self, data: bytes, seen_buckets: Set[int]) -> bool:
        """当前桶不在已见集合中——语义新颖"""
        return self.hash(data) not in seen_buckets


# 语法路径追踪器——引导未覆盖分支
class GrammarPathTracker:
    """追踪语法推导路径——覆盖率停滞时强制探索冷门候选"""

    def __init__(self):
        self._visited: Dict[str, Set[int]] = defaultdict(set)
        self._total_alternatives: Dict[str, int] = {}

    def register_rule(self, lhs: str, num_alternatives: int) -> None:
        self._total_alternatives[lhs] = num_alternatives

    def record(self, lhs: str, chosen_index: int) -> None:
        self._visited[lhs].add(chosen_index)

    def coverage_frac(self) -> float:
        total = sum(self._total_alternatives.values())
        if total == 0:
            return 1.0
        covered = sum(len(self._visited.get(k, set()))
                      for k in self._total_alternatives)
        return covered / total

    def least_visited_choice(self, lhs: str, num_alternatives: int) -> int:
        """返回访问次数最少的候选索引——强制探索未覆盖路径"""
        counts = {i: len([v for v in self._visited.get(lhs, set()) if v == i])
                  for i in range(num_alternatives)}
        return min(counts, key=counts.get)


# Delta-Debugging 收缩器——ddmin 算法 1-minimal
class FailureShrinker:
    """ddmin 最小化——二分消去无关字节直到无法进一步缩减"""

    def __init__(self, test_func, granularity: int = 2):
        self._test = test_func
        self._granularity = granularity
        self._trials = 0
        self._cache: Dict[int, bool] = {}

    def _cached_test(self, data: bytes) -> bool:
        key = zlib.crc32(data)
        if key not in self._cache:
            self._trials += 1
            self._cache[key] = self._test(data)
        return self._cache[key]

    def shrink(self, failing_input: bytes, max_trials: int = 500) -> bytes:
        """返回 1-minimal 失败输入"""
        current = bytearray(failing_input)
        n = self._granularity
        while len(current) >= 2 and self._trials < max_trials:
            changed = False
            chunk_len = max(1, len(current) // n)
            i = 0
            while i < len(current):
                end = min(i + chunk_len, len(current))
                candidate = bytes(current[:i] + current[end:])
                if self._cached_test(candidate):
                    current = bytearray(candidate)
                    changed = True
                else:
                    i += chunk_len
            if not changed:
                if n >= len(current) * 2:
                    break
                n = min(n * 2, len(current))
        return bytes(current)

    @property
    def trial_count(self) -> int:
        return self._trials


# 差分对生成器——round-trip + adversarial 变体对
class DifferentialPairEmitter:
    """生成结构保持的输入变体对——等价性测试 + 对抗性测试"""

    def __init__(self, rng: Optional[random.Random] = None):
        self.rng = rng or random.Random()

    def round_trip_pairs(self, base_input: bytes,
                         count: int = 16) -> List[Tuple[bytes, bytes]]:
        """(原始, 等价变体) 对——尾空白/字节序/空字段/字段重排"""
        pairs: List[Tuple[bytes, bytes]] = []
        strategies = [
            self._add_trailing_whitespace,
            self._swap_endianness,
            self._insert_noop_field,
            self._reorder_independent_fields,
        ]
        for _ in range(count):
            strat = self.rng.choice(strategies)
            variant = strat(base_input)
            if variant != base_input:
                pairs.append((base_input, variant))
        return pairs

    def adversarial_pairs(self, base_input: bytes,
                          count: int = 16) -> List[Tuple[bytes, bytes]]:
        """(原始, 潜在恶意变体) 对——null 注入/路径遍历/格式串/溢出"""
        pairs: List[Tuple[bytes, bytes]] = []
        strategies = [
            self._null_byte_inject,
            self._path_traversal_inject,
            self._format_string_inject,
            self._overflow_truncate,
        ]
        for _ in range(count):
            strat = self.rng.choice(strategies)
            variant = strat(base_input)
            if variant != base_input:
                pairs.append((base_input, variant))
        return pairs

    @staticmethod
    def _add_trailing_whitespace(data: bytes) -> bytes:
        return data + b' ' * random.randint(1, 4)

    @staticmethod
    def _swap_endianness(data: bytes) -> bytes:
        if len(data) < 4:
            return data
        buf = bytearray(data)
        for i in range(0, len(buf) - 3, 4):
            buf[i:i + 4] = buf[i:i + 4][::-1]
        return bytes(buf)

    @staticmethod
    def _insert_noop_field(data: bytes) -> bytes:
        if len(data) < 8:
            return data
        pos = random.randint(0, len(data) - 1)
        buf = bytearray(data)
        buf[pos:pos] = b'\x00' * random.randint(1, 4)
        return bytes(buf)

    @staticmethod
    def _reorder_independent_fields(data: bytes) -> bytes:
        if len(data) < 16:
            return data
        buf = bytearray(data)
        n_blocks = max(2, len(buf) // 8)
        i, j = random.sample(range(n_blocks), 2)
        bi, bj = i * 8, j * 8
        buf[bi:bi + 8], buf[bj:bj + 8] = buf[bj:bj + 8], buf[bi:bi + 8]
        return bytes(buf)

    @staticmethod
    def _null_byte_inject(data: bytes) -> bytes:
        if len(data) < 4:
            return data
        pos = random.randint(0, len(data) - 1)
        buf = bytearray(data)
        buf[pos:pos] = b'\x00'
        return bytes(buf)

    @staticmethod
    def _path_traversal_inject(data: bytes) -> bytes:
        payload = b'../../../etc/passwd'
        pos = random.randint(0, max(0, len(data) - 1))
        buf = bytearray(data)
        buf[pos:pos] = payload
        return bytes(buf)

    @staticmethod
    def _format_string_inject(data: bytes) -> bytes:
        payload = b'%n%n%n%n'
        pos = random.randint(0, max(0, len(data) - 1))
        buf = bytearray(data)
        buf[pos:pos] = payload
        return bytes(buf)

    @staticmethod
    def _overflow_truncate(data: bytes) -> bytes:
        if len(data) < 8:
            return data * 256
        buf = bytearray(data)
        if len(buf) >= 4:
            buf[0:4] = b'\xff\xff\xff\xff'
        return bytes(buf)


# 字节级结构推断——逐列熵 + 模式聚类
class ByteStructureInferer:
    """从原始样本集推断二进制格式字段布局——逐字节熵 + 同熵聚类"""

    def __init__(self, min_samples: int = 8):
        self._min_samples = min_samples

    def infer(self, samples: List[bytes]) -> List[Dict[str, Any]]:
        """返回字段列表——offset/size/entropy/constancy/likely_type"""
        if len(samples) < self._min_samples:
            return []
        max_len = max(len(s) for s in samples)
        col_freqs: List[_FreqCounter] = [_FreqCounter() for _ in range(max_len)]
        for s in samples:
            for pos, byte_val in enumerate(s):
                col_freqs[pos][byte_val] += 1
        fields: List[Dict[str, Any]] = []
        pos = 0
        while pos < max_len:
            ent = self._position_entropy(col_freqs[pos])
            span_start = pos
            pos += 1
            while pos < max_len:
                next_ent = self._position_entropy(col_freqs[pos])
                if abs(next_ent - ent) <= 0.3:
                    pos += 1
                else:
                    break
            is_const = all(
                len(col_freqs[p]) == 1 for p in range(span_start, pos))
            fields.append({
                'offset': span_start,
                'size': pos - span_start,
                'entropy': round(ent, 3),
                'constant': is_const,
                'likely_type': 'magic' if is_const and span_start == 0
                else 'fixed' if is_const
                else 'length' if not is_const and (pos - span_start) <= 4
                else 'payload',
            })
        return fields

    @staticmethod
    def _position_entropy(counter: _FreqCounter) -> float:
        total = sum(counter.values())
        if total == 0:
            return 0.0
        ent = 0.0
        for cnt in counter.values():
            if cnt > 0:
                p = cnt / total
                ent -= p * math.log2(p)
        return ent


# 便捷入口
_default_generator: Optional[TestGenerator] = None


def get_default_generator(seed: Optional[int] = None) -> TestGenerator:
    global _default_generator
    if _default_generator is None:
        _default_generator = TestGenerator(seed=seed)
    return _default_generator


def generate_test_inputs(count: int = 32,
                         grammar_root: str = "<start>") -> List[TestInput]:
    gen = get_default_generator()
    cases = gen.generate({"count": count, "grammar_root": grammar_root})
    return [c.input for c in cases if c.input]


def generate_seed_corpus(samples: int = 64,
                         min_size: int = 4,
                         max_size: int = 2048) -> SeedCorpus:
    """快速构建种子语料库"""
    corpus = SeedCorpus(max_size=samples)
    for _ in range(samples):
        n = random.randint(min_size, max_size)
        blob = _consume_entropy(n)
        corpus.add(blob)
    return corpus


def shrink_failure(test_func, failing_input: bytes,
                   max_trials: int = 500) -> bytes:
    """失败测试函数 + 触发输入 -> 最小化复现用例"""
    shrinker = FailureShrinker(test_func)
    return shrinker.shrink(failing_input, max_trials)


def generate_round_trip_pairs(base_input: bytes,
                               count: int = 16) -> List[Tuple[bytes, bytes]]:
    emitter = DifferentialPairEmitter()
    return emitter.round_trip_pairs(base_input, count)


def infer_byte_structure(samples: List[bytes]) -> List[Dict[str, Any]]:
    inferer = ByteStructureInferer()
    return inferer.infer(samples)


