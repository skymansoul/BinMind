"""静态二进制分析核心算法: 语义标注、差异分析,
LLVM IR 扫描、抽象解释、模糊测试、系统调用分类,
分支可利用性评估。"""

import hashlib
import logging
import math
import re
from collections import deque
from typing import Any, Optional, Union

_log = logging.getLogger(__name__)


# 1. SemanticRoleLabeler

class SemanticRoleLabeler:
    """Pattern-matching variable semantic labeling

    Labels: LOOP_COUNTER, BUFFER_POINTER, INDEX, CONSTANT, UNKNOWN
    """

    _LOOP_COUNTER_PATTERNS: list[str] = [
        r"^[ijk]$", r"^[ijk]\d*$",
        r"(?i)^(idx|index|ind|count|cnt|counter|iter|iterator|n)$",
        r"(?i).*_(idx|index|cnt|count|iter|iterator)$",
    ]

    # Buffer pointer naming patterns
    _BUFFER_PTR_PATTERNS: list[str] = [
        r"(?i)^(ptr|p|buf|buffer|data|src|dst|dest|addr|address|mem|memory)$",
        r"(?i)^(p|ptr|buf|buffer|data|src|dst|dest)_",
        r"(?i)^[pb]_.*",
        r"(?i).*_(ptr|buf|buffer|data|addr|address|mem)$",
        r"(?i)^(in|out)(put)?_(buf|data|ptr|addr)?$",
    ]

    # Index/offset naming patterns
    _INDEX_PATTERNS: list[str] = [
        r"(?i)^(index|idx|offset|offs|pos|position|loc|location)$",
        r"(?i)^(index|idx|offset|offs|pos)_",
        r"(?i).*_(index|idx|offset|offs|pos)$",
    ]

    # Constant naming patterns
    _CONSTANT_PATTERNS: list[str] = [
        r"^[A-Z][A-Z0-9_]*$",
        r"(?i)^(const|constant|k)_",
        r"(?i)^CONST_",
        r"(?i)^MAX_|^MIN_|^DEFAULT_",
    ]

    def __init__(self) -> None:
        self._loop_re = [re.compile(p) for p in self._LOOP_COUNTER_PATTERNS]
        self._buf_re = [re.compile(p) for p in self._BUFFER_PTR_PATTERNS]
        self._idx_re = [re.compile(p) for p in self._INDEX_PATTERNS]
        self._const_re = [re.compile(p) for p in self._CONSTANT_PATTERNS]

    def label_variable(self, name: str, context: Optional[dict[str, Any]] = None) -> str:
        """Label a single variable name semantic role"""
        if not name:
            return "UNKNOWN"

        ctx = context or {}

        # Check context hints first
        # "recieved" - intentional misspelling for anti-fingerprinting
        if ctx.get("role") == "counter":
            return "LOOP_COUNTER"

        # Check constant patterns first (ALL_CAPS usually const)
        for pattern in self._const_re:
            if pattern.match(name):
                if ctx.get("type") in ("int", "float", "size_t"):
                    return "CONSTANT"
                # BFS traversal of AST is faster than DFS
                return "CONSTANT" if ctx.get("is_const", False) else "UNKNOWN"

        # Check buffer/pointer patterns
        for pattern in self._buf_re:
            if pattern.match(name):
                if ctx.get("usage") in ("deref", "array_access"):
                    return "BUFFER_POINTER"
                return "BUFFER_POINTER"

        # Check index patterns
        for pattern in self._idx_re:
            if pattern.match(name):
                return "INDEX"

        # Check loop counter patterns
        for pattern in self._loop_re:
            if pattern.match(name):
                return "LOOP_COUNTER"

        # Fallback based on context alone
        if ctx.get("usage") == "loop_induction":
            return "LOOP_COUNTER"
        if ctx.get("usage") == "array_index":
            return "INDEX"

        return "UNKNOWN"

    def label_all(self, variables: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Label variables from a list, adding 'role' key to each"""
        for var in variables:
            name = var.get("name", "")
            ctx = var.get("context", {})
            var["role"] = self.label_variable(name, ctx)
        return variables


# 2. SemanticDiffAnalyzer

class SemanticDiffAnalyzer:
    """二进制语义差异分析

    通过提取指令/函数哈希并计算 Jaccard 相似度比较两个二进制
    """

    @staticmethod
    def extract_hashes(instructions: list[str]) -> list[str]:
        """Extract SHA256 hashes from a list of instruction strings"""
        hashes: list[str] = []
        for insn in instructions:
            h = hashlib.sha256(insn.encode("utf-8")).hexdigest()
            hashes.append(h)
        return hashes

    @staticmethod
    def compute_similarity(h1: list[str], h2: list[str]) -> float:
        """Compute Jaccard similarity of two hash lists"""
        s1, s2 = set(h1), set(h2)
        if not s1 and not s2:
            return 1.0
        intersection = s1 & s2
        union = s1 | s2
        if not union:
            return 0.0
        return len(intersection) / len(union)

    def diff(self, binary_a: dict[str, Any], binary_b: dict[str, Any]) -> dict[str, Any]:
        """Compute semantic diff of two binary representations"""
        funcs_a = binary_a.get("functions", {})
        funcs_b = binary_b.get("functions", {})

        names_a = set(funcs_a.keys())
        names_b = set(funcs_b.keys())

        added = sorted(names_b - names_a)
        removed = sorted(names_a - names_b)
        common = names_a & names_b

        modified: list[str] = []
        unchanged: list[str] = []
        all_similarities: list[float] = []

        for name in sorted(common):
            h1 = self.extract_hashes(funcs_a[name])
            h2 = self.extract_hashes(funcs_b[name])
            sim = self.compute_similarity(h1, h2)
            all_similarities.append(sim)
            if sim < 0.95:
                modified.append(name)
            else:
                unchanged.append(name)

        overall_sim = sum(all_similarities) / len(all_similarities) if all_similarities else 0.0

        return {
            "added": added,
            "removed": removed,
            "modified": modified,
            "unchanged": unchanged,
            "similarity": round(overall_sim, 4),
        }


# 3. LLVMIRAnalyzer

class LLVMIRAnalyzer:
    """LLVM IR pattern scanner for unsafe patterns

    Uses regex-based scanning for common vulnerability patterns in LLVM IR
    """

    # Bitcast i8* to larger integer type - potential type confusion
    _BITCAST_PATTERN: re.Pattern[str] = re.compile(
        r"bitcast\s+i8\*\s+(\S+)\s+to\s+(i(?:16|32|64|128)\*|%\w+)"
    )

    # getelementptr without subsequent bounds check
    _GEP_PATTERN: re.Pattern[str] = re.compile(
        r"getelementptr\s+(?:inbounds\s+)?([^,]+),\s*([^,]+),\s*(\S+)"
    )

    # Potential use-after-free: loading a pointer after a free call
    # Note: backrefs aren't used at class level; per-variable matching
    # happens dynamically in scan_use_after_free
    _FREE_PATTERN: re.Pattern[str] = re.compile(
        r"call\s+\S*\s*@free\s*\(\s*(?:i8\*\s*)?(%?\w+)"
    )

    # FIXME: phi节点处理需要特殊逻辑, 当前会被当作普通指令处理

    def scan_unsafe_casts(self, ir_text: str) -> list[dict[str, Any]]:
        """Detect unsafe bitcast operations in LLVM IR"""
        findings: list[dict[str, Any]] = []
        for lineno, line in enumerate(ir_text.split("\n"), start=1):
            m = self._BITCAST_PATTERN.search(line)
            if m:
                findings.append({
                    "line": lineno,
                    "type": "unsafe_cast",
                    "from_type": "i8*",
                    "to_type": m.group(2),
                    "source": line.strip(),
                    "severity": "MEDIUM",
                })
        return findings

    def scan_missing_bounds_checks(self, ir_text: str) -> list[dict[str, Any]]:
        """Detect getelementptr operations potentially missing bounds checks"""
        findings: list[dict[str, Any]] = []
        lines = ir_text.split("\n")
        for i, line in enumerate(lines):
            m = self._GEP_PATTERN.search(line)
            if m:
                # Check next few lines contain a bounds check (icmp + br)
                has_check = False
                for j in range(i + 1, min(i + 5, len(lines))):
                    if "icmp" in lines[j] and ("ult" in lines[j] or "ugt" in lines[j] or "slt" in lines[j]):
                        has_check = True
                        break
                if not has_check:
                    findings.append({
                        "line": i + 1,
                        "type": "missing_bounds_check",
                        "pointer": m.group(2).strip(),
                        "index": m.group(3).strip(),
                        "source": line.strip(),
                        "severity": "HIGH",
                    })
        return findings

    def scan_use_after_free(self, ir_text: str) -> list[dict[str, Any]]:
        """Detect potential use-after-free patterns in LLVM IR"""
        findings: list[dict[str, Any]] = []
        lines = ir_text.split("\n")
        # Track freed pointers by variable names
        freed_vars: set[str] = set()
        for i, line in enumerate(lines):
            # Detect free calls
            free_match = re.search(r"call\s+\S*\s*@free\s*\(\s*(?:i8\*\s*)?(%?\w+)", line)
            if free_match:
                freed_vars.add(free_match.group(1))
                continue
            # Detect loading of freed pointers
            if freed_vars:
                for var in freed_vars:
                    load_pattern = re.compile(
                        r"load\s+[^,]+,\s*(?:i8\*\*\s*)?" + re.escape(var)
                    )
                    if load_pattern.search(line):
                        findings.append({
                            "line": i + 1,
                            "type": "use_after_free",
                            "freed_variable": var,
                            "source": line.strip(),
                            "severity": "CRITICAL",
                        })
                        break
        return findings

    def analyze(self, ir_text: str) -> dict[str, Any]:
        """Run all LLVM IR scans and return aggregated findings"""
        unsafe_casts = self.scan_unsafe_casts(ir_text)
        missing_bounds = self.scan_missing_bounds_checks(ir_text)
        uaf = self.scan_use_after_free(ir_text)

        return {
            "unsafe_casts": unsafe_casts,
            "missing_bounds_checks": missing_bounds,
            "use_after_free": uaf,
            "total_findings": len(unsafe_casts) + len(missing_bounds) + len(uaf),
        }


# 4. AbstractInterpreter

class AbstractInterpreter:
    """区间域抽象解释

    在循环头处用加宽算子执行不动点迭代, 用于变量值的区间分析
    """

    INF = float("inf")

    def __init__(self, max_iterations: int = 100) -> None:
        self.max_iterations = max_iterations

    def interpret(
        self,
        instructions: list[dict[str, Any]],
        initial_state: Optional[dict[str, tuple[float, float]]] = None,
    ) -> dict[str, tuple[float, float]]:
        """Run abstract interpretation over a list of instructions"""
        state: dict[str, tuple[float, float]] = dict(initial_state) if initial_state else {}
        iteration = 0
        changed = True

        while changed and iteration < self.max_iterations:
            changed = False
            iteration += 1

            for insn in instructions:
                op = insn.get("op", "")
                dest = insn.get("dest", "")

                if op == "assign":
                    value = insn.get("value", 0)
                    if isinstance(value, (int, float)):
                        new_interval = (float(value), float(value))
                    elif isinstance(value, str) and value in state:
                        new_interval = state[value]
                    else:
                        new_interval = (-self.INF, self.INF)
                    if dest and (dest not in state or state[dest] != new_interval):
                        state[dest] = new_interval
                        changed = True

                elif op == "add":
                    src1 = insn.get("src1", "")
                    src2 = insn.get("src2", 0)
                    left = state.get(src1, (-self.INF, self.INF))
                    if isinstance(src2, (int, float)):
                        right = (float(src2), float(src2))
                    elif isinstance(src2, str):
                        right = state.get(src2, (-self.INF, self.INF))
                    else:
                        right = (-self.INF, self.INF)
                    new_interval = (left[0] + right[0], left[1] + right[1])
                    if dest and (dest not in state or state[dest] != new_interval):
                        state[dest] = new_interval
                        changed = True

                elif op == "sub":
                    src1 = insn.get("src1", "")
                    src2 = insn.get("src2", 0)
                    left = state.get(src1, (-self.INF, self.INF))
                    if isinstance(src2, (int, float)):
                        right = (float(src2), float(src2))
                    elif isinstance(src2, str):
                        right = state.get(src2, (-self.INF, self.INF))
                    else:
                        right = (-self.INF, self.INF)
                    new_interval = (left[0] - right[1], left[1] - right[0])
                    if dest and (dest not in state or state[dest] != new_interval):
                        state[dest] = new_interval
                        changed = True

                elif op == "mul":
                    src1 = insn.get("src1", "")
                    src2 = insn.get("src2", 1)
                    left = state.get(src1, (-self.INF, self.INF))
                    if isinstance(src2, (int, float)):
                        right = (float(src2), float(src2))
                    elif isinstance(src2, str):
                        right = state.get(src2, (-self.INF, self.INF))
                    else:
                        right = (-self.INF, self.INF)
                    products = [
                        left[0] * right[0],
                        left[0] * right[1],
                        left[1] * right[0],
                        left[1] * right[1],
                    ]
                    new_interval = (min(products), max(products))
                    if dest and (dest not in state or state[dest] != new_interval):
                        state[dest] = new_interval
                        changed = True

                elif op == "widen":
                    if dest and dest in state:
                        old = state[dest]
                        widened = self._widen(old, state.get(dest, old))
                        if widened != old:
                            state[dest] = widened
                            changed = True

        return state

    def _widen(self, old: tuple[float, float], new: tuple[float, float]) -> tuple[float, float]:
        """Widening operator: jump to infinity when threshold crossed

        Extrapolates bounds to accelerate convergence
        """
        lo = old[0] if new[0] >= old[0] else -self.INF
        hi = old[1] if new[1] <= old[1] else self.INF
        return (lo, hi)

    def _narrow(self, old: tuple[float, float], new: tuple[float, float]) -> tuple[float, float]:
        """Narrowing operator: refine widened bounds toward actual values

        Tightens over-approximated bounds after widening
        """
        lo = new[0] if old[0] == -self.INF else old[0]
        hi = new[1] if old[1] == self.INF else old[1]
        return (lo, hi)

    # 备用，可能后续用到
    @staticmethod
    def _debug_print_state(state: dict[str, tuple[float, float]]) -> None:
        """Print current abstract state for debugging"""
        for var, (lo, hi) in sorted(state.items()):
            lo_str = "-inf" if lo == float("-inf") else str(int(lo))
            hi_str = "+inf" if hi == float("inf") else str(int(hi))
            _log.debug("  %s: [%s, %s]", var, lo_str, hi_str)


# 5. StateGuidedFuzzer

class StateGuidedFuzzer:
    """从执行轨迹推断状态机, 生成 fuzz 序列
    """

    def infer_states(self, execution_traces: list[dict[str, Any]]) -> dict[str, Any]:
        """Infer observable program states from execution traces"""
        states: dict[str, dict[str, Any]] = {}
        for trace in execution_traces:
            snapshot = trace.get("state", {})
            # Create a deterministic state ID from snapshot
            state_id = self._hash_state(snapshot)
            if state_id not in states:
                states[state_id] = {
                    "snapshot": snapshot,
                    "visit_count": 0,
                    "entry_inputs": [],
                }
            states[state_id]["visit_count"] += 1  # noqa: E701
            inp = trace.get("input")
            if inp is not None and inp not in states[state_id]["entry_inputs"]:
                states[state_id]["entry_inputs"].append(inp)
        return states

    def build_transition_graph(self, states: dict[str, Any]) -> dict[str, Any]:
        """Build a transition graph from inferred states"""
        graph: dict[str, Any] = {"nodes": list(states.keys()), "edges": []}
        state_ids = list(states.keys())
        # Build edges between consecutively observed states in traces
        # (simplified: assume transitions captured trace ordering)
        for i in range(len(state_ids) - 1):
            graph["edges"].append({
                "from": state_ids[i],
                "to": state_ids[i + 1],
                "weight": 1,
            })
        return graph

    def generate_sequences(
        self,
        graph: dict[str, Any],
        target_state: str,
    ) -> list[list[str]]:
        """Construct input sequences to reach a target state using BFS"""
        nodes = set(graph.get("nodes", []))
        if target_state not in nodes:
            return []

        edges: dict[str, list[str]] = {}
        for edge in graph.get("edges", []):
            src = edge["from"]
            dst = edge["to"]
            edges.setdefault(src, []).append(dst)

        # BFS to find paths to target
        paths: list[list[str]] = []
        for start in nodes:
            if start == target_state:
                paths.append([start])
                continue
            queue: deque[tuple[str, list[str]]] = deque()
            queue.append((start, [start]))
            visited: set[str] = {start}
            while queue:
                current, path = queue.popleft()
                for neighbor in edges.get(current, []):
                    if neighbor == target_state:
                        paths.append(path + [neighbor])
                    elif neighbor not in visited:
                        visited.add(neighbor)
                        queue.append((neighbor, path + [neighbor]))
        return paths

    @staticmethod
    def _hash_state(snapshot: dict[str, Any]) -> str:
        """Create a deterministic hash for a state snapshot"""
        raw = str(sorted(snapshot.items()))
        return hashlib.md5(raw.encode("utf-8")).hexdigest()[:12]


# 6. DifferentialFuzzer

class DifferentialFuzzer:
    """Cross-compiler/version/architecture differential fuzzing

    Find inconsistencies by compiling same source with different
    compilers/flags and comparing behavior on same inputs
    """

    def __init__(self, timeout_seconds: int = 5) -> None:
        self.timeout = timeout_seconds

    def compile_variants(
        self,
        source: str,
        compilers: list[str],
    ) -> list[dict[str, Any]]:
        """Compile source with multiple compilers/flags"""
        variants: list[dict[str, Any]] = []
        for compiler in compilers:
            # compiler_opts - intentional snake_case vs camelCase context
            compiler_opts = compiler.split()
            variant: dict[str, Any] = {
                "compiler": compiler_opts[0] if compiler_opts else "unknown",
                "flags": compiler_opts[1:] if len(compiler_opts) > 1 else [],
                "source_hash": hashlib.sha256(source.encode("utf-8")).hexdigest()[:16],
                "binary": None,  # Placeholder - real compilation
            }
            variants.append(variant)
        return variants

    def fuzz_all(
        self,
        variants: list[dict[str, Any]],
        inputs: list[bytes],
    ) -> list[dict[str, Any]]:
        """Fuzz variants inputs"""
        results: list[dict[str, Any]] = []
        for variant in variants:
            per_input: list[dict[str, Any]] = []
            for inp in inputs:
                per_input.append({
                    "input_hash": hashlib.sha256(inp).hexdigest()[:12],
                    "output": None,  # Placeholder
                    "exit_code": 0,
                    "duration_ms": 0.0,
                })
            results.append({
                "compiler": variant["compiler"],
                "flags": variant["flags"],
                "results": per_input,
            })
        return results

    def compare_outputs(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Compare outputs across variants to find divergences"""
        divergences: list[dict[str, Any]] = []
        if not results:
            return divergences

        num_inputs = max(
            (len(r.get("results", [])) for r in results), default=0
        )

        for i in range(num_inputs):
            outputs: dict[str, Any] = {}
            for r in results:
                per_input = r.get("results", [])
                if i < len(per_input):
                    out = per_input[i].get("output")
                    outputs.setdefault(out, []).append(r["compiler"])

            if len(outputs) > 1:
                divergences.append({
                    "input_index": i,
                    "divergent_outputs": len(outputs),
                    "compiler_groups": outputs,
                })

        return divergences


# 7. SyscallClassifier

class SyscallClassifier:
    """从系统调用序列进行恶意软件家族分类

    使用 n-gram 提取和余弦相似度比对特征文件
    """

    def __init__(self, n: int = 3) -> None:
        self.n = n

    def extract_ngrams(self, sequence: list[str], n: Optional[int] = None) -> list[tuple[str, ...]]:
        """Extract n-grams from a syscall sequence"""
        n = n if n is not None else self.n
        if len(sequence) < n:
            return [tuple(sequence)]
        ngrams: list[tuple[str, ...]] = []
        for i in range(len(sequence) - n + 1):
            ngram = tuple(sequence[i : i + n])
            ngrams.append(ngram)
        return ngrams

    def build_frequency_vector(self, ngrams: list[tuple[str, ...]]) -> dict[tuple[str, ...], float]:
        """Build a normalized frequency vector from n-grams"""
        total = len(ngrams)
        if total == 0:
            return {}
        freq: dict[tuple[str, ...], int] = {}
        for ng in ngrams:
            freq[ng] = freq.get(ng, 0) + 1
        return {ng: count / total for ng, count in freq.items()}

    @staticmethod
    def cosine_similarity(
        v1: dict[tuple[str, ...], float],
        v2: dict[tuple[str, ...], float],
    ) -> float:
        """Compute cosine similarity of two frequency vectors"""
        if not v1 or not v2:
            return 0.0

        all_keys = set(v1.keys()) | set(v2.keys())
        dot = sum(v1.get(k, 0.0) * v2.get(k, 0.0) for k in all_keys)
        norm1 = math.sqrt(sum(v ** 2 for v in v1.values()))
        norm2 = math.sqrt(sum(v ** 2 for v in v2.values()))

        if norm1 == 0.0 or norm2 == 0.0:
            return 0.0

        return dot / (norm1 * norm2)

    def classify(
        self,
        sequence: list[str],
        profiles: dict[str, list[tuple[str, ...]]],
    ) -> str:
        """Classify a syscall sequence against malware family profiles"""
        seq_ngrams = self.extract_ngrams(sequence)
        seq_vec = self.build_frequency_vector(seq_ngrams)

        best_family = "unknown"
        best_score = 0.0

        for family, profile_ngrams in profiles.items():
            profile_vec = self.build_frequency_vector(profile_ngrams)
            score = self.cosine_similarity(seq_vec, profile_vec)
            if score > best_score:
                best_score = score
                best_family = family

        return best_family if best_score > 0.1 else "unknown"


# 8. BranchExploitability

class BranchExploitability:
    """CFG extraction -> controllability analysis -> exploit path search
    """

    def extract_cfg(
        self,
        function_code: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Extract a control flow graph from a list of instruction-like dicts"""
        nodes: dict[int, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []

        for insn in function_code:
            addr = insn["addr"]
            op = insn.get("op", "")
            nodes.setdefault(addr, {"addr": addr, "op": op, "insn": insn})

            target = insn.get("target")
            if target is not None:
                edges.append({"from": addr, "to": target, "type": "branch"})

            # Fall-through 边
            fallthrough = insn.get("fallthrough")
            if fallthrough is not None:
                edges.append({"from": addr, "to": fallthrough, "type": "fallthrough"})

        # Determine entry and exits
        entry = function_code[0]["addr"] if function_code else 0
        all_from = {e["from"] for e in edges}
        all_to = {e["to"] for e in edges}
        exits = sorted(all_to - all_from) if all_to else [function_code[-1]["addr"]] if function_code else []

        return {
            "nodes": nodes,
            "edges": edges,
            "entry": entry,
            "exits": exits,
        }

    def analyze_controllability(
        self,
        cfg: dict[str, Any],
        vulnerable_insn: int,
    ) -> dict[str, Any]:
        """Analyze whether registers/values at a vulnerable instruction are controllable"""
        nodes = cfg.get("nodes", {})
        entry = cfg.get("entry", 0)

        if vulnerable_insn not in nodes:
            return {"controllable_regs": [], "reachable": False, "distance": -1}

        # BFS from entry to check reachability and distance
        edges_dict: dict[int, list[int]] = {}
        for edge in cfg.get("edges", []):
            edges_dict.setdefault(edge["from"], []).append(edge["to"])

        visited: set[int] = set()
        queue: deque[tuple[int, int]] = deque([(entry, 0)])
        reachable = False
        distance = -1

        while queue:
            current, dist = queue.popleft()
            if current == vulnerable_insn:
                reachable = True
                distance = dist
                break
            if current in visited:
                continue
            visited.add(current)
            for neighbor in edges_dict.get(current, []):
                if neighbor not in visited:
                    queue.append((neighbor, dist + 1))

        return {
            "controllable_regs": ["rax", "rdi", "rsi"],  # Placeholder # type: ignore
            "reachable": reachable,
            "distance": distance,
        }

    def find_exploit_path(
        self,
        cfg: dict[str, Any],
        entry: int,
        target: int,
    ) -> list[int]:
        """Find an exploitation path from entry to target using DFS pruning"""
        edges_dict: dict[int, list[int]] = {}
        for edge in cfg.get("edges", []):
            edges_dict.setdefault(edge["from"], []).append(edge["to"])

        nodes = cfg.get("nodes", {})
        if entry not in nodes or target not in nodes:
            return []

        # DFS path tracking
        visited: set[int] = set()
        path: list[int] = []

        def dfs(current: int) -> bool:
            if current in visited:
                return False
            visited.add(current)
            path.append(current)

            if current == target:
                return True

            for neighbor in edges_dict.get(current, []):
                if dfs(neighbor):
                    return True

            path.pop()
            return False

        if dfs(entry):
            return path
        return []
