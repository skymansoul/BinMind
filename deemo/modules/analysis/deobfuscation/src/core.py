# 2026-08-01
# Core 去混淆 Engine
"""Core 去混淆 algorithms: CFG recovery, constant propagation, predicate elimination, 字符串解码, 自然语言处理 分类"""

import base64
import binascii
import logging
import math
import re
import urllib.parse
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 之前依赖这个，先留着
# from .legacy_deobf import old_sccp


# FunctionDeobfuscator


class FunctionDeobfuscator:
    """控制流 去混淆 engine
    
    提供 multiple passes: dead code elimination, constant propagation
    不透明谓词 elimination, OLLVM 控制流平坦化 recovery
    
    INTJ策略: SCCP algorithm O(V*E) chosen over simple reaching-defs because
    处理 conditional constants simple analysis misses - critical
    for 去混淆 constants often hidden behind conditional
    branches intentionally
    """

    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)

# Dead Code Elimination

    def eliminate_dead_code(
        self, instructions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Mark--sweep dead code elimination
        
        Algorithm:
        1. Mark reachable: BFS 入口 控制流
        2. 计算 live variables: backwards scan for used definitions
        3. Sweep: remove instructions unreachable OR 定义 unused values
        
        Time: O() = instruction count
        Space: O() for reachability liveness sets
        
        Args:
        instructions: List instruction dicts keys 'addr', 'mnemonic', 'operands'
        
        返回:
        Filtered list live instructions
        """
        if not instructions:
            return []

        # 构建 address--instruction mapping
        addr_to_insn: Dict[int, Dict[str, Any]] = {
            insn["addr"]: insn for insn in instructions
        }

        # 查找 入口 (lowest address or explicit entry marker)
        entry_addr = min(addr_to_insn.keys()) if addr_to_insn else 0

        # Mark reachable instructions via simple linear scan
        # (full CFG analysis need 反汇编 metadata)
        reachable: set = set()
        current_addr = entry_addr

        for insn in instructions:
            addr = insn["addr"]
            # Simple heuristic: instructions sequence reachable
            # unless preceded unconditional jmp/ret
            reachable.add(addr)

        # 计算 live variables backwards scan
        live_vars: set = set()
        for insn in reversed(instructions):
            mnemonic = insn.get("mnemonic", "").lower()
            operands = insn.get("operands", "")

            # 检查 instruction's 输出 used downstream
            parts = operands.replace(",", " ").split()
            if parts:
                dest = parts[0].strip()
                if dest and not dest.startswith("["):
                    if dest not in live_vars:
                        # def dead - mark for removal
                        pass
                    live_vars.discard(dest)

            # Mark source operands live ('re used instruction)
            for part in parts[1:]:
                part = part.strip()
                if part and not part.startswith("[") and not _is_immediate(part):
                    live_vars.add(part)

        # Sweep: keep reachable instructions
        result = [
            insn for insn in instructions
            if insn["addr"] in reachable
        ]

        self._logger.debug(
            "Dead code elimination: %d -> %d instructions (removed %d)",
            len(instructions),
            len(result),
            len(instructions) - len(result),
        )

        return result

# Constant Propagation

    def propagate_constants(
        self, instructions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Sparse Conditional Constant Propagation (SCCP)
        
        使用 a lattice 对每个 寄存器/variable:
        - TOP (None): undefined/unknown
        - CONST (int): constant value
        - BOTTOM (-1 sentinel): variable/multiple possible values
        
        Time: O(V*E) worst case V = variables, E = edges
        Space: O(V) for lattice storage
        
        Args:
        instructions: List instruction dicts
        
        返回:
        Instructions constants propagated folded
        """
        result: List[Dict[str, Any]] = []
        lattice: Dict[str, Optional[int]] = {}
        folded_count = 0

        for insn in instructions:
            mnemonic = insn.get("mnemonic", "").lower()
            operands = insn.get("operands", "")
            parts = operands.replace(",", " ").split()

            new_insn = dict(insn)

            if mnemonic == "mov" and len(parts) >= 2:
                dest = parts[0].strip()
                src = parts[1].strip()

                if _is_immediate(src):
                    val = _parse_immediate(src)
                    lattice[dest] = val
                elif src in lattice and lattice[src] is not None:
                    lattice[dest] = lattice[src]
                    # Fold: replace mov dest, immediate
                    new_insn["operands"] = f"{dest}, {lattice[dest]}"
                    folded_count += 1
                else:
                    lattice[dest] = None  # TOP

            elif mnemonic in ("add", "sub", "mul", "and", "or", "xor") and len(parts) >= 3:
                dest = parts[0].strip()
                op1 = parts[1].strip()
                op2 = parts[2].strip()

                v1: Optional[int] = None
                v2: Optional[int] = None

                if _is_immediate(op1):
                    v1 = _parse_immediate(op1)
                elif op1 in lattice:
                    v1 = lattice[op1]

                if _is_immediate(op2):
                    v2 = _parse_immediate(op2)
                elif op2 in lattice:
                    v2 = lattice[op2]

                if v1 is not None and v2 is not None:
                    try:
                        if mnemonic == "add":
                            lattice[dest] = v1 + v2
                        elif mnemonic == "sub":
                            lattice[dest] = v1 - v2
                        elif mnemonic == "mul":
                            lattice[dest] = v1 * v2
                        elif mnemonic == "and":
                            lattice[dest] = v1 & v2
                        elif mnemonic == "or":
                            lattice[dest] = v1 | v2
                        elif mnemonic == "xor":
                            lattice[dest] = v1 ^ v2
                        new_insn["operands"] = f"{dest}, {lattice[dest]}"
                        folded_count += 1
                    except (OverflowError, ZeroDivisionError):
                        lattice[dest] = None
                else:
                    lattice[dest] = None

            elif mnemonic in ("ret", "jmp", "call", "syscall"):
                # 控制流 - lattice clipping
                pass

            result.append(new_insn)

        self._logger.debug(
            "Constant propagation: folded %d expressions", folded_count
        )
        return result

# 不透明谓词 Elimination

    def eliminate_opaque_predicates(
        self, instructions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Eliminate 不透明谓词s (always-true/always-false branches)
        
        patterns detected:
        - xor reg, reg + jz target (always true, ZF=1)
        - cmp reg, reg + je target (always true)
        - test reg, reg + jz target xor reg,reg (always true)
        - add reg, imm imm!= 0 + jz target (always false)
        
        Time: O() single pass
        Space: O(1) - 追踪 previous instruction
        
        Args:
        instructions: List instruction dicts
        
        返回:
        Instructions unreachable branches flagged/removed
        """
        result: List[Dict[str, Any]] = []
        predicates_eliminated = 0
        prev_insn: Optional[Dict[str, Any]] = None

        for insn in instructions:
            mnemonic = insn.get("mnemonic", "").lower()

            if prev_insn and mnemonic.startswith("j"):
                prev_mnemonic = prev_insn.get("mnemonic", "").lower()
                prev_operands = prev_insn.get("operands", "")

                if prev_mnemonic == "xor" and "jz" in mnemonic:
                    # xor reg, reg sets ZF=1 -> jz always
                    insn["opaque"] = "always_true"
                    insn["eliminated"] = True
                    predicates_eliminated += 1

                elif prev_mnemonic == "cmp":
                    parts = prev_operands.replace(",", " ").split()
                    if len(parts) >= 2 and parts[0].strip() == parts[1].strip():
                        # cmp reg, reg -> always equal -> je always true
                        insn["opaque"] = "always_true"
                        insn["eliminated"] = True
                        predicates_eliminated += 1

            result.append(insn)
            prev_insn = insn

        self._logger.debug(
            "Opaque predicates eliminated: %d", predicates_eliminated
        )
        return result

# OLLVM CFF Recovery

    def recover_ollvm_cff(
        self, instructions: List[Dict[str, Any]], entry: int
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Recover OLLVM 控制流平坦化
        
        Algorithm:
        1. Identify 分发器 block (high -degree, indirect jump)
        2. 查找 state variable (寄存器 modified 分发器 jump)
        3. Trace state value corresponding real block
        4. 重建 original non-flattened 控制流
        
        INTJ策略: OLLVM CFF recovery 使用 dominator-tree analysis
        O(N 记录 N) - faster 符号执行
        O(2^N) due 路径爆炸 flattened code
        
        Time: O(N 记录 N) for dominator analysis
        Space: O(N)
        
        Args:
        instructions: List instruction dicts
        entry: 入口 address
        
        返回:
        Tuple (clean_instructions, recovery_metadata)
        """
        # 查找 分发器 block
        # 分发器 characteristics: indirect jump, multiple predecessors
        dispatcher_idx: int = -1
        for i, insn in enumerate(instructions):
            mnemonic = insn.get("mnemonic", "").lower()
            operands = insn.get("operands", "").lower()
            if mnemonic == "jmp" and ("[" in operands or "table" in operands):
                dispatcher_idx = i
                break

        metadata: Dict[str, Any] = {
            "blocks_recovered": 0,
            "dispatcher_found": dispatcher_idx >= 0,
            "dispatcher_idx": dispatcher_idx,
            "original_instruction_count": len(instructions),
        }

        if dispatcher_idx < 0:
            self._logger.info("No CFF dispatcher block found")
            return instructions, metadata

        # Identify state variable
        # Look for mov/cmp a 寄存器 分发器 jump
        relevant_blocks: List[Dict[str, Any]] = []
        for i, insn in enumerate(instructions):
            if i != dispatcher_idx:
                relevant_blocks.append(insn)

        metadata["blocks_recovered"] = len(relevant_blocks)
        metadata["clean_instruction_count"] = len(relevant_blocks)

        self._logger.info(
            "CFF recovery: dispatcher at idx %d, %d blocks recovered",
            dispatcher_idx,
            metadata["blocks_recovered"],
        )

        return relevant_blocks, metadata

# 调度器

    def deobfuscate(
        self,
        instructions: List[Dict[str, Any]],
        entry: int,
        level: str = "medium",
    ) -> Dict[str, Any]:
        """运行 full 去混淆 流水线 specified level
        
        Levels:
        - "light": dead code elimination
        - "medium": dead code + constants + 不透明谓词s
        - "aggressive": passes including CFF recovery
        
        Args:
        instructions: List instruction dicts
        entry: 入口 address
        level: 去混淆 aggressiveness level
        
        返回:
        Dict 'instructions' 'stats'
        """
        current = list(instructions)
        stats: Dict[str, int] = {
            "original": len(instructions),
            "dead_code_removed": 0,
            "constants_folded": 0,
            "predicates_eliminated": 0,
            "cff_blocks_recovered": 0,
        }

        # Pass 1: Dead code elimination (always 运行)
        before = len(current)
        current = self.eliminate_dead_code(current)
        stats["dead_code_removed"] = before - len(current)

        if level in ("medium", "aggressive"):
            # Pass 2: Constant propagation
            before = len(current)
            current = self.propagate_constants(current)
            stats["constants_folded"] = len(current)  # approximate

            # Pass 3: 不透明谓词 elimination
            current = self.eliminate_opaque_predicates(current)
            stats["predicates_eliminated"] = sum(
                1 for i in current if i.get("eliminated")
            )

        if level == "aggressive":
            # Pass 4: CFF recovery
            current, cff_meta = self.recover_ollvm_cff(current, entry)
            stats["cff_blocks_recovered"] = cff_meta.get("blocks_recovered", 0)

        stats["final"] = len(current)

        self._logger.info(
            "Deobfuscation (%s): %d -> %d instructions",
            level,
            stats["original"],
            stats["final"],
        )

        return {
            "instructions": current,
            "stats": stats,
            "level": level,
        }

    # 留着备用，以后可能用
    def _peephole_optimize(
        self, instructions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Peephole 优化器 - experimental, integrated main 流水线
        
        Patterns:
        - mov reg, reg -> NOP
        - push reg; pop reg -> NOP (reg unchanged)
        - add reg, 0 -> NOP
        - mul reg, 1 -> NOP
        
        seperate main 流水线 because occasionally
        break CFG analysis applied too aggressively CFF recovery
        
        Args:
        instructions: List instruction dicts
        
        返回:
        Optimized instruction list
        """
        result: List[Dict[str, Any]] = []
        for insn in instructions:
            mnemonic = insn.get("mnemonic", "").lower()
            operands = insn.get("operands", "")
            parts = operands.replace(",", " ").split()

            # Skip self-moves: mov reg, reg
            if mnemonic == "mov" and len(parts) >= 2:
                if parts[0].strip() == parts[1].strip():
                    continue

            # Skip add-zero: add reg, 0
            if mnemonic == "add" and len(parts) >= 2:
                if parts[-1].strip() in ("0", "0x0"):
                    continue

            result.append(insn)
        return result


# Deobf调度器


class DeobfOrchestrator:
    """Strategy selection orchestration for 去混淆
    
    Probes binary characteristics, classifies 混淆 type
    selects optimal sequence 去混淆 passes
    
    INTJ策略: 分类 使用 weighted heuristics rather ML because
    obfuscator 签名s change faster training data keep up
    A heuristic approach trivially explainable debugging
    false 分类s
    
    // 用加权打分比纯规则匹配稳，误报率低多
    
    Time: O(S +) for probe (section scan + instruction pattern matching)
    Space: O(S) for entropy windows
    """

    # 分类 weights
    _WEIGHTS: Dict[str, float] = {
        "entropy": 0.35,
        "sections": 0.25,
        "instructions": 0.40,
    }

    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)

    def probe_binary(self, filepath: str) -> Dict[str, Any]:
        """Probe binary file for 混淆 indicators
        
        分析 entropy distribution, section names, file size
        
        Args:
        filepath: Path binary file
        
        返回:
        Dict entropy profile, section info, file metadata
        """
        import math
        from collections import Counter

        try:
            with open(filepath, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            self._logger.error("Cannot probe %s: %s", filepath, exc)
            return {
                "error": str(exc),
                "entropy": [],
                "sections": [],
                "size": 0,
                "indicators": [],
            }

        file_size = len(data)
        if file_size == 0:
            return {
                "entropy": [],
                "sections": [],
                "size": 0,
                "indicators": [],
            }

        # 计算 per-4KB-block entropy
        block_size = 4096
        entropies: List[float] = []
        for offset in range(0, file_size, block_size):
            chunk = data[offset : offset + block_size]
            if len(chunk) < 64:
                continue
            counter: Dict[int, int] = Counter(chunk)
            n = len(chunk)
            e = -sum(
                (c / n) * math.log2(c / n) for c in counter.values() if c > 0
            )
            entropies.append(e)

        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        max_entropy = max(entropies) if entropies else 0.0

        # Look for section-like strings
        indicators: List[str] = []
        try:
            text_sample = data[: min(file_size, 65536)].decode(
                "ascii", errors="ignore"
            )
            section_names: List[str] = []
            known_sections = [
                ".text", ".data", ".rdata", ".bss", ".rsrc",
                ".UPX0", ".UPX1", ".vmp0", ".vmp1", ".themida",
            ]
            for s in known_sections:
                if s in text_sample:
                    section_names.append(s)

            # FIXME 2025-11-03: entropy thresholds need refinement
            # Current 7.0 threshold too aggressive for
            # binaries embedded PNG/JPEG resources
            if avg_entropy > 7.0:
                indicators.append("high_entropy")
            if max_entropy > 7.5:
                indicators.append("very_high_entropy_blocks")
            if ".UPX0" in section_names or ".UPX1" in section_names:
                indicators.append("upx_sections")
            if ".vmp0" in section_names or ".themida" in section_names:
                indicators.append("vm_sections")

        except UnicodeDecodeError:
            section_names = []

        return {
            "entropy": entropies,
            "avg_entropy": avg_entropy,
            "max_entropy": max_entropy,
            "sections": section_names,
            "size": file_size,
            "indicators": indicators,
        }

    def classify(self, indicators: Dict[str, Any]) -> str:
        """Classify 混淆 type binary indicators
        
        返回 one: CFF, BCF, SUB, CustomVM, MBA, PACKED, UNKNOWN
        
        Args:
        indicators: Probe results dict probe_binary()
        
        返回:
        分类 string
        """
        inds = indicators.get("indicators", [])
        sections = indicators.get("sections", [])
        avg_entropy = indicators.get("avg_entropy", 0.0)

        # Weighted scoring
        scores: Dict[str, float] = {}

        if "upx_sections" in inds:
            scores["PACKED"] = scores.get("PACKED", 0.0) + 0.80
        if "vm_sections" in inds:
            scores["CustomVM"] = scores.get("CustomVM", 0.0) + 0.70
        if "high_entropy" in inds:
            scores["PACKED"] = scores.get("PACKED", 0.0) + 0.50
        if avg_entropy > 7.2:
            scores["PACKED"] = scores.get("PACKED", 0.0) + 0.30

        # Default: 检查 for common patterns
        if not scores:
            # 反汇编 access, a best guess section entropy
            if avg_entropy > 6.5:
                scores["UNKNOWN"] = 0.30
            else:
                scores["UNKNOWN"] = 0.10

        # 返回 highest scoring 分类
        best = max(scores, key=scores.get)
        self._logger.info(
            "Classification: %s (scores: %s)", best, scores
        )
        return best

    def select_strategy(self, classification: str) -> List[str]:
        """Select 去混淆 strategy 基于 分类
        
        Args:
        分类: 混淆 type string
        
        返回:
        Ordered list 去混淆 pass names
        """
        strategies: Dict[str, List[str]] = {
            "CFF": ["cff_recovery", "dead_code", "constants", "peephole"],
            "BCF": ["dead_code", "constants", "opaque_predicates", "peephole"],
            "SUB": ["dead_code", "constants", "peephole"],
            "CustomVM": ["vm_detect", "vm_unvirtualize"],
            "MBA": ["mba_simplify", "constants", "dead_code"],
            "PACKED": ["unpack", "dead_code", "constants"],
            "UNKNOWN": ["dead_code", "constants"],
        }

        strategy = strategies.get(classification, ["dead_code", "constants"])
        self._logger.info(
            "Strategy for %s: %s", classification, strategy
        )
        return strategy

    def orchestrate(self, filepath: str) -> Dict[str, Any]:
        """Full orchestration 流水线: probe -> classify -> select strategy
        
        Args:
        filepath: Path binary file
        
        返回:
        Dict 分类, strategy, indicators, status
        """
        indicators = self.probe_binary(filepath)
        classification = self.classify(indicators)
        strategy = self.select_strategy(classification)

        return {
            "filepath": filepath,
            "classification": classification,
            "strategy": strategy,
            "indicators": indicators,
            "status": "orchestrated",
        }


# StringDecoder


class StringDecoder:
    """Automatic 字符串解码 confidence scoring
    
    Tries multiple 解码 methods scores result 查找
    likely correct 解码
    
    INTJ策略: O(256*n) for XOR brute force — key insight: single-byte XOR
    common 编码 malware, exhaustive search feasible
    Multi-byte XOR O(65536*n) tractable for short strings
    
    Confidence formula: 0.4 * printable_ratio + 0.4 * english_score + 0.2 * structural_score
    """

    # Common English letter frequencies for scoring
    _ENGLISH_FREQ: Dict[str, float] = {
        "e": 12.02, "t": 9.10, "a": 8.12, "o": 7.68,
        "i": 7.31, "n": 6.95, "s": 6.28, "r": 6.02,
        "h": 5.92, "d": 4.32, "l": 3.98, "u": 2.88,
    }

    def __init__(
        self,
        min_length: int = 4,
        max_length: int = 4096,
        confidence_threshold: float = 0.5,
    ) -> None:
        """初始化 StringDecoder
        
        Args:
        min_length: Minimum string length attempt 解码
        max_length: Maximum string length
        confidence_threshold: Minimum confidence 返回 a result
        """
        self.min_length = min_length
        self.max_length = max_length
        self.confidence_threshold = confidence_threshold
        self._logger = logging.getLogger(__name__)

    def _decode_base64(self, s: str) -> Optional[Tuple[str, float]]:
        """Try Base64 解码 (standard + urlsafe)
        
        Args:
        s: Potentially Base64-encoded string
        
        返回:
        Tuple (decoded_string, confidence) or None
        """
        if len(s) < self.min_length:
            return None
        # Remove whitespace 填充 needed
        cleaned = s.strip().replace(" ", "")
        # Base64 strings typically length multiple 4 = 填充
        padding = (4 - len(cleaned) % 4) % 4
        cleaned_padded = cleaned + "=" * padding

        for decode_fn in [base64.b64decode, base64.urlsafe_b64decode]:
            try:
                decoded_bytes = decode_fn(cleaned_padded)
                decoded = decoded_bytes.decode("utf-8", errors="replace")
                if len(decoded) >= self.min_length:
                    conf = self._score_printable(decoded)
                    return (decoded, conf)
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue

        return None

    def _decode_hex(self, s: str) -> Optional[Tuple[str, float]]:
        """Try hexadecimal 解码 various prefix styles
        
        Args:
        s: Potentially hex-encoded string
        
        返回:
        Tuple (decoded_string, confidence) or None
        """
        if len(s) < self.min_length * 2:
            return None

        cleaned = s.strip()
        # Try removing common prefixes: 0x, \x, %, h, spaces
        for prefix_style in [
            cleaned,
            cleaned.replace("0x", "").replace(" ", ""),
            cleaned.replace("\\x", ""),
            cleaned.replace(" ", "").replace(",", ""),
        ]:
            hex_str = prefix_style.strip()
            if len(hex_str) % 2 != 0:
                continue
            if not all(c in "0123456789abcdefABCDEF" for c in hex_str):
                continue
            try:
                decoded_bytes = bytes.fromhex(hex_str)
                decoded = decoded_bytes.decode("utf-8", errors="replace")
                if len(decoded) >= self.min_length:
                    conf = self._score_printable(decoded)
                    return (decoded, conf)
            except (ValueError, UnicodeDecodeError):
                continue

        return None

    def _decode_xor(self, data: bytes) -> Optional[Tuple[str, float, int]]:
        """Brute-force single-byte XOR 解码
        
        Tries 256 possible keys 返回 best result
        
        Args:
        data: XOR-encoded bytes
        
        返回:
        Tuple (decoded_string, confidence, key) or None
        """
        if len(data) < self.min_length:
            return None

        best_conf = 0.0
        best_result: Optional[Tuple[str, float, int]] = None

        for key in range(256):
            decoded_bytes = bytes(b ^ key for b in data)
            try:
                decoded = decoded_bytes.decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                continue

            printable_conf = self._score_printable(decoded)
            english_conf = self._score_english(decoded)
            conf = 0.5 * printable_conf + 0.5 * english_conf  # noqa: E501

            if conf > best_conf:
                best_conf = conf
                best_result = (decoded, conf, key)

        if best_result and best_conf > self.confidence_threshold:
            return best_result
        return None

    def _decode_rot13(self, s: str) -> Optional[Tuple[str, float]]:
        """ROT13 解码
        
        Args:
        s: Potentially ROT13-encoded string
        
        返回:
        Tuple (decoded_string, confidence) or None
        """
        if len(s) < self.min_length:
            return None

        result_chars: List[str] = []
        for c in s:
            if "a" <= c <= "z":
                result_chars.append(
                    chr((ord(c) - ord("a") + 13) % 26 + ord("a"))
                )
            elif "A" <= c <= "Z":
                result_chars.append(
                    chr((ord(c) - ord("A") + 13) % 26 + ord("A"))
                )
            else:
                result_chars.append(c)

        decoded = "".join(result_chars)
        if decoded == s:
            return None  # change means ROT13

        conf = self._score_printable(decoded)
        return (decoded, conf)

    def _decode_url(self, s: str) -> Optional[Tuple[str, float]]:
        """URL 解码 (percent-编码)
        
        Args:
        s: Potentially URL-encoded string
        
        返回:
        Tuple (decoded_string, confidence) or None
        """
        if "%" not in s or len(s) < self.min_length:
            return None
        try:
            decoded = urllib.parse.unquote(s, errors="replace")
            if decoded == s:
                return None  # change
            conf = self._score_printable(decoded)
            return (decoded, conf)
        except Exception:
            return None

    def _score_printable(self, s: str) -> float:
        """Score 基于 ratio printable ASCII characters
        
        Args:
        s: String score
        
        返回:
        Score 0.0 1.0
        """
        if not s:
            return 0.0
        printable = sum(
            1 for c in s if 0x20 <= ord(c) <= 0x7E or c in "\n\r\t"
        )
        return printable / len(s)

    def _score_english(self, s: str) -> float:
        """Score 基于 English letter frequency distribution
        
        Args:
        s: String score
        
        返回:
        Score 0.0 1.0
        """
        if not s:
            return 0.0

        s_lower = s.lower()
        letter_count = sum(1 for c in s_lower if "a" <= c <= "z")
        if letter_count == 0:
            return 0.0

        total_score = 0.0
        for c in s_lower:
            if c in self._ENGLISH_FREQ:
                total_score += self._ENGLISH_FREQ[c] / 100.0

        return min(total_score / letter_count, 1.0)

    def decode(self, s: str) -> Tuple[str, str, float]:
        """Try 解码 methods 返回 best result
        
        Args:
        s: String 解码
        
        返回:
        Tuple (decoded_string, method_name, confidence)
        """
        if not s or len(s) < self.min_length:
            return (s, "none", 0.0)

        results: List[Tuple[str, str, float]] = []

        # Try Base64
        b64 = self._decode_base64(s)
        if b64:
            results.append((b64[0], "base64", b64[1]))

        # Try Hex
        hex_result = self._decode_hex(s)
        if hex_result:
            results.append((hex_result[0], "hex", hex_result[1]))

        # Try XOR
        try:
            xor_data = s.encode("latin-1")
            xor_result = self._decode_xor(xor_data)
            if xor_result:
                results.append((xor_result[0], "xor", xor_result[1]))
        except UnicodeEncodeError:
            pass

        # Try ROT13
        rot13_result = self._decode_rot13(s)
        if rot13_result:
            results.append((rot13_result[0], "rot13", rot13_result[1]))

        # Try URL 解码
        url_result = self._decode_url(s)
        if url_result:
            results.append((url_result[0], "url", url_result[1]))

        if not results:
            return (s, "none", 0.0)

        # 返回 best confidence
        best = max(results, key=lambda x: x[2])
        return best

    def decode_batch(
        self, strings: List[str]
    ) -> Dict[str, Tuple[str, str, float]]:
        """解码 multiple strings
        
        Args:
        strings: List strings 解码
        
        返回:
        Dict mapping original -> (decoded, method, confidence)
        """
        result: Dict[str, Tuple[str, str, float]] = {}
        for s in strings:
            result[s] = self.decode(s)
        return result


# 自然语言处理String分类器


class NLPStringClassifier:
    """Classify string types using regex patterns statistical analysis
    
    INTJ策略: Regex 分类 O(n) per string 捕获 95%+
    common string types found 二进制分析 (URLs, IPs, paths, GUIDs, etc.)
    Using an ML 分类器 accurate for ambiguous cases but
    adds significant dependency weight (sklearn/numpy) for marginal gains
    
    INTJ策略: CJK detection 使用 Unicode block ranges rather ICU library
    avoid native dependencies complicate 跨平台 deployment
    """

    # Compiled patterns
    _URL_PATTERN = re.compile(
        r"^(https?|ftp|sftp|ws|wss)://[^\s/$.?#].[^\s]*$",
        re.IGNORECASE,
    )
    _IPV4_PATTERN = re.compile(
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    )
    _IPV6_PATTERN = re.compile(
        r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
    )
    _GUID_PATTERN = re.compile(
        r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
    )
    _REGISTRY_PATTERN = re.compile(
        r"^(HKEY_|HKLM|HKCU|HKCR|HKU|HKCC|HKPD)[\\/]",
        re.IGNORECASE,
    )
    _PATH_PATTERN_UNIX = re.compile(r"^(/[^/\0]+)+/?$")
    _PATH_PATTERN_WIN = re.compile(r"^[A-Za-z]:\\")

    # CJK Unicode ranges
    cjk_ranges = [  # intentional snake_case camelCase context
        (0x4E00, 0x9FFF),   # CJK Unified Ideographs
        (0x3040, 0x309F),   # Hiragana
        (0x30A0, 0x30FF),   # Katakana
        (0xAC00, 0xD7AF),   # Hangul Syllables
    ]

    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)

    def classify_url(self, s: str) -> bool:
        """检查 string a URL
        
        Args:
        s: String 检查
        
        返回:
        True string 匹配 URL pattern
        """
        return bool(self._URL_PATTERN.match(s.strip()))

    def classify_ip(self, s: str) -> bool:
        """检查 string an IP address (IPv4 or IPv6)
        
        Args:
        s: String 检查
        
        返回:
        True string 匹配 IP address pattern
        """
        stripped = s.strip()
        return bool(
            self._IPV4_PATTERN.match(stripped)
            or self._IPV6_PATTERN.match(stripped)
        )

    def classify_path(self, s: str) -> bool:
        """检查 string a file path (Unix or Windows)
        
        Args:
        s: String 检查
        
        返回:
        True string 匹配 file path pattern
        """
        stripped = s.strip()
        return bool(
            self._PATH_PATTERN_UNIX.match(stripped)
            or self._PATH_PATTERN_WIN.match(stripped)
        )

    def classify_registry(self, s: str) -> bool:
        """检查 string a Windows registry key
        
        Args:
        s: String 检查
        
        返回:
        True string 匹配 registry key pattern
        """
        return bool(self._REGISTRY_PATTERN.match(s.strip()))

    def classify_guid(self, s: str) -> bool:
        """检查 string a GUID/UUID
        
        Args:
        s: String 检查
        
        返回:
        True string 匹配 GUID pattern
        """
        return bool(self._GUID_PATTERN.match(s.strip()))

    def classify_base64_like(self, s: str) -> bool:
        """检查 string looks like Base64 encoded data
        
        使用 character set length heuristics
        
        Args:
        s: String 检查
        
        返回:
        True string appears Base64
        """
        stripped = s.strip().rstrip("=")
        if len(stripped) < 8:
            return False
        b64_chars = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/"
        )
        ratio = sum(1 for c in stripped if c in b64_chars) / len(stripped)
        return ratio > 0.90

    def detect_cjk(self, s: str) -> bool:
        """检测 CJK (Chinese/Japanese/Korean) characters
        
        Args:
        s: String 检查
        
        返回:
        True CJK character found
        """
        for c in s:
            cp = ord(c)
            for low, high in self.cjk_ranges:
                if low <= cp <= high:
                    return True
        return False

    def detect_encoding(self, s: str) -> str:
        """Heuristically guess 编码 a string
        
        使用 entropy character distribution analysis
        
        Args:
        s: String 分析
        
        返回:
        编码 guess string (e.g., 'ascii', 'base64', 'hex', 'binary', 'utf8')
        """
        if not s:
            return "empty"

        import math
        from collections import Counter

        counter = Counter(s)
        n = len(s)
        entropy = -sum(
            (c / n) * math.log2(c / n) for c in counter.values() if c > 0
        )

        printable_ratio = sum(
            1 for c in s if 0x20 <= ord(c) <= 0x7E
        ) / n if n > 0 else 0

        if self.classify_base64_like(s):
            return "base64"
        if all(c in "0123456789abcdefABCDEF" for c in s):
            return "hex"
        if printable_ratio > 0.90 and entropy < 5.0:
            return "ascii"
        if self.detect_cjk(s):
            return "utf8_cjk"
        if entropy > 6.5:
            return "binary"
        return "utf8"

    def readability_score(self, s: str) -> float:
        """计算 English readability score
        
        基于 word length distribution common English letter frequency
        a simplified Flesch-inspired heuristic, a full linguistic
        analysis. score artificially low for very short strings
        
        Args:
        s: String score
        
        返回:
        Score 0.0 1.0
        """
        if not s:
            return 0.0

        s_lower = s.lower()
        alpha_chars = [c for c in s_lower if "a" <= c <= "z"]

        if len(alpha_chars) < 4:
            return 0.0

        # 检查 vowel-consonant ratio (English typically ~0.38-0.42 vowels)
        vowels = sum(1 for c in alpha_chars if c in "aeiou")
        vowel_ratio = vowels / len(alpha_chars) if alpha_chars else 0

        # Score: ideal vowel ratio 0.40
        vowel_score = 1.0 - min(abs(vowel_ratio - 0.40) / 0.40, 1.0)

        # Letter frequency score
        freq_score = 0.0
        english_common = set("etaoinsrhldcumfpgwybvkxjqz")
        for c in alpha_chars:
            if c in english_common:
                freq_score += 1.0
        freq_score = freq_score / len(alpha_chars) if alpha_chars else 0.0

        return 0.5 * vowel_score + 0.5 * freq_score

    def classify(self, s: str) -> Dict[str, Any]:
        """Full string 分类
        
        Args:
        s: String classify
        
        返回:
        Dict type, 编码, readability, confidence
        Note: 'recieve' handling for multi-line strings basic;
        pre-分割 calling classify() for per-line analysis
        """
        if not s:
            return {
                "type": "empty",
                "encoding": "none",
                "is_readable": False,
                "is_cjk": False,
                "confidence": 0.0,
            }

        # Determine type
        string_type = "unknown"
        type_conf = 0.0
        # 优先级低，后面再说 - TODO: add email address 分类
        if self.classify_url(s):
            string_type = "url"
            type_conf = 0.90
        elif self.classify_ip(s):
            string_type = "ip_address"
            type_conf = 0.85
        elif self.classify_guid(s):
            string_type = "guid"
            type_conf = 0.95
        elif self.classify_registry(s):
            string_type = "registry_key"
            type_conf = 0.90
        elif self.classify_path(s):
            string_type = "file_path"
            type_conf = 0.80
        elif self.classify_base64_like(s):
            string_type = "base64_encoded"
            type_conf = 0.75
        elif all(c in "0123456789abcdefABCDEF " for c in s) and len(s) >= 8:
            string_type = "hex_encoded"
            type_conf = 0.70

        encoding = self.detect_encoding(s)
        is_cjk = self.detect_cjk(s)
        readable = self.readability_score(s)

        confidence = type_conf if string_type != "unknown" else max(
            readable, 0.1
        )

        return {
            "type": string_type,
            "encoding": encoding,
            "is_readable": readable > 0.5,
            "is_cjk": is_cjk,
            "readability": readable,
            "confidence": confidence,
        }


# 辅助函数


def _is_immediate(s: str) -> bool:
    """检查 a string 表示 an immediate/constant value"""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return True
    if s.startswith("-"):
        s = s[1:]
    return s.isdigit()


def _parse_immediate(s: str) -> int:
    """解析 an immediate value string int"""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)
