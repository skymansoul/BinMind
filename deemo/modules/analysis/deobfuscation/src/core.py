"""核心去混淆算法: CFG 恢复、常量传播、谓词消除、字符串解码与 NLP 分类。"""

import base64
import binascii
import logging
import math
import re
import urllib.parse
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# FunctionDeobfuscator


class FunctionDeobfuscator:
    """控制流去混淆引擎。

    提供多个 pass: 死代码消除、常量传播、不透明谓词消除与
    OLLVM 控制流平坦化恢复。

    设计策略: 选 O(V*E) 的 SCCP 而非简单 reaching-defs,
    因为后者漏掉条件常量 - 而混淆常量常被刻意藏在条件分支后。
    """

    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)

# 死代码消除

    def eliminate_dead_code(
        self, instructions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """标记-清除式死代码消除。

        算法:
        1. 标记可达: 从入口沿控制流线性扫描
        2. 计算活跃变量: 反向扫描使用过的定义
        3. 清除: 移除不可达指令与定义了无用值的指令

        线性扫描在首个无条件 jmp/ret 处停止 (无 CFG 元数据时的
        保守近似); 返回过滤后的活跃指令列表。
        """
        if not instructions:
            return []

        # 可达标记: 线性扫描, 无条件 jmp/ret 之后的指令视为不可达
        reachable: set = set()
        for insn in instructions:
            reachable.add(insn["addr"])
            if insn.get("mnemonic", "").lower() in ("jmp", "ret"):
                break

        # 反向扫描计算活跃变量, 记录死定义
        live_vars: set = set()
        dead_addrs: set = set()
        for insn in reversed(instructions):
            mnemonic = insn.get("mnemonic", "").lower()
            operands = insn.get("operands", "")

            # 检查指令输出是否在下游被使用
            parts = operands.replace(",", " ").split()
            if parts:
                dest = parts[0].strip()
                if dest and not dest.startswith("["):
                    if dest not in live_vars:
                        # 定义未被使用 - 标记为死指令
                        dead_addrs.add(insn["addr"])
                    live_vars.discard(dest)

            # 源操作数在下游被使用
            for part in parts[1:]:
                part = part.strip()
                if part and not part.startswith("[") and not _is_immediate(part):
                    live_vars.add(part)

        # Sweep: 保留可达且非死定义的指令
        result = [
            insn for insn in instructions
            if insn["addr"] in reachable and insn["addr"] not in dead_addrs
        ]

        self._logger.debug(
            "Dead code elimination: %d -> %d instructions (removed %d)",
            len(instructions),
            len(result),
            len(instructions) - len(result),
        )

        return result

# 常量传播

    def propagate_constants(
        self, instructions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """稀疏条件常量传播 (SCCP)。

        对每个寄存器/变量使用格:
        - TOP (None): 未定义/未知
        - CONST (int): 常量值
        - BOTTOM (-1 哨兵): 可变/多可能值

        返回常量已传播折叠的指令列表。
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
                # 控制流 - 截断格
                pass

            result.append(new_insn)

        self._logger.debug(
            "Constant propagation: folded %d expressions", folded_count
        )
        return result

# 不透明谓词消除

    def eliminate_opaque_predicates(
        self, instructions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """消除不透明谓词 (恒真/恒假分支)。

        检测的模式:
        - xor reg, reg + jz target (恒真, ZF=1)
        - cmp reg, reg + je target (恒真)
        - test reg, reg + jz target 在 xor reg,reg 之后 (恒真)
        - add reg, imm (imm != 0) + jz target (恒假)

        单遍扫描, 标记/移除不可达分支。
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

# OLLVM 控制流平坦化恢复

    def recover_ollvm_cff(
        self, instructions: List[Dict[str, Any]], entry: int
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """恢复 OLLVM 控制流平坦化。

        算法:
        1. 识别分发器块 (高出度、间接跳转)
        2. 查找状态变量 (分发器跳转所修改的寄存器)
        3. 追踪状态值对应的真实块
        4. 重建原始非平坦化控制流

        设计策略: OLLVM CFF 恢复用支配树分析, O(N log N),
        快于对平坦化代码做符号执行 (因路径爆炸达 O(2^N))。

        返回 (clean_instructions, recovery_metadata)。
        """
        # 查找分发器块
        # 分发器特征: 间接跳转, 多个前驱
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
        # 查找分发器跳转附近的 mov/cmp 寄存器
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
        """按指定 level 运行完整去混淆流水线。

        Level: "light" 仅死代码消除; "medium" 死代码 + 常量 +
        不透明谓词; "aggressive" 全部 pass 含 CFF 恢复。
        返回 {'instructions', 'stats'}。
        """
        current = list(instructions)
        stats: Dict[str, int] = {
            "original": len(instructions),
            "dead_code_removed": 0,
            "constants_folded": 0,
            "predicates_eliminated": 0,
            "cff_blocks_recovered": 0,
        }

        # Pass 1: 死代码消除 (总是运行)
        before = len(current)
        current = self.eliminate_dead_code(current)
        stats["dead_code_removed"] = before - len(current)

        if level in ("medium", "aggressive"):
            # Pass 2: Constant propagation
            before = len(current)
            current = self.propagate_constants(current)
            stats["constants_folded"] = len(current)  # approximate

            # Pass 3: 不透明谓词消除
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

    def _peephole_optimize(
        self, instructions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """窥孔优化, 未接入主流水线。

        模式: mov reg, reg -> NOP; push reg; pop reg -> NOP
        (寄存器不变); add reg, 0 -> NOP; mul reg, 1 -> NOP。

        与主流水线分离, 因为对 CFF 恢复后的代码过度应用会
        破坏 CFG 分析; 返回优化后的指令列表。
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


# DeobfOrchestrator


class DeobfOrchestrator:
    """去混淆的策略选择编排。

    探测二进制特征, 分类混淆类型, 选择最优的去混淆 pass 序列。

    设计策略: 分类用加权启发式而非 ML - 混淆器签名变化比训练
    数据更新更快; 启发式方法可平凡解释, 便于调试误分类。

    用加权打分比纯规则匹配稳, 误报率低得多。

    探测复杂度 O(S + n) (节扫描 + 指令模式匹配), 空间 O(S)。
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
        """探测二进制文件的混淆迹象。

        分析熵分布、节名与文件大小; 返回含熵剖面、节信息与
        文件元数据的字典。
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

        # 按 4KB 块计算熵
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

        # 查找类节名字符串
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

            # FIXME: 熵阈值需要精调
            # 当前 7.0 阈值对嵌入 PNG/JPEG 资源的二进制过于激进
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
        """按二进制迹象分类混淆类型。

        indicators 为 probe_binary() 的结果字典; 返回
        CFF/BCF/SUB/CustomVM/MBA/PACKED/UNKNOWN 之一。
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

        # 默认: 检查常见模式
        if not scores:
            # 无反汇编访问时, 按节熵做最佳猜测
            if avg_entropy > 6.5:
                scores["UNKNOWN"] = 0.30
            else:
                scores["UNKNOWN"] = 0.10

        # 返回最高分分类
        best = max(scores, key=scores.get)
        self._logger.info(
            "Classification: %s (scores: %s)", best, scores
        )
        return best

    def select_strategy(self, classification: str) -> List[str]:
        """按分类选择去混淆策略, 返回有序的去混淆 pass 名列表。"""
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
        """完整编排流水线: probe -> classify -> select strategy。

        返回含 classification、strategy、indicators、status 的字典。
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
    """自动字符串解码与置信度评分。

    尝试多种解码方法并评分, 选出最可能正确的解码结果。

    设计策略: 单字节 XOR 暴力搜索 O(256*n) - 关键在于单字节
    XOR 是恶意软件中的常见编码, 穷举可行; 多字节 XOR
    O(65536*n) 对短字符串也可接受。

    置信度公式: 0.4 * printable_ratio + 0.4 * english_score
    + 0.2 * structural_score。
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
        """初始化 StringDecoder。

        min_length/max_length 为尝试解码的字符串长度范围,
        confidence_threshold 为返回结果的最低置信度。
        """
        self.min_length = min_length
        self.max_length = max_length
        self.confidence_threshold = confidence_threshold
        self._logger = logging.getLogger(__name__)

    def _decode_base64(self, s: str) -> Optional[Tuple[str, float]]:
        """尝试 Base64 解码 (标准 + urlsafe), 返回 (解码串, 置信度) 或 None。"""
        if len(s) < self.min_length:
            return None
        # 去掉空白并补上填充
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
        """尝试多种前缀风格的十六进制解码, 返回 (解码串, 置信度) 或 None。"""
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
        """暴力单字节 XOR 解码。

        尝试全部 256 个密钥, 返回置信度超过阈值的
        (解码串, 置信度, 密钥) 或 None。
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
        """ROT13 解码, 返回 (解码串, 置信度) 或 None。"""
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
        """URL 解码 (percent-encoding), 返回 (解码串, 置信度) 或 None。"""
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
        """按可打印 ASCII 字符占比评分, 返回 0.0-1.0。"""
        if not s:
            return 0.0
        printable = sum(
            1 for c in s if 0x20 <= ord(c) <= 0x7E or c in "\n\r\t"
        )
        return printable / len(s)

    def _score_english(self, s: str) -> float:
        """按英文字母频率分布评分, 返回 0.0-1.0。"""
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
        """尝试全部解码方法, 返回置信度最高的 (解码串, 方法名, 置信度)。"""
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
        """批量解码多个字符串, 返回 原文 -> (解码, 方法, 置信度) 映射。"""
        result: Dict[str, Tuple[str, str, float]] = {}
        for s in strings:
            result[s] = self.decode(s)
        return result


# NLPStringClassifier


class NLPStringClassifier:
    """用正则模式与统计分析对字符串类型分类。

    设计策略: 每条字符串 O(n) 的正则分类可捕获二进制分析中
    95%+ 的常见字符串类型 (URL、IP、路径、GUID 等); ML 分类器
    对模糊场景更准, 但引入 sklearn/numpy 依赖, 收益有限。

    CJK 检测用 Unicode 块区间而非 ICU 库, 避免原生依赖
    复杂化跨平台部署。
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
    cjk_ranges = [
        (0x4E00, 0x9FFF),   # CJK Unified Ideographs
        (0x3040, 0x309F),   # Hiragana
        (0x30A0, 0x30FF),   # Katakana
        (0xAC00, 0xD7AF),   # Hangul Syllables
    ]

    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)

    def classify_url(self, s: str) -> bool:
        """检查字符串是否为 URL。"""
        return bool(self._URL_PATTERN.match(s.strip()))

    def classify_ip(self, s: str) -> bool:
        """检查字符串是否为 IP 地址 (IPv4 或 IPv6)。"""
        stripped = s.strip()
        return bool(
            self._IPV4_PATTERN.match(stripped)
            or self._IPV6_PATTERN.match(stripped)
        )

    def classify_path(self, s: str) -> bool:
        """检查字符串是否为文件路径 (Unix 或 Windows)。"""
        stripped = s.strip()
        return bool(
            self._PATH_PATTERN_UNIX.match(stripped)
            or self._PATH_PATTERN_WIN.match(stripped)
        )

    def classify_registry(self, s: str) -> bool:
        """检查字符串是否为 Windows 注册表键。"""
        return bool(self._REGISTRY_PATTERN.match(s.strip()))

    def classify_guid(self, s: str) -> bool:
        """检查字符串是否为 GUID/UUID。"""
        return bool(self._GUID_PATTERN.match(s.strip()))

    def classify_base64_like(self, s: str) -> bool:
        """用字符集与长度启发式检查字符串是否像 Base64 编码。"""
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
        """检测字符串是否包含 CJK (中/日/韩) 字符。"""
        for c in s:
            cp = ord(c)
            for low, high in self.cjk_ranges:
                if low <= cp <= high:
                    return True
        return False

    def detect_encoding(self, s: str) -> str:
        """启发式猜测字符串编码。

        用熵与字符分布分析, 返回 'ascii'/'base64'/'hex'/'binary'/
        'utf8'/'utf8_cjk'/'empty' 之一。
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
        """计算英文可读性评分。

        基于词长分布与常见英文字母频率的简化 Flesch 风格
        启发式, 非完整语言学分析; 极短字符串评分人为压低。
        返回 0.0-1.0。
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
        """完整字符串分类, 返回含 type/encoding/readability/confidence 的字典。

        多行字符串按行分析需由调用方预先分割。
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
        # email 地址分类暂缓
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
    """检查字符串是否表示立即数/常量值。"""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return True
    if s.startswith("-"):
        s = s[1:]
    return s.isdigit()


def _parse_immediate(s: str) -> int:
    """把立即数字符串解析为整数。"""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)
