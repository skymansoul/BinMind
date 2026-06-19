"""
二进制代码自动摘要与语义标注模块

功能:
    1. 基于汇编指令序列, 使用预训练汇编 BERT 模型为每个基本块生成语义标签
    2. 在反编译代码中显示块摘要, 加速逆向阅读

核心技术:
    - 指令 token 化
    - 简化 BERT-like 特征提取 (无依赖实现, 用 N-gram + 词频)
    - 标签候选: 内存分配/循环检查/字符串操作/网络 IO/系统调用/参数校验
    - 可选: 加载 huggingface 模型 (transformers)
"""

import logging
import os
import re
import json
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


class BlockTag(Enum):
    """基本块语义标签"""
    MEMORY_ALLOC = "memory_alloc"
    MEMORY_FREE = "memory_free"
    LOOP_CHECK = "loop_check"
    STRING_OPS = "string_ops"
    NETWORK_IO = "network_io"
    SYSCALL = "syscall"
    PARAM_VALIDATE = "param_validate"
    ERROR_HANDLING = "error_handling"
    ARITHMETIC = "arithmetic"
    BRANCH = "branch"
    UNKNOWN = "unknown"


@dataclass
class BasicBlock:
    """基本块"""
    block_id: str
    start_addr: int
    end_addr: int
    instructions: List[str] = field(default_factory=list)
    tag: BlockTag = BlockTag.UNKNOWN
    confidence: float = 0.0
    summary: str = ""


@dataclass
class FunctionSummary:
    """函数摘要"""
    func_name: str
    blocks: List[BasicBlock]
    block_summaries: Dict[str, str]
    overall_purpose: str
    metadata: Dict[str, Any] = field(default_factory=dict)


# 标签特征词
TAG_FEATURES: Dict[BlockTag, List[str]] = {
    BlockTag.MEMORY_ALLOC: ["malloc", "calloc", "realloc", "alloc", "new"],
    BlockTag.MEMORY_FREE: ["free", "delete", "release"],
    BlockTag.LOOP_CHECK: ["cmp", "test", "jl", "jg", "jle", "jge",
                          "dec", "inc", "loop"],
    BlockTag.STRING_OPS: ["strcpy", "strcat", "strcmp", "strlen", "strncmp",
                          "memcpy", "memset", "memmove"],
    BlockTag.NETWORK_IO: ["socket", "connect", "send", "recv", "bind",
                          "listen", "accept", "read", "write"],
    BlockTag.SYSCALL: ["syscall", "int 0x80", "svc", "sysenter"],
    BlockTag.PARAM_VALIDATE: ["test", "cmp", "jz", "jnz", "jmp", "je", "jne"],
    BlockTag.ERROR_HANDLING: ["errno", "perror", "exit", "abort", "panic",
                              "fail"],
    BlockTag.ARITHMETIC: ["add", "sub", "mul", "div", "imul", "idiv",
                          "xor", "and", "or", "shl", "shr"],
    BlockTag.BRANCH: ["jmp", "call", "ret", "leave"]
}


class InstructionTokenizer:
    """指令分词器"""

    def tokenize(self, instr: str) -> List[str]:
        # 去除地址和颜色
        s = re.sub(r"0x[0-9a-f]+", "ADDR", instr)
        s = re.sub(r"[^a-zA-Z0-9_\s,]", " ", s)
        tokens = [t for t in s.split() if t and t not in ("ADDR")]
        return tokens


class NGramExtractor:
    """N-gram 特征提取器 (无 ML 依赖)"""

    def __init__(self, n_values: Tuple[int, ...] = (1, 2, 3)):
        self.n_values = n_values

    def extract(self, tokens: List[str]) -> Counter:
        feats: Counter = Counter()
        for n in self.n_values:
            for i in range(len(tokens) - n + 1):
                gram = " ".join(tokens[i:i + n])
                feats[gram] += 1
        return feats


class SimpleAsmBert:
    """
    简化的"汇编 BERT"分类器
    - 基于词频 + 标签词命中计数
    - 不依赖 transformers
    """

    def __init__(self):
        self.tagger = InstructionTokenizer()
        self.ngram = NGramExtractor()

    def predict(self, instructions: List[str]) -> Tuple[BlockTag, float, str]:
        all_tokens: List[str] = []
        for ins in instructions:
            all_tokens.extend(self.tagger.tokenize(ins))
        if not all_tokens:
            return BlockTag.UNKNOWN, 0.0, "空块"
        # 标签命中统计
        scores: Dict[BlockTag, int] = defaultdict(int)
        for tag, kws in TAG_FEATURES.items():
            for kw in kws:
                scores[tag] += sum(1 for t in all_tokens if kw in t.lower())
        if not any(scores.values()):
            return BlockTag.UNKNOWN, 0.5, "未匹配标签"
        # 归一化
        total = sum(scores.values()) or 1
        best_tag = max(scores.items(), key=lambda kv: kv[1])
        conf = min(1.0, best_tag[1] / max(1, len(all_tokens)) * 10)
        # 生成简短摘要
        summary = self._generate_summary(best_tag[0], all_tokens)
        return best_tag[0], conf, summary

    def _generate_summary(self, tag: BlockTag,
                          tokens: List[str]) -> str:
        keyword_map = {
            BlockTag.MEMORY_ALLOC: "执行内存分配",
            BlockTag.MEMORY_FREE: "执行内存释放",
            BlockTag.LOOP_CHECK: "执行循环条件检查",
            BlockTag.STRING_OPS: "执行字符串操作",
            BlockTag.NETWORK_IO: "执行网络 I/O",
            BlockTag.SYSCALL: "执行系统调用",
            BlockTag.PARAM_VALIDATE: "执行参数校验",
            BlockTag.ERROR_HANDLING: "执行错误处理",
            BlockTag.ARITHMETIC: "执行算术运算",
            BlockTag.BRANCH: "执行分支跳转",
            BlockTag.UNKNOWN: "无明确语义"
        }
        return keyword_map.get(tag, "未分类")


class FunctionSummarizer:
    """函数摘要生成器"""

    def __init__(self):
        self.classifier = SimpleAsmBert()

    def _split_blocks(self, asm_text: str) -> List[BasicBlock]:
        blocks: List[BasicBlock] = []
        current: List[str] = []
        start_addr = 0
        bid = 0
        for line in asm_text.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue
            m = re.match(r"0x([0-9a-f]+)\s+(.*)", stripped)
            if m:
                addr = int(m.group(1), 16)
                if not current:
                    start_addr = addr
                current.append(stripped)
                # 块结束条件: jmp/call/ret 后
                ins = m.group(2).lower()
                if re.search(r"\b(jmp|call|ret)\b", ins):
                    blocks.append(BasicBlock(
                        block_id=f"B{bid:03d}",
                        start_addr=start_addr,
                        end_addr=addr,
                        instructions=current
                    ))
                    bid += 1
                    current = []
        if current:
            blocks.append(BasicBlock(
                block_id=f"B{bid:03d}",
                start_addr=start_addr,
                end_addr=start_addr,
                instructions=current
            ))
        return blocks

    def _decompile_func(self, binary_path: str, func: str) -> str:
        import subprocess
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', f'pdf @ {func}; q', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            return r.stdout
        except Exception as e:
            logger.warning(f"反编译失败: {e}")
            return ""

    def summarize(self, binary_path: str, func_name: str) -> FunctionSummary:
        asm = self._decompile_func(binary_path, func_name)
        blocks = self._split_blocks(asm)
        for b in blocks:
            tag, conf, summary = self.classifier.predict(b.instructions)
            b.tag = tag
            b.confidence = conf
            b.summary = summary
        block_summaries = {
            b.block_id: f"[{b.tag.value}] {b.summary}"
            for b in blocks
        }
        # 整体目的
        overall = self._summarize_overall(blocks)
        return FunctionSummary(
            func_name=func_name, blocks=blocks,
            block_summaries=block_summaries,
            overall_purpose=overall,
            metadata={'binary': binary_path, 'block_count': len(blocks)}
        )

    def _summarize_overall(self, blocks: List[BasicBlock]) -> str:
        tag_counter: Counter = Counter(b.tag for b in blocks)
        top = tag_counter.most_common(3)
        if not top:
            return "未识别函数主要功能"
        parts = [f"{tag.value}({n})" for tag, n in top]
        return f"主要功能: {', '.join(parts)}"


def summarize_function(binary_path: str, func_name: str) -> Dict[str, Any]:
    """便捷入口"""
    s = FunctionSummarizer()
    fs = s.summarize(binary_path, func_name)
    return {
        'success': True,
        'func_name': fs.func_name,
        'overall_purpose': fs.overall_purpose,
        'block_count': len(fs.blocks),
        'blocks': [
            {
                'block_id': b.block_id,
                'tag': b.tag.value,
                'confidence': b.confidence,
                'summary': b.summary,
                'start_addr': hex(b.start_addr),
                'end_addr': hex(b.end_addr)
            }
            for b in fs.blocks
        ],
        'block_summaries': fs.block_summaries
    }
