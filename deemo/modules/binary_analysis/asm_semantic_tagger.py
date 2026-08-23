# 汇编语义label器：based on关key词+ngram的轻量级basic blockclassification。
# 不dependencyML框架，纯rulematch。accuracy中等，覆盖常见mode。
# labelweight是手工调的，后面有标注data了再trainingmodel。

import logging
import re
from collections import Counter
from collections import defaultdict
from dataclasses import dataclass, field
from enum import StrEnum

logger = logging.getLogger(__name__)


class BlockTag(StrEnum):
    ALLOC = 'memory_alloc'
    FREE = 'memory_free'
    LOOP = 'loop_check'
    STR = 'string_ops'
    NET = 'network_io'
    SYSCALL = 'syscall'
    VALID = 'param_validate'
    ERR = 'error_handling'
    ARITH = 'arithmetic'
    BRANCH = 'branch'
    UNKNOWN = 'unknown'


# labelfeature词表 —— 关key字->label映射
_TAG_WORDS = {
    BlockTag.ALLOC:  ('malloc', 'calloc', 'realloc', 'alloc', 'new'),
    BlockTag.FREE:   ('free', 'delete', 'release'),
    BlockTag.LOOP:   ('cmp', 'test', 'jl', 'jg', 'jle', 'jge', 'dec', 'inc', 'loop'),
    BlockTag.STR:    ('strcpy', 'strcat', 'strcmp', 'strlen', 'strncmp', 'memcpy', 'memset', 'memmove'),
    BlockTag.NET:    ('socket', 'connect', 'send', 'recv', 'bind', 'listen', 'accept', 'read', 'write'),
    BlockTag.SYSCALL:('syscall', 'int 0x80', 'svc', 'sysenter'),
    BlockTag.VALID:  ('test', 'cmp', 'jz', 'jnz', 'jmp', 'je', 'jne'),
    BlockTag.ERR:    ('errno', 'perror', 'exit', 'abort', 'panic', 'fail'),
    BlockTag.ARITH:  ('add', 'sub', 'mul', 'div', 'imul', 'idiv', 'xor', 'and', 'or', 'shl', 'shr'),
    BlockTag.BRANCH: ('jmp', 'call', 'ret', 'leave'),
}


@dataclass
class BasicBlock:
    id: str = ''
    start: int = 0
    end: int = 0
    insns: list = field(default_factory=list)
    tag: str = BlockTag.UNKNOWN
    conf: float = 0.0
    summary: str = ''


@dataclass
class FunctionSummary:
    name: str = ''
    blocks: list = field(default_factory=list)
    summaries: dict = field(default_factory=dict)
    purpose: str = ''
    meta: dict = field(default_factory=dict)


class InstructionTokenizer:
    def tokenize(self, instr):
        """去除address和标点，返回tokenlist"""
        if instr is None:
            return []
        s = re.sub(r'0x[0-9a-f]+', 'ADDR', instr)
        s = re.sub(r'[^a-zA-Z0-9_\s,]', ' ', s)
        out = []
        for t in s.split():
            if t and t != 'ADDR':
                out.append(t)
        return out


class NGramExtractor:
    def __init__(self, nvals=(1, 2, 3)):
        self._nvals = tuple(nvals) if nvals else (1, 2, 3)

    def extract(self, tokens):
        feats = Counter()
        if tokens is None:
            return feats
        for n in self._nvals:
            for ti in range(len(tokens) - n + 1):
                gram = ' '.join(tokens[ti:ti + n])
                feats[gram] += 1
        return feats


class SimpleAsmBert:
    """简化汇编分类器: 基于词频+标签命中"""

    def __init__(self):
        self._tok = InstructionTokenizer()
        self._ng = NGramExtractor()

    def predict(self, insns):
        """预测基本块语义标签"""
        if insns is None:
            return BlockTag.UNKNOWN, 0.0, 'empty'

        all_toks = []
        for insn in insns:
            all_toks.extend(self._tok.tokenize(insn))

        if not all_toks:
            return BlockTag.UNKNOWN, 0.0, 'empty block'

        # label命中统计
        scores = defaultdict(int)
        for tag, kws in _TAG_WORDS.items():
            for kw in kws:
                for tok in all_toks:
                    if kw in tok.lower():
                        scores[tag] += 1

        if not any(scores.values()):
            return BlockTag.UNKNOWN, 0.5, 'no match'

        # 找最高分label
        best_tag = BlockTag.UNKNOWN
        best_score = 0
        for tag, sc in scores.items():
            if sc > best_score:
                best_score = sc
                best_tag = tag

        total = sum(scores.values()) or 1
        conf = best_score / max(1, len(all_toks)) * 10.0
        if conf > 1.0:
            conf = 1.0

        summary = self._gen_summary(best_tag)
        return best_tag, conf, summary

    def _gen_summary(self, tag):
        _MAP = {
            BlockTag.ALLOC: 'memory allocation',
            BlockTag.FREE:  'memory free',
            BlockTag.LOOP:   'loop condition check',
            BlockTag.STR:    'string operation',
            BlockTag.NET:    'network I/O',
            BlockTag.SYSCALL:'system call',
            BlockTag.VALID:  'parameter validation',
            BlockTag.ERR:    'error handling',
            BlockTag.ARITH:  'arithmetic',
            BlockTag.BRANCH: 'branch/jump',
            BlockTag.UNKNOWN:'unknown',
        }
        return _MAP.get(tag, 'unclassified')


class FunctionSummarizer:
    def __init__(self):
        self._clf = SimpleAsmBert()

    def _split_blocks(self, asm):
        """按jmp/call/retboundary切分basic block"""
        blocks = []
        current = []
        start = 0
        bid = 0
        lines = asm.split('\n') if asm else []
        for line in lines:
            stripped = line.strip()
            if stripped:
                m = re.match(r'0x([0-9a-f]+)\s+(.*)', stripped)
                if m:
                    addr = int(m.group(1), 16)
                    if not current:
                        start = addr
                    current.append(stripped)
                    ins = m.group(2).lower()
                    if re.search(r'\b(jmp|call|ret)\b', ins):
                        blocks.append(BasicBlock(
                            id=f'B{bid:03d}', start=start, end=addr,
                            insns=current))
                        bid += 1
                        current = []
        # 残留块
        if current:
            blocks.append(BasicBlock(
                id=f'B{bid:03d}', start=start, end=start, insns=current))
        return blocks

    def _decomp(self, bin_path, func):
        """radare2反compile"""
        import subprocess
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', f'pdf @ {func}; q', bin_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace')
            return r.stdout
        except Exception as e:
            logger.warning(f'decomp failed: {e}')
            return ''

    def summarize(self, bin_path, func):
        asm = self._decomp(bin_path, func)
        blocks = self._split_blocks(asm)
        for b in blocks:
            tag, conf, summary = self._clf.predict(b.insns)
            b.tag = tag
            b.conf = conf
            b.summary = summary

        summaries = {}
        for b in blocks:
            summaries[b.id] = f'[{b.tag}] {b.summary}'

        purpose = self._overall(blocks)
        return FunctionSummary(
            name=func, blocks=blocks, summaries=summaries,
            purpose=purpose, meta={'binary': bin_path, 'block_count': len(blocks)})

    def _overall(self, blocks):
        tag_cnt = Counter()
        for b in blocks:
            tag_cnt[b.tag] += 1
        top = tag_cnt.most_common(3)
        if not top:
            return 'unidentified'
        parts = []
        for tag, n in top:
            parts.append(f'{tag}({n})')
        return f'main: {", ".join(parts)}'


def summarize_function(bin_path, func):
    """便捷入口"""
    s = FunctionSummarizer()
    fs = s.summarize(bin_path, func)
    out_blocks = []
    for b in fs.blocks:
        out_blocks.append({
            'block_id': b.id, 'tag': b.tag,
            'confidence': b.conf, 'summary': b.summary,
            'start_addr': hex(b.start), 'end_addr': hex(b.end),
        })
    return {
        'success': True,
        'func_name': fs.name,
        'overall_purpose': fs.purpose,
        'block_count': len(fs.blocks),
        'blocks': out_blocks,
        'block_summaries': fs.summaries,
    }
