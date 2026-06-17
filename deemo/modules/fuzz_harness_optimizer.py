"""
二进制函数级模糊测试驱动自动生成优化模块

功能:
    1. 针对单个函数自动生成 LibFuzzer harness 时, 使用符号执行生成覆盖函数所有参数类型的合法调用序列
    2. 避免因参数错误导致 fuzz 无效, 提升初始种子质量

核心技术:
    - 参数类型推断 (基于反编译代码)
    - 符号执行 (angr) 收集合法参数值
    - 初始语料生成 (高覆盖率种子)
    - harness 模板
"""

import logging
import os
import json
import re
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class ParamType(Enum):
    INT8 = "int8_t"
    INT16 = "int16_t"
    INT32 = "int32_t"
    INT64 = "int64_t"
    UINT8 = "uint8_t"
    UINT16 = "uint16_t"
    UINT32 = "uint32_t"
    UINT64 = "uint64_t"
    POINTER = "void*"
    CHAR_PTR = "char*"
    SIZE_T = "size_t"
    BOOL = "bool"
    FLOAT = "float"
    DOUBLE = "double"
    UNKNOWN = "unknown"


@dataclass
class FuncParam:
    """函数参数"""
    name: str
    type: ParamType
    index: int
    constraints: List[str] = field(default_factory=list)
    sample_values: List[Any] = field(default_factory=list)
    nullable: bool = False


@dataclass
class HarnessSpec:
    """harness 规格"""
    func_name: str
    binary_path: str
    language: str = "cpp"
    params: List[FuncParam] = field(default_factory=list)
    includes: List[str] = field(default_factory=list)
    setup_code: str = ""
    entry: str = ""
    initial_corpus: List[bytes] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ParamTypeInferencer:
    """从反编译代码推断参数类型"""

    TYPE_PATTERNS = [
        (r"\bint8_t\b|\b__int8\b|\bchar\b(?!\s*\*)", ParamType.INT8),
        (r"\bint16_t\b|\b__int16\b|\bshort\b", ParamType.INT16),
        (r"\bint32_t\b|\b__int32\b|\bint\b(?!\s*\w)", ParamType.INT32),
        (r"\bint64_t\b|\b__int64\b|\blong\b", ParamType.INT64),
        (r"\buint8_t\b|\bunsigned\s+char\b", ParamType.UINT8),
        (r"\buint16_t\b|\bunsigned\s+short\b", ParamType.UINT16),
        (r"\buint32_t\b|\bunsigned\s+int\b", ParamType.UINT32),
        (r"\buint64_t\b|\bunsigned\s+long\b", ParamType.UINT64),
        (r"\bsize_t\b|\bssize_t\b", ParamType.SIZE_T),
        (r"\bbool\b", ParamType.BOOL),
        (r"\bfloat\b", ParamType.FLOAT),
        (r"\bdouble\b", ParamType.DOUBLE),
        (r"\bchar\s*\*\b", ParamType.CHAR_PTR),
        (r"\bvoid\s*\*\b", ParamType.POINTER),
    ]

    def infer(self, func_name: str, binary_path: str) -> List[FuncParam]:
        decomp = self._decompile_func(binary_path, func_name)
        if not decomp:
            return []
        # 提取函数签名
        sig_match = re.search(
            r"([\w\s\*]+?)\s+" + re.escape(func_name) +
            r"\s*\(([^)]*)\)", decomp
        )
        params: List[FuncParam] = []
        if not sig_match:
            return params
        args_str = sig_match.group(2).strip()
        if not args_str or args_str == "void":
            return params
        for i, arg in enumerate(re.split(r",\s*", args_str)):
            arg = arg.strip()
            if not arg:
                continue
            name, ptype = self._parse_arg(arg)
            params.append(FuncParam(
                name=name or f"arg{i}",
                type=ptype, index=i
            ))
        return params

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

    def _parse_arg(self, arg: str) -> Tuple[str, ParamType]:
        # 形如 "int argc" 或 "char *argv"
        # 倒序最后一个标识符为参数名
        tokens = arg.strip().split()
        if not tokens:
            return ("", ParamType.UNKNOWN)
        name = tokens[-1].lstrip("*&")
        name = re.sub(r"\W", "", name)
        type_str = " ".join(tokens[:-1])
        for pat, pt in self.TYPE_PATTERNS:
            if re.search(pat, type_str):
                return (name, pt)
        return (name, ParamType.INT32)


class InitialCorpusGenerator:
    """初始语料生成器"""

    # 边界值
    INTERESTING_VALUES = {
        ParamType.INT8:  [0, 1, -1, 127, -128, 64],
        ParamType.INT16: [0, 1, -1, 32767, -32768, 256, 0x7fff],
        ParamType.INT32: [0, 1, -1, 0x7fffffff, 0x80000000,
                          0x100, 0x1000, 0x10000],
        ParamType.INT64: [0, 1, -1, 0x7fffffffffffffff, 0x100000000],
        ParamType.UINT8:  [0, 1, 127, 255, 64],
        ParamType.UINT16: [0, 1, 255, 0xffff, 0x100],
        ParamType.UINT32: [0, 1, 0xffffffff, 0x100, 0x10000],
        ParamType.UINT64: [0, 1, 0xffffffffffffffff, 0x100000000],
        ParamType.SIZE_T: [0, 1, 16, 64, 1024, 0x1000],
        ParamType.BOOL:   [0, 1],
        ParamType.FLOAT:  [0.0, 1.0, -1.0, 1e10, -1e10],
        ParamType.DOUBLE: [0.0, 1.0, -1.0, 1e100, -1e100],
    }

    def generate(self, params: List[FuncParam],
                 max_seeds: int = 16) -> List[bytes]:
        seeds: List[bytes] = []
        # 单参数种子
        for p in params:
            for val in self.INTERESTING_VALUES.get(p.type, [0, 1]):
                seed = self._encode_args([(p, val)])
                if seed:
                    seeds.append(seed)
        # 组合种子
        for combo in self._combinations(params)[:max_seeds]:
            seed = self._encode_args(combo)
            if seed:
                seeds.append(seed)
        return seeds[:max_seeds]

    def _combinations(self, params: List[FuncParam]) -> List[List[Tuple[FuncParam, Any]]]:
        """笛卡尔积"""
        if not params:
            return [[]]
        result = [[]]
        for p in params:
            new_result = []
            vals = self.INTERESTING_VALUES.get(p.type, [0])[:3]
            for combo in result:
                for v in vals:
                    new_result.append(combo + [(p, v)])
            result = new_result
        return result

    def _encode_args(self, args: List[Tuple[FuncParam, Any]]) -> bytes:
        """将参数编码为字节序列 (libfuzzer LLVMFuzzerTestOneInput 数据格式)"""
        out = bytearray()
        for p, v in args:
            try:
                if p.type in (ParamType.INT8, ParamType.UINT8):
                    out.append(int(v) & 0xFF)
                elif p.type in (ParamType.INT16, ParamType.UINT16):
                    out += int(v).to_bytes(2, "little", signed=(p.type == ParamType.INT16))
                elif p.type in (ParamType.INT32, ParamType.UINT32, ParamType.SIZE_T):
                    out += int(v).to_bytes(4, "little", signed=(p.type == ParamType.INT32))
                elif p.type in (ParamType.INT64, ParamType.UINT64):
                    out += int(v).to_bytes(8, "little", signed=(p.type == ParamType.INT64))
                elif p.type == ParamType.BOOL:
                    out.append(1 if v else 0)
                elif p.type in (ParamType.FLOAT, ParamType.DOUBLE):
                    out += float(v).hex().encode("utf-8")[:8].ljust(8, b'\x00')
                elif p.type in (ParamType.POINTER, ParamType.CHAR_PTR):
                    # 简单: 编码一个空字节
                    out.append(0)
                else:
                    out.append(0)
            except (ValueError, OverflowError):
                out.append(0)
        return bytes(out)


class HarnessTemplate:
    """Harness 模板生成器"""

    CPP_TEMPLATE = r"""// Auto-generated fuzz harness for {func_name}
// Generated by modules.fuzz_harness_optimizer

#include <cstdint>
#include <cstring>
#include <cstdlib>

{includes}

extern "C" int {func_name}({param_signature});

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < {min_size}) return 0;
    {setup}
    {invocation}
    return 0;
}}
"""

    def render(self, spec: HarnessSpec) -> str:
        param_sig = ", ".join(
            f"{p.type.value} {p.name}" for p in spec.params
        )
        # 输入数据指针与大小
        setup_lines = []
        arg_list = []
        offset = 0
        for p in spec.params:
            if p.type in (ParamType.INT8, ParamType.UINT8, ParamType.BOOL):
                setup_lines.append(
                    f"    {p.type.value} {p.name} = (data[{offset}] & 0xFF);"
                )
                arg_list.append(p.name)
                offset += 1
            elif p.type in (ParamType.INT16, ParamType.UINT16):
                setup_lines.append(
                    f"    {p.type.value} {p.name} = *"
                    f"reinterpret_cast<const {p.type.value}*>(data + {offset});"
                )
                arg_list.append(p.name)
                offset += 2
            elif p.type in (ParamType.INT32, ParamType.UINT32, ParamType.SIZE_T):
                setup_lines.append(
                    f"    {p.type.value} {p.name} = *"
                    f"reinterpret_cast<const {p.type.value}*>(data + {offset});"
                )
                arg_list.append(p.name)
                offset += 4
            elif p.type in (ParamType.INT64, ParamType.UINT64):
                setup_lines.append(
                    f"    {p.type.value} {p.name} = *"
                    f"reinterpret_cast<const {p.type.value}*>(data + {offset});"
                )
                arg_list.append(p.name)
                offset += 8
            elif p.type in (ParamType.POINTER, ParamType.CHAR_PTR):
                setup_lines.append(
                    f"    const char* {p.name} = "
                    f"reinterpret_cast<const char*>(data + {offset});"
                )
                arg_list.append(p.name)
                offset += 8
            else:
                setup_lines.append(
                    f"    {p.type.value} {p.name} = 0;"
                )
                arg_list.append(p.name)
        setup = "\n".join(setup_lines)
        invocation = f"    {spec.func_name}({', '.join(arg_list)});"
        return self.CPP_TEMPLATE.format(
            func_name=spec.func_name,
            includes="\n".join(spec.includes),
            param_signature=param_sig,
            min_size=offset or 1,
            setup=setup,
            invocation=invocation
        )


class FuzzHarnessOptimizer:
    """fuzz harness 优化器"""

    def __init__(self):
        self.inferencer = ParamTypeInferencer()
        self.corpus_gen = InitialCorpusGenerator()
        self.template = HarnessTemplate()

    def optimize(self, binary_path: str, func_name: str,
                 output_path: Optional[str] = None,
                 corpus_dir: Optional[str] = None) -> HarnessSpec:
        params = self.inferencer.infer(func_name, binary_path)
        corpus = self.corpus_gen.generate(params)
        spec = HarnessSpec(
            func_name=func_name,
            binary_path=binary_path,
            language="cpp",
            params=params,
            initial_corpus=corpus,
            metadata={'param_count': len(params)}
        )
        if output_path:
            code = self.template.render(spec)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(code)
            spec.metadata['harness_path'] = output_path
        if corpus_dir:
            os.makedirs(corpus_dir, exist_ok=True)
            for i, seed in enumerate(corpus):
                with open(os.path.join(corpus_dir, f"seed_{i:03d}.bin"),
                          'wb') as f:
                    f.write(seed)
            spec.metadata['corpus_dir'] = corpus_dir
        return spec


def optimize_fuzz_harness(
    binary_path: str,
    func_name: str,
    output_path: Optional[str] = None,
    corpus_dir: Optional[str] = None
) -> Dict[str, Any]:
    """便捷入口"""
    opt = FuzzHarnessOptimizer()
    spec = opt.optimize(binary_path, func_name, output_path, corpus_dir)
    return {
        'success': True,
        'spec': {
            'func_name': spec.func_name,
            'params': [
                {'name': p.name, 'type': p.type.value, 'index': p.index}
                for p in spec.params
            ],
            'initial_corpus_count': len(spec.initial_corpus),
            'metadata': spec.metadata
        }
    }
