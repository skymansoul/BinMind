import logging
import os
import json
import re
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict, OrderedDict
from enum import Enum

logger = logging.getLogger(__name__)


class ParamType(str, Enum):
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


# ── 结构感知解析标记 ────────────────────────────────────────────

@dataclass
class StructField:
    name: str
    offset: int
    size: int
    ctype: ParamType
    constraints: List[str] = field(default_factory=list)
    is_checksum: bool = False           # 标记校验和字段
    depends_on: Optional[str] = None     # 依赖字段 (校验和依赖)


@dataclass
class FuncParam:
    name: str
    type: ParamType
    index: int
    constraints: List[str] = field(default_factory=list)
    sample_values: List[Any] = field(default_factory=list)
    nullable: bool = False


# ── Harness 生成模式 ────────────────────────────────────────────

class HarnessMode(str, Enum):
    STANDARD = "standard"      # 单次 LLVMFuzzerTestOneInput
    PERSISTENT = "persistent"  # AFL++ 持久模式
    MULTI_FUNC = "multi_func"  # 多函数组合


@dataclass
class HarnessSpec:
    func_name: str
    binary_path: str
    language: str = "cpp"
    params: List[FuncParam] = field(default_factory=list)
    includes: List[str] = field(default_factory=list)
    setup_code: str = ""
    entry: str = ""
    initial_corpus: List[bytes] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    # 增强字段
    mode: HarnessMode = HarnessMode.STANDARD
    sanitizers: List[str] = field(default_factory=list)
    target_funcs: List[str] = field(default_factory=list)
    struct_fields: List[StructField] = field(default_factory=list)
    has_checksum: bool = False
    checksum_info: Dict[str, Any] = field(default_factory=dict)


# ── 常见校验和算法检测模式 ──────────────────────────────────────

_CHECKSUM_FUNC_PATTERNS = [
    (r'\b(crc|CRC)\w*', 'CRC variant'),
    (r'\b(adler|Adler)\w*', 'Adler32'),
    (r'\b(md5|MD5)\b', 'MD5'),
    (r'\b(sha|SHA)\w*\b', 'SHA family'),
    (r'\b(checksum|chksum|chk_sum)\b', 'generic checksum'),
    (r'\b(validate|verify)_?(hash|integrity)\b', 'integrity check'),
]


class ParamTypeInferencer:
    """从反编译伪代码中通过正则匹配推断 C 参数类型"""

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
        # 从反编译伪代码中提取函数签名
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
            logger.warning("反编译失败: %s", e)
            return ""

    def _parse_arg(self, arg: str) -> Tuple[str, ParamType]:
        # 解析形如 "int argc" 或 "char *argv" 的参数声明
        # 末尾标识符为参数名，其前各 token 组成类型
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

    # ── 批量反编译发现全校验和函数 ──────────────────────────────

    def detect_checksum_funcs(self, binary_path: str) -> List[str]:
        """在反编译输出中搜索校验和函数名模式。"""
        import subprocess
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'afl; q', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            found = []
            for line in r.stdout.split('\n'):
                for pat, label in _CHECKSUM_FUNC_PATTERNS:
                    if re.search(pat, line, re.IGNORECASE):
                        parts = line.split()
                        if parts:
                            found.append((parts[-1], label))
            return [name for name, _ in found]
        except Exception:
            return []


class InitialCorpusGenerator:
    """初始语料种子生成 — 边界值 + 笛卡尔积组合"""

    # 各参数类型的边界及特殊取值
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
        # 单参数种子: 逐参数取边界值
        for p in params:
            for val in self.INTERESTING_VALUES.get(p.type, [0, 1]):
                seed = self._encode_args([(p, val)])
                if seed:
                    seeds.append(seed)
        # 组合种子: 参数间笛卡尔积
        for combo in self._combinations(params)[:max_seeds]:
            seed = self._encode_args(combo)
            if seed:
                seeds.append(seed)
        return seeds[:max_seeds]

    def _combinations(self, params: List[FuncParam]) -> List[List[Tuple[FuncParam, Any]]]:
        """所有参数边界值的笛卡尔积展开"""
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
        # 将类型化参数值序列化为 libFuzzer 兼容的字节序列
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
                    # 指针无法有意义地编码，以空字节占位
                    out.append(0)
                else:
                    out.append(0)
            except (ValueError, OverflowError):
                out.append(0)
        return bytes(out)


class HarnessTemplate:
    """C++ Harness 代码生成 — 填充 LLVMFuzzerTestOneInput 骨架"""

    CPP_TEMPLATE = r"""// Fuzz harness for {func_name}

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

    # ── 持久模式模板 (AFL++ persistent mode) ────────────────────

    PERSISTENT_TEMPLATE = r"""// Persistent harness for {func_name}
// 编译: afl-clang-fast -o harness harness.c

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

{includes}

extern "C" int {func_name}({param_signature});

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {{
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    {setup_code}

    while (__AFL_LOOP({loop_count})) {{
        int len = __AFL_FUZZ_TESTCASE_LEN;
        {setup}
        {invocation}
    }}
    return 0;
}}
"""

    # ── 多函数组合模板 ──────────────────────────────────────────

    MULTI_FUNC_TEMPLATE = r"""// Multi-function fuzz harness
// 由 {target_funcs} 生成

#include <cstdint>
#include <cstring>
#include <cstdlib>

{includes}

{declarations}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < {min_size}) return 0;
    {setup}
    {invocations}
    return 0;
}}
"""

    # ── 带校验和绕过的模板 ──────────────────────────────────────

    CHECKSUM_AWARE_TEMPLATE = r"""// Checksum-aware harness for {func_name}
// 自动重算 {checksum_field} 字段使输入通过完整性检查

#include <cstdint>
#include <cstring>
#include <cstdlib>
{includes}

extern "C" int {func_name}({param_signature});

// 由工具自动生成的校验和补丁函数
static inline void fix_{checksum_field}(
    uint8_t *buf, size_t size, size_t cs_offset, size_t data_start)
{{
    uint{cs_width}_t sum = {cs_init};
    for (size_t i = data_start; i < cs_offset; i++)
        sum = {cs_update_expr};
    memcpy(buf + cs_offset, &sum, sizeof(sum));
}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < {min_size}) return 0;

    uint8_t buf[{max_buf_size}];
    memcpy(buf, data, size);

    // 在每一轮变异后重算校验和，确保输入始终有效
    fix_{checksum_field}(buf, size, {cs_offset}, {data_start});

    {setup}
    {invocation}
    return 0;
}}
"""

    # ── 渲染 ────────────────────────────────────────────────────

    def render(self, spec: HarnessSpec) -> str:
        if spec.mode == HarnessMode.PERSISTENT:
            return self._render_persistent(spec)
        elif spec.mode == HarnessMode.MULTI_FUNC:
            return self._render_multi_func(spec)
        elif spec.has_checksum:
            return self._render_checksum_aware(spec)
        else:
            return self._render_standard(spec)

    def _render_standard(self, spec: HarnessSpec) -> str:
        param_sig = ", ".join(
            f"{p.type.value} {p.name}" for p in spec.params
        )
        setup, arg_list, offset = self._build_setup(spec.params)
        invocation = f"    {spec.func_name}({', '.join(arg_list)});"
        return self.CPP_TEMPLATE.format(
            func_name=spec.func_name,
            includes="\n".join(spec.includes),
            param_signature=param_sig,
            min_size=offset or 1,
            setup=setup,
            invocation=invocation
        )

    def _render_persistent(self, spec: HarnessSpec) -> str:
        param_sig = ", ".join(
            f"{p.type.value} {p.name}" for p in spec.params
        )
        setup, arg_list, offset = self._build_setup(spec.params)
        invocation = f"    {spec.func_name}({', '.join(arg_list)});"
        # 持久模式在每次循环中重新执行 setup，以更新参数指针
        persistent_setup = f"    size_t __len = __AFL_FUZZ_TESTCASE_LEN;\n"
        persistent_setup += f"    if (__len < {offset or 1}) continue;"
        return self.PERSISTENT_TEMPLATE.format(
            func_name=spec.func_name,
            includes="\n".join(spec.includes),
            param_signature=param_sig,
            setup_code=spec.setup_code or "// no global setup needed",
            setup=f"{persistent_setup}\n{setup}",
            invocation=invocation,
            loop_count=spec.metadata.get('persistent_loop_count', 10000),
        )

    def _render_multi_func(self, spec: HarnessSpec) -> str:
        declarations = "\n".join(
            f"extern \"C\" int {fn}({', '.join(p.type.value + ' ' + p.name for p in spec.params)});"
            for fn in spec.target_funcs
        ) if spec.target_funcs else ""
        setup, arg_list, offset = self._build_setup(spec.params)
        invocations = "\n".join(
            f"    {fn}({', '.join(arg_list)});"
            for fn in spec.target_funcs
        )
        return self.MULTI_FUNC_TEMPLATE.format(
            target_funcs=", ".join(spec.target_funcs),
            includes="\n".join(spec.includes),
            declarations=declarations,
            min_size=offset or 1,
            setup=setup,
            invocations=invocations,
        )

    def _render_checksum_aware(self, spec: HarnessSpec) -> str:
        param_sig = ", ".join(
            f"{p.type.value} {p.name}" for p in spec.params
        )
        setup, arg_list, offset = self._build_setup(spec.params)
        invocation = f"    {spec.func_name}({', '.join(arg_list)});"
        cs = spec.checksum_info
        return self.CHECKSUM_AWARE_TEMPLATE.format(
            func_name=spec.func_name,
            includes="\n".join(spec.includes),
            param_signature=param_sig,
            min_size=offset or 1,
            setup=setup,
            invocation=invocation,
            checksum_field=cs.get('field', 'checksum'),
            cs_width=cs.get('width', 32),
            cs_init=cs.get('init', '0'),
            cs_update_expr=cs.get('update', 'sum + buf[i]'),
            cs_offset=cs.get('offset', offset),
            data_start=cs.get('data_start', 0),
            max_buf_size=cs.get('max_buf', 4096),
        )

    def _build_setup(self, params: List[FuncParam]) -> Tuple[str, List[str], int]:
        setup_lines = []
        arg_list = []
        offset = 0
        for p in params:
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
        return "\n".join(setup_lines), arg_list, offset


class FuzzHarnessOptimizer:
    """Harness 优化管线: 反编译 → 类型推断 → 语料生成 → C++ 模板渲染"""

    def __init__(self):
        self.inferencer = ParamTypeInferencer()
        self.corpus_gen = InitialCorpusGenerator()
        self.template = HarnessTemplate()

    def optimize(self, binary_path: str, func_name: str,
                 output_path: Optional[str] = None,
                 corpus_dir: Optional[str] = None,
                 mode: HarnessMode = HarnessMode.STANDARD,
                 sanitizers: Optional[List[str]] = None,
                 checksum_detect: bool = True,
                 ) -> HarnessSpec:
        params = self.inferencer.infer(func_name, binary_path)
        corpus = self.corpus_gen.generate(params)

        # 检测校验和依赖
        has_cs = False
        cs_info: Dict[str, Any] = {}
        if checksum_detect:
            cs_funcs = self.inferencer.detect_checksum_funcs(binary_path)
            if cs_funcs:
                has_cs = True
                cs_info = {
                    'detected_funcs': cs_funcs,
                    'field': 'checksum',
                    'width': 32,
                    'init': '0',
                    'update': 'sum + buf[i]',
                    'offset': 0,
                    'data_start': 0,
                    'max_buf': 4096,
                }

        spec = HarnessSpec(
            func_name=func_name,
            binary_path=binary_path,
            language="cpp",
            params=params,
            initial_corpus=corpus,
            mode=mode,
            sanitizers=sanitizers or [],
            target_funcs=[func_name],
            has_checksum=has_cs,
            checksum_info=cs_info,
            metadata={'param_count': len(params), 'mode': mode.value}
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

        # 若启用 sanitizer，生成编译建议写入 metadata
        if sanitizers:
            spec.metadata['compile_flags'] = self._sanitizer_flags(sanitizers)

        return spec

    # ── 多函数批量优化 ──────────────────────────────────────────

    def optimize_multi(
        self, binary_path: str, func_names: List[str],
        output_path: Optional[str] = None,
        corpus_dir: Optional[str] = None,
    ) -> HarnessSpec:
        """为多个函数生成共享 harness — 单次输入分别注入每个目标函数。

        适用于 API 级别的 fuzz 测试，如同时测试 parse()/serialize()/free()
        三个函数组成的生命周期。"""
        if not func_names:
            raise ValueError("func_names 不能为空")
        primary = func_names[0]
        params = self.inferencer.infer(primary, binary_path)
        corpus = self.corpus_gen.generate(params)
        spec = HarnessSpec(
            func_name=primary,
            binary_path=binary_path,
            language="cpp",
            params=params,
            initial_corpus=corpus,
            mode=HarnessMode.MULTI_FUNC,
            target_funcs=func_names,
            metadata={'param_count': len(params), 'mode': 'multi_func',
                      'target_count': len(func_names)}
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

    def _sanitizer_flags(self, sanitizers: List[str]) -> str:
        flag_map = {
            'asan': '-fsanitize=address',
            'ubsan': '-fsanitize=undefined',
            'msan': '-fsanitize=memory',
            'tsan': '-fsanitize=thread',
            'lsan': '-fsanitize=leak',
        }
        flags = [flag_map.get(s.lower(), '') for s in sanitizers]
        flags = [f for f in flags if f]
        return ' '.join(flags)


def optimize_fuzz_harness(
    binary_path: str,
    func_name: str,
    output_path: Optional[str] = None,
    corpus_dir: Optional[str] = None
) -> Dict[str, Any]:
    # 模块级便捷入口
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
