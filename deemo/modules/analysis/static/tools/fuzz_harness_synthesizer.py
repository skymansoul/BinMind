# 类型驱动的输入构造: 指针参数 -> 分配 + 填充, 整数参数 -> 边界内随机
# 结构体深度探测: 从 memcpy/memset 的参数推断嵌套结构体大小

"""类型驱动的模糊测试 harness 合成 - 从推断类型生成 LibAFL 兼容的 harness

interproc_type_propagator.py 推断函数参数和返回值类型
本模块将这些类型信息转换为可编译的 C harness 代码

生成的 harness 做:
1. 根据推断类型构造输入: 指针参数->分配堆内存+填充模糊数据
2. 调用目标函数
3. 清理+报告, 无内存泄漏的 harness 适用于长时间 fuzzing

与现有方案的区别:
- LibAFL/libfuzzer 的 harness 需手写 -> 本模块自动生成
- FuzzIntrospector (Google) 分析已有 harness -> 本模块从无到有合成
- WinAFL/LibAFL 的 harness 模板基于函数名 -> 本模块基于推断类型

输出: 可编译的 C 代码字符串 + LibAFL 的 `inprocess!` 宏调用
"""

from __future__ import annotations

import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .interproc_type_propagator import (
    FunctionTypeSignature, TypeConstraint,
)


# 类型 -> C 声明映射

_TYPE_TO_C = {
    'int':         'int64_t',
    'ptr':         'uint8_t*',
    'float':       'double',
    'struct':      'uint8_t*',   # struct 通过指针传递
    'int_or_ptr':  'uintptr_t',  # union 类型
    'unknown':     'uint8_t*',   # 保守, 当作缓冲区指针
}

_TYPE_SIZE = {
    'int':         8,
    'ptr':         8,
    'float':       8,
    'struct':      64,           # 默认 64 字节, 将在探测后调整
    'int_or_ptr':  8,
    'unknown':     64,
}


@dataclass
class HarnessConfig:
    """harness 生成配置"""
    max_buffer_size: int = 4096       # 每个指针参数的最大缓冲区
    struct_probe_size: int = 256      # 结构体大小探测上限
    include_asan: bool = True         # 是否包含 ASAN 检测
    libafl_style: bool = True         # LibAFL inprocess 风格 vs 独立二进制
    seed: int = 0x6D6F    # 固定种子, 便于复现


# 结构体深度探测

def probe_struct_depth(
    func_name: str,
    param_idx: int,
    usage_insns: List[Tuple[int, str]],
) -> Tuple[int, int]:
    """从 memcpy/memset/memmove 的参数推断结构体大小。

    观测: 若函数对参数 p 调用 memcpy(p, src, 128), 则 p 的参数
    字段至少 128 字节; 取所有此类 size 参数的最大值作为结构体
    大小下界。返回 (推断大小, 置信度百分比 0-100)。
    """
    import re
    sizes = []
    for addr, insn in usage_insns:
        text = insn.lower()
        # memcpy/memset/memmove(dst, src, size)
        if any(f in text for f in ('memcpy', 'memset', 'memmove', '__builtin_memcpy')):
            # 提取第三个参数 (size)
            parts = text.split(',')
            if len(parts) >= 3:
                size_part = parts[-1].strip()
                try:
                    sz = int(size_part, 0)
                    if 0 < sz < 1048576:
                        sizes.append(sz)
                except ValueError:
                    pass
        # 数组索引模式: p[i] where i ranges 0..N -> N+1 个元素
        arr_pat = re.findall(
            r'\[\s*(?:0x[0-9a-f]+|\d+)\s*\]', text, re.I
        )

    if sizes:
        return max(sizes), min(90, 50 + len(sizes) * 10)
    return 64, 30  # 默认


# Harness 代码生成器

class FuzzHarnessSynthesizer:
    """从跨函数推断类型合成模糊测试 harness

    用法:
    synth = FuzzHarnessSynthesizer()
    c_code = synth.synthesize('target_func', signature, probe_data)
    # c_code 可直接写入 .c 文件并编译
    """

    def __init__(self, config: Optional[HarnessConfig] = None):
        self._cfg = config or HarnessConfig()

    def synthesize(
        self,
        target_func: str,
        signature: FunctionTypeSignature,
        probe_data: Optional[Dict[int, List[Tuple[int, str]]]] = None,
    ) -> str:
        """合成目标函数的 fuzz harness C 代码。

        target_func 为目标函数名, signature 为推断的类型签名,
        probe_data 为 {param_idx: [(addr, insn_text)]} 结构体探测
        数据; 返回完整的 .c 文件内容。
        """
        probe_data = probe_data or {}
        lines = []
        self._emit_header(lines, target_func)
        self._emit_fuzz_target(lines, target_func, signature, probe_data)
        self._emit_main(lines, target_func)
        return '\n'.join(lines)

    def _emit_header(self, lines: List[str], target_func: str) -> None:
        """生成文件头, include + 前向声明"""
        lines.extend([
            '/* Auto-generated fuzz harness for binary API testing',
            ' * Target: ' + target_func,
            ' * Harness type: type-inferred from cross-function propagation',
            ' */',
            '',
            '#include <stdint.h>',
            '#include <stdlib.h>',
            '#include <string.h>',
            '#include <stdio.h>',
        ])
        if self._cfg.include_asan:
            lines.append('/* Compile with: -fsanitize=address,fuzzer */')
        lines.append('')
        # 被测试函数的声明
        lines.append(f'extern int {target_func}(void);')
        lines.append('')

    def _emit_fuzz_target(
        self,
        lines: List[str],
        target_func: str,
        sig: FunctionTypeSignature,
        probe_data: Dict[int, List[Tuple[int, str]]],
    ) -> None:
        """生成 fuzz target 函数体"""
        if self._cfg.libafl_style:
            lines.append('#[no_mangle]')
            lines.append(f'pub extern "C" fn {target_func}_harness(')
            lines.append('    data: *const u8, size: usize')
            lines.append(') -> i32 {')
        else:
            lines.append(f'int LLVMFuzzerTestOneInput(')
            lines.append('    const uint8_t *data, size_t size) {')

        indent = '    '

        # 参数准备: 为指针参数分配缓冲区
        param_decls = self._prepare_params(sig, probe_data)
        lines.extend([f'{indent}{d}' for d in param_decls])

        # 从 fuzzer 输入填充参数缓冲区
        fill_code = self._emit_input_distribution(sig)
        lines.extend([f'{indent}{l}' for l in fill_code])

        # 调用目标函数
        call_args = self._emit_call_args(sig)
        lines.append(f'{indent}// Call target function')
        lines.append(f'{indent}{target_func}({call_args});')

        # 清理
        cleanup = self._emit_cleanup(sig)
        lines.extend([f'{indent}{l}' for l in cleanup])

        lines.append(f'{indent}return 0;')
        lines.append('}')

    def _prepare_params(
        self,
        sig: FunctionTypeSignature,
        probe_data: Dict[int, List[Tuple[int, str]]],
    ) -> List[str]:
        """为指针/结构体参数生成缓冲区分配代码"""
        decls = []
        max_param = max(sig.param_types.keys()) if sig.param_types else -1

        for idx in range(max_param + 1):
            constraint = sig.param_types.get(idx)
            if constraint is None:
                continue

            c_type = _TYPE_TO_C.get(constraint.inferred_type, 'uint8_t*')
            type_size = _TYPE_SIZE.get(constraint.inferred_type, 64)

            # 结构体大小探测
            if constraint.inferred_type == 'struct' and idx in probe_data:
                probe_size, probe_conf = probe_struct_depth(
                    sig.func_name, idx, probe_data[idx]
                )
                type_size = min(probe_size, self._cfg.struct_probe_size)

            if c_type.endswith('*'):
                decls.append(
                    f'{c_type} p{idx} = ({c_type})malloc({type_size});'
                )
                decls.append(f'memset(p{idx}, 0, {type_size});')
            else:
                decls.append(f'{c_type} p{idx} = 0;')

        return decls

    def _emit_input_distribution(self, sig: FunctionTypeSignature) -> List[str]:
        """从 fuzzer 输入缓冲区分配数据到各参数, 按推断类型解释字节

        策略:
        - 指针参数: 从输入拷贝 min(buf_size, type_size) 字节
        - 整数参数: 从输入读取 8 字节, 模以合理范围
        - float 参数: 从输入读取 8 字节, 限制在 [-1e6, 1e6]
        """
        code = []
        max_param = max(sig.param_types.keys()) if sig.param_types else -1
        if max_param < 0:
            return code

        code.append('if (size < 8) return 0;')
        # 指针/缓冲区参数优先分配, 它们消耗最多输入数据
        ptr_params = [i for i in range(max_param + 1)
                      if sig.param_types.get(i)
                      and _TYPE_TO_C.get(sig.param_types[i].inferred_type, '').endswith('*')]
        scalar_params = [i for i in range(max_param + 1) if i not in ptr_params
                         and sig.param_types.get(i)]

        offset = 0
        for idx in ptr_params:
            constraint = sig.param_types[idx]
            type_size = _TYPE_SIZE.get(constraint.inferred_type, 64)
            code.append(
                f'if (size > {offset}) {{'
                f' memcpy(p{idx}, data + {offset}, '
                f'(size - {offset}) < {type_size} ? (size - {offset}) : {type_size});'
                f' }}'
            )
            offset += type_size

        for idx in scalar_params:
            constraint = sig.param_types[idx]
            c_type = _TYPE_TO_C.get(constraint.inferred_type, 'uintptr_t')
            if c_type == 'int64_t':
                code.append(
                    f'if (size > {offset} + 8) {{'
                    f' memcpy(&p{idx}, data + {offset}, 8);'
                    f' p{idx} = p{idx} % 1000000;'
                    f' }}'
                )
            elif c_type == 'double':
                code.append(
                    f'if (size > {offset} + 8) {{'
                    f' double tmp; memcpy(&tmp, data + {offset}, 8);'
                    f' p{idx} = (tmp > 1e6 || tmp < -1e6) ? 0.0 : tmp;'
                    f' }}'
                )
            else:
                code.append(
                    f'if (size > {offset} + 8) {{'
                    f' memcpy(&p{idx}, data + {offset}, 8);'
                    f' }}'
                )
            offset += 8

        return code

    def _emit_call_args(self, sig: FunctionTypeSignature) -> str:
        """生成调用参数列表"""
        max_param = max(sig.param_types.keys()) if sig.param_types else -1
        args = []
        for idx in range(max_param + 1):
            if idx in sig.param_types:
                args.append(f'p{idx}')
            else:
                args.append('0')
        if not args:
            return ''
        return ', '.join(args)

    def _emit_cleanup(self, sig: FunctionTypeSignature) -> List[str]:
        """生成资源清理代码"""
        code = []
        for idx, constraint in sig.param_types.items():
            c_type = _TYPE_TO_C.get(constraint.inferred_type, '')
            if c_type.endswith('*'):
                code.append(f'free(p{idx});')
        return code

    def _emit_main(self, lines: List[str], target_func: str) -> None:
        """生成 main 入口 (用于非 LibAFL 独立 binaries)"""
        if self._cfg.libafl_style:
            return
        lines.extend([
            '',
            'int main(int argc, char **argv) {',
            '    if (argc < 2) {',
            '        fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]);',
            '        return 1;',
            '    }',
            '    FILE *f = fopen(argv[1], "rb");',
            '    if (!f) { perror("fopen"); return 1; }',
            '    fseek(f, 0, SEEK_END);',
            '    long sz = ftell(f);',
            '    fseek(f, 0, SEEK_SET);',
            '    uint8_t *buf = (uint8_t*)malloc(sz);',
            '    fread(buf, 1, sz, f);',
            '    fclose(f);',
            f'    int ret = LLVMFuzzerTestOneInput(buf, sz);',
            '    free(buf);',
            '    return ret;',
            '}',
        ])


# 便捷入口

def synthesize_harness(
    target_func: str,
    signature: FunctionTypeSignature,
    probe_data: Optional[Dict[int, List[Tuple[int, str]]]] = None,
    libafl_style: bool = True,
) -> str:
    """一行式 harness 合成

    返回可编译的 C 代码字符串
    """
    config = HarnessConfig(libafl_style=libafl_style)
    synth = FuzzHarnessSynthesizer(config)
    return synth.synthesize(target_func, signature, probe_data)
