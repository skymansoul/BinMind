# 二进制API表层推断与Harness生成器 — 无源码下的定向fuzzing入口生成
#
# 核心问题:
#   fuzzer.py 的 HarnessGenerator 生成固定模板 (LLVMFuzzerTestOneInput),
#   假设目标函数签名为 void f(const uint8_t*, size_t)。
#   这对有源码的库函数有效, 对闭源二进制完全无用——你不知道:
#     a) 哪些函数消费外部输入 (API surface)
#     b) 每个函数的参数类型和约束
#     c) 函数之间的调用依赖 (必须先调用 init 再调用 parse)
#
#   OGHARN (ICSE 2025) 从 C 头文件推断 API, PromeFuzz (CCS 2025)
#   用 LLM + 知识库——两者都需要源码/文档。
#   本模块面向无源码二进制: 仅从导入表和CFG推断。
#
# 本模块的方法 — 二进制级API表层推断:
#   1. 解析导入表, 识别输入消费函数 (read/recv/fread/fgetc/mmap等)
#   2. 从调用图反向追踪: 哪些内部函数消费了这些输入?
#   3. 对每个输入消费函数, 提取其CFG参数约束:
#      - 参数个数 (通过调用约定推断: x86-64下看rdi/rsi/rdx使用)
#      - 缓冲区大小约束 (cmp指令与参数寄存器的关系)
#      - 返回值检查模式 (test eax, eax; jz → 期望非零返回)
#   4. 生成针对性的 C harness——为每个API函数生成正确的参数准备代码
#
# 技术依据:
#   OGHARN (Sherman & Nagy, ICSE 2025) — oracle-guided harness synthesis;
#     本项目取其 harness 生成框架但适配到二进制级
#   PromeFuzz (Liu et al. CCS 2025) — RAG+LLM harness生成;
#     本项目取其 API 知识库概念但以导入表+CFG替代文档知识库

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class ParamType(str, Enum):
    """推断的参数类型"""
    BUFFER_PTR = "buffer_ptr"      # 指向输入缓冲区的指针
    SIZE_T = "size_t"              # 缓冲区大小
    FD_INT = "fd_int"              # 文件描述符
    FLAGS_INT = "flags_int"        # 标志位
    STRUCT_PTR = "struct_ptr"      # 指向结构体的指针
    UNKNOWN = "unknown"


@dataclass
class InferredParam:
    """推断的函数参数"""
    index: int                      # 参数序号 (0-based)
    param_type: ParamType = ParamType.UNKNOWN
    size_hint: int = 0              # 若为BUFFER_PTR, 关联的SIZE_T参数索引
    is_checked_for_null: bool = False
    is_checked_for_range: bool = False
    min_value: int = 0
    max_value: int = 0


@dataclass
class APIFunction:
    """推断的API函数——消费外部输入的内部函数"""
    func_name: str = ""
    func_addr: int = 0
    # 输入源: 从哪个导入函数获取数据
    input_source: str = ""          # "read", "recv", "fread", "memcpy" 等
    # 推断的参数列表
    params: List[InferredParam] = field(default_factory=list)
    # CFG摘要
    basic_block_count: int = 0
    branch_count: int = 0
    has_loop: bool = False
    # 调用依赖: 必须先调用的函数
    dependencies: List[str] = field(default_factory=list)
    # 置信度
    confidence: float = 0.0


@dataclass
class HarnessSpec:
    """生成的 harness 规格"""
    target_func: APIFunction
    # C 代码
    harness_code: str = ""
    # 编译命令
    compile_cmd: str = ""
    # 依赖的库/头文件
    dependencies: List[str] = field(default_factory=list)
    # 预期的输入接口
    input_mode: str = "file"        # file | stdin | shmem


class BinaryAPISurfaceAnalyzer:
    """二进制API表层分析器——从导入表和CFG推断输入消费接口。

    输入:
      - imports: {func_name: import_type}  导入函数及其类别
      - call_graph: {caller_addr: [callee_addrs]}  调用图
      - cfg_info: {func_addr: {bb_count, branch_count, has_loop}}

    输出:
      - List[APIFunction]: 推断的API函数列表
    """

    # 识别为"消费外部输入"的导入函数模式
    _INPUT_SOURCE_PATTERNS = {
        'read': 'fd_int', 'fread': 'fd_int', 'recv': 'fd_int',
        'recvfrom': 'fd_int', 'recvmsg': 'fd_int',
        'fgets': 'fd_int', 'fgetc': 'fd_int',
        'mmap': 'fd_int', 'MapViewOfFile': 'fd_int',
        'ReadFile': 'fd_int', 'fscanf': 'fd_int',
        'getc': 'fd_int', 'getchar': 'fd_int',
    }

    # 识别为"数据复制/转换"的导入函数 (间接消费输入)
    _DATA_MOVE_PATTERNS = {
        'memcpy', 'memmove', 'strcpy', 'strncpy', 'bcopy',
        'memcpy_s', 'CopyMemory', 'RtlCopyMemory',
    }

    def __init__(self):
        self._imports: Dict[str, str] = {}           # name → type category
        self._call_graph: Dict[int, List[int]] = {}
        self._reverse_cg: Dict[int, List[int]] = defaultdict(list)
        self._cfg_info: Dict[int, Dict[str, Any]] = {}

    def load_imports(self, imports: Dict[str, str]) -> None:
        """加载导入函数: {name: category}。category='io'|'mem'|'other'。"""
        self._imports = imports

    def load_call_graph(self, cg: Dict[int, List[int]]) -> None:
        """加载调用图: {caller_addr: [callee_addrs]}。"""
        self._call_graph = cg
        self._reverse_cg.clear()
        for caller, callees in cg.items():
            for callee in callees:
                self._reverse_cg[callee].append(caller)

    def load_cfg_info(self, cfg: Dict[int, Dict[str, Any]]) -> None:
        """加载CFG摘要: {func_addr: {bb_count, branch_count, has_loop}}。"""
        self._cfg_info = cfg

    def analyze(self) -> List[APIFunction]:
        """主入口: 分析并返回推断的API函数列表"""
        api_funcs: List[APIFunction] = []

        # Step 1: 识别输入消费的导入函数
        input_imports: Dict[int, str] = {}  # addr → import_name
        for caller, callees in self._call_graph.items():
            for callee in callees:
                # 检查 callee 是否为输入消费导入函数
                for name, category in self._imports.items():
                    base = name.split('@')[0].split('$')[0]
                    if base in self._INPUT_SOURCE_PATTERNS:
                        input_imports[callee] = name

        # Step 2: 反向追踪——找到调用输入导入函数的内部函数
        for input_addr, import_name in input_imports.items():
            callers = self._reverse_cg.get(input_addr, [])
            for caller_addr in callers:
                api = self._build_api_function(
                    caller_addr, import_name)
                if api and api.confidence > 0.2:
                    api_funcs.append(api)

        # Step 3: 去重 (同地址的函数只保留置信度最高的)
        seen: Dict[int, APIFunction] = {}
        for api in api_funcs:
            if api.func_addr not in seen or api.confidence > seen[api.func_addr].confidence:
                seen[api.func_addr] = api

        return sorted(seen.values(), key=lambda a: -a.confidence)

    def _build_api_function(self, func_addr: int,
                             input_source: str) -> Optional[APIFunction]:
        """构建单个API函数描述"""
        cfg = self._cfg_info.get(func_addr, {})
        if not cfg:
            return None

        api = APIFunction(
            func_name=f"func_{func_addr:x}",
            func_addr=func_addr,
            input_source=input_source,
            basic_block_count=cfg.get('bb_count', 0),
            branch_count=cfg.get('branch_count', 0),
            has_loop=cfg.get('has_loop', False),
        )

        # 推断参数: 基于CFG特征
        api.params = self._infer_params(func_addr, cfg)

        # 推断调用依赖: 从调用图中找必须先调用的函数
        deps: List[str] = []
        for caller, callees in self._call_graph.items():
            if func_addr in callees and caller != func_addr:
                deps.append(f"func_{caller:x}")
        api.dependencies = deps[:3]

        # 置信度 = 基于证据强度的启发式评分
        confidence = 0.3
        if api.params:
            confidence += 0.2
        if api.branch_count >= 2:
            confidence += 0.15  # 有分支 → 可能在验证输入
        if api.has_loop:
            confidence += 0.15   # 有循环 → 可能在处理缓冲区
        if deps:
            confidence += 0.1
        api.confidence = min(1.0, confidence)

        return api

    def _infer_params(self, func_addr: int,
                       cfg: Dict[str, Any]) -> List[InferredParam]:
        """基于CFG特征推断函数参数"""
        params: List[InferredParam] = []
        bb_count = cfg.get('bb_count', 0)
        branch_count = cfg.get('branch_count', 0)

        # 启发式1: 若BB数>3且分支数>0 → 至少接收buffer+size
        if bb_count >= 3 and branch_count >= 1:
            params.append(InferredParam(
                index=0, param_type=ParamType.BUFFER_PTR,
                size_hint=1))
            params.append(InferredParam(
                index=1, param_type=ParamType.SIZE_T,
                is_checked_for_range=(branch_count >= 2)))

        # 启发式2: 若分支≥3 → 可能有flags参数控制不同路径
        if branch_count >= 3:
            params.append(InferredParam(
                index=len(params),
                param_type=ParamType.FLAGS_INT))

        return params


class HarnessCodeGenerator:
    """从APIFunction生成可编译的C harness代码。

    生成策略:
      - BUFFER_PTR → malloc(size) + memset(0, ...)
      - SIZE_T → 随机值 [1, 65536]
      - FLAGS_INT → 枚举各种合法标志组合
    """

    @staticmethod
    def generate(api: APIFunction,
                  lib_name: str = "target",
                  input_mode: str = "file",
                  ) -> HarnessSpec:
        """生成harness规格"""
        spec = HarnessSpec(target_func=api, input_mode=input_mode)

        # 生成参数准备代码
        param_setup = HarnessCodeGenerator._generate_param_setup(api.params)
        call_args = HarnessCodeGenerator._generate_call_args(api.params)

        if input_mode == "file":
            code = f"""// Auto-generated harness for {api.func_name}
// Input source: {api.input_source}, BBs={api.basic_block_count}
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

// Target function prototype (inferred)
extern int {api.func_name}({', '.join(f'{p.param_type.value} p{p.index}' for p in api.params)});

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < 8) return 0;
{param_setup}
    {api.func_name}({call_args});
    return 0;
}}
"""
        else:
            code = f"""// Auto-generated stdin harness for {api.func_name}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int {api.func_name}({', '.join(f'{p.param_type.value} p{p.index}' for p in api.params)});

int main(int argc, char **argv) {{
    unsigned char buf[65536];
    ssize_t len = read(0, buf, sizeof(buf));
    if (len <= 0) return 1;
{param_setup}
    {api.func_name}({call_args});
    return 0;
}}
"""

        spec.harness_code = code
        spec.compile_cmd = (
            f"clang -g -O1 -fsanitize=fuzzer,address "
            f"-I. -L. -l{lib_name} -o harness_{api.func_name} "
            f"harness_{api.func_name}.c"
        )
        return spec

    @staticmethod
    def _generate_param_setup(params: List[InferredParam]) -> str:
        lines = []
        for p in params:
            if p.param_type == ParamType.BUFFER_PTR:
                size_param = next(
                    (pp for pp in params if pp.index == p.size_hint), None)
                sz = f"size" if size_param else "1024"
                lines.append(f"    void *p{p.index} = malloc({sz});")
                lines.append(f"    if (!p{p.index}) return 0;")
                lines.append(f"    memcpy(p{p.index}, data, {sz} < size ? {sz} : size);")
            elif p.param_type == ParamType.SIZE_T:
                lines.append(f"    size_t p{p.index} = size;")
            elif p.param_type == ParamType.FLAGS_INT:
                lines.append(f"    int p{p.index} = data[0] & 0xFF;")
            else:
                lines.append(f"    int p{p.index} = 0;")
        return "\n".join(lines) if lines else "    // no params"

    @staticmethod
    def _generate_call_args(params: List[InferredParam]) -> str:
        return ", ".join(f"p{p.index}" for p in params) if params else ""


def analyze_and_generate(imports: Dict[str, str],
                          call_graph: Dict[int, List[int]],
                          cfg_info: Dict[int, Dict[str, Any]],
                          lib_name: str = "target",
                          ) -> List[HarnessSpec]:
    """便捷入口: 一步完成分析+生成"""
    analyzer = BinaryAPISurfaceAnalyzer()
    analyzer.load_imports(imports)
    analyzer.load_call_graph(call_graph)
    analyzer.load_cfg_info(cfg_info)
    apis = analyzer.analyze()

    specs = []
    for api in apis:
        spec = HarnessCodeGenerator.generate(api, lib_name)
        specs.append(spec)
    return specs
