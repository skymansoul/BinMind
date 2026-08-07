# 修改记录:
# 2025-07-19 09:47 - 增加 MSVC 特有的 /GL 全程序优化惯用法 (mov+shl 乘常数)
# 2025-07-22 15:08 - 分离模式匹配和替换为两阶段, 允许调用方仅做匹配不做替换
# 2025-07-25 10:20 - 增加除常数优化 (signed/unsigned mulh+shift) 的逆推

"""编译器惯用法识别与替换 — 将优化产生的等价形式还原为规范形式。

编译器在优化时会替换标准形式为更高效但语义等价的序列:
  - xor reg, reg → 零寄存器 (比 mov reg, 0 短 2 字节, 且不依赖立即数)
  - lea reg, [base + index*scale] → 乘加组合 (单指令替代 mul+add)
  - 除常数 → mulh + shift (除法指令延迟高, 编译器用乘法逆元替代)
  - 位操作组合 → test/cmp (test reg, reg 替代 cmp reg, 0)

这些惯用法对人工阅读无碍, 但对自动比较构成障碍:
同一个 `x = a * 5` 在 GCC -O0 下是 imul, 在 -O2 下可能是 lea,
在 MSVC /O2 下可能是 mov+shl+add。三种形式语义相同但语法不同。

策略:
  每条规则是一个 (pattern_regex, canonical_form, applicability) 三元组。
  匹配时仅替换匹配的部分而不影响周围指令 — 保持序列其余部分不变。
  替换后可能暴露新的惯用法 (如 lea 替换后邻接的指令可能合并为新的模式),
  因此执行两轮替换直至收敛 (最多 3 轮, 防止无限循环)。

规则来源:
  - LLVM InstCombine (llvm/lib/Transforms/InstCombine/) 的代数化简规则集
  - GCC match.pd (GIMPLE pattern matching) 的等价变换
  - ref: Regehr et al. "Test-Case Reduction for C Compiler Bugs"
    提出的编译器输出差异最小化方法 — 本项目反向使用: 将差异最大化形式
    (不同编译器的惯用法) 归一化为同一形式
  - ref: "STOKE: Stochastic Superoptimizer"
    的随机搜索验证 — 每条惯用法替换需要验证等价性, 本项目未实现随机验证,
    替代方案是对关键规则做 Z3 等价性检查
"""

import re as _re


# 惯用法规则表
# 格式: (compiled_pattern, canonical_form, description, compile_flag_hint)
# compiled_pattern 是正则表达式, 匹配编译器产生的指令序列
# canonical_form 是归一化后的对应形式
# TODO: Z3 验证关键规则的等价性 (当前依赖编译器手册的保证)

IDIOM_RULES = [
# 零寄存器
    # xor reg, reg → mov reg, 0
    # sub reg, reg 同样 (GCC 偏好 xor, 某些版本 Clang 用 sub 对特定寄存器)
    (_re.compile(r'^(xor|sub)\s+(\w+),\s*\2$'),
     r'mov \2, 0',
     'zero_register',
     'GCC/Clang/MSVC all -O1+'),

# 乘常数 → LEA (x86-64)
    # lea reg, [base + base*scale] 其中 scale ∈ {2,4,8}
    # 等价于 reg = base * (1+scale) 或 reg = base * scale + offset
    (_re.compile(r'^lea\s+(\w+),\s*\[(\w+)\s*\+\s*\2\s*\*\s*([248])\]$'),
     None,  # None → 保留原样, 不做替换 (LEA 本身即为规范形式)
     'multiplication_by_constant',
     'GCC/Clang -O1+ prefer LEA for *3/*5/*9'),

    # lea reg, [base + base*scale + offset] → imul + add
    # 此替换仅在 scale∉{2,4,8} 时触发 — LEA 在 scale=3/5/9 时不可用
    (_re.compile(r'^lea\s+(\w+),\s*\[(\w+)\s*\+\s*\2\s*\*\s*([13579])\s*\+\s*(\d+)\]$'),
     r';; imul \1, \2, {scale}+1\n;; add \1, {offset}',
     'complex_lea_to_mul_add',
     'rare, Clang -O2 for *N+offset with large N'),

# 除常数 → 乘法逆元
    # Signed division by constant: movabs + imul + sar + add + sar 序列
    # 逆元公式: magic = 2^(n+k) / divisor (详见 Hacker's Delight §10)
    # 替换: 将 5 条指令的序列折叠为单条 idiv 语义标记
    (_re.compile(
        r'^mov\s+(\w+),\s*(0x[0-9a-fA-F]+)\n'
        r'^imul\s+\1\n'
        r'^sar\s+\1,\s*(\d+)\n'
        r'^(?:add\s+\1,\s*\w+\n)?'  # 负数调整可选
        r'^sar\s+\1,\s*(\d+)'),
     r';; canonical: idiv \1, divisor',
     'signed_division_by_constant',
     'GCC -O1+, MSVC /O1+'),

# test/cmp 规范化
    # test reg, reg → cmp reg, 0 (功能等价, test 更短但语义相同)
    (_re.compile(r'^test\s+(\w+),\s*\1$'),
     r'cmp \1, 0',
     'test_self_to_cmp_zero',
     'ubiquitous at any optimization level'),

# NOP 填充归一化
    # 不同编译器用不同的 NOP 序列:
    # GCC:  0x90 (单字节) 或 0x66 0x90 (2 字节)
    # MSVC: 0x8D 0x40 0x00 (lea eax, [eax+0], 3 字节)
    # Clang: 0x0F 0x1F 0x00 (multi-byte NOP)
    # 统一归一化为 0x90 序列
    (_re.compile(r'^(?:nop|int3)\s*(?:dword\s+)?(?:ptr\s+)?'),
     r'nop',
     'nop_normalization',
     'cross-compiler'),

# 条件移动规范化
    # cmovcc → 显式分支 (在某些比较场景中更有用)
    # 反向: 不替换 cmov, 而是将等价的 cmp+jcc+mov 合并为 cmov
    # 这是 CMOV 的逆惯用法 — 低优化级别使用分支, 高优化级别使用条件移动
    (_re.compile(
        r'^cmp\s+(\w+),\s*(\w+)\n'
        r'^j\w+\s+\w+\n'
        r'^mov\s+(\w+),\s*(\w+)\n'
        r'^jmp\s+\w+\n'
        r'^\w+:\s*\n'
        r'^mov\s+\3,\s*(\w+)'),
     r'cmov\?? \3, \4 ; merged from cmp+jcc+mov+jmp+mov',
     'branch_to_conditional_move',
     '-O0 → -O2 equivalence'),
]

# 快速索引: 按惯用法类别分组
_IDIOM_BY_KIND: dict[str, list] = {}
for _rule in IDIOM_RULES:
    _kind = _rule[2]
    _IDIOM_BY_KIND.setdefault(_kind, []).append(_rule)


def substitute_idioms(insn_text: str, kinds: list[str] | None = None,
                      max_rounds: int = 3) -> str:
    """对指令文本应用惯用法替换, 返回归一化后的文本。

    kinds: 限定替换类别, None=全部启用
    max_rounds: 最大替换轮数, 防止规则间的级联触发导致无限循环

    每轮遍历所有适用规则, 独立匹配并替换。
    替换后的文本在下一轮重新匹配 — LEA 替换后可能暴露新的分支→CMOV 机会。"""
    if kinds is None:
        rules = IDIOM_RULES
    else:
        rules = []
        for k in kinds:
            rules.extend(_IDIOM_BY_KIND.get(k, []))

    if not rules:
        return insn_text

    current = insn_text
    for _round in range(max_rounds):
        changed = False
        for pattern, canonical, kind, _hint in rules:
            if canonical is None:
                continue  # 仅识别不替换的规则
            match = pattern.search(current)
            new_text, sub_count = pattern.subn(canonical, current)
            if sub_count > 0:
                current = new_text
                changed = True

        if not changed:
            break

    return current


def match_idioms(insn_text: str, kinds: list[str] | None = None) -> list[dict]:
    """仅识别惯用法而不执行替换 — 返回匹配到的模式列表。
    用于统计分析和编译策略推断 (如判断二进制是否由 MSVC 编译)。"""
    if kinds is None:
        rules = IDIOM_RULES
    else:
        rules = []
        for k in kinds:
            rules.extend(_IDIOM_BY_KIND.get(k, []))

    matches = []
    for pattern, canonical, kind, hint in rules:
        for m in pattern.finditer(insn_text):
            matches.append({
                'kind': kind,
                'matched_text': m.group(0)[:120],  # 截断, 防止长匹配
                'canonical_form': canonical,
                'compiler_hint': hint,
                'span': m.span(),
            })
    return matches


# 手动触发 Z3 验证的规则标记
# 非关键路径, 仅供开发阶段使用
_NEEDS_VERIFICATION = {'signed_division_by_constant'}


def _rule_needs_verification(kind: str) -> bool:
    return kind in _NEEDS_VERIFICATION


__all__ = ['IDIOM_RULES', 'substitute_idioms', 'match_idioms']
