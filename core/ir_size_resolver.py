"""将sizeof/宏/结构体解析为具体值，供IR区间传播。"""

from __future__ import annotations
import re
from typing import Dict, List, Optional, Tuple

from core.loop_write_detector import add_loop_write_hints


# 模式定义 ───────────────────────────────────────────────────────────

# 匹配 sizeof(类型名)、sizeof(表达式)、sizeof 表达式
_SIZEOF_RE = re.compile(
    r'sizeof\s*\(\s*([^()]+?)\s*\)|'
    r'sizeof\s+([a-zA-Z_]\w*(?:\s*\[[^\]]*\])?)')

# 匹配结构体字段: var->field, var.field
_FIELD_ACCESS = re.compile(r'(\w[\w.]*)\s*->\s*(\w[\w.]*)')

# 匹配数组定义: type name[N];
_ARRAY_DEF = re.compile(
    r'(?:char|int|short|long|float|double|void|unsigned|'
    r'u?int\d+_t|size_t)\s+(\w[\w.]*)\s*\[(\d+)\]')

# 匹配结构体成员: type field[N];
_STRUCT_MEMBER = re.compile(
    r'(?:char|int|short|long|float|double|void|unsigned|'
    r'u?int\d+_t|size_t)\s+(\w[\w.]*)\s*\[(\d+)\]\s*;')

# 字符串字面量: "..." 字符计数
_STRING_LIT = re.compile(r'"((?:[^"\\]|\\.)*)"')

# 全大写常量赋值: MACRO_NAME = number;
_CONST_DEF = re.compile(r'(\b[A-Z][A-Z_0-9]+\b)\s*=\s*(\d+)\s*;')

# 变量别名拷贝: var1 = var2;
_VAR_COPY = re.compile(r'(\w[\w.]*)\s*=\s*(\w[\w.]*)\s*;')

# malloc携带变量: var = malloc(size_var);
_MALLOC_VAR = re.compile(
    r'(\w[\w.]*)\s*=\s*(?:\([^)]*\))?\s*malloc\s*\(\s*(\w[\w.]*)\s*\)')

# strcpy/sprintf: func(buf, "literal")
_STRCPY_LIT = re.compile(
    r'(strcpy|sprintf)\s*\(\s*(\w[\w.]*)\s*,\s*"((?:[^"\\]|\\.)*)"')

# memcpy三元大小: memcpy(dst, src, cond ? a : b)
_MEMCPY_TERNARY = re.compile(
    r'memcpy\s*\(\s*(\w[\w.]*)\s*,[^,]*,\s*'
    r'(\w[\w.]*)\s*\?\s*(\d+)\s*:\s*(\w[\w.]*)')


class IrSizeResolver:
    """基于源码上下文解析IR尺寸表达式：解析结构体定义、数组大小、
    字符串字面量与宏常量，为IR行标注具体尺寸提示。"""

    def __init__(self):
        # 源码分析得到的已知尺寸
        self._struct_fields: Dict[str, Dict[str, int]] = {}
        # 结构体名 → {字段名 → 尺寸}
        self._struct_bodies: Dict[str, str] = {}
        # 结构体名 → 原始体文本（用于嵌套解析）
        self._struct_sizes: Dict[str, int] = {}
        # 结构体/typedef名 → 总字节数
        self._array_sizes: Dict[str, int] = {}
        # 变量名 → 元素个数（如 char name[N]）
        self._constants: Dict[str, int] = {}
        # 宏 → 值
        self._variable_constants: Dict[str, int] = {}
        # 变量 → 值（const限定赋值）

    def analyze_source(self, c_source: str) -> None:
        """解析C源码，提取类型尺寸、结构体定义与常量。"""
        # 剥离注释
        s = re.sub(r'/\*.*?\*/', '', c_source, flags=re.DOTALL)
        s = re.sub(r'//[^\n]*', '', s)

        # 结构体定义：查找全部struct块，提取数组成员并保存体文本
        struct_blocks = re.finditer(
            r'(?:typedef\s+)?struct\s+(?:(\w+)\s*)?\{([^}]+)\}\s*'
            r'(?:(\w+)\s*)?;',
            s, re.DOTALL)
        for m in struct_blocks:
            struct_tag = m.group(1) or m.group(3) or ''
            body = m.group(2) or ''
            if struct_tag:
                self._struct_fields.setdefault(struct_tag, {})
                self._struct_bodies[struct_tag] = body
            # 提取数组成员: type name[N];
            for mm in _STRUCT_MEMBER.finditer(body):
                fname = mm.group(1)
                fsize = int(mm.group(2))
                if struct_tag:
                    self._struct_fields[struct_tag][fname] = fsize
                self._array_sizes[fname] = fsize

        # #define 常量（须在结构体尺寸计算前）
        for dm in re.finditer(
            r'#define\s+(\w[\w.]*)\s+(\d+)\b', c_source):
            self._constants[dm.group(1)] = int(dm.group(2))
        for m in _CONST_DEF.finditer(s):
            self._constants[m.group(1)] = int(m.group(2))

        # 计算结构体总尺寸（宏已展开）
        for sname in list(self._struct_bodies.keys()):
            self._struct_sizes[sname] = self._compute_struct_size(sname)

        # 顶层数组定义
        for m in _ARRAY_DEF.finditer(s):
            self._array_sizes[m.group(1)] = int(m.group(2))

        # 变量常量赋值
        for m in re.finditer(
            r'(?:size_t|int|unsigned)\s+(\w[\w.]*)\s*=\s*(\d+)\s*;', s):
            self._variable_constants[m.group(1)] = int(m.group(2))

    def resolve(self, ir_lines: List[str],
                c_source: str = '') -> List[str]:
        """解析 sizeof/strcpy/三元表达式为具体值。"""
        if c_source:
            self.analyze_source(c_source)
        enhanced: List[str] = []
        var_values: Dict[str, int] = dict(self._variable_constants)
        var_values.update(self._constants)
        for i, line in enumerate(ir_lines):
            for macro, val in self._constants.items():
                if macro in line and macro not in (
                    'malloc','calloc','realloc','memcpy','free',
                    'sizeof','if','for','while','return','goto'):
                    line = re.sub(rf'\b{re.escape(macro)}\b', str(val), line)
                    var_values[macro] = val
            # sizeof resolution
            sm = _SIZEOF_RE.search(line)
            if sm:
                size_val = self._resolve_sizeof(
                    sm, line, ir_lines, var_values)
                if size_val is not None:
                    eq_pos = line.find('=')
                    if eq_pos > 0:
                        var = line[:eq_pos].strip()
                        # 保留malloc/calloc/realloc标记以便分配器模型识别
                        am = re.search(r'(malloc|calloc|realloc)\s*\(', line[eq_pos:])
                        fn = am.group(1) if am else ''
                        enhanced.append(
                            f'{var} = {fn}({size_val});' if fn
                            else f'{var} = {size_val};')
                        var_values[var] = size_val
                        continue

            # strcpy/sprintf 字面量 → 合成memcpy
            slm = _STRCPY_LIT.search(line)
            if slm:
                fn = slm.group(1)
                dst = slm.group(2)
                lit = slm.group(3)
                lit_len = self._string_len(lit)
                if lit_len > 0:
                    # 输出为: dst = memcpy(dst, "lit", len); 前向传播器按写操作解析
                    enhanced.append(
                        f'memcpy({dst}, "<literal>", {lit_len});')
                    continue  # replace original strcpy/sprintf

            # memcpy中的三元: var ? N : other → 输出上界
            tlm = _MEMCPY_TERNARY.search(line)
            if tlm:
                dst = tlm.group(1)
                const_val = int(tlm.group(3))
                # 用上界(N)替换为memcpy
                enhanced.append(
                    f'memcpy({dst}, "<input>", {const_val});')
                continue

            # 变量拷贝传播
            vcm = _VAR_COPY.match(line.strip().rstrip(';'))
            if vcm:
                src = vcm.group(2)
                dst = vcm.group(1)
                if src in var_values and dst not in var_values:
                    var_values[dst] = var_values[src]

            enhanced.append(line)

        return enhanced
    _MEMBER_RE = re.compile(r'^\s*(?:const\s+)?(?:unsigned\s+)?(?:struct\s+)?'
        r'(\w[\w.]*)\s+(\w[\w.]*)\s*(?:\[(\d+)\])?\s*;', re.MULTILINE)
    _TYPE_SIZES = {'char':1,'unsigned char':1,'signed char':1,'short':2,'unsigned short':2,
        'int':4,'unsigned int':4,'unsigned':4,'long':8,'unsigned long':8,'long long':8,
        'unsigned long long':8,'float':4,'double':8,'size_t':8,'ssize_t':8,'ptrdiff_t':8,
        'void*':8,'char*':8,'int*':8}

    def _compute_struct_size(self, name: str) -> int:
        """递归计算struct总大小 (含嵌套类型+宏常量维度)。"""
        body = self._struct_bodies.get(name, '')
        if not body: return 0
        # 展开宏常量 (如 PAYLOAD_MAX → 256)
        for macro, val in self._constants.items():
            body = re.sub(rf'\b{re.escape(macro)}\b', str(val), body)
        total = 0
        for mm in self._MEMBER_RE.finditer(body):
            mtype, mname = mm.group(1), mm.group(2)
            n = int(mm.group(3)) if mm.group(3) else 1
            if mtype in self._TYPE_SIZES:
                total += self._TYPE_SIZES[mtype] * n
            elif mtype in self._struct_sizes:
                total += self._struct_sizes[mtype] * n
            elif mtype in self._struct_bodies:
                self._struct_sizes[mtype] = self._compute_struct_size(mtype)
                total += self._struct_sizes[mtype] * n
            elif mname in self._array_sizes:
                total += self._array_sizes[mname]
            elif mtype in self._array_sizes:
                total += self._array_sizes[mtype] * n
        return total

    def _resolve_sizeof(
        self, sm: re.Match, line: str,
        ir_lines: List[str], var_values: Dict[str, int],
    ) -> Optional[int]:
        """将 sizeof 解析为具体数值。"""
        inner = (sm.group(1) or sm.group(2) or '').strip()

        # 情形1: sizeof(已知类型)
        if inner in self._TYPE_SIZES:
            return self._TYPE_SIZES[inner]

        # 情形2: sizeof(typedef结构体名)
        if inner in self._struct_sizes:
            return self._struct_sizes[inner]

        # 情形3: sizeof(数组名) 或 sizeof(type[N])
        if inner in self._array_sizes:
            return self._array_sizes[inner]

        # 情形5: sizeof(expr->field) 或 sizeof(expr.field)
        fm = _FIELD_ACCESS.search(inner)
        if fm:
            obj = fm.group(1)
            field = fm.group(2)
            # 尝试从obj的结构体类型解析；源码中obj可能声明为 struct_name *obj
            for sname, fields in self._struct_fields.items():
                if field in fields:
                    # 启发式: 检查obj类型是否为sname
                    return fields[field]
            # 回退: 查数组尺寸表
            if field in self._array_sizes:
                return self._array_sizes[field]

        # 情形6: sizeof(变量)，可能为已知数组
        if re.match(r'^[a-zA-Z_]\w*$', inner):
            if inner in self._array_sizes:
                return self._array_sizes[inner]

        return None

    @staticmethod
    def _string_len(literal: str) -> int:
        """计算C字符串字面量长度（基础转义处理）。"""
        length, i = 0, 0
        while i < len(literal):
            if literal[i] == '\\':
                i += 1
                if i < len(literal):
                    if literal[i] in 'x0123456789':  # hex/oct: skip digits
                        while i+1 < len(literal) and literal[i+1] in '0123456789abcdefABCDEF':
                            i += 1
                    length += 1
            else:
                length += 1
            i += 1
        return length

def _expand_defines(c_source: str) -> str:
    """#define NAME→value 宏展开, loop_write_detector识别常量偏移。"""
    defines = {m.group(1): m.group(2) for m in
               re.finditer(r'#define\s+(\w+)\s+(\d+)\b', c_source)}
    lines = []
    for line in c_source.splitlines():
        if line.strip().startswith('#define'):
            lines.append(line); continue
        for n, v in defines.items():
            line = re.sub(rf'\b{re.escape(n)}\b', v, line)
        lines.append(line)
    return '\n'.join(lines)


def resolve_ir(c_source: str, ir_lines: List[str]) -> List[str]:
    """sizeof/loop_write_hints → resolved IR lines."""
    resolver = IrSizeResolver()
    enhanced = resolver.resolve(ir_lines, c_source)
    return add_loop_write_hints(_expand_defines(c_source), enhanced)


__all__ = ['IrSizeResolver', 'resolve_ir', '_expand_defines']
