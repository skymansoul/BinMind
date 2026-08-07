"""sizeof/macro/struct → concrete values for IR interval propagation."""

from __future__ import annotations
import re
from typing import Dict, List, Optional, Tuple

from core.loop_write_detector import add_loop_write_hints


# patterns ───────────────────────────────────────────────────────────

# Match: sizeof(type_name), sizeof(expr), sizeof expr
_SIZEOF_RE = re.compile(
    r'sizeof\s*\(\s*([^()]+?)\s*\)|'
    r'sizeof\s+([a-zA-Z_]\w*(?:\s*\[[^\]]*\])?)')

# Match struct field: var->field, var.field
_FIELD_ACCESS = re.compile(r'(\w[\w.]*)\s*->\s*(\w[\w.]*)')

# Match array definition: type name[N];
_ARRAY_DEF = re.compile(
    r'(?:char|int|short|long|float|double|void|unsigned|'
    r'u?int\d+_t|size_t)\s+(\w[\w.]*)\s*\[(\d+)\]')

# Match struct member: type field[N];
_STRUCT_MEMBER = re.compile(
    r'(?:char|int|short|long|float|double|void|unsigned|'
    r'u?int\d+_t|size_t)\s+(\w[\w.]*)\s*\[(\d+)\]\s*;')

# String literal: "..." — count characters
_STRING_LIT = re.compile(r'"((?:[^"\\]|\\.)*)"')

# ALL_CAPS constant assignment: MACRO_NAME = number;
_CONST_DEF = re.compile(r'(\b[A-Z][A-Z_0-9]+\b)\s*=\s*(\d+)\s*;')

# Variable aliasing: var1 = var2;
_VAR_COPY = re.compile(r'(\w[\w.]*)\s*=\s*(\w[\w.]*)\s*;')

# malloc with variable: var = malloc(size_var);
_MALLOC_VAR = re.compile(
    r'(\w[\w.]*)\s*=\s*(?:\([^)]*\))?\s*malloc\s*\(\s*(\w[\w.]*)\s*\)')

# strcpy/sprintf: func(buf, "literal")
_STRCPY_LIT = re.compile(
    r'(strcpy|sprintf)\s*\(\s*(\w[\w.]*)\s*,\s*"((?:[^"\\]|\\.)*)"')

# memcpy with ternary size: memcpy(dst, src, cond ? a : b)
_MEMCPY_TERNARY = re.compile(
    r'memcpy\s*\(\s*(\w[\w.]*)\s*,[^,]*,\s*'
    r'(\w[\w.]*)\s*\?\s*(\d+)\s*:\s*(\w[\w.]*)')


class IrSizeResolver:
    """Resolve IR size expressions using source-level context.

    Parses struct definitions, array sizes, string literals, and
    macro constants from C source to annotate IR lines with
    concrete size hints.
    """

    def __init__(self):
        # Known sizes from source analysis
        self._struct_fields: Dict[str, Dict[str, int]] = {}
        # struct_name → {field_name → size}
        self._struct_bodies: Dict[str, str] = {}
        # struct_name → raw body text (for nested resolution)
        self._struct_sizes: Dict[str, int] = {}
        # struct/typedef name → total byte size
        self._array_sizes: Dict[str, int] = {}
        # var_name → element_count (for char name[N])
        self._constants: Dict[str, int] = {}
        # MACRO → value
        self._variable_constants: Dict[str, int] = {}
        # var → value (const-qualified assignments)

    def analyze_source(self, c_source: str) -> None:
        """Parse C source to extract type sizes, struct defs, constants."""
        # Strip comments
        s = re.sub(r'/\*.*?\*/', '', c_source, flags=re.DOTALL)
        s = re.sub(r'//[^\n]*', '', s)

        # struct definitions
        # Find all struct { ... } blocks, extract member arrays + save body
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
            # Extract array members: type name[N];
            for mm in _STRUCT_MEMBER.finditer(body):
                fname = mm.group(1)
                fsize = int(mm.group(2))
                if struct_tag:
                    self._struct_fields[struct_tag][fname] = fsize
                self._array_sizes[fname] = fsize

        # #define constants (must precede struct size calc)
        for dm in re.finditer(
            r'#define\s+(\w[\w.]*)\s+(\d+)\b', c_source):
            self._constants[dm.group(1)] = int(dm.group(2))
        for m in _CONST_DEF.finditer(s):
            self._constants[m.group(1)] = int(m.group(2))

        # compute total struct sizes (macros now resolved)
        for sname in list(self._struct_bodies.keys()):
            self._struct_sizes[sname] = self._compute_struct_size(sname)

        # top-level array definitions
        for m in _ARRAY_DEF.finditer(s):
            self._array_sizes[m.group(1)] = int(m.group(2))

        # variable const assignments
        for m in re.finditer(
            r'(?:size_t|int|unsigned)\s+(\w[\w.]*)\s*=\s*(\d+)\s*;', s):
            self._variable_constants[m.group(1)] = int(m.group(2))

    def resolve(self, ir_lines: List[str],
                c_source: str = '') -> List[str]:
        """sizeof/strcpy/ternary → concrete values."""
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

            # strcpy/sprintf literal → synthetic memcpy
            slm = _STRCPY_LIT.search(line)
            if slm:
                fn = slm.group(1)
                dst = slm.group(2)
                lit = slm.group(3)
                lit_len = self._string_len(lit)
                if lit_len > 0:
                    # Emit as: dst = memcpy(dst, "lit", len);
                    # The forward propagator will parse this as a write
                    enhanced.append(
                        f'memcpy({dst}, "<literal>", {lit_len});')
                    continue  # replace original strcpy/sprintf

            # ternary in memcpy: var ? N : other → emit upper bound
            tlm = _MEMCPY_TERNARY.search(line)
            if tlm:
                dst = tlm.group(1)
                const_val = int(tlm.group(3))
                # Replace with memcpy using the upper bound (N)
                enhanced.append(
                    f'memcpy({dst}, "<input>", {const_val});')
                continue

            # variable copy propagation
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
        """Resolve sizeof to a concrete number."""
        inner = (sm.group(1) or sm.group(2) or '').strip()

        # Case 1: sizeof(type) where type is known (int, char, etc.)
        if inner in self._TYPE_SIZES:
            return self._TYPE_SIZES[inner]

        # Case 2: sizeof(struct_type) — typedef'd struct name
        if inner in self._struct_sizes:
            return self._struct_sizes[inner]

        # Case 3: sizeof(array_name) or sizeof(type[N])
        if inner in self._array_sizes:
            return self._array_sizes[inner]

        # Case 5: sizeof(expr->field) or sizeof(expr.field)
        fm = _FIELD_ACCESS.search(inner)
        if fm:
            obj = fm.group(1)
            field = fm.group(2)
            # Try to resolve from struct type of obj
            # obj might be typed as struct_name *obj in source
            for sname, fields in self._struct_fields.items():
                if field in fields:
                    # Check if obj has type sname (heuristic)
                    return fields[field]
            # Fallback: check array_sizes
            if field in self._array_sizes:
                return self._array_sizes[field]

        # Case 6: sizeof(variable) — variable might be known array
        if re.match(r'^[a-zA-Z_]\w*$', inner):
            if inner in self._array_sizes:
                return self._array_sizes[inner]

        return None

    @staticmethod
    def _string_len(literal: str) -> int:
        """C string literal length (basic escape handling)."""
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
