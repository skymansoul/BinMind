"""
Copy约束值流提取器 — ValueFlowExtractor + GuardConditionExtractor.

提取 size 变量的值来源 (常量/外部输入/类型推断) 和守卫条件.
"""

import re

from core.copy_constraint_types import SizeVarOrigin


class ValueFlowExtractor:
    """从 IR 行中提取值流: 变量 → 表达式 → 外部输入."""

    _EXT_INPUT_PATTERNS = [
        (r'atoi\s*\(\s*argv\[', 'argv'),
        (r'strtol\s*\(', 'external'),
        (r'getenv\s*\(', 'env'),
        (r'recv\s*\(', 'network'),
        (r'fread\s*\(', 'file'),
        (r'scanf\s*\(', 'stdin'),
        (r'ntohl?\s*\(', 'network'),
        (r'\bpayload\b', 'network'),
        (r'\binput\b', 'external'),
        (r'\bdata_len\b', 'external'),
        (r'\bstream\b', 'external'),
    ]

    def extract_origin(self, ir_lines: list[str], size_var: str,
                       start_pc: int) -> SizeVarOrigin:
        """向上追溯 size_var 的值来源."""
        origin = SizeVarOrigin(var_name=size_var)
        if not size_var:
            return origin
        try:
            cv = int(size_var, 0)
            origin.is_constant = True
            origin.constant_value = cv
            return origin
        except (ValueError, TypeError):
            pass

        for i in range(start_pc, -1, -1):
            line = ir_lines[i]
            m = re.search(rf'{re.escape(size_var)}\s*=\s*(.+)', line)
            if not m:
                continue
            rhs = m.group(1).strip()
            try:
                cv = int(rhs, 0)
                origin.is_constant = True
                origin.constant_value = cv
                return origin
            except (ValueError, TypeError):
                pass
            for pat, src_type in self._EXT_INPUT_PATTERNS:
                if re.search(pat, rhs):
                    origin.is_external_input = True
                    origin.input_source = src_type
                    origin.derived_vars.append(rhs)
                    origin.has_upper_bound, origin.upper_bound = (
                        self._infer_type_bound(size_var, ir_lines, i))
                    return origin
            parts = re.split(r'[+\-*/()]', rhs)
            for part in parts:
                part = part.strip()
                if part and re.match(r'^[a-zA-Z_]\w*$', part):
                    origin.derived_vars.append(part)
            return origin
        return origin

    def _infer_type_bound(self, var_name: str, ir_lines: list[str],
                          pc: int) -> tuple[bool, int]:
        """从类型声明推断上界: uint16_t→65535, uint8_t→255."""
        type_bounds = {
            'uint8_t': 255, 'int8_t': 127,
            'uint16_t': 65535, 'int16_t': 32767,
            'uint32_t': 0xFFFFFFFF, 'int32_t': 0x7FFFFFFF,
            'size_t': 0xFFFFFFFFFFFFFFFF,
        }
        for i in range(max(0, pc - 10), pc + 1):
            for tname, bound in type_bounds.items():
                if re.search(rf'{tname}\s+.*{re.escape(var_name)}',
                              ir_lines[i]):
                    return True, bound
        return False, 0


class GuardConditionExtractor:
    """从 IR 行中提取对 size 变量的守卫条件."""

    _GUARD_PATTERNS = [
        (r'if\s*\(\s*(\w+)\s*(<=|<)\s*(\d+)\s*\)', 'upper_bound'),
        (r'if\s*\(\s*(\w+)\s*(>=|>)\s*(\d+)\s*\)', 'lower_bound'),
        (r'(\w+)\s*(>|<)\s*(\d+).*\{?\s*(\w+)\s*=\s*(\d+)', 'cap'),
        (r'(\w+)\s*=\s*\(\s*\w+\s*>\s*(\d+)\s*\)\s*\?\s*\2\s*:', 'cap'),
    ]

    def extract(self, ir_lines: list[str], var_names: set[str],
                window_start: int, window_end: int) -> dict[str, list[tuple[int, str, str]]]:
        """搜索守卫条件, 返回 {var: [(bound_value, op, type), ...]}."""
        guards: dict[str, list[tuple[int, str, str]]] = {}
        for i in range(max(0, window_start), min(len(ir_lines), window_end)):
            line = ir_lines[i]
            for pat, gtype in self._GUARD_PATTERNS:
                m = re.search(pat, line)
                if not m:
                    continue
                groups = m.groups()
                if groups[0] in var_names:
                    try:
                        bound = int(groups[1] if len(groups) > 2 else groups[-1], 0)
                        op = groups[1] if len(groups) > 2 else 'bound'
                    except (ValueError, TypeError):
                        continue
                    gv = guards.setdefault(groups[0], [])
                    gv.append((bound, op, gtype))
        return guards


__all__ = ['ValueFlowExtractor', 'GuardConditionExtractor']
