"""Indirect call resolution: vtable dispatch, PLT stubs, function pointer tables."""

import re
import struct
from enum import Enum
from collections import defaultdict

name = "CallGraphEnhancer"
module = "call_graph_enhancer"

# pattern library -------------------------------------------------
_VTABLE_PAT = re.compile(
    rb'(?:lea|mov).*?(?:0x[0-9a-f]+)?\(.*?\)'   # rough LEA/MOV for vtable load
)
_PLT_SIG = rb'\xff\x25'                           # jmp *offset(%rip) / jmp [addr]
_FPTR_TABLE_SIG = re.compile(
    rb'\.quad\s+(0x[0-9a-f]+)'                    # function pointer arrays in .rodata
)
_CALL_INDIRECT = re.compile(
    rb'\xff[\x10\x11\x12\x13\x14\x15\x16\x17\x50\x51\x52\x53\x54\x55\x56\x57\x90\x91\x92\x93\x94\x95\x96\x97\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7]'
    rb'|'
    rb'\x41\xff[\x10\x11\x12\x13\x14\x15\x16\x17\x50\x51\x52\x53\x54\x55\x56\x57]'
)

# 反编译伪代码中的间接调用形态：虚表/对象方法、回调注册、函数指针调用。
# 按具体形态优先匹配：虚表索引调用先于普通对象方法，避免误吞。
_PSEUDO_INDIRECT_PAT = re.compile(
    r'(?P<vtable>\b\w+\s*->\s*v(?:ptr|table|tbl)\s*\[[^\]]*\]\s*\()'
    r'|(?P<method>\b\w+\s*->\s*\w+\s*\()'
    r'|(?P<callback>register\w*\s*\(\s*\w+)'
    r'|(?P<fptr>\b\w*(?:ptr|fn|func|handler|cb)\w*\s*\(\s*\))',
    re.IGNORECASE
)

# 汇编文本中的寄存器间接调用：call *reg
_CALL_REG_PAT = re.compile(r'\bcall\s+\*\s*([a-z][a-z0-9_]*)\b', re.IGNORECASE)


class IndirectCallType(Enum):
    VTABLE = "vtable"
    FUNCTION_POINTER = "function_pointer"
    FUNCTION_POINTER_ARRAY = "function_pointer_array"
    CALL_REGISTER = "call_register"
    CALLBACK = "callback"
    PLT_STUB = "plt_stub"
    UNKNOWN = "unknown"


class VTableInfo:
    def __init__(self, cls_name=None, methods=None, vtable_addr=None,
                 *, vtable_address=None, class_name=None, confidence=0.5):
        # 同时兼容旧式位置参数 (cls_name, methods, vtable_addr) 与新式关键字参数
        self.class_name = class_name if class_name is not None else cls_name
        self.methods = methods or []        # [(offset, func_name), ...]
        self.vtable_address = vtable_address if vtable_address is not None else vtable_addr
        self.confidence = confidence

    def resolve(self, offset):
        for m_offset, func_name in self.methods:
            if m_offset == offset:
                return func_name
        return None

    def to_dict(self):
        return {
            "vtable_address": self.vtable_address,
            "class_name": self.class_name,
            "methods": list(self.methods),
            "confidence": self.confidence,
        }


class IndirectCallSite:
    def __init__(self, call_id="", call_type=IndirectCallType.UNKNOWN, location="",
                 address=0, instruction="", source_register=None,
                 context=None, resolved_targets=None):
        self.call_id = call_id
        self.call_type = call_type
        self.location = location
        self.address = address
        self.instruction = instruction
        self.source_register = source_register
        self.context = context or {}
        self.resolved_targets = list(resolved_targets or [])

    def to_dict(self):
        return {
            "call_id": self.call_id,
            "call_type": self.call_type.value,
            "location": self.location,
            "address": self.address,
            "instruction": self.instruction,
            "source_register": self.source_register,
            "context": dict(self.context),
            "resolved_targets": list(self.resolved_targets),
        }


class FunctionPointerArray:
    def __init__(self, base_address=None, entries=None, *, array_address=None,
                 array_name=None, element_size=8, elements=None):
        # 兼容旧式位置参数 (base_address, entries)
        self.array_address = array_address if array_address is not None else base_address
        self.base_address = self.array_address
        self.array_name = array_name or ""
        self.element_size = element_size
        self.entries = entries if entries is not None else (elements or [])

    def lookup(self, offset):
        lo = 0; hi = len(self.entries) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            entry_offset, func_addr = self.entries[mid]
            if entry_offset == offset:
                return func_addr
            elif entry_offset < offset:
                lo = mid + 1
            else:
                hi = mid - 1
        return None


class FunctionInfo:
    # address 允许缺省：仅以函数名建图时无需地址
    def __init__(self, name, address=0, size=0):
        self.name = name
        self.address = address
        self.size = size
        self.callees = []
        self.callers = []
        self.is_exported = False

    def __repr__(self):
        return f"<Func {self.name} @ {self.address:#x}>"

class EnhancedCallGraph:
    def __init__(self, binary_name="unknown"):
        self.binary_name = binary_name
        self.functions = {}             # name -> FunctionInfo
        self.edges = defaultdict(set)   # caller -> {callee, ...}
        self.indirect_sites = []        # list of IndirectCallSite
        self.resolved_indirect = 0
        self.new_indirect_calls = 0
        self.vtables_discovered = 0
        self.original_functions = 0
        self.original_edges = 0

    def add_edge(self, caller, callee):
        self.edges[caller].add(callee)

    def get_callees(self, addr):
        return sorted(self.edges.get(addr, []))

    def stats(self):
        total = len(self.functions)
        resolved = self.resolved_indirect
        return {'total_functions': total, 'indirect_calls_resolved': resolved}

    def to_dict(self):
        return {
            "binary_name": self.binary_name,
            "new_indirect_calls": self.new_indirect_calls,
            "vtables_discovered": self.vtables_discovered,
            "original_functions": self.original_functions,
            "original_edges": self.original_edges,
            "statistics": self.stats(),
        }

    def to_dot(self):
        lines = ["digraph call_graph {"]
        for caller, callees in self.edges.items():
            for callee in sorted(callees):
                lines.append(f'  "{caller}" -> "{callee}";')
        lines.append("}")
        return "\n".join(lines)


class CallGraphEnhancer:
    """Resolve indirect calls in a call graph using binary pattern analysis."""

    def __init__(self, binary_path=None, binary_data=None):
        self.binary_name = binary_path if binary_path is not None else "unknown"
        self.min_confidence = 0.5
        self.indirect_calls = []        # 检测到的全部间接调用点
        self.vtables = {}               # addr -> VTableInfo
        self.fp_arrays = {}             # addr -> FunctionPointerArray
        self.functions = {}             # name -> FunctionInfo
        self._data = binary_data or b''
        self._plt_entries = {}          # addr -> func_name
        self._call_ids = set()

    def enhance(self, functions=None, call_graph=None, decomp_data=None):
        """Augment an existing call graph with resolved indirect calls."""
        if functions:
            for f in functions:
                fname = f.get("name")
                if not fname:
                    continue
                info = FunctionInfo(fname, f.get("address", 0), f.get("size", 0))
                for callee in f.get("calls", []) or []:
                    info.callees.append(callee)
                self.functions[fname] = info

        if decomp_data:
            self._analyze_indirect_calls_decomp(decomp_data)

        if isinstance(call_graph, dict):
            result = self._build_enhanced_call_graph(call_graph)
        else:
            result = EnhancedCallGraph(binary_name=self.binary_name)

        # 二进制数据存在时先扫描 PLT/虚表/函数指针表，供后续解析使用
        if self._data:
            self._parse_plt()
            self._find_vtables([f.address for f in self.functions.values() if f.address])
            self._find_fptr_tables()

        # for each indirect call site, try to resolve
        for call in self.indirect_calls:
            if call.call_type is IndirectCallType.CALLBACK:
                self._resolve_callback_call(call)
                if call.resolved_targets:
                    result.resolved_indirect += 1
            elif self._data:
                self._resolve_site(call, result)

        result.new_indirect_calls = len(self.indirect_calls)
        result.vtables_discovered = len(self.vtables)
        result.functions.update(self.functions)
        return result

    # -- internal resolvers -----------------------------------------------

    def _add_indirect_call(self, call_type, location, address, instruction,
                           source_register=None, context=None):
        # 同一调用点重复分析时按 call_id 去重，避免增强图统计膨胀
        call_id = f"{location}_{call_type.value}_{len(self.indirect_calls)}"
        if call_id in self._call_ids:
            return
        self._call_ids.add(call_id)
        call = IndirectCallSite(
            call_id=call_id, call_type=call_type, location=location,
            address=address, instruction=instruction,
            source_register=source_register, context=context,
        )
        self.indirect_calls.append(call)
        return call

    def _analyze_indirect_calls_decomp(self, decomp):
        """从反编译伪代码中识别虚表、对象方法、回调注册与函数指针调用点。"""
        for func_name, info in (decomp or {}).items():
            pseudo = (info or {}).get("pseudocode") or ""
            for m in _PSEUDO_INDIRECT_PAT.finditer(pseudo):
                if m.group("vtable") or m.group("method"):
                    call_type = IndirectCallType.VTABLE
                    instruction = m.group("vtable") or m.group("method")
                    context = {}
                elif m.group("callback"):
                    call_type = IndirectCallType.CALLBACK
                    instruction = m.group("callback")
                    name_m = re.search(r'\(\s*(\w+)', instruction)
                    context = {"callback_name": name_m.group(1)} if name_m else {}
                else:
                    call_type = IndirectCallType.FUNCTION_POINTER_ARRAY
                    instruction = m.group("fptr")
                    context = {}
                self._add_indirect_call(call_type, func_name, 0, instruction, context=context)

    def _analyze_indirect_calls_asm(self, asm_data):
        """从汇编文本中识别 call *reg 形式的寄存器间接调用。"""
        for func_name, info in (asm_data or {}).items():
            assembly = (info or {}).get("assembly") or ""
            for line in assembly.splitlines():
                for m in _CALL_REG_PAT.finditer(line):
                    self._add_indirect_call(
                        IndirectCallType.CALL_REGISTER, func_name, 0,
                        m.group(0), source_register=m.group(1),
                    )

    def add_vtable(self, address, class_name, methods):
        """登记一个已知虚函数表，供后续间接调用解析引用。"""
        vt = VTableInfo(vtable_address=address, class_name=class_name, methods=methods)
        self.vtables[address] = vt
        return vt

    def add_fp_array(self, address, array_name, elements):
        """登记一个已知函数指针数组，供后续间接调用解析引用。"""
        fpa = FunctionPointerArray(array_address=address, array_name=array_name,
                                   elements=elements or [])
        self.fp_arrays[address] = fpa
        return fpa

    def _resolve_callback_call(self, call):
        """按注册名在已登记函数中解析回调调用的目标。"""
        cname = (call.context or {}).get("callback_name")
        if not cname:
            return
        # 名称完全匹配优先；未命中时容忍尾部 _handler 之类的后缀变体
        if cname in self.functions:
            call.resolved_targets.append(cname)
            return
        for known in self.functions:
            if known == cname or known.endswith("_" + cname) or cname.endswith("_" + known):
                call.resolved_targets.append(known)
                return

    def _build_enhanced_call_graph(self, orig):
        """把 {caller: [callee, ...]} 原始图转成增强调用图并统计原始规模。"""
        result = EnhancedCallGraph(binary_name=self.binary_name)
        for caller, callees in orig.items():
            if caller not in result.functions:
                result.functions[caller] = FunctionInfo(caller)
            for callee in callees:
                if callee not in result.functions:
                    result.functions[callee] = FunctionInfo(callee)
                result.edges[caller].add(callee)
                result.original_edges += 1
        # 孤立函数（既无出边也无入边）计入 original_functions
        involved = set(result.edges.keys())
        for callees in result.edges.values():
            involved.update(callees)
        for fname in result.functions:
            if fname not in involved:
                result.original_functions += 1
        return result

    def _parse_plt(self):
        """Parse Procedure Linkage Table entries from ELF binaries."""
        if self._data[:4] != b'\x7fELF':
            return
        # scan for PLT stubs: ff 25 XX XX XX XX (jmp *offset(%rip))
        for m in re.finditer(rb'\xff\x25(....)', self._data):
            offset = struct.unpack('<i', m.group(1))[0]
            pos = m.start()
            self._plt_entries[pos] = f'plt_{len(self._plt_entries):04d}'

    def _find_vtables(self, known_func_addrs):
        """Locate vtable structures by scanning for function pointer arrays."""
        if not self._data:
            return
        known_addrs = set(known_func_addrs)

        # scan aligned pointer arrays in .rdata/.rodata
        step = 8  # 64-bit pointers
        for base in range(0, len(self._data) - step * 2, step):
            ptrs = []
            for i in range(20):  # up to 20 methods
                off = base + i * step
                if off + step > len(self._data):
                    break
                try:
                    val = struct.unpack_from('<Q', self._data, off)[0]
                except struct.error:
                    break
                if val in known_addrs:
                    ptrs.append((i * step, val))
                elif val == 0:
                    pass  # padding slot
                else:
                    break  # no longer a vtable
            if len(ptrs) >= 2:
                self.vtables[base] = VTableInfo(f'class_{base:#x}', ptrs, base)

    def _find_fptr_tables(self):
        """Find function pointer jump tables (common in switch cases)."""
        if not self._data:
            return
        for m in _FPTR_TABLE_SIG.finditer(self._data):
            addr = int(m.group(1), 16)
            base = m.start()
            entries = [(0, addr)]
            # scan consecutive entries
            for i in range(1, 32):
                off = m.start() + i * 8
                if off + 8 > len(self._data):
                    break
                try:
                    val = struct.unpack_from('<Q', self._data, off)[0]
                except struct.error:
                    break
                entries.append((i * 8, val))
            if len(entries) >= 3:
                self.fp_arrays[base] = FunctionPointerArray(base, entries)

    def _resolve_site(self, site, cg):
        """Attempt to match an indirect call site to known targets."""
        if not self._data or not site.address:
            return
        if site.address >= len(self._data):
            return

        # try PLT match
        if site.address in self._plt_entries:
            func_name = self._plt_entries[site.address]
            site.resolved_targets.append(func_name)
            cg.resolved_indirect += 1
            return

        # try vtable match: check nearby instructions for vtable base load
        window = self._data[max(0, site.address - 16):site.address + 8]
        for vt in self.vtables.values():
            # crude heuristic: if vtable address appears in instruction bytes
            vt_bytes = struct.pack('<Q', vt.vtable_address)
            if vt_bytes[:4] in window or vt_bytes[4:] in window:
                for m_offset, func_name in vt.methods:
                    site.resolved_targets.append(func_name)
                cg.resolved_indirect += 1
                return

        # try function pointer table match
        for fpa in self.fp_arrays.values():
            if abs(fpa.base_address - site.address) < 0x1000:
                for _, func_addr in fpa.entries:
                    site.resolved_targets.append(f'func_{func_addr:#x}')
                cg.resolved_indirect += 1
                return


# ── module-level shim ─────────────────────────────────────────────────────
def enhance_call_graph(binary_path="test.bin", functions=None, call_graph=None):
    """便捷入口：构造增强器并一次完成函数登记与调用图增强。"""
    enhancer = CallGraphEnhancer(binary_path=binary_path)
    return enhancer.enhance(functions=functions, call_graph=call_graph)
