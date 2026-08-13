# coding: utf-8
"""
类型混淆检测 — CWE-843 (Access of Resource Using Incompatible Type).

核心洞察: C++ 类型混淆在二进制层面的可检测信号:
  1. vtable 指针被覆写 → 虚函数调用跳转到错误地址
  2. dynamic_cast 失败后仍使用指针 → 对象布局不匹配
  3. 基类指针 reinterpret_cast 到不兼容的派生类 → 字段偏移错位

二进制检测策略 (不需要符号表):
  S1: 对象构造检测 — 识别 vtable 指针写入模式 (object+0 = &vtable)
  S2: 类型转换检测 — 在调用点检查指针偏移是否匹配对象布局
  S3: 虚函数调用目标验证 — 检查 vtable 指针是否仍在合法范围内

三个分析层次:
  L1: vtable 写入/读取模式匹配 — 识别对象创建和使用
  L2: 类型层级不一致检测 — 检查同一指针的不同 cast 之间的布局冲突
  L3: 利用链分析 — 类型混淆 → vtable 劫持 → 任意代码执行

  - "TypeSan: Practical Type Confusion Detection"
  - "HexType: Efficient Detection of Type Confusion Errors"
  - "VTrust: Vtable hijacking detection"

"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

class TCOpType(Enum):
    """类型混淆相关操作类型."""
    VTABLE_WRITE = auto()      # object+0 = &vtable (构造函数)
    VTABLE_READ = auto()       # call [object+0+N] (虚函数调用)
    CAST_DYNAMIC = auto()      # dynamic_cast<D*>(base)
    CAST_STATIC = auto()       # static_cast<D*>(base)
    CAST_REINTERPRET = auto()  # reinterpret_cast<D*>(base)
    MEMBER_ACCESS = auto()     # object+offset 字段访问
    DELETE = auto()            # delete (析构函数 → vtable 写入)

@dataclass
class VtableInfo:
    """虚表信息."""
    vtable_addr: int           # 虚表地址
    object_type_size: int      # 对象大小 (从 vtable 推断)
    num_virtual_methods: int   # 虚函数数量
    method_addrs: List[int]    # 虚函数地址列表

@dataclass
class ObjectInfo:
    """对象实例信息."""
    obj_addr: int              # 对象地址
    vtable_addr: int           # 当前虚表指针值
    allocated_size: int        # 分配时的大小
    creation_site: int         # 构造函数地址
    type_name_hint: str = ''   # 类型名 (若可推断)

@dataclass
class TCDetection:
    """类型混淆检测结果."""
    address: int               # 检测点地址
    obj_info: ObjectInfo       # 涉及的对象
    expected_size: int         # 期望对象大小
    actual_size: int           # 实际对象大小
    op_type: TCOpType          # 触发操作类型
    confidence: float          # 置信度
    is_exploitable: bool       # 是否可被利用
    description: str

class TypeStateTracker:
    """对象类型状态追踪器.

    追踪对象的生命周期: 构造 → 类型转换 → 使用 → 析构.
    检测类型不一致: 同一个对象的不同 view 产生的字段偏移冲突.
    """

    def __init__(self):
        self._objects: Dict[int, ObjectInfo] = {}  # obj_addr → ObjectInfo
        self._vtables: Dict[int, VtableInfo] = {}  # vtable_addr → VtableInfo
        self._cast_history: Dict[int, List[Tuple[int, int]]] = {}
        # obj_addr → [(cast_type, expected_size)]

    def record_construction(self, obj_addr: int, vtable_addr: int,
                            alloc_size: int, site: int):
        """记录对象构造."""
        self._objects[obj_addr] = ObjectInfo(
            obj_addr=obj_addr, vtable_addr=vtable_addr,
            allocated_size=alloc_size, creation_site=site)
        self._cast_history[obj_addr] = [(alloc_size, site)]

    def record_vtable(self, vtable_addr: int, obj_size: int,
                      method_addrs: List[int]):
        """记录虚表信息."""
        self._vtables[vtable_addr] = VtableInfo(
            vtable_addr=vtable_addr, object_type_size=obj_size,
            num_virtual_methods=len(method_addrs),
            method_addrs=method_addrs)

    def record_cast(self, obj_addr: int, new_type_size: int,
                    cast_type: TCOpType, site: int):
        """记录类型转换."""
        if obj_addr in self._cast_history:
            self._cast_history[obj_addr].append((new_type_size, site))

    def check_type_confusion(self, obj_addr: int,
                             access_offset: int,
                             access_site: int) -> Optional[TCDetection]:
        """检查是否存在类型混淆.

        Args:
          obj_addr: 被访问的对象地址
          access_offset: 字段访问偏移
          access_site: 访问点地址

        Returns: TCDetection 或 None (安全).
        """
        if obj_addr not in self._objects:
            return None

        obj = self._objects[obj_addr]
        alloc_sz = obj.allocated_size

        # 检查访问偏移是否超出对象范围 (可能的类型混淆)
        if access_offset >= alloc_sz:
            return TCDetection(
                address=access_site,
                obj_info=obj,
                expected_size=alloc_sz,
                actual_size=access_offset + 8,  # 假设至少读 8 字节
                op_type=TCOpType.MEMBER_ACCESS,
                confidence=0.75,
                is_exploitable=True,
                description=(
                    f'字段访问偏移 {access_offset} 超出分配大小 {alloc_sz}, '
                    f'可能通过 reinterpret_cast 将基类指针转换为不兼容的派生类'),
            )

        # 检查历史 cast 是否有大小冲突
        history = self._cast_history.get(obj_addr, [])
        sizes = {sz for sz, _ in history}
        if len(sizes) >= 2:
            min_sz, max_sz = min(sizes), max(sizes)
            if max_sz > min_sz * 2:
                return TCDetection(
                    address=access_site,
                    obj_info=obj,
                    expected_size=min_sz,
                    actual_size=max_sz,
                    op_type=TCOpType.CAST_STATIC,
                    confidence=0.65,
                    is_exploitable=True,
                    description=(
                        f'类型转换大小冲突: 同一对象被解释为 {min_sz}B 和 '
                        f'{max_sz}B → 可能是错误的下行转换 (downcast)'),
                )

        return None

    def check_vtable_integrity(self, obj_addr: int,
                                expected_vtable: int,
                                site: int) -> Optional[TCDetection]:
        """检查 vtable 指针完整性."""
        if obj_addr not in self._objects:
            return None

        obj = self._objects[obj_addr]
        if obj.vtable_addr != expected_vtable:
            return TCDetection(
                address=site,
                obj_info=obj,
                expected_size=obj.allocated_size,
                actual_size=0,
                op_type=TCOpType.VTABLE_READ,
                confidence=0.90,
                is_exploitable=True,
                description=(
                    f'Vtable 指针被覆写: 期望 0x{expected_vtable:x}, '
                    f'实际 0x{obj.vtable_addr:x} → 可能 vtable 劫持'),
            )

        return None

def detect_type_confusion_from_ir(
    ir_ops: Dict[int, Dict], callee_names: Dict[int, str],
) -> Tuple[List[TCDetection], Dict]:
    """从 IR 操作中检测类型混淆.

    输入格式:
      ir_ops: {addr: {'op_type': str, 'dest': str, 'src': str, ...}}
      callee_names: {addr: 'function_name'}

    返回: (detections, stats).
    """
    tracker = TypeStateTracker()
    detections = []
    stats = {'objects': 0, 'casts': 0, 'vtables': 0, 'confusions': 0}

    # 按地址排序 IR 操作
    sorted_ops = sorted(ir_ops.items(), key=lambda x: x[0])

    for addr, op in sorted_ops:
        op_type = op.get('op_type', '')
        callee = callee_names.get(addr, '')

        # 检测对象构造 (malloc → vtable write)
        if op_type == 'store' and op.get('offset', 0) == 0:
            obj_addr = op.get('dest', 0)
            vtable = op.get('value', op.get('src', 0))
            alloc_sz = op.get('alloc_size', 0)
            if isinstance(obj_addr, int) and isinstance(vtable, int) and alloc_sz > 0:
                tracker.record_construction(obj_addr, vtable, alloc_sz, addr)
                stats['objects'] += 1

        # 检测 static_cast / reinterpret_cast (对象大小变化)
        elif callee in ('static_cast', 'reinterpret_cast', 'dynamic_cast'):
            obj_addr = op.get('src', 0)
            new_size = op.get('type_size', 0)
            cast_type = {
                'static_cast': TCOpType.CAST_STATIC,
                'reinterpret_cast': TCOpType.CAST_REINTERPRET,
                'dynamic_cast': TCOpType.CAST_DYNAMIC,
            }.get(callee, TCOpType.CAST_STATIC)

            if isinstance(obj_addr, int) and new_size > 0:
                tracker.record_cast(obj_addr, new_size, cast_type, addr)
                stats['casts'] += 1

        # 检测虚函数调用 (vtable read + call)
        elif op_type == 'load' and op.get('base', '') == 'vtable':
            obj_addr = op.get('obj', 0)
            access_offset = op.get('method_offset', 0)
            result = tracker.check_type_confusion(obj_addr, access_offset, addr)
            if result:
                detections.append(result)
                stats['confusions'] += 1

        # 检测字段访问偏移冲突
        elif op_type == 'load' and 'offset' in op:
            obj_addr = op.get('base', op.get('src', 0))
            access_offset = op.get('offset', 0)
            result = tracker.check_type_confusion(obj_addr, access_offset, addr)
            if result:
                detections.append(result)
                stats['confusions'] += 1

    return detections, stats

def demonstrate_vtable_hijack() -> Dict:
    """演示经典的 vtable 劫持场景.

    C++ 虚表劫持的工作原理:
      1. 对象布局: [vtable_ptr][field_1][field_2]...
      2. vtable: [&typeinfo][&method_0][&method_1]...
      3. 漏洞: vtable_ptr 被覆写 (通过堆溢出/UAF/类型混淆)
      4. 利用: 下次虚函数调用 → call [fake_vtable + offset] → 任意代码执行
    """
    return {
        'technique': 'Vtable hijacking via type confusion',
        'prerequisite_cve': ['CVE-2015-6097 (MS Office)', 'CVE-2016-0189 (IE)'],
        'steps': [
            '1. class Base { virtual void f(); }; class Derived : Base { int x; };',
            '2. Derived* d = new Derived;  // alloc 16B [vtable+8+4+padding]',
            '3. Base* b = reinterpret_cast<Base*>(d);  // 类型混淆',
            '4. 通过堆溢出覆写 b 的 vtable_ptr',
            '5. b->f();  // call [fake_vtable + 0] → 劫持 RIP',
        ],
        'our_detection': (
            '检测: (1) reinterpret_cast 后对象大小不一致, '
            '(2) vtable 指针不匹配期望值, '
            '(3) 虚函数调用目标在任何已知 vtable 之外'),
        'mitigation': 'CFI (Control Flow Integrity), Clang CFI, MS Control Flow Guard',
    }


import re as _re
from typing import Any as _Any, Dict as _Dict, List as _List, Optional as _Optional

_SUSPICIOUS_TYPES = {'void*', 'char*', 'unsigned char*', '__int8*'}
_HIGH_RISK_TYPES = {'void*', 'char*', 'unsigned char*'}


class TypeConfusionAnalyzer:
    """类型混淆分析器 —— 强转审计与虚表劫持风险评估。

    对反编译伪代码中的 static_cast / reinterpret_cast / C 风格强转
    进行识别，结合 void* 等可疑目标类型判定风险等级。
    """

    def __init__(self, binary_path: _Optional[str] = None):
        self.binary_path = binary_path
        self.suspicious_casts: _List[_Dict[str, _Any]] = []
        self.vtable_hijack_risk: _List[_Dict[str, _Any]] = []
        self.type_info: _Dict[str, _Any] = {}

    def _is_suspicious_conversion(self, from_type: str, var_name: str) -> bool:
        """判定目标类型是否为可疑的指针强转。"""
        return from_type.strip() in _SUSPICIOUS_TYPES

    def _is_high_risk(self, from_type: str) -> bool:
        """判定目标类型是否属于高危指针类型。"""
        return from_type.strip() in _HIGH_RISK_TYPES

    def _find_suspicious_casts(self, func_name: str,
                               pseudocode: str) -> _List[_Dict[str, _Any]]:
        """扫描伪代码中的可疑类型转换。"""
        casts: _List[_Dict[str, _Any]] = []
        if not pseudocode:
            return casts

        static_pat = _re.compile(r'static_cast\s*<([^>]+)>\s*\(([^)]*)\)')
        reinterpret_pat = _re.compile(r'reinterpret_cast\s*<([^>]+)>\s*\(([^)]*)\)')
        c_style_pat = _re.compile(r'\(\s*(\w+\s*\*?)\s*\)\s*(\w+)')

        for m in static_pat.finditer(pseudocode):
            target = m.group(1).strip()
            if self._is_suspicious_conversion(target, ''):
                casts.append({
                    'cast_type': 'static_cast',
                    'target_type': target,
                    'expression': m.group(2).strip(),
                    'function': func_name,
                    'risk': 'high' if self._is_high_risk(target) else 'low',
                })

        for m in reinterpret_pat.finditer(pseudocode):
            target = m.group(1).strip()
            casts.append({
                'cast_type': 'reinterpret_cast',
                'target_type': target,
                'expression': m.group(2).strip(),
                'function': func_name,
                'risk': 'high' if self._is_high_risk(target) else 'medium',
            })

        for m in c_style_pat.finditer(pseudocode):
            target = m.group(1).strip()
            casts.append({
                'cast_type': 'c_style_cast',
                'target_type': target,
                'expression': m.group(2),
                'function': func_name,
                'risk': 'high' if self._is_high_risk(target) else 'medium',
            })

        return casts

    def _extract_types_from_pseudocode(self, pseudocode: str) -> _Dict[str, _Any]:
        """提取伪代码中的类/结构体定义与对象方法调用。"""
        types: _Dict[str, _Any] = {}
        if not pseudocode:
            return types

        class_pat = _re.compile(r'class\s+(\w+)\s*\{(.*?)\}', _re.S)
        struct_pat = _re.compile(r'struct\s+(\w+)\s*\{(.*?)\}', _re.S)

        for m in class_pat.finditer(pseudocode):
            name = m.group(1)
            methods = _re.findall(r'(\w+)\s*\(', m.group(2))
            types[name] = {'type': 'class', 'methods': methods}

        for m in struct_pat.finditer(pseudocode):
            name = m.group(1)
            fields = _re.findall(r'([\w\s\*]+?)\s+(\w+)\s*;', m.group(2))
            types[name] = {
                'type': 'struct',
                'fields': [{'type': ft.strip(), 'name': fname}
                           for ft, fname in fields],
            }

        obj_pat = _re.compile(r'(\w+)\s*->\s*(\w+)\s*\(')
        obj_methods: _Dict[str, _List[str]] = {}
        for m in obj_pat.finditer(pseudocode):
            obj_methods.setdefault(m.group(1), []).append(m.group(2))
        for obj, methods in obj_methods.items():
            types[obj] = {'type': 'object', 'methods': methods}

        return types

    def _calculate_risk_level(self) -> str:
        """按可疑转换数量与虚表风险聚合风险等级。"""
        if self.vtable_hijack_risk:
            return 'high'

        high_count = sum(1 for c in self.suspicious_casts
                         if c.get('risk') == 'high')
        total = len(self.suspicious_casts)
        if high_count >= 2:
            return 'high'
        if high_count == 1 or total >= 3:
            return 'medium'
        if total >= 1:
            return 'low'
        return 'none'

    def generate_exploit(self, vuln_info: _Dict[str, _Any]) -> str:
        """生成类型混淆利用说明。"""
        func = vuln_info.get('function', 'unknown')
        target = vuln_info.get('target_type', 'unknown')
        return (
            f'Type Confusion exploit for {func}\n'
            f'target type: {target}\n'
            'attack: 诱导虚表劫持 (vtable hijack)\n'
            'CWE-843: Type Confusion\n'
        )

    def analyze(self) -> _Dict[str, _Any]:
        """执行分析并汇总结果。

        未设置 binary_path 时保留调用方预置的检测结果，
        仅在给定二进制路径时重新扫描。
        """
        if self.binary_path:
            pseudocode = ''
            try:
                with open(self.binary_path, 'r', errors='replace') as f:
                    pseudocode = f.read()
            except OSError:
                pseudocode = ''
            self.suspicious_casts = self._find_suspicious_casts('', pseudocode)
            self.type_info = self._extract_types_from_pseudocode(pseudocode)
            self.vtable_hijack_risk = (
                [{'risk': 'high'}]
                if any('vtable' in k.lower() for k in self.type_info)
                else []
            )

        return {
            'suspicious_casts': self.suspicious_casts,
            'vtable_hijack_risk': self.vtable_hijack_risk,
            'type_info': self.type_info,
            'risk_level': self._calculate_risk_level(),
        }
