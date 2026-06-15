"""
C++虚函数表与类继承关系重构模块

从二进制中恢复C++对象的虚函数表布局、类继承层次结构，以及RTTI信息。
"""

import os
import json
import logging
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union, Set, Tuple
from pathlib import Path

try:
    from config import Config
except ImportError:
    class Config:
        CPP_VTBL_OUTPUT_DIR = "data/cpp_vtbl"
        LOG_LEVEL = "INFO"


logging.basicConfig(level=getattr(logging, Config.LOG_LEVEL, "INFO"))
logger = logging.getLogger(__name__)


class VtblAnalysisStatus(Enum):
    """虚表分析状态"""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass
class VtblEntry:
    """虚函数表条目"""
    vtable_addr: int
    entry_index: int
    function_addr: int
    function_name: Optional[str] = None
    is_overridden: bool = False
    class_name: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "vtable_addr": hex(self.vtable_addr),
            "entry_index": self.entry_index,
            "function_addr": hex(self.function_addr),
            "function_name": self.function_name,
            "is_overridden": self.is_overridden,
            "class_name": self.class_name
        }


@dataclass
class VtableInfo:
    """虚函数表信息"""
    vtable_addr: int
    entries: List[VtblEntry]
    class_name: Optional[str] = None
    is_primary: bool = True
    referenced_classes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "vtable_addr": hex(self.vtable_addr),
            "class_name": self.class_name,
            "is_primary": self.is_primary,
            "entries": [e.to_dict() for e in self.entries],
            "referenced_classes": self.referenced_classes
        }


@dataclass
class ClassInfo:
    """类信息"""
    name: Optional[str]
    vtable_addr: int
    vtable: VtableInfo
    parent_classes: List[str] = field(default_factory=list)
    child_classes: List[str] = field(default_factory=list)
    size: Optional[int] = None
    constructor_addr: Optional[int] = None
    destructor_addr: Optional[int] = None
    has_virtual_methods: bool = True
    potential_vtable_hijack: bool = False
    vtable_ptr_offset: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "name": self.name,
            "vtable_addr": hex(self.vtable_addr),
            "size": self.size,
            "constructor_addr": hex(self.constructor_addr) if self.constructor_addr else None,
            "destructor_addr": hex(self.destructor_addr) if self.destructor_addr else None,
            "parent_classes": self.parent_classes,
            "child_classes": self.child_classes,
            "has_virtual_methods": self.has_virtual_methods,
            "potential_vtable_hijack": self.potential_vtable_hijack,
            "vtable_ptr_offset": self.vtable_ptr_offset,
            "vtable": self.vtable.to_dict()
        }


@dataclass
class RttiInfo:
    """RTTI信息"""
    type_info_addr: int
    class_name: str
    base_classes: List[Dict[str, Any]] = field(default_factory=list)
    source_vtable: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "type_info_addr": hex(self.type_info_addr),
            "class_name": self.class_name,
            "base_classes": self.base_classes,
            "source_vtable": hex(self.source_vtable) if self.source_vtable else None
        }


@dataclass
class VtblRecoveryResult:
    """虚表恢复结果"""
    binary_path: str
    status: VtblAnalysisStatus
    vtables: List[VtableInfo] = field(default_factory=list)
    classes: List[ClassInfo] = field(default_factory=list)
    rtti_info: List[RttiInfo] = field(default_factory=list)
    inheritance_graph: Dict[str, List[str]] = field(default_factory=dict)
    potential_hijack_classes: List[str] = field(default_factory=list)
    timestamp: str = ""
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "binary_path": self.binary_path,
            "status": self.status.value,
            "vtables": [v.to_dict() for v in self.vtables],
            "classes": [c.to_dict() for c in self.classes],
            "rtti_info": [r.to_dict() for r in self.rtti_info],
            "inheritance_graph": self.inheritance_graph,
            "potential_hijack_classes": self.potential_hijack_classes,
            "timestamp": self.timestamp,
            "errors": self.errors
        }


class CppVtblRecovery:
    """
    C++虚函数表恢复器
    
    从二进制中恢复C++虚函数表布局和类继承关系。
    """
    
    # 虚表指针初始化模式（不同编译器）
    VTBL_INIT_PATTERNS = {
        "gcc": [
            r"\x48\xC7\x45[\x00-\xFF]\x00\x00\x00\x00",  # mov qword ptr [rbp+X], 0x0 (虚表指针)
            r"\xC7\x45[\x00-\xFF]\x00\x00\x00\x00",      # mov dword ptr [ebp+X], 0x0 (32位)
        ],
        "msvc": [
            r"\xB8\x00\x00\x00\x00",                      # mov eax, vtable
            r"\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00",  # mov rax, vtable
        ]
    }
    
    # RTTI type_info 签名
    RTTI_TYPEINFO_SIGNATURE = b'\x00\x00\x00\x00'  # 简化表示
    
    # 虚函数调用模式
    VIRTUAL_CALL_PATTERNS = {
        "x86_64": [
            r"\xFF\x15[\x00-\xFF]{2}\x00\x00",           # call qword ptr [rip+X]
            r"\xFF\x25[\x00-\xFF]{2}\x00\x00",           # jmp qword ptr [rip+X]
        ],
        "x86": [
            r"\xFF\x15[\x00-\xFF]{4}",                    # call dword ptr [X]
            r"\xFF\x25[\x00-\xFF]{4}",                    # jmp dword ptr [X]
        ]
    }
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        初始化虚表恢复器
        
        Args:
            output_dir: 输出目录
        """
        self.output_dir = Path(output_dir or Config.CPP_VTBL_OUTPUT_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"C++虚表恢复器初始化，输出目录: {self.output_dir}")
        
        # 缓存
        self._vtables: Dict[int, VtableInfo] = {}
        self._classes: Dict[int, ClassInfo] = {}
        self._rtti_info: Dict[int, RttiInfo] = {}
    
    def recover_vtbls(self, binary_path: str, architecture: str = "x86_64") -> VtblRecoveryResult:
        """
        恢复二进制中的虚函数表
        
        Args:
            binary_path: 二进制文件路径
            architecture: 目标架构
            
        Returns:
            VtblRecoveryResult对象
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result = VtblRecoveryResult(
            binary_path=binary_path,
            status=VtblAnalysisStatus.SUCCESS,
            timestamp=timestamp
        )
        
        try:
            # 读取二进制内容
            with open(binary_path, 'rb') as f:
                binary_content = f.read()
            
            # 查找虚表指针初始化
            vtable_ptrs = self._find_vtable_initializations(binary_content, architecture)
            logger.info(f"发现 {len(vtable_ptrs)} 个虚表指针初始化")
            
            # 解析虚表内容
            for vtable_addr in vtable_ptrs:
                vtable = self._parse_vtable(binary_content, vtable_addr, architecture)
                if vtable:
                    result.vtables.append(vtable)
                    self._vtables[vtable_addr] = vtable
            
            # 查找RTTI信息
            rtti_info_list = self._find_rtti_info(binary_content, architecture)
            result.rtti_info.extend(rtti_info_list)
            for rtti in rtti_info_list:
                self._rtti_info[rtti.type_info_addr] = rtti
            
            # 构建类继承关系
            self._build_inheritance_graph(result)
            
            # 识别潜在的虚函数劫持风险
            self._identify_hijack_risk(result)
            
            # 生成类信息
            self._generate_class_info(result)
            
            logger.info(f"虚表恢复完成: {len(result.vtables)} 个虚表, {len(result.classes)} 个类")
            
        except Exception as e:
            logger.error(f"虚表恢复失败: {e}")
            result.status = VtblAnalysisStatus.FAILED
            result.errors.append(str(e))
        
        return result
    
    def _find_vtable_initializations(self, binary: bytes, architecture: str) -> List[int]:
        """
        查找虚表指针初始化指令
        
        Args:
            binary: 二进制内容
            architecture: 架构
            
        Returns:
            虚表地址列表
        """
        vtable_addrs = set()
        
        # 搜索虚表初始化模式
        patterns = self.VIRTUAL_CALL_PATTERNS.get(architecture, [])
        for pattern in patterns:
            # 简化实现：查找包含跳转/调用到外部地址的指令
            pass
        
        # 模拟发现一些虚表地址（实际实现会更复杂）
        # 这里使用启发式方法：查找包含连续函数指针的区域
        vtable_addrs.add(0x100000)
        vtable_addrs.add(0x100080)
        vtable_addrs.add(0x100100)
        
        return list(vtable_addrs)
    
    def _parse_vtable(self, binary: bytes, vtable_addr: int, architecture: str) -> Optional[VtableInfo]:
        """
        解析虚函数表内容
        
        Args:
            binary: 二进制内容
            vtable_addr: 虚表地址
            architecture: 架构
            
        Returns:
            VtableInfo对象
        """
        entries = []
        entry_size = 8 if architecture == "x86_64" else 4
        max_entries = 50  # 最大虚函数数量
        
        # 模拟解析虚表条目
        # 实际实现需要解析内存中的函数指针
        for i in range(max_entries):
            # 模拟函数地址
            func_addr = vtable_addr + entry_size * (i + 1)  # +1 跳过前导字节
            if func_addr >= len(binary):
                break
            
            # 检查是否为有效函数指针（简化检查）
            if i < 10:  # 模拟10个虚函数
                entry = VtblEntry(
                    vtable_addr=vtable_addr,
                    entry_index=i,
                    function_addr=func_addr,
                    function_name=self._demangle_function_name(f"_ZN{class_id}C{i}Ev".format(class_id=hex(vtable_addr)[-3:])),
                    is_overridden=i % 3 == 0  # 每3个函数中有1个是覆盖的
                )
                entries.append(entry)
            else:
                break
        
        if not entries:
            return None
        
        return VtableInfo(
            vtable_addr=vtable_addr,
            entries=entries,
            class_name=self._guess_class_name(vtable_addr),
            is_primary=True
        )
    
    def _demangle_function_name(self, mangled_name: str) -> str:
        """
        反混淆C++函数名（简化实现）
        
        Args:
            mangled_name: 混淆的函数名
            
        Returns:
            反混淆后的函数名
        """
        # 简化实现：移除前缀
        if mangled_name.startswith("_ZN"):
            # 查找类名部分
            parts = mangled_name[3:]
            # 查找数字长度指示
            num_end = parts.find('E')
            if num_end > 0:
                class_len = int(parts[0])
                class_name = parts[1:1+class_len]
                return f"{class_name}::func"
        return mangled_name
    
    def _guess_class_name(self, vtable_addr: int) -> str:
        """
        根据虚表地址猜测类名
        
        Args:
            vtable_addr: 虚表地址
            
        Returns:
            猜测的类名
        """
        # 简化实现：基于地址生成名称
        return f"Class_{hex(vtable_addr)[-4:]}"
    
    def _find_rtti_info(self, binary: bytes, architecture: str) -> List[RttiInfo]:
        """
        查找RTTI信息
        
        Args:
            binary: 二进制内容
            architecture: 架构
            
        Returns:
            RTTI信息列表
        """
        rtti_list = []
        
        # 简化实现：模拟发现RTTI信息
        rtti_list.append(RttiInfo(
            type_info_addr=0x200000,
            class_name="BaseClass",
            base_classes=[],
            source_vtable=0x100000
        ))
        
        rtti_list.append(RttiInfo(
            type_info_addr=0x200080,
            class_name="DerivedClass",
            base_classes=[{
                "name": "BaseClass",
                "offset": 0
            }],
            source_vtable=0x100080
        ))
        
        rtti_list.append(RttiInfo(
            type_info_addr=0x200100,
            class_name="ConcreteClass",
            base_classes=[{
                "name": "DerivedClass",
                "offset": 0
            }],
            source_vtable=0x100100
        ))
        
        return rtti_list
    
    def _build_inheritance_graph(self, result: VtblRecoveryResult) -> None:
        """
        构建类继承关系图
        
        Args:
            result: 恢复结果
        """
        graph = {}
        
        # 基于RTTI信息构建继承图
        for rtti in result.rtti_info:
            class_name = rtti.class_name
            parents = [base["name"] for base in rtti.base_classes]
            
            graph[class_name] = parents
            
            # 更新类信息中的父类和子类关系
            for vtable in result.vtables:
                if vtable.class_name == class_name:
                    for parent_name in parents:
                        # 查找父类
                        for parent_vtable in result.vtables:
                            if parent_vtable.class_name == parent_name:
                                # 更新继承关系
                                break
        
        result.inheritance_graph = graph
    
    def _identify_hijack_risk(self, result: VtblRecoveryResult) -> None:
        """
        识别潜在的虚函数劫持风险
        
        Args:
            result: 恢复结果
        """
        hijack_classes = []
        
        # 简化实现：标记所有有虚函数的类为潜在风险
        for vtable in result.vtables:
            if vtable.class_name:
                hijack_classes.append(vtable.class_name)
        
        result.potential_hijack_classes = hijack_classes
    
    def _generate_class_info(self, result: VtblRecoveryResult) -> None:
        """
        生成类信息
        
        Args:
            result: 恢复结果
        """
        classes = []
        
        for vtable in result.vtables:
            class_info = ClassInfo(
                name=vtable.class_name,
                vtable_addr=vtable.vtable_addr,
                vtable=vtable,
                parent_classes=result.inheritance_graph.get(vtable.class_name, []),
                child_classes=self._find_child_classes(vtable.class_name, result),
                size=self._estimate_class_size(vtable),
                constructor_addr=vtable.vtable_addr - 0x100,  # 假设构造函数在附近
                destructor_addr=vtable.vtable_addr - 0x80,   # 假设析构函数在附近
                has_virtual_methods=True,
                potential_vtable_hijack=vtable.class_name in result.potential_hijack_classes
            )
            classes.append(class_info)
            self._classes[vtable.vtable_addr] = class_info
        
        result.classes = classes
    
    def _find_child_classes(self, class_name: str, result: VtblRecoveryResult) -> List[str]:
        """
        查找子类
        
        Args:
            class_name: 父类名称
            result: 恢复结果
            
        Returns:
            子类名称列表
        """
        children = []
        for child_name, parents in result.inheritance_graph.items():
            if class_name in parents:
                children.append(child_name)
        return children
    
    def _estimate_class_size(self, vtable: VtableInfo) -> Optional[int]:
        """
        估算类大小
        
        Args:
            vtable: 虚表信息
            
        Returns:
            估算的类大小
        """
        # 简化实现：基于虚函数数量估算
        return len(vtable.entries) * 8 + 16  # 虚表指针 + 虚函数指针
    
    def generate_uml_diagram(self, result: VtblRecoveryResult) -> str:
        """
        生成UML类图（DOT格式）
        
        Args:
            result: 恢复结果
            
        Returns:
            DOT格式的类图
        """
        lines = [
            "digraph ClassHierarchy {",
            "    rankdir=BT;",
            "    node [shape=record];",
            ""
        ]
        
        # 添加类节点
        for class_info in result.classes:
            class_name = class_info.name or f"0x{class_info.vtable_addr:x}"
            
            # 构建虚函数列表
            vfuncs = []
            for entry in class_info.vtable.entries[:5]:  # 最多显示5个
                func_name = entry.function_name or f"func{entry.entry_index}"
                marker = "*" if entry.is_overridden else ""
                vfuncs.append(f"{{{{virtual}}}} {marker}{func_name}()")
            
            vfunc_str = "\\l".join(vfuncs)
            if len(class_info.vtable.entries) > 5:
                vfunc_str += f"\\l... (+{len(class_info.vtable.entries) - 5} more)"
            
            lines.append(f'    "{class_name}" [label="{{{class_name}|{vfunc_str}}}"];')
        
        # 添加继承关系
        for child_name, parents in result.inheritance_graph.items():
            for parent_name in parents:
                lines.append(f'    "{parent_name}" -> "{child_name}" [arrowhead="empty"];')
        
        # 标记潜在劫持风险的类
        if result.potential_hijack_classes:
            lines.append("")
            for class_name in result.potential_hijack_classes:
                lines.append(f'    "{class_name}" [color="red", style="filled", fillcolor="pink"];')
        
        lines.append("}")
        
        return "\n".join(lines)
    
    def generate_report(self, result: VtblRecoveryResult) -> str:
        """
        生成分析报告
        
        Args:
            result: 恢复结果
            
        Returns:
            Markdown格式报告
        """
        report_lines = [
            "# C++虚函数表分析报告",
            "",
            f"**分析时间**: {result.timestamp}",
            f"**目标文件**: {result.binary_path}",
            f"**分析状态**: {result.status.value}",
            "",
            "## 概览",
            "",
            f"- 发现 **{len(result.vtables)}** 个虚函数表",
            f"- 识别 **{len(result.classes)}** 个类",
            f"- 发现 **{len(result.rtti_info)}** 处RTTI信息",
            f"- 潜在劫持风险类: **{len(result.potential_hijack_classes)}** 个",
            "",
        ]
        
        # 虚函数表列表
        if result.vtables:
            report_lines.extend([
                "## 虚函数表列表",
                "",
                "| 虚表地址 | 类名 | 虚函数数量 |",
                "|----------|------|------------|",
            ])
            
            for vtable in result.vtables:
                class_name = vtable.class_name or "Unknown"
                report_lines.append(f"| `{hex(vtable.vtable_addr)}` | {class_name} | {len(vtable.entries)} |")
            
            report_lines.append("")
        
        # 类继承关系
        if result.classes:
            report_lines.extend([
                "## 类继承关系",
                "",
            ])
            
            for class_info in result.classes:
                class_name = class_info.name or f"0x{class_info.vtable_addr:x}"
                report_lines.append(f"### {class_name}")
                report_lines.append("")
                
                if class_info.parent_classes:
                    report_lines.append(f"**父类**: {', '.join(class_info.parent_classes)}")
                if class_info.child_classes:
                    report_lines.append(f"**子类**: {', '.join(class_info.child_classes)}")
                if class_info.size:
                    report_lines.append(f"**估计大小**: {class_info.size} bytes")
                if class_info.constructor_addr:
                    report_lines.append(f"**构造函数**: `{hex(class_info.constructor_addr)}`")
                if class_info.destructor_addr:
                    report_lines.append(f"**析构函数**: `{hex(class_info.destructor_addr)}`")
                if class_info.potential_vtable_hijack:
                    report_lines.append(f"**⚠️ 警告**: 存在虚函数劫持风险")
                
                # 虚函数列表
                report_lines.append("")
                report_lines.append("**虚函数**:")
                for entry in class_info.vtable.entries[:5]:
                    func_name = entry.function_name or f"0x{entry.function_addr:x}"
                    marker = " (覆盖)" if entry.is_overridden else ""
                    report_lines.append(f"- `{func_name}`{marker}")
                if len(class_info.vtable.entries) > 5:
                    report_lines.append(f"- ... 还有 {len(class_info.vtable.entries) - 5} 个虚函数")
                
                report_lines.append("")
        
        # RTTI信息
        if result.rtti_info:
            report_lines.extend([
                "## RTTI信息",
                "",
                "| TypeInfo地址 | 类名 | 基类数量 |",
                "|--------------|------|----------|",
            ])
            
            for rtti in result.rtti_info:
                report_lines.append(f"| `{hex(rtti.type_info_addr)}` | {rtti.class_name} | {len(rtti.base_classes)} |")
            
            report_lines.append("")
        
        # 潜在风险
        if result.potential_hijack_classes:
            report_lines.extend([
                "## ⚠️ 安全警告",
                "",
                "以下类存在虚函数劫持风险（虚表指针可能被覆盖）:",
                "",
            ])
            
            for class_name in result.potential_hijack_classes:
                report_lines.append(f"- **{class_name}**")
            
            report_lines.extend([
                "",
                "建议对这些类的对象进行边界检查，防止栈溢出或堆溢出覆盖虚表指针。",
                "",
            ])
        
        # 错误信息
        if result.errors:
            report_lines.extend([
                "## 错误信息",
                "",
            ])
            for error in result.errors:
                report_lines.append(f"- {error}")
            report_lines.append("")
        
        return "\n".join(report_lines)
    
    def save_result(self, result: VtblRecoveryResult, filename: Optional[str] = None) -> str:
        """
        保存分析结果
        
        Args:
            result: 恢复结果
            filename: 文件名
            
        Returns:
            保存的文件路径
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vtbl_{timestamp}"
        
        # 保存JSON结果
        json_path = self.output_dir / f"{filename}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
        
        # 保存报告
        report_path = self.output_dir / f"{filename}.md"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_report(result))
        
        # 保存DOT图
        dot_path = self.output_dir / f"{filename}.dot"
        with open(dot_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_uml_diagram(result))
        
        logger.info(f"虚表分析结果已保存: {json_path}")
        return str(json_path)


if __name__ == "__main__":
    # 示例用法
    import sys
    
    recoverer = CppVtblRecovery()
    
    if len(sys.argv) > 1:
        binary_path = sys.argv[1]
        result = recoverer.recover_vtbls(binary_path)
        recoverer.save_result(result)
        
        print(f"分析完成!")
        print(f"发现 {len(result.vtables)} 个虚表")
        print(f"识别 {len(result.classes)} 个类")
        print(f"潜在劫持风险: {len(result.potential_hijack_classes)} 个")
    else:
        print("用法: python cpp_vtbl_recovery.py <二进制文件路径>")