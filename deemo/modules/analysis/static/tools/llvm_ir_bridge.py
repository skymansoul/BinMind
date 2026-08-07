# 修改记录:
# 2025-08-13 09:30 - 安全元数据注入: 将二进制分析发现映射为 LLVM 函数属性+全局元数据
# 2025-08-13 15:18 - Hardening 遍选择: 基于注解类型推荐 Clang/GCC 安全编译选项
# 2025-08-16 12:05 - 修复元数据格式: 生成合法 LLVM IR 元数据节点 (!N = !{...})
# 2025-08-20 09:40 - 增加编译片段生成: 输出可直接 include 的 Makefile/CMake 安全选项片段

"""二进制分析->编译器安全选项的桥接映射

本模块聚合二进制分析的发现, 输出:
  1. 每函数的推荐编译器安全属性 (sanitize/stack-protector/cfi 等)
  2. 全局 LLVM IR 元数据节点--可被自定义 LLVM pass 消费
  3. Clang/GCC 命令行选项--可直接用于重编译

输出格式:
  - 函数属性: __attribute__((annotate("binsec:taint=NETWORK")))
  - LLVM 元数据: !binsec_0 = !{!"taint_source", !"func:read_input"}
  - 编译器选项: -fstack-protector-strong -fsanitize=cfi

适用场景: 假设二进制已被 Forklift/LeanBin 提升至 LLVM IR
本模块的输出作为重编译阶段的辅助输入--而非独立的 IR 变换遍
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# 安全注解类型

@dataclass
class SecurityAnnotation:
    """单个安全注解--二进制分析->IR 的映射"""
    annotation_type: str       # taint_source | crypto_primitive | exploit_primitive
                               # | ct_violation | heap_operation
    ir_location: str           # IR 中的位置: 'func:<name>' 或 'func:<name>:bb:<id>'
    binary_address: int = 0    # 原始二进制地址 (可追溯)
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnnotationReport:
    """安全注解报告"""
    total_annotations: int
    annotations_by_type: Dict[str, List[SecurityAnnotation]]
    # 推荐的 LLVM hardening 遍
    recommended_passes: List[str]
    # IR 元数据文本--可直接嵌入 .ll 文件
    ir_metadata_lines: List[str]


# 桥接器

class LLVMIRSecurityBridge:
    """将二进制分析结果桥接到 LLVM IR 安全注解

    用法:
    bridge = LLVMIRSecurityBridge()
    report = bridge.annotate(
        taint_findings=[...],
        crypto_findings=[...],
        exploit_findings=[...],
        ct_findings=[...],
    )
    # report.ir_metadata_lines 可嵌入 LLVM IR
    """

    # 注解类型->LLVM hardening 遍映射
    _ANNOTATION_TO_PASSES: Dict[str, List[str]] = {
        'taint_source': [
            '-mllvm -stack-protector-strong',
            '-fstack-protector-strong',
        ],
        'crypto_primitive': [
            '-mllvm -enable-constraint-elimination',
        ],
        'exploit_primitive': [
            '-mllvm -cfi-check-function-pointers',
            '-fsanitize=cfi',
        ],
        'ct_violation': [
            '-mllvm -speculative-load-hardening',
        ],
        'heap_operation': [
            '-mllvm -enable-gvn-hoist',
            '-fsanitize=address',
        ],
    }

    def annotate(
        self,
        taint_findings: Optional[List[Dict[str, Any]]] = None,
        crypto_findings: Optional[List[Dict[str, Any]]] = None,
        exploit_findings: Optional[List[Dict[str, Any]]] = None,
        ct_findings: Optional[List[Dict[str, Any]]] = None,
        heap_ops: Optional[List[Dict[str, Any]]] = None,
    ) -> AnnotationReport:
        """聚合所有二进制分析发现->生成 IR 注解

        每类 finding 格式: [{'function': str, 'address': int, 'confidence': float, ...}]

        返回 AnnotationReport 含 IR 元数据行 + 推荐 hardening 遍
        """
        annotations: Dict[str, List[SecurityAnnotation]] = defaultdict(list)
        all_passes: Set[str] = set()

        # 污点源
        for f in (taint_findings or []):
            ann = SecurityAnnotation(
                annotation_type='taint_source',
                ir_location=f"func:{f.get('function', 'unknown')}",
                binary_address=f.get('address', 0),
                confidence=f.get('confidence', 0.5),
                metadata={'taint_type': f.get('taint_type', 'unknown')},
            )
            annotations['taint_source'].append(ann)

        # 加密原语
        for f in (crypto_findings or []):
            ann = SecurityAnnotation(
                annotation_type='crypto_primitive',
                ir_location=f"func:{f.get('function', 'unknown')}",
                binary_address=f.get('offset', 0),
                confidence=f.get('confidence', 0.5),
                metadata={
                    'algorithm': f.get('algorithm', 'unknown'),
                    'size_hint': f.get('size_hint', 0),
                },
            )
            annotations['crypto_primitive'].append(ann)

        # 利用原语
        for f in (exploit_findings or []):
            ann = SecurityAnnotation(
                annotation_type='exploit_primitive',
                ir_location=f"func:{f.get('function', 'unknown')}",
                binary_address=f.get('address', 0),
                confidence=f.get('confidence', 0.5),
                metadata={
                    'primitive_type': f.get('primitive_type', 'unknown'),
                    'register': f.get('register', ''),
                },
            )
            annotations['exploit_primitive'].append(ann)

        # CT 违规
        for f in (ct_findings or []):
            ann = SecurityAnnotation(
                annotation_type='ct_violation',
                ir_location=f"func:{f.get('function_name', 'unknown')}",
                binary_address=f.get('address', 0),
                confidence=f.get('confidence', 0.5),
                metadata={
                    'violation_type': f.get('violation_type', 'unknown'),
                    'leakage_bits': f.get('leakage_bits', 0),
                },
            )
            annotations['ct_violation'].append(ann)

        # 堆操作
        for f in (heap_ops or []):
            ann = SecurityAnnotation(
                annotation_type='heap_operation',
                ir_location=f"func:{f.get('function', 'unknown')}",
                binary_address=f.get('address', 0),
                confidence=f.get('confidence', 0.5),
                metadata={
                    'heap_op': f.get('op_type', 'unknown'),
                    'size': f.get('size', 0),
                },
            )
            annotations['heap_operation'].append(ann)

        # 收集推荐的 LLVM passes
        total = 0
        for atype, anns in annotations.items():
            total += len(anns)
            if anns:
                passes = self._ANNOTATION_TO_PASSES.get(atype, [])
                all_passes.update(passes)

        # 生成 IR 元数据文本
        ir_lines = self._generate_ir_metadata(annotations)

        return AnnotationReport(
            total_annotations=total,
            annotations_by_type=dict(annotations),
            recommended_passes=sorted(all_passes),
            ir_metadata_lines=ir_lines,
        )

    def _generate_ir_metadata(
        self,
        annotations: Dict[str, List[SecurityAnnotation]],
    ) -> List[str]:
        """生成 LLVM IR 兼容的元数据--合法 !N = !{...} 格式

        每注解产生一个 LLVM 具名元数据节点
        格式: !binsec_N = !{!"type", !"location_str", f64 confidence}
        以及对应的函数属性字符串供 Clang 直接使用
        """
        lines = [
            '; ----------------------------------------',
            '; Binary Analysis Annotations for LLVM IR',
            '; Paste the !binsec_N lines into your .ll file',
            '; ----------------------------------------',
            '',
        ]

        meta_id = 0
        func_attrs: Dict[str, List[str]] = {}

        for atype, anns in annotations.items():
            for ann in anns:
                # 合法 LLVM 元数据: !binsec_N = !{!"type", !"loc", f64 conf}
                lines.append(
                    f'!binsec_{meta_id} = !{{'
                    f'!"{ann.annotation_type}", '
                    f'!"{ann.ir_location}", '
                    f'double {ann.confidence:.6f}'
                    f'}}'
                )
                # 收集函数属性
                func_name = ann.ir_location.replace('func:', '')
                if func_name not in func_attrs:
                    func_attrs[func_name] = []
                func_attrs[func_name].append(ann.annotation_type)
                meta_id += 1

        lines.append('')
        lines.append(f'; Total: {meta_id} metadata nodes')
        lines.append('')
        # 附加每函数的 GCC/Clang 属性建议
        lines.append('; --- Per-function attribute suggestions ---')
        for fname, atypes in sorted(func_attrs.items()):
            deduped = list(set(atypes))
            attr_str = ','.join(f'binsec:{t}' for t in deduped)
            lines.append(
                f'; __attribute__((annotate("{attr_str}"))) '
                f'void {fname}(void);'
            )

        return lines

    def generate_build_fragment(self, report: AnnotationReport) -> str:
        """生成可直接嵌入 Makefile/CMakeLists.txt 的编译选项片段

        根据检测到的注解类型, 输出对应编译器安全标志。
        产物可直接复制到构建系统中使用。
        """
        lines = ['# --- Binary Analysis Security Flags ---',
                 '# Generated by LLVMIRSecurityBridge',
                 '# Copy the relevant flags to your CFLAGS/CXXFLAGS',
                 '']

        # 去重并分类
        flags_by_category: Dict[str, List[str]] = {}
        for p in report.recommended_passes:
            if p.startswith('-f'):
                cat = 'SANITIZE'
            elif p.startswith('-mllvm'):
                cat = 'LLVM_EXTRA'
            else:
                cat = 'MISC'
            if cat not in flags_by_category:
                flags_by_category[cat] = []
            flags_by_category[cat].append(p)

        if 'SANITIZE' in flags_by_category:
            lines.append('# Sanitizer flags')
            lines.append('BINSEC_CFLAGS += ' + ' '.join(flags_by_category['SANITIZE']))
            lines.append('')

        if 'LLVM_EXTRA' in flags_by_category:
            lines.append('# Extra LLVM passes')
            for f in flags_by_category['LLVM_EXTRA']:
                lines.append(f'BINSEC_CFLAGS += {f}')
            lines.append('')

        lines.append('# Usage:')
        lines.append('#   make CFLAGS="$(BINSEC_CFLAGS)" target')
        lines.append('# Or in CMake:')
        lines.append('#   target_compile_options(my_target PRIVATE ${BINSEC_CFLAGS})')

        return '\n'.join(lines)
