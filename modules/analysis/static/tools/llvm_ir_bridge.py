# 安全元数据注入: 将二进制分析发现映射为 LLVM 函数属性+全局元数据
# Hardening 遍选择: 基于注解类型推荐 Clang/GCC 安全编译选项
# 修复元数据格式: 生成合法 LLVM IR 元数据节点 (!N = !{...})
# 增加编译片段生成: 输出可直接 include 的 Makefile/CMake 安全选项片段

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# 安全注解类型

@dataclass
class SecurityAnnotation:
    annotation_type: str       # taint_source | crypto_primitive | exploit_primitive
                               # | ct_violation | heap_operation
    ir_location: str           # func:<name> 或 func:<name>:bb:<id>
    binary_address: int = 0    # 原始二进制地址 (可追溯)
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnnotationReport:
    total_annotations: int
    annotations_by_type: Dict[str, List[SecurityAnnotation]]
    # 推荐的 LLVM hardening 遍
    recommended_passes: List[str]
    # IR 元数据文本, 可直接嵌入 .ll 文件
    ir_metadata_lines: List[str]


# 桥接器

class LLVMIRSecurityBridge:

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
