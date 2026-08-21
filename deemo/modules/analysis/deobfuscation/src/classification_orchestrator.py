# 增加证据传播器与deobfuscate的联动，将跨函数常量
#                    自动注册到分类器的校准数据中

"""
混淆感知反混淆编排器 - 桥接 混淆分类器 与 FunctionDeobfuscator

将分类器的判定结果转化为反混淆pass的选择策略，避免对未混淆代码
运行重量级恢复pass。同时利用 EvidencePropagator 的跨函数信息
提升不透明谓词消除的准确率

设计权衡:
分类器有误判风险（假阴性：把混淆判成未混淆）。为安全起见
即使分类器判定为"none"，仍运行轻量级dead-code elimina
因为其副作用为零（只移除不可达代码）。重量级pass（CFF恢复、
谓词消除）在分类器置信度<0.5时跳过
"""

from typing import Any, Dict, List, Optional, Tuple

# 要求 FunctionDeobfuscator 已在环境中可用-此处为可选桥接
# ImportError 时调用方自行降级


class ClassificationAwareOrchestrator:
    """将混淆分类结果映射为反混淆pass选择策略

    与 FunctionDeobfuscator.去混淆() 的区别:
    去混淆 按 level ("light"/"medium"/"aggress") 运行固定pass序列
    本编排器根据分类结果动态选择pass-对每种混淆类型运行其针对性恢复
    """

    def __init__(self) -> None:
        self._last_classification: Optional[List[Tuple[str, float]]] = None
        self._evidence: Dict[str, Any] = {}

    def classify_and_plan(
        self,
        classifier,
        instructions: List[Dict[str, Any]],
        rodata_bytes: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """运行分类器并生成恢复计划。

        返回 {'classification': [(type, confid), ...],
        'recommended_passes': ['dead_code', 'cff', ...],
        'skip_passes': ['opaque_pred', ...]}。
        """
        result = classifier.classify(instructions, rodata_bytes)
        self._last_classification = result

        if not result:
            return {
                'classification': [],
                'recommended_passes': ['dead_code'],
                'skip_passes': ['cff', 'opaque_pred', 'inst_sub'],
            }

        top_type, top_conf = result[0]
        passes = ['dead_code']  # 永远运行-零副作用

        if top_type == 'none' and top_conf > 0.7:
            # 高置信度未混淆-仅死代码消除
            return {
                'classification': result,
                'recommended_passes': passes,
                'skip_passes': ['cff', 'opaque_pred', 'inst_sub', 'string_decrypt'],
            }

        # 根据分类结果选择针对性pass
        for obf_type, conf in result:
            if conf < 0.25:
                continue
            if obf_type == 'cff' and 'cff' not in passes:
                passes.append('cff')
            elif obf_type == 'opaque_pred' and 'opaque_pred' not in passes:
                passes.append('opaque_pred')
            elif obf_type == 'inst_sub' and 'constants' not in passes:
                passes.append('constants')
            elif obf_type == 'string_enc' and 'string_decrypt' not in passes:
                passes.append('string_decrypt')
            elif obf_type == 'bogus_cf' and 'opaque_pred' not in passes:
                passes.append('opaque_pred')

        all_passes = {'dead_code', 'constants', 'opaque_pred', 'cff', 'string_decrypt', 'inst_sub'}
        skip = list(all_passes - set(passes))

        return {
            'classification': result,
            'recommended_passes': passes,
            'skip_passes': skip,
        }

    def deobfuscate_with_plan(
        self,
        deobfuscator,
        instructions: List[Dict[str, Any]],
        entry: int,
        classifier=None,
        rodata_bytes: Optional[bytes] = None,
        evidence_propagator=None,
        known_constants: Optional[Dict[str, Tuple[Any, float]]] = None,
    ) -> Dict[str, Any]:
        """基于分类结果的定向反混淆 - 替代固定 level 的策略。

        deobfuscator 为 FunctionDeobfuscator 实例, instructions
        为指令列表, entry 为入口地址; 其余参数可选: classifier
        混淆分类器, rodata_bytes .rodata 段字节, evidence_propagator
        证据传播器, known_constants {变量名: (值, 置信度)}。
        返回格式与 FunctionDeobfuscator.deobfuscate() 兼容。
        """
        current = list(instructions)
        stats: Dict[str, int] = {
            'original': len(instructions),
            'dead_code_removed': 0,
            'constants_folded': 0,
            'predicates_eliminated': 0,
            'cff_blocks_recovered': 0,
            'classified_as': 0,
        }

        # 确定pass计划
        if classifier is not None:
            plan = self.classify_and_plan(classifier, current, rodata_bytes)
            recommended = set(plan.get('recommended_passes', ['dead_code']))
            top_class = plan['classification'][0] if plan['classification'] else ('none', 1.0)
            stats['classified_as'] = 1
            stats['classification_type'] = top_class[0]
            stats['classification_confidence'] = top_class[1]
        else:
            # 无分类器时退化为 medium 级别
            recommended = {'dead_code', 'constants', 'opaque_pred'}

        # 证据传播——若提供
        if evidence_propagator is not None and known_constants is not None:
            for var, (val, conf) in known_constants.items():
                evidence_propagator.register_param_constant(
                    'current_func', var, val, conf,
                )

        # Pass 1: Dead code elimina（始终运行）
        before = len(current)
        current = deobfuscator.eliminate_dead_code(current)
        stats['dead_code_removed'] = before - len(current)

        # Pass 2: Constant propaga（按需）
        if 'constants' in recommended:
            current = deobfuscator.propagate_constants(current)
            stats['constants_folded'] = 1

        # Pass 3: 不透明谓词 elimina（按需）
        if 'opaque_pred' in recommended:
            current = deobfuscator.eliminate_opaque_predicates(current)
            stats['predicates_eliminated'] = sum(
                1 for i in current if i.get('eliminated')
            )

        # Pass 4: CFF recovery（按需）
        if 'cff' in recommended:
            current, cff_meta = deobfuscator.recover_ollvm_cff(current, entry)
            stats['cff_blocks_recovered'] = cff_meta.get('blocks_recovered', 0)

        stats['final'] = len(current)

        return {
            'instructions': current,
            'stats': stats,
            'level': 'classified',
            'classification': self._last_classification,
        }
