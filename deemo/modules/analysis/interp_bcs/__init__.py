# interp_bcs/ - 可解释特征二进制相似性 + 神经反编译等价校验
#
# 概览:
# features.py：- 可解释特征提取
# equivalence.py：- 细粒度等价校验
# 签名.py：- 组合约束签名恢复
#
# 设计意图:
#   现有反编译/相似性依赖端到端嵌入，是黑盒。本包在其上叠加三层
# 可解释性: 结构化语义特征、等价性证明/反例、跨架构签名约束
# 把相似性判定从"分数"降级为"证据链"
#
# 使用:
#   from modules.analysis.interp_bcs import analyze_function_bcs
#   report = analyze_function_bcs(decompiled_text, reference=ref_text)

import logging
from typing import Any, Dict, List, Optional, Tuple

from .features import (
    CfgMorphology,
    ConstantStats,
    CallPattern,
    StringRef,
    FunctionFeature,
    FeatureExtractor,
    SimilarityReport,
    InterpretableSimilarity,
)
from .equivalence import (
    EquivVerdict,
    EquivResult,
    EquivalenceChecker,
)
from .signature import (
    RecoveredSignature,
    SignatureRecoverer,
    normalize_arch,
)

logger = logging.getLogger(__name__)

__version__ = "0.1.0"

# 模块级单例：解析/相似度/等价/签名器均无状态或仅含可复用缓存
_feature_extractor = FeatureExtractor()
_similarity = InterpretableSimilarity()
_equivalence = EquivalenceChecker()
_signature_recoverer = SignatureRecoverer()


def extract_features(pseudocode: Optional[str],
                     function_name: str = '') -> FunctionFeature:
    """提取单个函数的可解释结构化语义特征"""
    return _feature_extractor.extract(pseudocode, function_name)


def compare_similarity(pseudocode_a: Optional[str],
                       pseudocode_b: Optional[str],
                       name_a: str = '',
                       name_b: str = '') -> SimilarityReport:
    """对两段伪代码做可解释相似性判定，返回逐维度审计报告"""
    fa = _feature_extractor.extract(pseudocode_a, name_a)
    fb = _feature_extractor.extract(pseudocode_b, name_b)
    return _similarity.compare(fa, fb)


def recover_signature(pseudocode: Optional[str],
                      arch: str = 'x86_64',
                      asm_text: Optional[str] = None,
                      function_name: str = '') -> RecoveredSignature:
    """从组合约束恢复函数签名（跨架构）"""
    return _signature_recoverer.recover(pseudocode or '', normalize_arch(arch),
                                        asm_text, function_name)


def check_equivalence(decompiled: Optional[str],
                      reference: Optional[str],
                      param_names: Optional[List[str]] = None,
                      input_ranges: Optional[List[Tuple[int, int]]] = None,
                      use_symbolic: bool = True) -> EquivResult:
    """对反编译结果与参考实现做细粒度等价校验"""
    return _equivalence.check(decompiled or '', reference or '',
                              param_names=param_names,
                              input_ranges=input_ranges,
                              use_symbolic=use_symbolic)


def analyze_function_bcs(pseudocode: Optional[str],
                         function_name: str = '',
                         reference: Optional[str] = None,
                         arch: str = 'x86_64',
                         asm_text: Optional[str] = None,
                         samples: int = 24,
                         use_symbolic: bool = True) -> Dict[str, Any]:
    """InterpBCS 一站式流水线

    步骤:
    1. 提取可解释特征（审计 + 向量）
    2. 组合约束恢复签名
    3. (可选) 对参考实现做等价校验
    返回统一报告字典
    """
    arch = normalize_arch(arch)
    code = pseudocode or ''

    report: Dict[str, Any] = {
        'function_name': function_name,
        'arch': arch,
        'features': _feature_extractor.extract(code, function_name).to_dict(),
        'signature': _signature_recoverer.recover(
            code, arch, asm_text, function_name).to_dict(),
    }

    if reference:
        checker = EquivalenceChecker(samples=samples)
        eq = checker.check(code, reference,
                           use_symbolic=use_symbolic)
        report['equivalence'] = eq.to_dict()
        sim = _similarity.compare(
            _feature_extractor.extract(code, function_name),
            _feature_extractor.extract(reference, function_name + '__ref'),
        )
        report['similarity_vs_reference'] = sim.to_dict()
    else:
        report['equivalence'] = None
        report['similarity_vs_reference'] = None

    return report


def decompile_and_audit(binary_path: str,
                        function_name: str,
                        reference: Optional[str] = None,
                        decompiler: str = 'auto',
                        arch: str = 'x86_64',
                        use_symbolic: bool = True) -> Dict[str, Any]:
    """与 decomp_ai.py 衔接：反编译后执行 InterpBCS 流水线

    惰性导入 DecompilerAI 避免在无反编译器环境下拖慢包导入；
    DecompilerAI 构造依赖 modules.info 采集子模块，若该子模块在
    当前代码库状态下不可用，则返回结构化错误而非中断调用方
    """
    try:
        from modules.analysis.decompiler.decomp_ai import DecompilerAI
        decomp_ai = DecompilerAI(binary_path, decompiler=decompiler)
    except Exception as e:  # noqa: BLE001 — 上游依赖缺失时优雅降级
        logger.warning('DecompilerAI 初始化失败: %s', e)
        return {
            'function_name': function_name,
            'error': f'DecompilerAI 初始化失败: {e}',
            'decompiler': decompiler,
        }
    pseudocode = decomp_ai.decompile(function_name)
    if not pseudocode:
        return {
            'function_name': function_name,
            'error': f'反编译失败 ({decomp_ai.active_decompiler} 不可用)',
            'decompiler': decomp_ai.active_decompiler,
        }
    report = analyze_function_bcs(
        pseudocode, function_name=function_name, reference=reference,
        arch=arch, use_symbolic=use_symbolic,
    )
    report['decompiler'] = decomp_ai.active_decompiler
    return report


__all__ = [
    '__version__',
    # 子模块类
    'CallPattern', 'ConstantStats', 'StringRef', 'CfgMorphology',
    'FunctionFeature', 'FeatureExtractor', 'SimilarityReport',
    'InterpretableSimilarity',
    'EquivVerdict', 'EquivResult', 'EquivalenceChecker',
    'RecoveredSignature', 'SignatureRecoverer', 'normalize_arch',
    # 顶层函数
    'extract_features', 'compare_similarity', 'recover_signature',
    'check_equivalence', 'analyze_function_bcs', 'decompile_and_audit',
]
