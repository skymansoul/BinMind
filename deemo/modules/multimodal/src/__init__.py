# 加入三模态融合模块导出
# 导出熵加权注意力，供外部直接获取融合权重

# multimodal/src — CLI、配置、工具的入口层
# 意图：src/ 面向用户操作，根目录的 *.py 是领域模型层。
# 分离的代价是 sys.path 操作，收益是清晰的关注点边界。

from .config_loader import ConfigLoader, load_config, get_config
from .utils import setup_logging, retry_with_backoff, TTLCache

# 三模态融合
# 可选依赖——ImportError 时静默跳过，维持向后兼容。
try:
    from .tri_modal_fusion import (
        TriModalFusionEngine, ModalityConflictArbiter,
    )
    _HAS_TRI_MODAL = True
except ImportError:
    TriModalFusionEngine = None
    ModalityConflictArbiter = None
    _HAS_TRI_MODAL = False

try:
    from .entropy_weighted_attention import (
        EntropyWeightedAttention, entropy_gated_fusion,
    )
except ImportError:
    EntropyWeightedAttention = None
    entropy_gated_fusion = None

try:
    from .fusion_provenance import (
        FusionProvenanceTracker, ProvenanceEdge, FusionRecord,
    )
except ImportError:
    FusionProvenanceTracker = None
    ProvenanceEdge = None
    FusionRecord = None

try:
    from .causal_modality_router import (
        CausalModalityRouter, causal_weighted_fusion,
    )
except ImportError:
    CausalModalityRouter = None
    causal_weighted_fusion = None

try:
    from .orthogonal_decomposition_fusion import (
        OrthogonalDecompositionFusion, orthogonal_decompose_fuse,
    )
except ImportError:
    OrthogonalDecompositionFusion = None
    orthogonal_decompose_fuse = None

try:
    from .adversarial_modality_dropout import (
        EntropyGradientCurriculum, egac_train_step_wrapper, fast_renyi_entropy,
    )
except ImportError:
    EntropyGradientCurriculum = None
    egac_train_step_wrapper = None
    fast_renyi_entropy = None

try:
    from .conformal_multimodal_ensemble import (
        MultimodalConformalPredictor, multimodal_conformal_predict,
        MultimodalConformalResult, ModalConformalResult,
    )
except ImportError:
    MultimodalConformalPredictor = None
    multimodal_conformal_predict = None
    MultimodalConformalResult = None
    ModalConformalResult = None

__all__ = ["ConfigLoader", "load_config", "get_config",
           "setup_logging", "retry_with_backoff", "TTLCache",
           "TriModalFusionEngine", "ModalityConflictArbiter",
           "EntropyWeightedAttention", "entropy_gated_fusion",
           "FusionProvenanceTracker", "ProvenanceEdge", "FusionRecord",
           "CausalModalityRouter", "causal_weighted_fusion",
           "OrthogonalDecompositionFusion", "orthogonal_decompose_fuse",
           "EntropyGradientCurriculum", "egac_train_step_wrapper",
           "fast_renyi_entropy",
           "MultimodalConformalPredictor", "multimodal_conformal_predict",
           "MultimodalConformalResult", "ModalConformalResult"]
