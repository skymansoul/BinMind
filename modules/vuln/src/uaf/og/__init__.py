"""UAF-OG — Object-Generation 对象代际误报压缩.

UAF 检测的误报压缩包: free 后指针重赋值 (任意来源) 使对象代际
推进, 后续使用不构成 UAF. 与既有 DRIFT Phase0 (仅查 malloc 覆盖)
互补: 本包覆盖 mov 拷贝/参数传递/清零等全部重赋值形式.
"""

from .gen_flow import GenState, SlotGen, GEN_NULL, GEN_UNKNOWN
from .gen_flow import GenFlowTracker, GenEvent
from .og_filter import GenVerifier, GenVerdict, GenProof
from .og_filter import CallGenPropagator, ParamBinding
from .og_filter import OgFilter, OgResult, OgStats

__all__ = [
    'GenState', 'SlotGen', 'GEN_NULL', 'GEN_UNKNOWN',
    'GenFlowTracker', 'GenEvent',
    'CallGenPropagator', 'ParamBinding',
    'GenVerifier', 'GenVerdict', 'GenProof',
    'OgFilter', 'OgResult', 'OgStats',
]
