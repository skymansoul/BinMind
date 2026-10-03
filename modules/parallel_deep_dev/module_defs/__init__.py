"""
module_defs — 20 个子模块的元数据、功能描述、创新点和支撑论文。

每个子模块一个文件, 此 __init__.py 负责聚合并导出统一的 MODULE_DEFINITIONS 字典。
"""

from .ai_ml import AI_ML
from .analysis import ANALYSIS
from .core import CORE
from .crypto import CRYPTO
from .cve import CVE
from .data import DATA
from .distributed import DISTRIBUTED
from .exploit import EXPLOIT
from .fuzzing import FUZZING
from .info import INFO
from .multimodal import MULTIMODAL
from .network import NETWORK
from .output import OUTPUT
from .patching import PATCHING
from .platform import PLATFORM
from .project import PROJECT
from .stubs import STUBS
from .testing import TESTING
from .utils import UTILS
from .vuln import VULN

MODULE_DEFINITIONS: dict = {
    "ai_ml":       AI_ML,
    "analysis":    ANALYSIS,
    "core":        CORE,
    "crypto":      CRYPTO,
    "cve":         CVE,
    "data":        DATA,
    "distributed": DISTRIBUTED,
    "exploit":     EXPLOIT,
    "fuzzing":     FUZZING,
    "info":        INFO,
    "multimodal":  MULTIMODAL,
    "network":     NETWORK,
    "output":      OUTPUT,
    "patching":    PATCHING,
    "platform":    PLATFORM,
    "project":     PROJECT,
    "stubs":       STUBS,
    "testing":     TESTING,
    "utils":       UTILS,
    "vuln":        VULN,
}

__all__ = ["MODULE_DEFINITIONS"]
