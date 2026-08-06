"""
module_defs — 20 个子模块的元数据、功能描述、创新点和支撑论文。

每个子模块一个文件, 此 __init__.py 负责聚合并导出统一的 MODULE_DEFINITIONS 字典。
"""

from parallel_deep_dev.module_defs.ai_ml import AI_ML
from parallel_deep_dev.module_defs.analysis import ANALYSIS
from parallel_deep_dev.module_defs.core import CORE
from parallel_deep_dev.module_defs.crypto import CRYPTO
from parallel_deep_dev.module_defs.cve import CVE
from parallel_deep_dev.module_defs.data import DATA
from parallel_deep_dev.module_defs.distributed import DISTRIBUTED
from parallel_deep_dev.module_defs.exploit import EXPLOIT
from parallel_deep_dev.module_defs.fuzzing import FUZZING
from parallel_deep_dev.module_defs.info import INFO
from parallel_deep_dev.module_defs.multimodal import MULTIMODAL
from parallel_deep_dev.module_defs.network import NETWORK
from parallel_deep_dev.module_defs.output import OUTPUT
from parallel_deep_dev.module_defs.patching import PATCHING
from parallel_deep_dev.module_defs.platform import PLATFORM
from parallel_deep_dev.module_defs.project import PROJECT
from parallel_deep_dev.module_defs.stubs import STUBS
from parallel_deep_dev.module_defs.testing import TESTING
from parallel_deep_dev.module_defs.utils import UTILS
from parallel_deep_dev.module_defs.vuln import VULN

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
