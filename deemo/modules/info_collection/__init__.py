# 2026-07-14
# info_collection — binary intelligence & information gathering subsystem
# 统一入口：延迟加载 src 包，对外暴露公共 API

from .src import __version__, binary_info, config, utils, anonymizer
from .src import findings, injection_detect, lateral, persistence
from .src import spoofing, tls_detect, leak_analyzer, pii, cli

# //// 批量导出常用符号以便外部直接 import ////
_info = binary_info.get_binary_info
_scan = findings.extract_findings
_anonymize = anonymizer.Anonymizer

__all__ = [
    "__version__",
    "binary_info", "config", "utils", "anonymizer",
    "findings", "injection_detect", "lateral", "persistence",
    "spoofing", "tls_detect", "leak_analyzer", "pii", "cli",
    "get_binary_info", "scan", "anonymize_code",
]
get_binary_info = _info
scan = _scan
anonymize_code = _anonymize
