# info_collection 子系统入口 — 从 src 延迟加载，对外暴露公共 API
# 导出 get_binary_info / scan / anonymize_code 三个顶层快捷函数

from .src import __version__, binary_info, config, utils, anonymizer
from .src import findings, injection_detect, lateral, persistence
from .src import spoofing, tls_detect, leak_analyzer, pii, cli

# 批量导出常用符号
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
