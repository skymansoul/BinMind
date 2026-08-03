from .src.core.vuln_db_core import VulnerabilityDatabaseCore, VECTOR_STORAGE_AVAILABLE
from .src.core.vuln_db_stats import VulnerabilityDatabaseStats


class VulnerabilityDatabase(VulnerabilityDatabaseCore, VulnerabilityDatabaseStats):
    """
    本地漏洞知识库

    核心能力:
        1. 持久化分析结果与利用脚本
        2. 基于代码片段/危险函数的相似性检索
        3. 知识库导入导出
        4. 向量存储与语义检索（可选FAISS加速）
        5. 外部漏洞源集成（CVE、Exploit-DB）
    """

    pass


def get_vuln_db() -> VulnerabilityDatabase:
    """
    获取漏洞数据库单例

    Returns:
        VulnerabilityDatabase实例
    """
    return VulnerabilityDatabase()
