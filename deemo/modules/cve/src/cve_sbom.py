# cve_sbom.py — 薄兼容包装层。
# 在重命名（cve_sbom → cve_sbom_matcher）之前编写的测试从此模块名导入。
# 与其更新所有测试的导入（可能破坏其他特性分支），不如从cve_sbom_matcher重导出。
#
# 注意：不导入cve_sbom_import——那是SBOM *导入*模块（从项目文件解析/生成SBOM）。
# 不同职责。

import json
import os
import re
from typing import Dict, List, Optional, Any

# 从匹配器重导出全部符号
from .cve_sbom_matcher import (
    match_component,
    match_sbom,
    build_sbom_report,
    _norm_name,
    _token_overlap,
    _check_version_affected,
    _extract_fix,
    _kb_lookup,
)

# 重导出purl转换工具
from .cve_purl_cpe import (
    purl_to_cpe,
    cpe_to_purl,
    parse_purl,
    propagate_risk,
    transitive_risk_report,
)

__all__ = [
    "match_component",
    "match_sbom",
    "build_sbom_report",
    "parse_purl",
    "import_sbom",
    "purl_to_cpe",
    "cpe_to_purl",
    "propagate_risk",
    "transitive_risk_report",
    "_norm_name",
    "_token_overlap",
    "_check_version_affected",
    "_extract_fix",
    "_kb_lookup",
]


# ---- 带补丁的purl解析 ----

# npm作用域包模式: @scope/name
_NPM_SCOPED_RE = re.compile(r"^@([^/]+)/(.+)$")

# Go模块路径: domain/org/repo等
_GO_MODULE_RE = re.compile(r"^([^/]+\.[^/]+)/(.+)$")


def parse_purl(purl_str: str) -> Optional[Dict]:
    """解析purl字符串，含npm作用域包和Go模块的生态系统特定补丁。
    包装cve_purl_cpe.parse_purl，但增加了基础解析器为保持PURL→CPE管道纯净
    而有意图省略的生态系统特定处理。"""

    if not purl_str or not purl_str.startswith("pkg:"):
        return None

    # 委托给基础解析器
    from .cve_purl_cpe import parse_purl as _base_parse_purl

    result = _base_parse_purl(purl_str)
    if not result:
        return None

    eco = result.get("type", "")
    name = result.get("name", "")
    namespace = result.get("namespace", "")

    # npm作用域包：确保namespace已设置
    if eco == "npm" and not namespace:
        m = _NPM_SCOPED_RE.match(name)
        if m:
            result["namespace"] = m.group(1)
            result["name"] = m.group(2)
        else:
            # 同时检查可能含@scope/name的原始名称字段
            raw_name = result.get("raw", "")
            if raw_name:
                # 尝试从限定purl路径中提取
                pass

    # Go模块：规范化模块路径
    if eco == "golang":
        # 若namespace看起来像完整路径，重新解析
        full_name = f"{namespace}/{name}" if namespace else name
        m = _GO_MODULE_RE.match(full_name)
        if m:
            result["namespace"] = m.group(1)
            result["name"] = m.group(2)

    return result


# ---- SBOM文件导入 ----

def import_sbom(path: str) -> Dict:
    """加载SBOM JSON文件并返回规范化字典。
    同时处理CycloneDX和SPDX格式。返回字典始终包含'components'键供下游使用。"""

    if not os.path.exists(path):
        raise FileNotFoundError(f"SBOM file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        sbom = json.load(f)

    # 规范化为统一格式
    result = {
        "source_path": os.path.abspath(path),
        "format": "unknown",
        "components": [],
        "metadata": {},
    }

    # CycloneDX
    if "bomFormat" in sbom or "specVersion" in sbom:
        result["format"] = "cyclonedx"
        result["metadata"] = sbom.get("metadata", {})
        result["components"] = sbom.get("components", [])
        # 同时处理services（SaaSBOM）
        if "services" in sbom:
            for svc in sbom.get("services", []):
                svc["_type"] = "service"
                result["components"].append(svc)

    # SPDX
    elif "spdxVersion" in sbom or "SPDXID" in sbom:
        result["format"] = "spdx"
        result["metadata"] = {
            "name": sbom.get("name", ""),
            "spdxVersion": sbom.get("spdxVersion", ""),
            "creationInfo": sbom.get("creationInfo", {}),
        }
        # SPDX packages → components
        packages = sbom.get("packages", [])
        for pkg in packages:
            comp = {
                "name": pkg.get("name", ""),
                "version": pkg.get("versionInfo", ""),
                "purl": None,
                "cpe": None,
                "ecosystem": None,
            }
            # 从externalRefs提取purl/cpe
            for ref in pkg.get("externalRefs", []):
                ref_type = ref.get("referenceType", "")
                ref_locator = ref.get("referenceLocator", "")
                if "purl" in ref_type and not comp["purl"]:
                    comp["purl"] = ref_locator
                if "cpe" in ref_type and not comp["cpe"]:
                    comp["cpe"] = ref_locator
            result["components"].append(comp)

    # 未知/裸格式——假设包含components键
    else:
        result["format"] = "raw"
        if isinstance(sbom, list):
            result["components"] = sbom
        else:
            result["components"] = sbom.get("components", sbom.get("packages", []))

    return result
