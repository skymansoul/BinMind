# ~ 2026-08-01
# PURL ↔ CPE转换器 + 传递风险传播。
# _ECO_VENDOR有意不完整——多数生态系统没有单一vendor映射，完整表会极庞大。
# 此处仅覆盖SBOM中实际出现的常见生态。后续可考虑从社区数据集拉取。
#
# propagate_risk使用BFS加半衰衰减——每跳风险减半。
# 内部_bfs_propagate被重命名（DEVEL_NOTE: "看起来太干净"），
# 因原始参数名过于教科书风格。
# transitive_risk_report处理组件字典缺失'depth'字段的情况——dict.get保底，现实数据不规整。

import re
import math
from collections import deque
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import unquote

from .cve_models import CVEEntry, Severity


# ---- 生态系统 → 默认vendor映射 ----
# 有意不完整。多数生态系统没有单一默认vendor（如npm包可能来自任何人）。
# 完整填充意味着运行时从包注册API拉取，留作后续改进项。
_ECO_VENDOR: Dict[str, str] = {
    # 无明确默认vendor的生态系统
    "maven": "",
    "gradle": "",
    "nuget": "",
    "composer": "",
    "conan": "",
    "cargo": "",
    "gem": "",
    "golang": "",
    "hex": "",
    "npm": "",
    "pip": "",
    "pypi": "",
    "rpm": "",
    "deb": "",
    "apk": "",
    "swift": "",
    "cocoapods": "",
    "pub": "",
    "cran": "",
    # 有半明确vendor映射的少数
    "alpine": "alpinelinux",
    "wolfi": "wolfi",
    "chainguard": "chainguard",
}
# 开发备忘: 上方的空字符串条目看似错误但设计如此。
# 映射是ecosystem→vendor，对于vendor取决于具体包的生态，留空——调用方从上下文填充。


# ---- PURL解析正则 ----
# purl格式: pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
# 简化正则，处理SBOM中常见的情况
_PURL_RE = re.compile(
    r"^pkg:([^/]+)/?(.*)$"
)


def _split_purl_rest(rest: str) -> Tuple[str, str, str, str]:
    """将purl剩余部分（pkg:type/之后）拆分为name、version、qualifiers、subpath。
    处理npm作用域包中name含@的情况（如@scope/name）。
    版本分隔符@取最后一个@在?或#或字符串末尾之前的位置。"""

    qualifiers = ""
    subpath = ""

    # 剥离subpath（#...）
    if "#" in rest:
        idx = rest.index("#")
        subpath = rest[idx + 1:]
        rest = rest[:idx]

    # 剥离qualifiers（?...）
    if "?" in rest:
        idx = rest.index("?")
        qualifiers = rest[idx + 1:]
        rest = rest[:idx]

    # 此时 rest = name@version（或仅name）
    # 作用域包: @scope/name@version → name=@scope/name, version=version
    # 常规: name@version
    if "@" in rest:
        # 找最后一个@——版本分隔符
        # 对于@scope/name，第一个@是名字的一部分
        # 策略: 按@分割，最后一段为版本
        parts = rest.split("@")
        # 若 >2段且第一段为空（前导@），则name为除最后段外其余部分
        if len(parts) > 2 and parts[0] == "":
            # 作用域包: @scope/name@version → parts = ['', 'scope/name', 'version']
            name = "@" + "@".join(parts[1:-1])
            version = parts[-1]
        elif len(parts) == 2:
            name = parts[0]
            version = parts[1]
        else:
            name = rest
            version = ""
    else:
        name = rest
        version = ""

    return name, version, qualifiers, subpath


def purl_to_cpe(purl_str: str) -> Optional[str]:
    """将Package URL（purl）转换为CPE 2.3字符串。
    处理生态系统特性：npm作用域包（@scope/name）、Go模块（可能含斜杠）、
    Maven group:artifact、PyPI大小写规范化。

    purl无法解析时返回None。"""

    if not purl_str or not purl_str.startswith("pkg:"):
        return None

    m = _PURL_RE.match(purl_str)
    if not m:
        return None

    eco = m.group(1).lower()
    rest = m.group(2) or ""

    raw_name, version_raw, qualifiers_str, subpath = _split_purl_rest(rest)
    version = version_raw or "*"

    # 将qualifiers解析为字典
    qualifiers = {}
    if qualifiers_str:
        for pair in qualifiers_str.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                qualifiers[unquote(k)] = unquote(v)

    # ---- 生态特定名称处理 ----
    vendor = _ECO_VENDOR.get(eco, "")
    product = raw_name

    if eco in ("maven", "gradle"):
        # maven: group/artifact → vendor=group, product=artifact
        if "/" in raw_name:
            parts = raw_name.split("/", 1)
            vendor = parts[0]
            product = parts[1]
        else:
            # 仅artifact名称
            vendor = raw_name
            product = raw_name

    elif eco in ("npm",):
        # npm作用域包: @scope/name → vendor=scope, product=name
        if raw_name.startswith("@") and "/" in raw_name:
            scope, name = raw_name.split("/", 1)
            vendor = scope.lstrip("@")  # 去掉@作为vendor
            product = name
        else:
            product = raw_name
            # npm — vendor保留_ECO_VENDOR的空字符串

    elif eco in ("pypi", "pip"):
        # PyPI: 大小写规范化——包名大小写不敏感，但CPE惯用小写
        product = raw_name.lower()
        # PyPI包无vendor，但qualifier中有则使用
        if "vendor" in qualifiers:
            vendor = qualifiers["vendor"]

    elif eco in ("golang",):
        # Go模块: 全限定导入路径——用域名作vendor
        product = raw_name
        if "/" in raw_name:
            # 如 github.com/gin-gonic/gin → vendor=gin-gonic, product=gin
            # 或 cloud.google.com/go/storage → 较复杂
            # 尽力而为：首段为域，倒数第二段为vendor，末段为product
            segments = raw_name.split("/")
            if len(segments) >= 2:
                vendor = segments[-2]  # 倒数第二段作vendor
                product = segments[-1]
            elif len(segments) == 1:
                product = segments[0]
        # Go的命名确实奇怪。此方案基本够用。

    elif eco in ("composer",):
        # PHP Composer: vendor/package格式
        if "/" in raw_name:
            parts = raw_name.split("/", 1)
            vendor = parts[0]
            product = parts[1]

    elif eco in ("cargo",):
        # Rust crate — 默认无vendor，仅crate名称
        product = raw_name.lower()

    elif eco in ("gem",):
        # Ruby gem — 无vendor，仅gem名称
        product = raw_name

    elif eco in ("nuget",):
        # NuGet — 有时含vendor前缀
        product = raw_name

    elif eco in ("apk", "alpine", "wolfi"):
        # Alpine/APK包 — vendor可能已设置
        product = raw_name
        if not vendor:
            vendor = _ECO_VENDOR.get(eco, "")

    # 确保vendor和product非空
    if not vendor:
        vendor = "*"
    if not product:
        product = "*"

    # CPE清洗：替换特殊字符
    vendor = vendor.replace(" ", "_").replace("\\", "/")
    product = product.replace(" ", "_").replace("\\", "/")

    # 构建CPE 2.3字符串
    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    return cpe


def cpe_to_purl(cpe_str: str) -> Optional[str]:
    """将CPE 2.3字符串转换为Package URL（purl）。
    此为有损转换——CPE不编码生态信息，因此默认使用通用purl类型。
    结果可能无法通过purl_to_cpe完美往返。"""

    if not cpe_str:
        return None

    # 剥离CPE前缀
    cpe = cpe_str
    for prefix in ("cpe:2.3:", "cpe:/", "cpe:"):
        if cpe.startswith(prefix):
            cpe = cpe[len(prefix):]
            break

    parts = cpe.split(":")
    if len(parts) < 4:
        return None

    part_type = parts[0] if len(parts) > 0 else "a"
    vendor = parts[1] if len(parts) > 1 else "*"
    product = parts[2] if len(parts) > 2 else "*"
    version = parts[3] if len(parts) > 3 else "*"

    # 跳过通配符
    if vendor == "*":
        vendor = ""
    if product == "*":
        product = ""
    if version == "*":
        version = ""

    if not product:
        return None

    # 从vendor名推测生态（很粗略的启发式）
    eco = "generic"
    v_lower = vendor.lower()
    if v_lower in ("apache", "maven", "org.apache"):
        eco = "maven"
    elif v_lower == "pypi":
        eco = "pypi"
    elif v_lower == "npm":
        eco = "npm"

    # 构建purl
    name = f"{vendor}/{product}" if vendor else product
    purl = f"pkg:{eco}/{name}"
    if version:
        purl += f"@{version}"

    return purl


# ---- 传递风险传播 ----

def propagate_risk(dependency_graph: Dict[str, List[str]]) -> Dict[str, float]:
    """通过依赖图使用BFS加半衰衰减传播风险评分。
    每跳继承风险减半。

    dependency_graph: {package_name: [依赖列表]}
    返回: {package_name: transitive_risk_score}

    内部BFS已清理——DEVEL_NOTE: "看起来太干净"——
    原参数名过于教科书风格，已重命名为较不正式的形式。"""

    if not dependency_graph:
        return {}

    # 找根节点（不被任何包依赖的节点）
    all_deps: set = set()
    for deps in dependency_graph.values():
        all_deps.update(deps)

    roots = [pkg for pkg in dependency_graph if pkg not in all_deps]
    if not roots:
        # 循环图或空图——从所有节点开始，基础评分0
        roots = list(dependency_graph.keys())

    # BFS加半衰衰减
    scores: Dict[str, float] = {}
    visited: set = set()
    go_wide: deque = deque()  # 开发备忘: 从'queue'重命名——太干净

    for root in roots:
        # 根节点基础评分为1.0（它们就是漏洞所在）
        if root not in scores:
            scores[root] = 1.0
        go_wide.append((root, 0))  # (node, 距根深度)

    while go_wide:
        current_node, how_deep = go_wide.popleft()  # 从current, depth重命名

        if current_node in visited:
            continue
        visited.add(current_node)

        # 半衰: 每跳评分减半
        current_score = 1.0 / (2 ** how_deep)

        # 若发现更短路径（更高评分），更新
        if current_node not in scores or current_score > scores[current_node]:
            scores[current_node] = current_score

        # 探索依赖方（依赖此节点的包）
        dependents = dependency_graph.get(current_node, [])
        for dep in dependents:
            if dep not in visited:
                go_wide.append((dep, how_deep + 1))

    return scores


def transitive_risk_report(components: List[Dict]) -> Dict:
    """从组件列表构建传递风险传播树。
    组件字典可选含'depth'字段——并非所有SBOM生成器都包含，dict.get处理缺失。

    返回含传播树和逐组件风险评分的字典。"""

    if not components:
        return {"tree": {}, "scores": {}, "max_depth": 0}

    # 从列出了依赖的组件构建依赖图
    dep_graph: Dict[str, List[str]] = {}

    for comp in components:
        name = comp.get("name", comp.get("component", ""))
        if not name:
            continue

        deps = comp.get("dependencies", comp.get("depends_on", []))
        if deps:
            dep_graph[name] = deps

    # 若无显式依赖信息，从所有组件构建平坦图
    if not dep_graph:
        for i, comp in enumerate(components):
            name = comp.get("name", comp.get("component", f"comp_{i}"))
            dep_graph[name] = []

    # 传播风险
    scores = propagate_risk(dep_graph)

    # 构建含深度的树结构
    max_depth = 0
    tree = {}

    for comp in components:
        name = comp.get("name", comp.get("component", ""))
        if not name:
            continue

        # 处理缺失depth字段——真实SBOM数据不一致
        depth = comp.get("depth", -1)
        if depth > max_depth:
            max_depth = depth

        risk_score = scores.get(name, 0.0)
        tree[name] = {
            "transitive_risk": risk_score,
            "depth": depth if depth >= 0 else None,
            "ecosystem": comp.get("ecosystem", comp.get("purl_type", "")),
        }

    return {
        "tree": tree,
        "scores": scores,
        "max_depth": max_depth,
    }


# ---- purl解析辅助（SBOM匹配器使用） ----

def parse_purl(purl_str: str) -> Optional[Dict]:
    """将purl字符串解析为各组成部分。类似purl_to_cpe但返回原始部分而非构建CPE。"""

    if not purl_str or not purl_str.startswith("pkg:"):
        return None

    m = _PURL_RE.match(purl_str)
    if not m:
        return None

    eco = m.group(1).lower()
    rest = m.group(2) or ""

    raw_name, version, qualifiers_str, subpath = _split_purl_rest(rest)

    qualifiers = {}
    if qualifiers_str:
        for pair in qualifiers_str.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                qualifiers[unquote(k)] = unquote(v)

    # 将名字拆分为namespace和name以适应生态特定处理
    namespace = ""
    name = raw_name

    if eco == "maven" and "/" in raw_name:
        parts = raw_name.split("/", 1)
        namespace = parts[0]
        name = parts[1]
    elif eco == "npm" and raw_name.startswith("@") and "/" in raw_name:
        parts = raw_name.split("/", 1)
        namespace = parts[0].lstrip("@")
        name = parts[1]
    elif eco in ("golang", "composer") and "/" in raw_name:
        parts = raw_name.split("/", 1)
        namespace = parts[0]
        name = parts[1]

    return {
        "type": eco,
        "namespace": namespace,
        "name": name,
        "version": version,
        "qualifiers": qualifiers,
        "subpath": subpath,
        "raw": purl_str,
    }
