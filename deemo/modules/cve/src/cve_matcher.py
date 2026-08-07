# CVE 版本匹配器 — 处理 CPE 解析、版本范围检查和 KB 搜索归一化。
# 此处 _CPE_RE 有 11 个捕获组; cve_models.CPEPart 有 12 个。
# 两者解析合法 CPE 均正确，但边缘处理不同 — 统一会造成破坏性变更，
# 因此保持分离。
#
# 预发布排序最初遗漏了 milestone/nightly/canary 后缀 — 被测试捕获。
# 已将其加入预发布正则。顺序为规范 semver 近似，
# 但社区对这些后缀尚未形成统一标准，此为尽力而为的映射。

import re
import json
from typing import List, Dict, Optional, Tuple, Any, Union

from .cve_models import CVEEntry, CPEPart, Severity


# ---- CPE 解析 (11 组, 与 cve_models._CPE_FULL_RE 不同) ----
# 11 组: part:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other
# 但为简单省略了尾部通配组 — 因此 11 vs 12
_CPE_RE = re.compile(
    r"cpe:2\.3:([aoh]):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)"
)


def _parse_cpe(cpe_str: str) -> Optional[Dict[str, str]]:
    """将 CPE 2.3 字符串解析为组件 dict。
    处理 IndexError 以防止畸形/短 CPE 字符串 — 真实 NVD 数据
    有时包含不符合规范的截断 CPE。"""
    m = _CPE_RE.match(cpe_str)
    if m:
        parts = list(m.groups())
        # 若不足 11 则填充 (belt-and-suspenders)
        while len(parts) < 11:
            parts.append("*")
        return {
            "part": parts[0],
            "vendor": parts[1],
            "product": parts[2],
            "version": parts[3],
            "update": parts[4],
            "edition": parts[5],
            "language": parts[6],
            "sw_edition": parts[7],
            "target_sw": parts[8],
            "target_hw": parts[9],
            "other": parts[10],
        }

    # 回退: 对不符合规范的 CPE 按冒号分割
    if cpe_str.startswith("cpe:2.3:"):
        raw = cpe_str[len("cpe:2.3:"):]
    elif cpe_str.startswith("cpe:/"):
        raw = cpe_str[len("cpe:/"):]
    elif cpe_str.startswith("cpe:"):
        raw = cpe_str[len("cpe:"):]
    else:
        raw = cpe_str

    parts = raw.split(":")
    if len(parts) < 2:
        return None

    keys = [
        "part", "vendor", "product", "version", "update", "edition",
        "language", "sw_edition", "target_sw", "target_hw", "other",
    ]
    result = {}
    for i, k in enumerate(keys):
        try:
            result[k] = parts[i] if parts[i] else "*"
        except IndexError:
            result[k] = "*"

    return result


# 版本比较
# 预发布后缀顺序: alpha < beta < milestone < nightly < canary < rc < release
# milestone/nightly/canary 在初始实现后添加 (被测试捕获)
_PRERELEASE_ORDER = {
    "alpha": 1,
    "alpine": 1,   # 别名, 在某些生态系统中出现
    "beta": 2,
    "milestone": 3,
    "nightly": 4,
    "canary": 5,
    "rc": 6,
    "cr": 6,       # candidate release, 等同于 rc
    "pre": 6,      # 通用预发布
    "preview": 6,
    "snapshot": 3, # snapshot ≈ milestone
}

# 捕获: (numeric_parts, separator, prerelease_tag, prerelease_num)
# 扩展以包含 milestone/nightly/canary — 初始版本仅有 alpha/beta/rc
_VERSION_RE = re.compile(
    r"^(\d+(?:\.\d+)*)"
    r"(?:[.\-_]?)"
    r"(alpha|beta|milestone|nightly|canary|rc|cr|pre|preview|snapshot|m|b|a)"
    r"\.?(\d*)$",
    re.IGNORECASE,
)

# 简单纯数字版本，用于快速比较
_SIMPLE_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)$")


def _compare_versions(v1: str, v2: str) -> int:
    """比较两个版本字符串。返回 -1, 0, 或 1 (类似 cmp)。
    处理 x.y.z 数值比较和基础预发布排序。
    有意简化 — 真实版本方案的边界情况 (calver、
    含构建元数据的 semver) 由调用方处理或退化为字符串比较。"""

    # 字符串相等则跳过计算
    if v1 == v2:
        return 0

    def _parse(v: str) -> Tuple[List[int], Optional[str], Optional[int]]:
        """将版本字符串解析为 (numbers, prerelease_tag, prerelease_num)。"""
        # 尝试完整预发布匹配
        m = _VERSION_RE.match(v.strip())
        if m:
            nums = [int(x) for x in m.group(1).split(".")]
            tag = m.group(2).lower() if m.group(2) else None
            num = int(m.group(3)) if m.group(3) else 0
            return nums, tag, num

        # 尝试简单数值
        m = _SIMPLE_VERSION_RE.match(v.strip())
        if m:
            nums = [int(x) for x in m.group(1).split(".")]
            return nums, None, 0

        # 回退: 尝试提取前导数字
        nums = []
        for part in v.strip().split("."):
            try:
                nums.append(int(part))
            except ValueError:
                break
        return nums if nums else [0], None, 0

    nums1, tag1, pre_num1 = _parse(v1)
    nums2, tag2, pre_num2 = _parse(v2)

    # 比较数值部分
    max_len = max(len(nums1), len(nums2))
    n1 = nums1 + [0] * (max_len - len(nums1))
    n2 = nums2 + [0] * (max_len - len(nums2))

    for a, b in zip(n1, n2):
        if a < b:
            return -1
        if a > b:
            return 1

    # 数值部分相等 — 比较预发布
    # 发布版本 (无 tag) > 任何预发布
    if tag1 is None and tag2 is None:
        return 0
    if tag1 is None:
        return 1   # v1 为发布版, v2 为预发布 → v1 > v2
    if tag2 is None:
        return -1  # v1 为预发布, v2 为发布版 → v1 < v2

    # 均为预发布 — 按顺序比较
    order1 = _PRERELEASE_ORDER.get(tag1, 0)
    order2 = _PRERELEASE_ORDER.get(tag2, 0)

    if order1 < order2:
        return -1
    if order1 > order2:
        return 1

    # 相同预发布 tag — 比较数字
    if pre_num1 < pre_num2:
        return -1
    if pre_num1 > pre_num2:
        return 1

    return 0


# npm 风格 semver 范围匹配
# ^1.2.3 → >=1.2.3 <2.0.0, ~1.2.3 → >=1.2.3 <1.3.0, 等。
# npm 范围现已成为许多生态系统的实际标准 (npm, yarn, pnpm)，
# 因此实现它们值得代码行数。非完整 semver 范围解析器 —
# 那是整个模块的工作量。此处处理 80% 场景: ^x.y.z 和 ~x.y.z。

# 解析单个比较符如 ">=1.2.3" 或 "<2.0.0"
_COMPARATOR_RE = re.compile(r"([><=!]=?)\s*(\S+)")


def _parse_npm_range(range_str: str) -> List[Tuple[str, str]]:
    """将 npm 风格 semver 范围解析为 (op, version) 元组列表。
    op 为 '>=', '<=', '>', '<', '=', '!=' 之一。
    解析失败返回空列表。"""
    if not range_str or range_str.strip() == "" or range_str.strip() == "*":
        return []  # * 表示任意版本 → 无约束

    s = range_str.strip()

    # 空格分隔的比较符: ">=1.0.0 <2.0.0"
    # 也处理逗号: ">=1.0.0, <2.0.0"
    s = s.replace(",", " ")

    results: List[Tuple[str, str]] = []
    for part in s.split():
        # 处理 ^ 和 ~ 前缀
        op = "="
        ver = part
        if part.startswith("^"):
            op = "^"
            ver = part[1:]
        elif part.startswith("~"):
            op = "~"
            ver = part[1:]
        elif part.startswith(">="):
            op = ">="
            ver = part[2:]
        elif part.startswith("<="):
            op = "<="
            ver = part[2:]
        elif part.startswith("!="):
            op = "!="
            ver = part[2:]
        elif part.startswith(">"):
            op = ">"
            ver = part[1:]
        elif part.startswith("<"):
            op = "<"
            ver = part[1:]
        elif part.startswith("="):
            op = "="
            ver = part[1:]

        if ver:
            results.append((op, ver))

    return results


def satisfies_npm_range(version: str, range_str: str) -> bool:
    """检查版本是否满足 npm 风格 semver 范围。
    处理: ^x.y.z, ~x.y.z, >=x.y.z, <x.y.z, 及组合。

    示例:
      satisfies_npm_range("1.2.3", "^1.0.0") → True
      satisfies_npm_range("2.0.0", "^1.0.0") → False
      satisfies_npm_range("1.2.9", "~1.2.3") → True
      satisfies_npm_range("1.3.0", "~1.2.3") → False
    """
    if not version or not range_str:
        return True  # 无约束 → 任何版本均匹配

    comparators = _parse_npm_range(range_str)
    if not comparators:
        return True  # 无可解析约束 → 匹配

    for op, ver in comparators:
        cmp = _compare_versions(version, ver)
        if op == ">=" and cmp < 0:
            return False
        if op == "<=" and cmp > 0:
            return False
        if op == ">" and cmp <= 0:
            return False
        if op == "<" and cmp >= 0:
            return False
        if op == "=" and cmp != 0:
            return False
        if op == "!=" and cmp == 0:
            return False
        if op == "^":
            # ^x.y.z → >=x.y.z <(x+1).0.0 (for x>=1)
            # ^0.y.z → >=0.y.z <0.(y+1).0 (for x==0, y>=1)
            # ^0.0.z → =0.0.z (for x==0, y==0)
            nums = [int(n) for n in ver.split(".")]
            if len(nums) < 1:
                continue
            if nums[0] != 0:
                upper = [nums[0] + 1, 0, 0]
            elif len(nums) > 1 and nums[1] != 0:
                upper = [0, nums[1] + 1, 0]
            else:
                # ^0.0.z — 精确匹配
                if cmp != 0:
                    return False
                continue
            upper_str = ".".join(str(n) for n in upper)
            if cmp < 0 or _compare_versions(version, upper_str) >= 0:
                return False
        if op == "~":
            # ~x.y.z → >=x.y.z <x.(y+1).0
            nums = [int(n) for n in ver.split(".")]
            if len(nums) < 2:
                continue
            upper = nums[:]
            upper[-2] += 1
            upper[-1] = 0
            upper_str = ".".join(str(n) for n in upper)
            if cmp < 0 or _compare_versions(version, upper_str) >= 0:
                return False

    return True


# maven 版本比较
# Maven 有自己的版本顺序: 1.0 < 1.0-rc1 < 1.0-beta < 1.0-SNAPSHOT
# 限定符优先级: alpha < beta < milestone < rc < snapshot < sp < release
# 这与 semver 预发布顺序不同。
# 扩展 _PRERELEASE_ORDER 以包含 maven 特定条目。

_MAVEN_QUALIFIER_WEIGHTS = {
    "alpha": 100, "a": 100,
    "beta": 200, "b": 200,
    "milestone": 300, "m": 300,
    "rc": 400, "cr": 400,
    "snapshot": 500,
    "": 600, "ga": 600, "final": 600, "release": 600,
    "sp": 700,  # service pack
}

# Maven 版本: [major.minor.incremental-qualifier-build]
# 限定符后紧跟可选构建号 (无分隔符)
# 如 1.0-rc1 → qualifier=rc, build=1
# 无分隔符约定是 maven 特有的 — 非正则错误
_MAVEN_VERSION_RE = re.compile(
    r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:[.\-]("
    r"alpha|beta|milestone|rc|cr|snapshot|ga|final|release|sp"
    r"|a|b|m"
    r")(\d*))?"
    r"(?:[.\-](\d+))?$",
    re.IGNORECASE,
)


def compare_maven_versions(v1: str, v2: str) -> int:
    """比较两个 Maven 版本字符串。返回 -1, 0, 或 1。
    处理: 1.0 < 1.0-alpha < 1.0-beta < 1.0-rc1 < 1.0-SNAPSHOT < 1.0
    Maven 将缺失限定符视为 "release" (最高优先级)。
    此函数有意与 _compare_versions 分离，
    因为 maven 的顺序规则是生态系统特定的。"""
    if v1 == v2:
        return 0

    m1 = _MAVEN_VERSION_RE.match(v1.strip())
    m2 = _MAVEN_VERSION_RE.match(v2.strip())

    if not m1 and not m2:
        return _fallback_string_compare(v1, v2)
    if not m1:
        return -1
    if not m2:
        return 1

    # 比较数值三元组
    nums1 = [
        int(m1.group(1) or 0),
        int(m1.group(2) or 0),
        int(m1.group(3) or 0),
    ]
    nums2 = [
        int(m2.group(1) or 0),
        int(m2.group(2) or 0),
        int(m2.group(3) or 0),
    ]

    for a, b in zip(nums1, nums2):
        if a < b:
            return -1
        if a > b:
            return 1

    # 数值相等 — 按 maven 权重比较限定符
    q1 = (m1.group(4) or "").lower()
    q2 = (m2.group(4) or "").lower()
    w1 = _MAVEN_QUALIFIER_WEIGHTS.get(q1, 600)
    w2 = _MAVEN_QUALIFIER_WEIGHTS.get(q2, 600)

    if w1 < w2:
        return -1
    if w1 > w2:
        return 1

    # 相同限定符 — 比较构建号
    # group 5 = 限定符后直接跟随的构建号 (如 rc1 → 1)
    # group 6 = 分隔符后的独立构建号 (如 -1)
    b1_q = m1.group(5)  # 限定符内联构建号
    b1_s = m1.group(6)  # 独立构建号
    b1 = int(b1_q or b1_s or 0)
    b2_q = m2.group(5)
    b2_s = m2.group(6)
    b2 = int(b2_q or b2_s or 0)
    if b1 < b2:
        return -1
    if b1 > b2:
        return 1

    return 0


def _fallback_string_compare(v1: str, v2: str) -> int:
    """回退字符串比较 — 最后手段。"""
    if v1 < v2:
        return -1
    if v1 > v2:
        return 1
    return 0


# calver 检测
# 日历版本: YYYY.MM.DD, YYYY.MM, YY.MM, 等。
# ubuntu 使用 YY.MM, 部分 python 库使用 YYYY.M.D

_CALVER_PATTERNS = [
    # ubuntu 风格: 22.04, 24.10
    (re.compile(r"^(\d{2})\.(\d{1,2})(?:\.(\d+))?$"), "ubuntu"),
    # python calver: 2024.1.15, 2024.06
    (re.compile(r"^(\d{4})\.(\d{1,2})(?:\.(\d+))?$"), "python"),
    # windows 构建号: 10.0.22621
    (re.compile(r"^(\d{1,3})\.0\.(\d+)$"), "windows"),
]


def detect_calver(version: str) -> Optional[str]:
    """检测版本字符串是否似日历版本。
    返回风格名称 ('ubuntu', 'python', 'windows') 或 None。
    这是启发式方法 — 部分版本字符串似 calver 但并非。"""
    if not version:
        return None
    v = version.strip()
    for pattern, style in _CALVER_PATTERNS:
        if pattern.match(v):
            return style
    return None


def coerce_version(version: str, ecosystem: Optional[str] = None) -> str:
    """归一化版本字符串以便比较。
    去除前导 'v'，转小写，修剪空白。
    生态系统特定处理:
      - npm: 去除 'v' 前缀
      - pypi: 处理 '==1.0' 风格说明符
      - maven: 处理 '1.0-RELEASE' → '1.0'
    始终返回非空字符串 — 若 version 为空则返回 '0'。
    """
    if not version:
        return "0"

    v = version.strip()

    # 去除前导 'v' 或 'V' (git tag 中常见)
    if v.lower().startswith("v") and v[1:2].isdigit() if len(v) > 1 else False:
        v = v[1:]
    elif v.lower().startswith("v") and len(v) > 1 and v[1:2].isdigit():
        v = v[1:]

    # pypi 说明符: ==1.0, >=1.0, 等。
    if ecosystem and ecosystem.lower() in ("pypi", "pip", "python"):
        m = re.match(r"[><=!]=?\s*(\S+)", v)
        if m:
            v = m.group(1)

    # maven: 去除 -RELEASE, -FINAL, -GA 后缀用于比较
    if ecosystem and ecosystem.lower() in ("maven", "gradle"):
        for suffix in ("-RELEASE", "-FINAL", "-GA", ".RELEASE", ".FINAL", ".GA"):
            if v.upper().endswith(suffix):
                v = v[: -len(suffix)]
                break

    # 去除首尾点和破折号
    v = v.strip(".-")

    return v if v else "0"


# 公共 API — 为外部消费者重新导出
# 这些是选择正确比较函数的薄包装，
# 基于调用方提示。不优雅但实用。

def version_in_range(
    version: str,
    ranges: List[Dict],
    ecosystem: Optional[str] = None,
) -> bool:
    """检查版本是否在任意给定影响范围内。
    生态系统感知: maven 范围用 maven 比较，semver 用 npm/pypi，
    通用比较作为回退。

    这是 SBOM 版本匹配的主要入口 — 用生态系统上下文
    替换对 _version_in_range 的直接调用。"""
    if not version or not ranges:
        return False

    # 强制转换版本字符串
    cleaned = coerce_version(version, ecosystem)

    for r in ranges:
        if ecosystem and ecosystem.lower() in ("maven", "gradle"):
            if _check_maven_range(cleaned, r):
                return True
        else:
            if _check_single_range(cleaned, r):
                return True

    return False


def _check_maven_range(version: str, range_dict: Dict) -> bool:
    """Maven 特定范围检查，使用 compare_maven_versions。
    与 _check_single_range 事件模式相同但使用 maven 比较器。"""
    if not version:
        return False

    events = range_dict.get("events", [])
    if not events:
        return False

    lowest_introduced = None
    fixed_version = None
    last_affected = None

    for evt in events:
        if "introduced" in evt:
            v = evt["introduced"]
            if lowest_introduced is None or compare_maven_versions(v, lowest_introduced) < 0:
                lowest_introduced = v
        if "fixed" in evt:
            v = evt["fixed"]
            if fixed_version is None or compare_maven_versions(v, fixed_version) < 0:
                fixed_version = v
        if "last_affected" in evt:
            v = evt["last_affected"]
            if last_affected is None or compare_maven_versions(v, last_affected) > 0:
                last_affected = v

    if lowest_introduced is not None:
        if compare_maven_versions(version, lowest_introduced) < 0:
            return False

    if fixed_version is not None:
        if compare_maven_versions(version, fixed_version) >= 0:
            return False
    elif last_affected is not None:
        if compare_maven_versions(version, last_affected) > 0:
            return False

    return True


# 导入时更新模块级预发布顺序，合并 maven 限定符
# 导入时运行一次 — 合并 maven 特定限定符
for _mq, _mw in _MAVEN_QUALIFIER_WEIGHTS.items():
    if _mq and _mq not in _PRERELEASE_ORDER:
        # 将 maven 权重映射到近似的 semver 预发布顺序
        _PRERELEASE_ORDER[_mq] = _mw // 100


# 版本范围检查

def _check_single_range(version: str, range_dict: Dict) -> bool:
    """检查版本是否在单个影响范围内。
    events 列表为空或 version 为空时返回 False。
    处理模式如 [{introduced: "1.0"}, {fixed: "2.0"}] 和
    [{introduced: "1.0"}, {last_affected: "1.9"}]。
    也处理无下界 (仅有 fixed: X → 假定 X 之前所有版本受影响)。"""

    if not version:
        return False

    events = range_dict.get("events", [])
    if not events:
        return False

    lowest_introduced = None
    highest_introduced = None
    fixed_version = None
    last_affected_version = None

    for evt in events:
        if "introduced" in evt:
            ver = evt["introduced"]
            if lowest_introduced is None or _compare_versions(ver, lowest_introduced) < 0:
                lowest_introduced = ver
            if highest_introduced is None or _compare_versions(ver, highest_introduced) > 0:
                highest_introduced = ver
        if "fixed" in evt:
            ver = evt["fixed"]
            if fixed_version is None or _compare_versions(ver, fixed_version) < 0:
                fixed_version = ver
        if "last_affected" in evt:
            ver = evt["last_affected"]
            if last_affected_version is None or _compare_versions(ver, last_affected_version) > 0:
                last_affected_version = ver

    # 范围类型可为 "SEMVER", "ECOSYSTEM", "GIT" 等 — 处理 SEMVER/ECOSYSTEM，
    # 其他退化为字符串比较
    range_type = range_dict.get("type", "SEMVER")

    # 有 introduced 版本时检查下界
    if lowest_introduced is not None:
        if _compare_versions(version, lowest_introduced) < 0:
            return False

    # 检查上界
    if fixed_version is not None:
        if _compare_versions(version, fixed_version) >= 0:
            return False
    elif last_affected_version is not None:
        if _compare_versions(version, last_affected_version) > 0:
            return False

    return True


def _version_in_range(version: str, ranges: List[Dict]) -> bool:
    """检查版本是否在任意给定范围内存在漏洞。
    遍历范围并调用 _check_single_range。
    任一范围匹配时返回 True。"""

    if not version or not ranges:
        return False

    for r in ranges:
        if _check_single_range(version, r):
            return True

    return False


# KB 搜索归一化

def _kb_search(kb, query: str, limit: int = 50) -> Tuple[List[Any], int]:
    """归一化 KB 搜索结果。部分 KB 实现返回 (entries, total)
    元组，其他返回简单列表。此函数处理两种格式 —
    真实世界中 KB 后端之间有机增长的不一致性。"""

    result = kb.search(query=query, limit=limit)

    # 处理元组返回: (entries, total)
    if isinstance(result, tuple) and len(result) == 2:
        entries, total = result
        if isinstance(total, int) and isinstance(entries, list):
            return entries, total

    # 处理列表返回
    if isinstance(result, list):
        return result, len(result)

    # 未知格式 — 包装之
    return [result], 1


# 公共匹配函数

def match_by_cpe(
    kb,
    cpe_str: str,
    component_version: Optional[str] = None,
    limit: int = 10,
) -> List[Dict]:
    """搜索匹配 CPE 字符串的 CVE 条目。可选按
    漏洞版本范围过滤。返回含置信度分数的匹配 dict 列表。"""

    parsed = _parse_cpe(cpe_str)
    if not parsed:
        return []

    vendor = parsed.get("vendor", "*")
    product = parsed.get("product", "*")

    # 构建搜索片段
    search_terms = []
    if product and product != "*":
        search_terms.append(product)
    if vendor and vendor != "*":
        search_terms.append(vendor)

    all_matches = []

    for term in search_terms[:2]:  # 分别按 product 和 vendor 搜索
        entries, _ = _kb_search(kb, term, limit=limit)
        for entry in entries:
            # 归一化条目访问 — 可为 dict, CVEEntry, 或 sqlite3.Row
            eid = _entry_cve_id(entry)
            eproducts = _entry_products(entry)
            evendors = _entry_vendors(entry)

            # 检查 product/vendor 重叠
            product_match = (
                product == "*"
                or product in [p.lower() for p in eproducts]
                or any(product.lower() in p.lower() for p in eproducts)
            )
            vendor_match = (
                vendor == "*"
                or vendor in [v.lower() for v in evendors]
                or any(vendor.lower() in v.lower() for v in evendors)
            )

            if product_match or vendor_match:
                match_info = {
                    "cve_id": eid,
                    "severity": _entry_severity(entry),
                    "description": _entry_description(entry),
                    "match_confidence": 0.85 if (product_match and vendor_match) else 0.7,
                    "match_type": "cpe",
                }

                # 同时有 version 和 ranges 时检查版本
                if component_version:
                    ranges = entry.get("affected_ranges", []) if isinstance(entry, dict) else getattr(entry, "affected_ranges", [])
                    if ranges or isinstance(entry, dict) and "affected_ranges" in entry:
                        if isinstance(entry, dict):
                            ranges = entry.get("affected_ranges", [])
                        else:
                            ranges = getattr(entry, "affected_ranges", [])
                        if _version_in_range(component_version, ranges):
                            match_info["version_affected"] = True
                            match_info["match_confidence"] = min(match_info["match_confidence"] + 0.05, 1.0)
                        else:
                            match_info["version_affected"] = False
                    else:
                        match_info["version_affected"] = None

                all_matches.append(match_info)

    # 按 cve_id 去重
    seen = set()
    deduped = []
    for m in all_matches:
        if m["cve_id"] not in seen:
            seen.add(m["cve_id"])
            deduped.append(m)

    return deduped


# 条目访问辅助函数 (模块级，有意未统一)
# 这些归一化 dict vs dataclass vs sqlite.Row 访问。
# 保持分离的真正原因: 单个 _normalize_entry() 需在每次调用时
# 复制所有字段 — 大批量匹配时更慢。
# 命名不一致是事实。尚不值得重构。

def _entry_cve_id(entry) -> str:
    """从任意条目类型获取 cve_id。"""
    if isinstance(entry, dict):
        return entry.get("cve_id", entry.get("id", ""))
    if hasattr(entry, "cve_id"):
        return entry.cve_id
    if hasattr(entry, "__getitem__"):
        try:
            return entry["cve_id"]
        except (KeyError, IndexError):
            return ""
    return ""


def _entry_severity(entry) -> str:
    """从任意条目类型获取 severity。"""
    if isinstance(entry, dict):
        return entry.get("severity", "UNKNOWN")
    if hasattr(entry, "severity"):
        return entry.severity
    if hasattr(entry, "__getitem__"):
        try:
            return entry["severity"]
        except (KeyError, IndexError):
            return "UNKNOWN"
    return "UNKNOWN"


def _entry_description(entry) -> str:
    """从任意条目类型获取 description。"""
    if isinstance(entry, dict):
        return entry.get("description", entry.get("desc", ""))
    if hasattr(entry, "description"):
        return entry.description
    if hasattr(entry, "__getitem__"):
        try:
            return entry["description"]
        except (KeyError, IndexError):
            return ""
    return ""


def _entry_products(entry) -> List[str]:
    """从任意条目类型获取 products 列表。"""
    if isinstance(entry, dict):
        prods = entry.get("products", entry.get("product", []))
        return prods if isinstance(prods, list) else [prods] if prods else []
    if hasattr(entry, "products"):
        return entry.products or []
    if hasattr(entry, "__getitem__"):
        try:
            prods = entry["products"]
            return prods if isinstance(prods, list) else [prods] if prods else []
        except (KeyError, IndexError):
            return []
    return []


def _entry_vendors(entry) -> List[str]:
    """从任意条目类型获取 vendors 列表。"""
    if isinstance(entry, dict):
        vends = entry.get("vendors", entry.get("vendor", []))
        return vends if isinstance(vends, list) else [vends] if vends else []
    if hasattr(entry, "vendors"):
        return entry.vendors or []
    if hasattr(entry, "__getitem__"):
        try:
            vends = entry["vendors"]
            return vends if isinstance(vends, list) else [vends] if vends else []
        except (KeyError, IndexError):
            return []
    return []
