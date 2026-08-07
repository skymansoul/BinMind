# Created: 2026-06-03 20:23:15
#
# cfg_entropy_fingerprint — 多尺度 CFG 结构熵指纹
# 不依赖完整反汇编，基于函数尺寸分布 + 导入调用拓扑 + 段代码密度 三层信号
# 每层独立计算 Shannon 熵后加权几何合成，跨架构可比
#
# 设计依据：
# 1. 函数尺寸分布的熵捕获编译器/优化级别的结构性痕迹
# 高熵 → 大量不同尺寸函数（解释器/JIT 生成代码特征）
# 低熵 → 函数尺寸高度集中（静态链接库 / 模板展开）
# 2. 导入调用熵从二分图视角刻画外部依赖复杂度
# 高熵 → 调用分散在多个 DLL/库（正常应用）
# 低熵 + 危险函数集中 → 可能的漏洞利用工具链
# 3. 段代码/数据比熵反映二进制布局策略
# 差异显著 → 打包器/加密器修改了原始段布局
# 4. 三层熵值的归一化复合向量可用作相似性检索的局部敏感哈希

import math
import hashlib
import struct
from typing import Dict, List, Tuple, Optional
from collections import Counter
from ._shared import shannon_entropy as _shannon_entropy



def _adaptive_binning(sizes: List[int], bin_count: int = 16) -> Counter:
    """自适应分箱：对数宽度箱避免长尾大函数支配计数。
    bin_count 控制分辨率，实际箱数取决于数据跨度。
    """
    if not sizes:
        return Counter()
    _min_s = min(sizes)
    _max_s = max(sizes)
    if _min_s == _max_s:
        return Counter({f"bin_{_min_s}": len(sizes)})

    # 对数尺度：exp(linspace(log(min+1), log(max+1), bin_count))
    _log_min = math.log(_min_s + 1)
    _log_max = math.log(_max_s + 1)
    _step = (_log_max - _log_min) / bin_count

    _bins = Counter()
    for _sz in sizes:
        _log_sz = math.log(_sz + 1)
        _idx = int((_log_sz - _log_min) / _step)
        _idx = min(_idx, bin_count - 1)
        _lo = int(math.exp(_log_min + _idx * _step)) - 1
        _hi = int(math.exp(_log_min + (_idx + 1) * _step))
        _bins[f"[{_lo},{_hi})"] += 1
    return _bins


def compute_function_size_entropy(
    functions: List[Dict],
    bin_count: int = 16,
) -> Dict:
    """函数尺寸分布的结构熵。
    functions: [{"name":..., "size":...}, ...]
    返回原始熵、归一化熵、分箱计数。
    归一化用 log2(bin_count)，使不同箱数结果可比。
    """
    _sizes = [f.get("size", 0) for f in functions if f.get("size", 0) > 0]
    if len(_sizes) < 2:
        return {
            "entropy_raw": 0.0,
            "entropy_normalized": 0.0,
            "function_count": len(_sizes),
            "size_range": (0, 0),
            "bin_counts": {},
        }

    _bins = _adaptive_binning(_sizes, bin_count)
    _raw = _shannon_entropy(_bins, len(_sizes))
    _max_ent = math.log(min(bin_count, len(_bins))) if _bins else 1.0
    _norm = _raw / _max_ent if _max_ent > 0 else 0.0

    return {
        "entropy_raw": round(_raw, 6),
        "entropy_normalized": round(min(1.0, _norm), 6),
        "function_count": len(_sizes),
        "size_range": (min(_sizes), max(_sizes)),
        "bin_counts": {k: v for k, v in sorted(_bins.items())},
    }


def compute_import_topology_entropy(
    imports: Dict[str, List[str]],
    dangerous_set: List[str] = None,
) -> Dict:
    """导入调用拓扑的结构熵。
    计算两个维度：(a) 库间调用分布熵 (b) 危险函数集中度。
    高库间熵 + 低危险集中度 → 正常应用。
    低库间熵 + 高危险集中度 → 专用工具/exploit。
    """
    if not imports:
        return {
            "inter_library_entropy": 0.0,
            "dangerous_concentration": 0.0,
            "library_count": 0,
            "total_imports": 0,
            "topology_signature": "",
        }

    _dangerous = set(dangerous_set or [])
    _lib_counter = Counter()
    _total_funcs = 0
    _dangerous_count = 0
    _all_funcs: List[str] = []

    for _lib, _funcs in imports.items():
        _lib_counter[_lib] += len(_funcs)
        _total_funcs += len(_funcs)
        _all_funcs.extend(_funcs)
        if _dangerous:
            _dangerous_count += sum(1 for f in _funcs if f in _dangerous)

    _inter_lib_ent = _shannon_entropy(_lib_counter, _total_funcs)

    # 危险函数集中度：危险函数在总导入中的比例归一化
    _dang_conc = _dangerous_count / _total_funcs if _total_funcs > 0 else 0.0

    # 拓扑签名：库分布熵 + 危险集中度的低位哈希，用于快速聚类
    _sig_bytes = struct.pack(">dd", _inter_lib_ent, _dang_conc)
    _sig = hashlib.blake2b(_sig_bytes, digest_size=8).hexdigest()[:12]

    return {
        "inter_library_entropy": round(_inter_lib_ent, 6),
        "dangerous_concentration": round(_dang_conc, 6),
        "library_count": len(_lib_counter),
        "total_imports": _total_funcs,
        "topology_signature": _sig,
    }


def _classify_section_type(name: str, characteristics: list = None) -> str:
    """段名称 → 语义分类：CODE / DATA / RODATA / BSS / OTHER。
    基于常见段命名约定，不依赖平台特定解析。
    """
    _n = name.lower().lstrip("._")
    if _n in ("text", "code", "itext"):
        return "CODE"
    if _n in ("data", "rdata", "idata"):
        return "DATA"
    if _n in ("rdata", "rodata", "const"):
        return "RODATA"
    if _n in ("bss",):
        return "BSS"
    if characteristics and "MEM_EXECUTE" in str(characteristics):
        return "CODE"
    return "OTHER"


def compute_section_density_entropy(sections: List[Dict], fmt: str = "ELF") -> Dict:
    """段代码/数据密度分布的结构熵。
    核心假设：正常编译器产物的段类型比例在某个窄区间内。
    打包/加密会破坏这个比例，导致密度熵异常。
    """
    if not sections:
        return {
            "density_entropy": 0.0,
            "code_ratio": 0.0,
            "type_distribution": {},
            "layout_anomaly_score": 0.0,
        }

    _type_counter = Counter()
    _total_size = 0
    _code_size = 0

    for _sec in sections:
        _type = _classify_section_type(
            _sec.get("name", _sec.get("segment", "")),
            _sec.get("characteristics"),
        )
        _sz = _sec.get("size", _sec.get("vmsize", _sec.get("filesz", 0)))
        if _sz > 0:
            _type_counter[_type] += _sz
            _total_size += _sz
            if _type == "CODE":
                _code_size += _sz

    _dens_ent = _shannon_entropy(_type_counter, _total_size)
    _code_ratio = _code_size / _total_size if _total_size > 0 else 0.0

    # 布局异常评分：代码比偏离典型区间 (0.15-0.55) 的程度
    # 使用二次惩罚函数，中心点 0.35
    _anomaly = max(0.0, 1.0 - math.exp(-8 * (_code_ratio - 0.35) ** 2))

    _type_dist = {
        _t: round(_sz / _total_size, 4) if _total_size > 0 else 0.0
        for _t, _sz in _type_counter.items()
    }

    return {
        "density_entropy": round(_dens_ent, 6),
        "code_ratio": round(_code_ratio, 4),
        "type_distribution": _type_dist,
        "layout_anomaly_score": round(_anomaly, 4),
    }


def _weighted_geometric_pool(
    values: List[float],
    weights: List[float],
    damp: float = 0.1,
) -> float:
    """加权几何池化：带阻尼的幂平均，压制单一维度的主导效应。
    权重自动归一化，damp 控制极端值的衰减。
    """
    if not values:
        return 0.0
    _total_w = sum(weights)
    if _total_w <= 0:
        return 0.0
    _log_sum = sum(
        w * math.log(max(v, 1e-9) + damp)
        for v, w in zip(values, weights)
    )
    return math.exp(_log_sum / _total_w) - damp


def compute_cfg_fingerprint(
    binary_info: Dict,
    functions: List[Dict] = None,
    imports: Dict = None,
    sections: List[Dict] = None,
) -> Dict:
    """多尺度 CFG 结构熵指纹的统一入口。
    输入：binary_info 字典 + 可选的外部函数/导入/段覆盖。

    输出指纹包含：
    - function_entropy: 函数尺寸分布熵
    - import_entropy: 导入拓扑熵
    - section_entropy: 段密度熵
    - composite_vector: [norm_func_ent, inter_lib_ent, code_ratio, layout_anomaly]
    - composite_hash: 复合向量的 BLAKE2b 哈希（局部敏感）
    - fingerprint_id: 完整指纹的短标识符
    """
    _fmt = binary_info.get("format", "ELF")
    _funcs = functions or binary_info.get("functions", [])
    _imps = imports or binary_info.get("imports", {})
    # 兼容两种导入格式：{dll: [funcs]} 和 {"all_imports": {dll: [funcs]}}
    if isinstance(_imps, dict) and "all_imports" in _imps:
        _imps = _imps["all_imports"]
    _secs = sections or binary_info.get("sections", [])

    _func_ent = compute_function_size_entropy(_funcs)
    _import_ent = compute_import_topology_entropy(_imps)
    _section_ent = compute_section_density_entropy(_secs, _fmt)

    # 复合向量：4 维归一化特征
    _vec = [
        _func_ent["entropy_normalized"],
        _import_ent["inter_library_entropy"] / max(math.log(max(_import_ent["library_count"], 2)), 1e-6),
        _section_ent["code_ratio"],
        _section_ent["layout_anomaly_score"],
    ]
    _vec = [round(min(1.0, max(0.0, v)), 6) for v in _vec]

    # 加权几何合成：函数熵权重 0.35, 导入熵 0.30, 代码比 0.20, 布局异常 0.15
    _weights = [0.35, 0.30, 0.20, 0.15]
    _composite = _weighted_geometric_pool(_vec, _weights)

    _vec_bytes = struct.pack(">4d", *_vec)
    _composite_hash = hashlib.blake2b(_vec_bytes, digest_size=16).hexdigest()

    _fp_raw = f"{_fmt}:{_func_ent['function_count']}:{_import_ent['total_imports']}:{_composite_hash[:8]}"
    _fp_id = hashlib.blake2b(_fp_raw.encode(), digest_size=8).hexdigest()[:12]

    return {
        "function_entropy": _func_ent,
        "import_entropy": _import_ent,
        "section_entropy": _section_ent,
        "composite_vector": _vec,
        "composite_score": round(_composite, 6),
        "composite_hash": _composite_hash,
        "fingerprint_id": _fp_id,
    }
