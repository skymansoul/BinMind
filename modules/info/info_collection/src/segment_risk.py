# segment_risk — 内存段邻接风险分析
# 从段布局推断可利用原语：权限组合 + 空间邻接 → exploit 路径长度
# 核心假设：RW 段紧邻 RX 段且间距 < 4K → 写原语可升级为代码执行

from typing import Dict, List, Tuple, Optional, Set
import math


_PAGE_SIZE = 0x1000

_R = 0x4
_W = 0x2
_X = 0x1

_PERM_NAMES = {_R: "R", _W: "W", _X: "X", _R | _W: "RW", _R | _X: "RX",
               _W | _X: "WX", _R | _W | _X: "RWX"}


def _decode_elf_phdr_flags(flags: int) -> int:
    """ELF p_flags → 内部权限位图 (R=4, W=2, X=1)。"""
    _perm = 0
    if flags & 4: _perm |= _R
    if flags & 2: _perm |= _W
    if flags & 1: _perm |= _X
    return _perm


def _section_perm_from_chars(chars: list) -> int:
    """PE characteristics 列表 → 内部权限位图。"""
    _perm = 0
    _char_set = set(chars)
    if "MEM_READ" in _char_set: _perm |= _R
    if "MEM_WRITE" in _char_set: _perm |= _W
    if "MEM_EXECUTE" in _char_set: _perm |= _X
    return _perm


def _is_exec_segment(seg: dict, fmt: str) -> bool:
    """ELF 用 flags & 0x1，PE 用 characteristics 中的 MEM_EXECUTE，
    Mach-O 用 segment 名称 __TEXT。"""
    if fmt == "ELF":
        _p = seg.get("flags", 0)
        return bool(_p & _X) if isinstance(_p, int) else bool(_p & 0x1)
    elif fmt == "PE":
        _chars = seg.get("characteristics", [])
        return "MEM_EXECUTE" in _chars
    elif fmt == "MACHO":
        return seg.get("segment", "") in ("__TEXT",)
    return False


def _is_writable_segment(seg: dict, fmt: str) -> bool:
    if fmt == "ELF":
        _p = seg.get("flags", 0)
        return bool(_p & _W) if isinstance(_p, int) else bool(_p & 0x2)
    elif fmt == "PE":
        _chars = seg.get("characteristics", [])
        return "MEM_WRITE" in _chars
    elif fmt == "MACHO":
        return seg.get("segment", "") in ("__DATA", "__DATA_CONST", "__DATA_DIRTY")
    return False


def _segment_extent(seg: dict, fmt: str) -> Tuple[int, int]:
    """返回段虚拟地址区间 (start, end)。"""
    if fmt == "ELF":
        _start = seg.get("vaddr", 0)
        _size = seg.get("filesz", 0)
    elif fmt == "PE":
        _start = seg.get("va", 0)
        _size = seg.get("raw_size", 0)
    elif fmt == "MACHO":
        _start = seg.get("vmaddr", 0)
        _size = seg.get("vmsize", 0)
    else:
        return (0, 0)
    return (_start, _start + _size)


def _gap_size(seg_a: Tuple[int, int], seg_b: Tuple[int, int]) -> int:
    return seg_b[0] - seg_a[1]


def compute_segment_risk(sections: List[dict], fmt: str, image_base: int = 0) -> Dict:
    """分析段布局邻接风险。
    按 VA 排序后遍历相邻对，生成风险评分、原语估计与 guard page 覆盖率。
    """
    if not sections or len(sections) < 2:
        return {
            "adjacency_pairs": [],
            "rwx_adjacent_count": 0,
            "min_inter_segment_gap": 0,
            "adjacency_risk_score": 0.0,
            "primitive_estimate": "insufficient_data",
            "guard_page_coverage": 1.0,
        }

    _valid = []
    for _s in sections:
        _start, _end = _segment_extent(_s, fmt)
        if _start > 0 and _end > _start:
            _valid.append((_start, _end, _s))

    _valid.sort(key=lambda x: x[0])

    _adjacency_pairs = []
    _rwx_adjacent = 0
    _gaps = []
    _segment_count = len(_valid)

    for i in range(_segment_count - 1):
        _s1_start, _s1_end, _seg1 = _valid[i]
        _s2_start, _s2_end, _seg2 = _valid[i + 1]

        _gap = _gap_size((_s1_start, _s1_end), (_s2_start, _s2_end))
        if _gap >= 0:
            _gaps.append(_gap)

        _w1 = _is_writable_segment(_seg1, fmt)
        _x1 = _is_exec_segment(_seg1, fmt)
        _w2 = _is_writable_segment(_seg2, fmt)
        _x2 = _is_exec_segment(_seg2, fmt)

        _risk_adjacent = (_w1 and _x2) or (_x1 and _w2)
        if _risk_adjacent:
            _rwx_adjacent += 1

        if _risk_adjacent or (0 <= _gap < _PAGE_SIZE and _gap >= 0):
            _adjacency_pairs.append({
                "segment_a": _seg1.get("name", _seg1.get("segment", f"seg_{i}")),
                "segment_b": _seg2.get("name", _seg2.get("segment", f"seg_{i+1}")),
                "a_range": f"0x{_s1_start:x}-0x{_s1_end:x}",
                "b_range": f"0x{_s2_start:x}-0x{_s2_end:x}",
                "gap": _gap,
                "a_writable": _w1,
                "b_executable": _x2,
                "risk_type": _classify_risk(_w1, _x1, _w2, _x2, _gap),
            })

    _adj_score = _compute_adjacency_score(_rwx_adjacent, _gaps, _segment_count)
    _guard_cov = _estimate_guard_coverage(_gaps)
    _primitive = _estimate_primitive(_rwx_adjacent, _gaps, _adj_score)

    return {
        "adjacency_pairs": _adjacency_pairs,
        "rwx_adjacent_count": _rwx_adjacent,
        "min_inter_segment_gap": min(_gaps) if _gaps else 0,
        "adjacency_risk_score": round(_adj_score, 4),
        "primitive_estimate": _primitive,
        "guard_page_coverage": round(_guard_cov, 4),
    }


def _classify_risk(w1: bool, x1: bool, w2: bool, x2: bool, gap: int) -> str:
    """邻接对风险分类：guarded/write_to_exec_direct/write_to_data_proximity/data_proximity。"""
    if gap >= _PAGE_SIZE:
        return "guarded"
    if (w1 and x2):
        return "write_to_exec_direct"
    if w1 and not x2 and gap < _PAGE_SIZE:
        return "write_to_data_proximity"
    if not w1 and not x2:
        return "data_proximity"
    return "unknown"


def _compute_adjacency_score(rwx_count: int, gaps: List[int], seg_count: int) -> float:
    """综合邻接评分：pair_density×0.7 + tight_ratio×0.3，logistic 平滑。"""
    if seg_count < 2:
        return 0.0

    _pair_density = rwx_count / (seg_count - 1)

    _tight_gaps = sum(1 for g in gaps if 0 <= g < _PAGE_SIZE)
    _tight_ratio = _tight_gaps / max(1, len(gaps))

    _raw = 0.7 * _pair_density + 0.3 * _tight_ratio
    _score = 1.0 / (1.0 + math.exp(-6 * (_raw - 0.15)))
    return _score


def _estimate_guard_coverage(gaps: List[int]) -> float:
    """间距 >= PAGE_SIZE 的对占比，近似 guard page 覆盖率。"""
    if not gaps:
        return 1.0
    _guarded = sum(1 for g in gaps if g >= _PAGE_SIZE)
    return _guarded / len(gaps)


def _estimate_primitive(rwx_count: int, gaps: List[int], adj_score: float) -> str:
    """邻接评分映射到可利用原语定性估计。"""
    if adj_score < 0.2:
        return "data_corruption_only"
    if adj_score < 0.45:
        return "potential_arbitrary_write_via_overflow"
    _tight = sum(1 for g in gaps if 0 <= g < _PAGE_SIZE)
    if rwx_count >= 2 and _tight >= 2:
        return "likely_code_execution_primitive"
    if rwx_count >= 1:
        return "possible_code_execution_via_segment_overflow"
    return "unclear_require_dynamic_confirmation"
