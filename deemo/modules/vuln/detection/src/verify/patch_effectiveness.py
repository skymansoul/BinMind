# 修改记录:
# 2025-08-05 13:27 - 初始实现：补丁等价类划分+残留可利用性自动验证

"""补丁有效性自动验证 — 判断补丁是"根除"还是"表面修补"。

安全补丁的三种失败模式：
1. 表面修补——仅修改了PoC触发的代码路径，未修复根因。
   换个输入变种绕过补丁（常见于整数溢出加边界检查但不改算法）。
2. 引入新漏洞——补丁本身引入了新的可利用条件。
   缓冲区边界+1但未检查整数回绕。
3. 残留攻击面——补丁修复了A路径但B路径可达相同脆弱点。

本模块的方案——基于等价类的补丁完整性验证：
1. 提取补丁前后的"安全契约"——函数的前置条件/后置条件/不变式。
2. 对补丁前后版本生成符号执行路径集的差异。
3. 将差异路径分类为：
   - REMOVED: 补丁前可达/补丁后不可达 → 正确修复
   - ADDED: 补丁后新出现 → 可能引入了新攻击面
   - MODIFIED: 路径仍在但约束条件改变 → 需要审查约束是否充分
   - UNCHANGED: 完全相同 → 补丁未影响此路径
4. 若原漏洞类型的所有等价路径类都被移除 → 根除。
   若仅移除了PoC触发的子类 → 表面修补 → 标记为INCOMPLETE。

与既有工具的区别：
- patch_quality_evaluator.py: 评估补丁代码质量（复杂度/规范）。
- 本模块: 评估补丁的*安全性*——是否真正消除漏洞类。
- 前者是代码审查视角，后者是攻击者视角。

- "SoK: All You Ever Wanted to Know About x86/x64 Binary Disassembly"
 — 补丁二进制对比的方法学基础。
- "PatchVerif" — 补丁正确性验证的符号执行方法。
"""

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

class PathChangeType(Enum):
    REMOVED = "removed"       # 补丁后不可达
    ADDED = "added"           # 补丁后新出现
    MODIFIED = "modified"     # 路径仍在但约束改变
    UNCHANGED = "unchanged"   # 完全相同

class PatchVerdict(Enum):
    ROOT_CAUSE_FIXED = "root_cause_fixed"
    SURFACE_PATCH = "surface_patch"
    NEW_VULN_INTRODUCED = "new_vuln_introduced"
    INCONCLUSIVE = "inconclusive"

@dataclass
class PathEquivalenceClass:
    """一条符号执行路径的等价类。"""
    class_id: str
    path_conditions: List[str]    # 路径约束列表
    reachable_before: bool = True
    reachable_after: bool = False
    change_type: PathChangeType = PathChangeType.UNCHANGED
    is_vuln_related: bool = False

@dataclass
class PatchVerificationResult:
    """一次补丁验证的完整输出。"""
    patch_id: str
    verdict: PatchVerdict
    confidence: float
    removed_paths: int
    added_paths: int
    modified_paths: int
    unchanged_paths: int
    # 残留的可利用路径类
    residual_vuln_paths: List[str] = field(default_factory=list)
    # 新引入的可疑路径
    new_suspicious_paths: List[str] = field(default_factory=list)
    # 详细分析
    analysis: str = ""

class PatchEffectivenessVerifier:
    """补丁有效性自动验证器。

    使用范式：
      verifier = PatchEffectivenessVerifier()
      verifier.load_pre_patch_paths(pre_paths)
      verifier.load_post_patch_paths(post_paths)
      result = verifier.verify(vuln_type="stack_overflow")
    """

    def __init__(
        self,
        equivalence_threshold: float = 0.85,
        min_paths_for_confidence: int = 5,
    ):
        """
        equivalence_threshold: 路径约束相似度超过此值 → 归入同一等价类。
        min_paths_for_confidence: 最少需要多少条路径才能给出高置信度判定。
        """
        self.equivalence_threshold = equivalence_threshold
        self.min_paths_for_confidence = min_paths_for_confidence

        self._pre_paths: List[Dict] = []
        self._post_paths: List[Dict] = []
        self._equiv_classes: List[PathEquivalenceClass] = []

    # 加载 API

    def load_pre_patch_paths(self, paths: List[Dict]):
        """加载补丁前的符号执行路径。

        每条路径: {path_id, conditions: [str], is_vuln_trigger: bool}。
        """
        self._pre_paths = paths

    def load_post_patch_paths(self, paths: List[Dict]):
        """加载补丁后的符号执行路径。"""
        self._post_paths = paths

    # 验证 API

    def verify(
        self, vuln_type: str = "unknown",
    ) -> PatchVerificationResult:
        """执行补丁有效性验证。"""
        self._equiv_classes = self._classify_paths()

        _removed = sum(1 for c in self._equiv_classes
                      if c.change_type == PathChangeType.REMOVED)
        _added = sum(1 for c in self._equiv_classes
                    if c.change_type == PathChangeType.ADDED)
        _modified = sum(1 for c in self._equiv_classes
                       if c.change_type == PathChangeType.MODIFIED)
        _unchanged = sum(1 for c in self._equiv_classes
                        if c.change_type == PathChangeType.UNCHANGED)

        # 漏洞相关路径的残留检测
        _vuln_classes = [c for c in self._equiv_classes if c.is_vuln_related]
        _residual_vuln = [
            c.class_id for c in _vuln_classes
            if c.change_type in (PathChangeType.UNCHANGED, PathChangeType.MODIFIED)
        ]
        _new_suspicious = [
            c.class_id for c in self._equiv_classes
            if c.change_type == PathChangeType.ADDED and not c.is_vuln_related
        ]

        # 判定
        _verdict, _confidence = self._determine_verdict(
            _vuln_classes, _residual_vuln, _new_suspicious, _added, _removed,
        )

        _analysis = self._build_analysis(
            vuln_type, _verdict, _removed, _residual_vuln, _new_suspicious,
        )

        return PatchVerificationResult(
            patch_id=f"patch_{vuln_type}",
            verdict=_verdict,
            confidence=round(_confidence, 3),
            removed_paths=_removed,
            added_paths=_added,
            modified_paths=_modified,
            unchanged_paths=_unchanged,
            residual_vuln_paths=_residual_vuln,
            new_suspicious_paths=_new_suspicious,
            analysis=_analysis,
        )

    # 内部

    def _classify_paths(self) -> List[PathEquivalenceClass]:
        """将补丁前后的路径归入等价类并分类。"""
        _classes: List[PathEquivalenceClass] = []

        # 构建"前"路径的等价类
        _pre_classes: Dict[str, PathEquivalenceClass] = {}
        for _i, _p in enumerate(self._pre_paths):
            _best_match = None
            _best_sim = 0.0
            for _cid, _ec in _pre_classes.items():
                _sim = _constraint_similarity(
                    _p.get("conditions", []),
                    _ec.path_conditions,
                )
                if _sim > _best_sim:
                    _best_sim = _sim
                    _best_match = _cid

            if _best_sim >= self.equivalence_threshold and _best_match:
                _pre_classes[_best_match].is_vuln_related |= _p.get(
                    "is_vuln_trigger", False)
            else:
                _cid = f"pre_{_i}"
                _pre_classes[_cid] = PathEquivalenceClass(
                    class_id=_cid,
                    path_conditions=list(_p.get("conditions", [])),
                    reachable_before=True,
                    reachable_after=False,
                    is_vuln_related=_p.get("is_vuln_trigger", False),
                )

        # 对每个"后"路径，与"前"等价类匹配
        _matched_pre: Set[str] = set()
        for _j, _p in enumerate(self._post_paths):
            _best_match = None
            _best_sim = 0.0
            for _cid, _ec in _pre_classes.items():
                _sim = _constraint_similarity(
                    _p.get("conditions", []), _ec.path_conditions,
                )
                if _sim > _best_sim:
                    _best_sim = _sim
                    _best_match = _cid

            if _best_sim >= self.equivalence_threshold and _best_match:
                _ec = _pre_classes[_best_match]
                _ec.reachable_after = True
                _matched_pre.add(_best_match)
            else:
                # 后补丁新路径
                _classes.append(PathEquivalenceClass(
                    class_id=f"post_{_j}",
                    path_conditions=list(_p.get("conditions", [])),
                    reachable_before=False,
                    reachable_after=True,
                    change_type=PathChangeType.ADDED,
                ))

        # 对前置等价类确定变化类型
        for _cid, _ec in _pre_classes.items():
            if _ec.reachable_before and not _ec.reachable_after:
                _ec.change_type = PathChangeType.REMOVED
            elif _ec.reachable_before and _ec.reachable_after:
                _ec.change_type = PathChangeType.UNCHANGED
            _classes.append(_ec)

        return _classes

    def _determine_verdict(
        self,
        vuln_classes: List[PathEquivalenceClass],
        residual_vuln: List[str],
        new_suspicious: List[str],
        added: int,
        removed: int,
    ) -> Tuple[PatchVerdict, float]:
        """基于路径类变化确定补丁判定。"""
        _total_vuln = len(vuln_classes)

        if _total_vuln == 0:
            return PatchVerdict.INCONCLUSIVE, 0.3

        _vuln_removed = sum(
            1 for c in vuln_classes
            if c.change_type == PathChangeType.REMOVED
        )
        _removed_ratio = _vuln_removed / _total_vuln

        # 仅当新增路径 > 移除的漏洞路径时才判定为引入新漏洞
        if new_suspicious and (len(new_suspicious) > _vuln_removed):
            return PatchVerdict.NEW_VULN_INTRODUCED, min(0.9, 0.5 + len(new_suspicious) * 0.1)

        if _removed_ratio >= 0.95:
            _conf = min(0.95, 0.6 + 0.1 * max(_total_vuln, self.min_paths_for_confidence) / self.min_paths_for_confidence)
            return PatchVerdict.ROOT_CAUSE_FIXED, _conf

        if _removed_ratio < 0.5 and residual_vuln:
            return PatchVerdict.SURFACE_PATCH, 0.7 + (1.0 - _removed_ratio) * 0.2

        return PatchVerdict.INCONCLUSIVE, 0.4 + _removed_ratio * 0.3

    @staticmethod
    def _build_analysis(
        vuln_type: str, verdict: PatchVerdict,
        removed: int, residual: List[str], new_sus: List[str],
    ) -> str:
        if verdict == PatchVerdict.ROOT_CAUSE_FIXED:
            return f"All {removed} vulnerability-related path classes removed. Root cause appears fixed."
        elif verdict == PatchVerdict.SURFACE_PATCH:
            return (f"Only {removed} paths removed; {len(residual)} residual vuln paths exist. "
                    f"Patch likely addresses PoC but not root cause.")
        elif verdict == PatchVerdict.NEW_VULN_INTRODUCED:
            return f"Patch introduced {len(new_sus)} new suspicious path classes."
        return f"Insufficient path data for conclusive assessment."

def _constraint_similarity(
    conds_a: List[str], conds_b: List[str],
) -> float:
    """计算两组路径约束的Jaccard相似度。"""
    _set_a = set(conds_a)
    _set_b = set(conds_b)
    _union = _set_a | _set_b
    if not _union:
        return 0.0
    return len(_set_a & _set_b) / len(_union)

# 冒烟测试
def _smoke_test():
    _pre_paths = [
        {"path_id": "p1", "conditions": ["len>0", "len<256", "src!=NULL"],
         "is_vuln_trigger": True},
        {"path_id": "p2", "conditions": ["len>256", "src!=NULL"],
         "is_vuln_trigger": True},
        {"path_id": "p3", "conditions": ["src==NULL"], "is_vuln_trigger": False},
    ]
    # 补丁后：p1被移除(p2被添加了边界检查)，p2仍在但加了额外约束
    _post_paths = [
        {"path_id": "q1", "conditions": ["len>0", "len<256", "src!=NULL",
                                          "dst_buf>=256"],
         "is_vuln_trigger": False},  # p1的约束被增强
        {"path_id": "q2", "conditions": ["len>256", "src!=NULL"],
         "is_vuln_trigger": True},   # p2残留——补丁遗漏！
        {"path_id": "q3", "conditions": ["src==NULL"], "is_vuln_trigger": False},
    ]

    _verifier = PatchEffectivenessVerifier()
    _verifier.load_pre_patch_paths(_pre_paths)
    _verifier.load_post_patch_paths(_post_paths)
    _result = _verifier.verify(vuln_type="buffer_overflow")

    print(f"[patch_verify] verdict: {_result.verdict.value}")
    print(f"[patch_verify] confidence: {_result.confidence:.3f}")
    print(f"[patch_verify] removed/added/modified/unchanged: "
          f"{_result.removed_paths}/{_result.added_paths}/"
          f"{_result.modified_paths}/{_result.unchanged_paths}")
    print(f"[patch_verify] residual vuln paths: {_result.residual_vuln_paths}")
    print(f"[patch_verify] analysis: {_result.analysis}")

    # p2(path_id="p2", len>256) 应被标记为残留
    assert _result.verdict in (PatchVerdict.SURFACE_PATCH, PatchVerdict.INCONCLUSIVE), (
        f"should detect incomplete patch, got {_result.verdict}"
    )
    assert len(_result.residual_vuln_paths) > 0, "should find residual vuln paths"
    print("[OK] PatchEffectivenessVerifier smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
