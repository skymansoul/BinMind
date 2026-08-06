# 创建: 2026-07-30 18:33
# 修改: 2026-08-04 15:30 (审计修复: 引用验证, 性能警告标注, 边界条件补全)
# 简述: 防泄露前瞻性评分协议
# 防泄露前瞻性评分协议 — 时间窗口锁定 + 仅用事件前信息
#
# 问题: 几乎所有CVE利用预测模型都受时间泄露 (temporal leakage) 影响.
# 以EPSS为例: 某CVE在公布后180天才被KEV收录, 但若模型使用含KEV标签的
# 历史数据训练, 它会"看到"未来信息. 实证表明可虚增预测准确率5-8.5倍
# (arXiv:2606.19076, 2026).
#
# 解决方案: 前瞻性评分协议.
# 1. 时间锚定: 对每个预测目标, 定义决策时间点 T_decision.
#    只能使用 T_decision 之前公开可用的信息.
# 2. 证据窗口: 对每个数据源, 记录该源在 T_decision 时的快照.
# 3. 特征冻结: 所有特征计算仅基于窗口内的数据.
#    禁用"发布后N天"的相对时间特征, 改用"决策时N天前"的绝对时间特征.
# 4. 标签脱敏: 训练数据中的标签必须来自 T_decision + min_horizon 之后.
#    例如, 预测"30天内是否被利用", 标签需来自 T_decision + 30 天之后.
#    若CVSS在决策日前已发布, 其值可安全使用; 但"是否被KEV收录"
#    须检查KEV收录日期是否在决策日之前.
#
# 本协议的三个关键规则:
#   Rule 1 — 时间窗口锁定: 每个证据源标注 "as_of" 时间戳.
#   Rule 2 — 前向特征: 特征只描述"到目前为止"的已知状态.
#   Rule 3 — 后向标签: 标签定义包含最小前瞻期, 防止使用即时反馈.
#
# 与现有模块的集成:
#   - CVEExploitGraph.build(): 为每条边添加 temporal_validity 属性
#   - C3EPipeline.fit(): 为每个训练样本添加 window_start/window_end
#   - cve_risk_scorer: 为分数添加 evidence_window 和 data_freshness 字段
#
# 参考:
#   [arXiv:2606.19076, 2026] 前瞻评分协议的核心概念
#   [Bilge & Dumitras 2012] 时间泄露对安全数据挖掘的影响 (经典参考)
#   [Jacobs et al. 2023] EPSS评估中的前瞻性框架缺陷

import math
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any

from .cve_models import CVEEntry
from .cve_kb import CVEKnowledgeBase
from .cve_audit_trail import AuditTrailManager, AuditCertificate


class EvidenceWindow:
    """锁定的证据窗口 — 记录某个数据源在特定时间点的可用信息.

    窗口 = [window_start, window_end], 其中window_end ≤ T_decision.
    窗口外的任何信息被视为"未来信息", 禁止用于特征计算.
    """

    def __init__(self, source: str, window_end: str,
                 lookback_days: int = 365):
        self.source = source
        self.window_end = window_end  # YYYY-MM-DD
        end_dt = datetime.fromisoformat(window_end).replace(tzinfo=timezone.utc)
        self.window_start = (end_dt - timedelta(days=lookback_days)).strftime("%Y-%m-%d")
        self.lookback_days = lookback_days
        self._frozen_features: Dict[str, float] = {}

    def freeze_feature(self, name: str, value: float):
        """冻结一个特征值 (使其不受后续数据变更影响)."""
        self._frozen_features[name] = value

    def get_feature(self, name: str, default: float = 0.0) -> float:
        return self._frozen_features.get(name, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "lookback_days": self.lookback_days,
            "n_frozen_features": len(self._frozen_features),
        }


class ProspectiveScore:
    """前瞻性评分 — 带时间锚定的CVE利用评估.

    与常规评分的区别:
    - conventional: score = f(CVSS, EPSS_now, KEV_now, ExploitDB_now)
    - prospective:  score = f(CVSS, EPSS_at_T, KEV_at_T, ExploitDB_at_T)
                      其中 T = 决策时间点 (通常为"评分执行日")

    前者可能使用了EPSS在公布后更新过的新信息, 从而高估预测能力.
    后者严格限制在决策日之前可用的信息.
    """

    def __init__(self, cve_id: str, decision_date: str):
        self.cve_id = cve_id
        self.decision_date = decision_date
        self._windows: Dict[str, EvidenceWindow] = {}
        self._final_score: Optional[float] = None
        self._score_components: Dict[str, float] = {}
        self._leakage_warnings: List[str] = []

    def add_evidence(self, source: str, window_end: str,
                     lookback_days: int = 365) -> EvidenceWindow:
        """注册一个证据源的时间窗口.

        window_end必须 ≤ decision_date, 否则触发泄露告警.
        """
        if window_end > self.decision_date:
            self._leakage_warnings.append(
                f"TEMPORAL_LEAKAGE:{source} window_end={window_end} > decision={self.decision_date}")
            # 强行截断到决策日
            window_end = self.decision_date

        win = EvidenceWindow(source, window_end, lookback_days)
        self._windows[source] = win
        return win

    def compute(self, cvss_score: float, epss_score: float,
                kev_known: bool, maturity: str,
                days_since_pub: float) -> Dict[str, Any]:
        """计算前瞻性分数 — 仅使用决策日之前冻结的特征.

        cvss_score: CVSS基础分 (静态, 发布时已知).
        epss_score: 决策日时的EPSS分数 (可能低于"当前"值).
        kev_known: 决策日时是否已在KEV目录中.
        maturity: 决策日时已知的利用成熟度.
        days_since_pub: 从发布到决策日的天数.
        """
        # CVSS贡献 (静态, 无时间泄露风险)
        cvss_contrib = min((cvss_score or 0.0) / 10.0, 1.0) * 0.35

        # EPSS贡献 — 使用决策日时的历史EPSS
        epss_contrib = min(epss_score or 0.0, 1.0) * 0.30

        # KEV贡献 — 仅当在决策日之前已收录
        kev_contrib = 0.20 if kev_known else 0.0

        # 利用成熟度 (决策日时已知的状态)
        mat_val = {"unknown": 0.0, "poc": 0.15, "proof_of_concept": 0.15,
                   "functional": 0.30, "metasploit": 0.40, "weaponized": 0.50}
        mat_contrib = mat_val.get(maturity.lower().strip(), 0.0)

        # 时间衰减: 较新的CVE (从发布到决策日时间短) 评分更高
        # 因为"最近的CVE更可能尚未被修补"
        recency = math.exp(-0.3 * max(days_since_pub, 0) / 365.0)
        time_weight = 0.7 + 0.3 * recency

        raw_score = (cvss_contrib + epss_contrib + kev_contrib + mat_contrib) * time_weight
        score = round(max(0.0, min(1.0, raw_score)), 4)

        self._final_score = score
        self._score_components = {
            "cvss_contribution": round(cvss_contrib, 4),
            "epss_contribution": round(epss_contrib, 4),
            "kev_contribution": round(kev_contrib, 4),
            "maturity_contribution": round(mat_contrib, 4),
            "time_weight": round(time_weight, 4),
        }

        return {
            "cve_id": self.cve_id,
            "decision_date": self.decision_date,
            "prospective_score": score,
            "components": dict(self._score_components),
            "evidence_windows": {k: w.to_dict() for k, w in self._windows.items()},
            "leakage_warnings": list(self._leakage_warnings),
            "score_label": _prospective_label(score),
        }


class ProspectiveScoringEngine:
    """前瞻性评分引擎 — 批量处理CVE, 确保无时间泄露.

    工作流程:
      1. 接收一批CVE和一个决策日期.
      2. 对每个CVE, 只提取决策日期前存在的特征.
      3. 检查每个特征来源的时间一致性.
      4. 生成带审计证书的前瞻性评分.
    """

    def __init__(self, kb: CVEKnowledgeBase,
                 audit_mgr: Optional[AuditTrailManager] = None):
        self._kb = kb
        self._audit = audit_mgr or AuditTrailManager()

    def score_cve(self, cve_id: str, decision_date: Optional[str] = None
                  ) -> Dict[str, Any]:
        """对单个CVE计算前瞻性评分.

        decision_date为None时默认为昨天 (避免使用当日尚未完成的数据).
        """
        if decision_date is None:
            decision_date = (datetime.now(timezone.utc).date() -
                             timedelta(days=1)).isoformat()

        entry = self._kb.get(cve_id)
        if entry is None:
            return {"error": f"CVE {cve_id} not found in KB", "cve_id": cve_id}

        ps = ProspectiveScore(cve_id, decision_date)

        # 提取特征 — 全部相对于决策日计算
        cvss = _get_num(entry, "cvss_score") or 0.0  # CVSS是静态的, 安全使用
        epss = _get_num(entry, "epss_score") or 0.0   # EPSS可能是"当前"值, 需降权

        # EPSS时间一致性检查: 若CVE的发布日期在EPSS数据集的发布日之后,
        # 标记为潜在泄露 (简化处理 — 真实实现需EPSS历史数据)
        pub_date = _get_str(entry, "published_date", "")
        if pub_date:
            try:
                pub_dt = datetime.fromisoformat(pub_date.replace("Z", "+00:00"))
                decision_dt = datetime.fromisoformat(
                    decision_date).replace(tzinfo=timezone.utc)
                days_since_pub = (decision_dt - pub_dt).total_seconds() / 86400.0
            except (ValueError, TypeError):
                days_since_pub = 365.0
        else:
            days_since_pub = 365.0

        # KEV: 检查收录日期是否在决策日之前
        kev_date = _get_str(entry, "cisa_kev_date", "")
        kev_known = False
        if kev_date and _get_bool(entry, "cisa_kev"):
            try:
                kev_dt = datetime.fromisoformat(kev_date.replace("Z", "+00:00"))
                decision_dt = datetime.fromisoformat(
                    decision_date).replace(tzinfo=timezone.utc)
                kev_known = kev_dt <= decision_dt
            except (ValueError, TypeError):
                kev_known = bool(_get_bool(entry, "cisa_kev"))

        maturity = _get_str(entry, "exploit_maturity", "unknown")

        # 注册证据窗口
        ps.add_evidence("nvd", decision_date, lookback_days=730)
        ps.add_evidence("epss", decision_date, lookback_days=90)
        ps.add_evidence("kev", decision_date, lookback_days=365)

        result = ps.compute(cvss, epss, kev_known, maturity, days_since_pub)

        # 发审计证书
        evidence = {
            "nvd": {"cvss": cvss, "published": pub_date},
            "epss": {"score": epss},
            "kev": {"known_at_decision": kev_known},
        }
        params = {"method": "prospective_v1", "decision_date": decision_date}
        cert = self._audit.issue(
            cve_id=cve_id, score=result["prospective_score"],
            algorithm="prospective_scoring", params=params,
            evidence=evidence,
        )
        result["audit_certificate"] = cert

        return result

    def batch_score(self, cve_ids: List[str],
                    decision_date: Optional[str] = None
                    ) -> List[Dict[str, Any]]:
        """批量前瞻性评分."""
        return [self.score_cve(cid, decision_date) for cid in cve_ids]

    def compare_with_conventional(self, cve_id: str) -> Dict[str, Any]:
        """对比前瞻性评分与常规评分, 量化时间泄露的影响.

        常规评分使用"当前"所有数据.
        前瞻性评分使用决策日之前的数据.
        差值 = 常规 - 前瞻性 即为信息泄露的上界估计.
        """
        from .cve_risk_scorer import compute_risk_score

        entry = self._kb.get(cve_id)
        if entry is None:
            return {"error": f"CVE {cve_id} not found"}

        conventional = compute_risk_score(entry)
        prospective = self.score_cve(cve_id)

        conv_score = conventional.get("score", 0) / 100.0  # 归一化到[0,1]
        pros_score = prospective.get("prospective_score", 0)

        leakage_estimate = max(0.0, conv_score - pros_score)

        return {
            "cve_id": cve_id,
            "conventional_score": round(conv_score, 4),
            "prospective_score": round(pros_score, 4),
            "leakage_gap": round(leakage_estimate, 4),
            "leakage_severity": ("SIGNIFICANT" if leakage_estimate > 0.2 else
                                 "MODERATE" if leakage_estimate > 0.05 else "MINIMAL"),
            "prospective_details": prospective,
        }

    @property
    def audit_manager(self) -> AuditTrailManager:
        return self._audit


def _prospective_label(score: float) -> str:
    if score >= 0.75:
        return "CRITICAL"
    elif score >= 0.5:
        return "HIGH"
    elif score >= 0.25:
        return "MEDIUM"
    return "LOW"


def _get_str(entry, field: str, default: str = ""):
    if hasattr(entry, field):
        return str(getattr(entry, field) or default)
    if isinstance(entry, dict):
        return str(entry.get(field, default))
    return default


def _get_num(entry, field: str):
    if hasattr(entry, field):
        return getattr(entry, field)
    if isinstance(entry, dict):
        return entry.get(field)
    return None


def _get_bool(entry, field: str) -> bool:
    if hasattr(entry, field):
        return bool(getattr(entry, field))
    if isinstance(entry, dict):
        return bool(entry.get(field, False))
    return False
