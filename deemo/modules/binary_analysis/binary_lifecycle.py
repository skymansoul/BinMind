"""Binary lifecycle: file hashing, version tracking by hash, JSON metadata store."""
import hashlib
import json
import os
import time as _time
import logging
from enum import Enum
from collections import OrderedDict
from typing import Dict, Optional, List, Tuple

logger = logging.getLogger(__name__)


class LifecycleStage(Enum):
    IMPORTED = "imported"
    ANALYZED = "analyzed"
    REPORTED = "reported"
    ARCHIVED = "archived"


class Severity(Enum):
    # 严重度改为 Enum，保证 .value 语义与 vuln_counts 字典键一致
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MetricType(Enum):
    COMPLEXITY = "complexity"
    SIZE = "size"
    SECURITY = "security"
    VULN_COUNT = "vulnerability_count"
    ATTACK_SURFACE = "attack_surface"
    HARDENING = "hardening_score"


class BinarySignature:
    __slots__ = ('path', 'hash', 'sha1', 'md5', 'sha256', 'size', 'file_size',
                 'mtime', 'stage', 'tags', 'added', 'architecture')

    def __init__(self, path="", hash="", md5="", sha256="", file_size=0, architecture="", **kwargs):
        # **kwargs 吸收历史调用方的多余参数，避免构造期异常
        self.path = path
        self.hash = hash            # sha256
        self.sha1 = ""
        self.md5 = md5
        self.sha256 = sha256 or hash
        self.size = file_size
        self.file_size = file_size
        self.mtime = 0.0
        self.stage = LifecycleStage.IMPORTED
        self.tags: List[str] = []
        self.added = _time.time()
        self.architecture = architecture

    def to_dict(self):
        return {
            "path": self.path, "hash": self.hash, "sha1": self.sha1,
            "md5": self.md5, "size": self.size, "mtime": self.mtime,
            "stage": self.stage.value, "tags": self.tags, "added": self.added,
        }

    @classmethod
    def from_dict(cls, d: dict):
        sig = cls(d.get("path", ""), d.get("hash", ""))
        sig.sha1 = d.get("sha1", "")
        sig.md5 = d.get("md5", "")
        sig.size = d.get("size", 0)
        sig.file_size = sig.size
        sig.mtime = d.get("mtime", 0)
        stage_raw = d.get("stage", "imported")
        try:
            sig.stage = LifecycleStage(stage_raw)
        except ValueError:
            sig.stage = LifecycleStage.IMPORTED
        sig.tags = d.get("tags", [])
        sig.added = d.get("added", _time.time())
        return sig


class AnalysisRecord:
    __slots__ = ('record_id', 'id', 'binary_signature', 'binary_hash', 'version',
                 'analysis_timestamp', 'timestamp', 'metrics', 'findings',
                 'duration', 'tool_version', 'metadata', 'binary_name')

    def __init__(self, record_id="", binary_signature=None, version="", analysis_timestamp=None,
                 metrics=None, metadata=None, binary_name="", id="", binary_hash="",
                 timestamp=None, findings=None, duration=0.0, tool_version="", **kwargs):
        self.record_id = record_id or id
        self.id = self.record_id
        self.binary_signature = binary_signature
        self.binary_hash = binary_hash
        self.version = version
        ts = analysis_timestamp if analysis_timestamp is not None \
            else (timestamp if timestamp is not None else _time.time())
        self.analysis_timestamp = ts
        self.timestamp = ts
        self.metrics = metrics if metrics is not None else SecurityMetrics()
        self.metadata = metadata
        self.binary_name = binary_name
        self.findings = findings if findings is not None else []
        self.duration = duration
        self.tool_version = tool_version


class SecurityMetrics:
    def __init__(self, total_vulns=0, critical_vulns=0, high_vulns=0,
                 vuln_counts=None, attack_surface_score=0.0, hardening_score=0.0, **kwargs):
        # 新字段为测试规格主接口；vulns/score 等旧字段保留给历史调用方
        self.total_vulns = total_vulns
        self.critical_vulns = critical_vulns
        self.high_vulns = high_vulns
        self.vuln_counts = vuln_counts if vuln_counts is not None else {}
        self.attack_surface_score = attack_surface_score
        self.hardening_score = hardening_score
        self.vulns = total_vulns
        self.score = 0.0
        self.high_count = high_vulns
        self.critical_count = critical_vulns


class TrendData:
    __slots__ = ('metric_name', 'timestamps', 'values', 'trend_direction',
                 'trend_percentage', 'points')

    def __init__(self, metric_name="", timestamps=None, values=None, trend_direction="",
                 trend_percentage=0.0, **kwargs):
        self.metric_name = metric_name
        self.timestamps = timestamps if timestamps is not None else []
        self.values = values if values is not None else []
        self.trend_direction = trend_direction
        self.trend_percentage = trend_percentage
        self.points = []


class LifecycleReport:
    __slots__ = ('binary_name', 'total_versions', 'analysis_period', 'current_metrics',
                 'maturity_score', 'recommendations', 'alerts', 'trends')

    def __init__(self, binary_name="", total_versions=0, analysis_period=(0.0, 0.0),
                 current_metrics=None, maturity_score=0.0, recommendations=None,
                 alerts=None, trends=None, **kwargs):
        self.binary_name = binary_name
        self.total_versions = total_versions
        self.analysis_period = analysis_period
        self.current_metrics = current_metrics if current_metrics is not None else SecurityMetrics()
        self.maturity_score = maturity_score
        self.recommendations = recommendations if recommendations is not None else []
        self.alerts = alerts if alerts is not None else []
        self.trends = trends if trends is not None else []


def format_lifecycle_report(report, history=None):
    """渲染生命周期报告文本。
    单参数为 LifecycleReport 对象（新规格）；双参数为旧的 (binary_path, history) 形式。"""
    if history is None:
        lines = [f"Lifecycle Report: {report.binary_name}", "-" * 40]
        lines.append(f"安全成熟度评分: {report.maturity_score}")
        lines.append(f"版本总数: {report.total_versions}")
        period = report.analysis_period
        if isinstance(period, (tuple, list)) and len(period) == 2:
            lines.append(f"分析周期: {period[0]} ~ {period[1]}")
        m = report.current_metrics
        lines.append(f"漏洞总数: {m.total_vulns}")
        lines.append(f"攻击面得分: {m.attack_surface_score}")
        if report.alerts:
            lines.append("告警:")
            for a in report.alerts:
                lines.append(f"  - {a}")
        if report.recommendations:
            lines.append("建议:")
            for r in report.recommendations:
                lines.append(f"  - {r}")
        return "\n".join(lines)
    lines = [f"Lifecycle Report: {report}", "-" * 40]
    for entry in history:
        ts = _time.strftime("%Y-%m-%d %H:%M", _time.localtime(entry.get("timestamp", 0)))
        stage = entry.get("stage", "unknown")
        lines.append(f"  [{ts}] {stage}")
    return "\n".join(lines)


class BinaryLifecycleManager:
    """Tracks binary files by content hash, stores versioned metadata in JSON."""

    _CHUNK = 65536

    def __init__(self, data_dir=None, **kwargs):
        self.data_dir = data_dir or os.path.join(os.path.dirname(__file__), '..', 'data', 'lifecycle')
        os.makedirs(self.data_dir, exist_ok=True)
        self._index_path = os.path.join(self.data_dir, "index.json")
        self.binaries: OrderedDict[str, BinarySignature] = OrderedDict()
        self._history: Dict[str, list] = {}
        # binary_index 为登记接口主索引；_records 按哈希归档分析记录
        self.binary_index: Dict[str, BinarySignature] = {}
        self._records: Dict[str, list] = {}
        self._load_index()

    # -- hashing --------------------------------------------------

    @classmethod
    def compute_hashes(cls, filepath: str) -> Tuple[str, str, str]:
        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1()
        md5 = hashlib.md5()
        try:
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(cls._CHUNK)
                    if not chunk:
                        break
                    sha256.update(chunk)
                    sha1.update(chunk)
                    md5.update(chunk)
        except OSError as e:
            logger.warning("hash read error: %s", e)
        return sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest()

    # -- registration ---------------------------------------------

    def _compute_signature(self, filepath: str) -> BinarySignature:
        """计算文件签名：sha256 + sha1 + md5 + 文件大小。"""
        sha256, sha1, md5 = self.compute_hashes(filepath)
        try:
            st = os.stat(filepath)
            fsize = st.st_size
        except OSError:
            fsize = 0
        sig = BinarySignature(path=filepath, hash=sha256, md5=md5, sha256=sha256, file_size=fsize)
        sig.sha1 = sha1
        sig.size = fsize
        return sig

    def register_binary(self, filepath: str, binary_name: str = "") -> str:
        """登记二进制文件，返回 sha256 字符串。"""
        sig = self._compute_signature(filepath)
        self.binary_index[sig.sha256] = sig
        self.binaries[sig.sha256] = sig
        return sig.sha256

    def register(self, path: str, hash: str = "") -> BinarySignature:
        if not hash and os.path.isfile(path):
            hash, sha1sum, md5sum = self.compute_hashes(path)
            st = os.stat(path)
            sig = BinarySignature(path, hash)
            sig.sha1 = sha1sum
            sig.md5 = md5sum
            sig.size = st.st_size
            sig.file_size = st.st_size
            sig.mtime = st.st_mtime
        else:
            sig = BinarySignature(path, hash)
        self.binaries[hash or path] = sig
        self._append_history(hash or path, {"stage": sig.stage.value, "timestamp": _time.time()})
        return sig

    def lookup(self, filepath: str) -> Optional[BinarySignature]:
        h, _, _ = self.compute_hashes(filepath)
        return self.binaries.get(h)

    def update_stage(self, binary_hash: str, stage: LifecycleStage):
        sig = self.binaries.get(binary_hash)
        if sig:
            sig.stage = stage
            self._append_history(binary_hash, {"stage": stage.value, "timestamp": _time.time()})

    # -- analysis records -----------------------------------------

    def _generate_record_id(self, sig, version: str) -> str:
        """按签名与版本生成 16 位记录 ID。"""
        raw = f"{getattr(sig, 'sha256', '')}{version}{_time.time()}"
        return hashlib.md5(raw.encode('utf-8')).hexdigest()[:16]

    def add_analysis_record(self, binary_path=None, binary_name="", version="", metrics=None,
                            metadata=None, **kwargs) -> AnalysisRecord:
        """添加一条分析记录，按二进制哈希归档。"""
        sig = self._compute_signature(binary_path)
        record = AnalysisRecord(
            record_id=self._generate_record_id(sig, version),
            binary_signature=sig,
            binary_name=binary_name,
            version=version,
            analysis_timestamp=_time.time(),
            metrics=metrics if metrics is not None else SecurityMetrics(),
            metadata=metadata,
        )
        self._records.setdefault(sig.sha256, []).append(record)
        # 同步写入历史，供旧的 trends/history 接口读取
        self._append_history(sig.sha256, {
            "stage": LifecycleStage.ANALYZED.value,
            "timestamp": record.analysis_timestamp,
            "findings": [],
        })
        return record

    def load_records(self, binary_hash: str) -> list:
        """按哈希加载分析记录，无记录返回空列表。"""
        return self._records.get(binary_hash, [])

    # -- trend & alert --------------------------------------------

    def _analyze_trend_direction(self, values: list) -> Tuple[str, float]:
        """按首尾值判断趋势方向，返回 (方向, 百分比)。"""
        if not values:
            return "stable", 0.0
        first, last = values[0], values[-1]
        if last > first:
            direction = "increasing"
        elif last < first:
            direction = "decreasing"
        else:
            direction = "stable"
        if first == 0:
            pct = 100.0 if last != 0 else 0.0
        else:
            pct = round((last - first) / abs(first) * 100.0, 2)
        return direction, pct

    analyze_trend_direction = _analyze_trend_direction

    def compute_trends(self, binary_hash: str) -> list:
        """按三条指标分别计算趋势；记录不足 2 条时返回空列表。"""
        records = self.load_records(binary_hash)
        if len(records) < 2:
            return []
        metric_getters = (
            (MetricType.VULN_COUNT, lambda r: getattr(r.metrics, 'total_vulns', 0)),
            (MetricType.ATTACK_SURFACE, lambda r: getattr(r.metrics, 'attack_surface_score', 0.0)),
            (MetricType.HARDENING, lambda r: getattr(r.metrics, 'hardening_score', 0.0)),
        )
        trends = []
        for mt, getter in metric_getters:
            timestamps = [r.analysis_timestamp for r in records]
            values = [getter(r) for r in records]
            direction, pct = self._analyze_trend_direction(values)
            trends.append(TrendData(
                metric_name=mt.value,
                timestamps=timestamps,
                values=values,
                trend_direction=direction,
                trend_percentage=pct,
            ))
        return trends

    def generate_alerts(self, binary_hash: str) -> list:
        """对比最近两条记录生成告警；记录不足 2 条不告警。"""
        records = self.load_records(binary_hash)
        if len(records) < 2:
            return []
        prev, cur = records[-2], records[-1]
        pm, cm = prev.metrics, cur.metrics
        alerts = []
        delta_vulns = cm.total_vulns - pm.total_vulns
        if delta_vulns > 0:
            alerts.append(f"漏洞数增加: +{delta_vulns}")
        delta_crit = cm.critical_vulns - pm.critical_vulns
        if delta_crit > 0:
            alerts.append(f"严重漏洞增加: +{delta_crit}")
        delta_high = cm.high_vulns - pm.high_vulns
        if delta_high > 0:
            alerts.append(f"高危漏洞增加: +{delta_high}")
        if cm.attack_surface_score > pm.attack_surface_score:
            alerts.append(f"攻击面增大: +{cm.attack_surface_score - pm.attack_surface_score}")
        return alerts

    def calculate_maturity_score(self, records: list) -> float:
        """按最近一次记录的加固分、攻击面与漏洞量计算成熟度。"""
        if not records:
            return 0.0
        m = records[-1].metrics
        hardening = getattr(m, 'hardening_score', 0.0)
        attack_surface = getattr(m, 'attack_surface_score', 0.0)
        vuln_penalty = m.total_vulns * 2.0 + m.critical_vulns * 5.0 + m.high_vulns * 3.0
        score = hardening * 0.6 + (100.0 - attack_surface) * 0.3 - vuln_penalty
        return round(min(100.0, max(0.0, score)), 1)

    def _generate_recommendations(self, records: list, trends: list, alerts: list) -> list:
        """按告警与趋势生成修复建议。"""
        recommendations = []
        if not records:
            recommendations.append("首次分析，建议建立安全基线")
        for alert in alerts:
            if "漏洞数增加" in alert:
                recommendations.append("修复新增漏洞，升级受影响组件")
            elif "严重漏洞" in alert:
                recommendations.append("优先修复严重漏洞")
            elif "攻击面" in alert:
                recommendations.append("收缩攻击面，关闭非必要暴露")
        if not recommendations:
            recommendations.append("保持当前安全实践")
        return recommendations

    generate_recommendations = _generate_recommendations

    # -- report ---------------------------------------------------

    def generate_report(self, binary_hash: str) -> LifecycleReport:
        """生成生命周期报告；无记录时返回空报告并标记无分析记录。"""
        records = self.load_records(binary_hash)
        if not records:
            report = LifecycleReport(
                binary_name="unknown",
                total_versions=0,
                analysis_period=(0.0, 0.0),
                current_metrics=SecurityMetrics(),
            )
            report.alerts = ["没有found分析记录"]
            return report
        timestamps = [r.analysis_timestamp for r in records]
        alerts = self.generate_alerts(binary_hash)
        trends = self.compute_trends(binary_hash)
        report = LifecycleReport(
            binary_name=records[-1].binary_name or "unknown",
            total_versions=len(records),
            analysis_period=(min(timestamps), max(timestamps)),
            current_metrics=records[-1].metrics,
            maturity_score=self.calculate_maturity_score(records),
            recommendations=self._generate_recommendations(records, trends, alerts),
            alerts=alerts,
            trends=trends,
        )
        return report

    def export_report_json(self, report: LifecycleReport, filepath: str) -> bool:
        """导出报告为 JSON 文件，成功返回 True。"""
        try:
            data = {
                "binary_name": report.binary_name,
                "total_versions": report.total_versions,
                "analysis_period": list(report.analysis_period),
                "maturity_score": report.maturity_score,
                "alerts": report.alerts,
                "recommendations": report.recommendations,
                "current_metrics": {
                    "total_vulns": report.current_metrics.total_vulns,
                    "critical_vulns": report.current_metrics.critical_vulns,
                    "high_vulns": report.current_metrics.high_vulns,
                    "attack_surface_score": report.current_metrics.attack_surface_score,
                    "hardening_score": report.current_metrics.hardening_score,
                },
            }
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except (OSError, TypeError):
            return False

    def export_trend_csv(self, binary_hash: str, filepath: str) -> bool:
        """导出趋势为 CSV；无趋势数据返回 False。"""
        trends = self.compute_trends(binary_hash)
        if not trends:
            return False
        try:
            with open(filepath, 'w', encoding='utf-8', newline='') as f:
                f.write("metric,timestamp,value,trend_direction,trend_percentage\n")
                for td in trends:
                    for ts, val in zip(td.timestamps, td.values):
                        f.write(f"{td.metric_name},{ts},{val},{td.trend_direction},{td.trend_percentage}\n")
            return True
        except OSError:
            return False

    # -- version comparison ---------------------------------------

    def compare_versions(self, hash1: str, hash2: str) -> dict:
        sig1, sig2 = self.binaries.get(hash1), self.binaries.get(hash2)
        if not sig1 or not sig2:
            return {"added": [], "removed": [], "changed": []}
        return {
            "added": list(set(sig2.tags) - set(sig1.tags)),
            "removed": list(set(sig1.tags) - set(sig2.tags)),
            "changed": ["size"] if sig1.size != sig2.size else [],
        }

    # -- history --------------------------------------------------

    def get_history(self, binary_path: str) -> list:
        if os.path.isfile(binary_path):
            h, _, _ = self.compute_hashes(binary_path)
            return self._history.get(h, [])
        return self._history.get(binary_path, [])

    def export_timeline(self, binary_path: str) -> list:
        history = self.get_history(binary_path)
        return sorted(history, key=lambda x: x.get("timestamp", 0))

    def _append_history(self, key: str, entry: dict):
        self._history.setdefault(key, []).append(entry)

    # -- persistence ----------------------------------------------

    def _load_index(self):
        if os.path.isfile(self._index_path):
            try:
                with open(self._index_path, 'r') as f:
                    data = json.load(f)
                for item in data.get("binaries", []):
                    sig = BinarySignature.from_dict(item)
                    self.binaries[sig.hash or sig.path] = sig
                self._history = data.get("history", {})
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("index load failed: %s", e)

    def save_index(self):
        data = {
            "binaries": [s.to_dict() for s in self.binaries.values()],
            "history": {str(k): v for k, v in self._history.items()},
            "updated": _time.time(),
        }
        tmp = self._index_path + ".tmp"
        with open(tmp, 'w') as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._index_path)

    def list_by_stage(self, stage: LifecycleStage) -> List[BinarySignature]:
        return [s for s in self.binaries.values() if s.stage == stage]

    def search(self, tag: str) -> List[BinarySignature]:
        return [s for s in self.binaries.values() if tag in s.tags]

    def compute_security_metrics(self, binary_hash: str) -> SecurityMetrics:
        m = SecurityMetrics()
        history = self._history.get(binary_hash, [])
        for entry in history:
            findings = entry.get("findings", [])
            m.vulns += len(findings)
            m.total_vulns += len(findings)
            for f in findings:
                sev = f.get("severity", "low")
                if sev == Severity.CRITICAL.value:
                    m.critical_count += 1
                    m.critical_vulns += 1
                elif sev == Severity.HIGH.value:
                    m.high_count += 1
                    m.high_vulns += 1
        m.score = m.critical_count * 10 + m.high_count * 7 + m.vulns * 3
        return m

    def trends(self, binary_hash: str) -> TrendData:
        td = TrendData()
        history = self.get_history(binary_hash)
        for entry in history:
            td.points.append({
                "ts": entry.get("timestamp", 0),
                "stage": entry.get("stage", ""),
                "findings": len(entry.get("findings", [])),
            })
        return td
