# 指标异常检测: 自适应阈值/指数加权移动统计/多尺度残差/季节性分解启发式
# KAN-AD "Time Series Anomaly Detection with Kolmogorov-Arnold Networks" (, ICML 2025)
#       MTAD "Tools and Benchmarks for Multivariate Time Series Anomaly Detection" (, 2024)
#       Argos "Agentic Time-Series Anomaly Detection with Autonomous Rule Generation via LLMs" (, 2025)
#       TelecomTS数据集分析 (, 2025)
import math, logging, time, json, threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Callable
from collections import deque, defaultdict
from enum import Enum

log = logging.getLogger(__name__)

class AnomalyLevel(Enum):
    NORMAL   = "normal"
    WARNING  = "warning"
    CRITICAL = "critical"

@dataclass
class AnomalyPoint:
    timestamp: float
    metric_name: str
    value: float
    expected: float
    z_score: float
    level: AnomalyLevel
    detail: str = ""

# 指数加权移动平均+自适应标准差 [Holt 2004/Winters 1960季节性扩展]
# EWMA对近期观测权重更高, 比SMA更敏感于趋势变化

class EWMAStats:
    """指数加权移动统计量. alpha越大对近期值越敏感."""
    def __init__(self, alpha: float = 0.2, warmup: int = 30):
        self.alpha = alpha; self.warmup = warmup
        self.mean: float = 0.0; self.var: float = 0.0
        self._count: int = 0
        self._lk = threading.Lock()

    def update(self, value: float) -> Tuple[float, float]:
        """更新统计量, 返回(mean, std). 前warmup个值用于初始化."""
        with self._lk:
            self._count += 1
            if self._count <= self.warmup:
                delta = value - self.mean
                self.mean += delta / self._count
                self.var += delta * (value - self.mean) if self._count > 1 else 0.0
            else:
                delta = value - self.mean
                self.mean += self.alpha * delta
                self.var = (1 - self.alpha) * (self.var + self.alpha * delta * delta)
            std = math.sqrt(max(self.var / max(self._count - 1, 1), 1e-10))
            return self.mean, std

    @property
    def std(self) -> float:
        with self._lk: return math.sqrt(max(self.var / max(self._count - 1, 1), 1e-10))


class AdaptiveThresholdDetector:
    """自适应阈值检测器.
    每指标维护EWMA统计量, Z-score判定异常.
    动态阈值: 最近N个观测滚动百分位而非固定值 [MTAD 2024].
    季节性: 简单差分法 (x_t - x_{t-period}).
    """

    def __init__(self, alpha: float = 0.15, z_warning: float = 2.5, z_critical: float = 4.0,
                 buffer_size: int = 200, period: int = 0):
        self.alpha = alpha; self._z_w = z_warning; self._z_c = z_critical
        self._period = period
        self._stats: Dict[str, EWMAStats] = defaultdict(lambda: EWMAStats(alpha))
        self._buffer: Dict[str, deque] = defaultdict(lambda: deque(maxlen=buffer_size))
        self._prev: Dict[str, float] = {}

    def detect(self, metric_name: str, value: float,
               timestamp: float = None) -> Optional[AnomalyPoint]:
        ts = timestamp or time.time()

        adj_value = value
        if self._period > 0 and metric_name in self._prev:
            pv = self._prev.get(metric_name, value)
            adj_value = value - pv if abs(value - pv) < abs(value) * 3 else value
        self._prev[metric_name] = value

        mean, std = self._stats[metric_name].update(adj_value)

        # 冷启动: 预热期不判定异常
        if self._stats[metric_name]._count <= self._stats[metric_name].warmup:
            self._buffer[metric_name].append((ts, adj_value))
            return None

        z = abs(adj_value - mean) / max(std, 1e-8)
        self._buffer[metric_name].append((ts, adj_value))

        # 动态阈值: 缓冲区百分位
        z_scores = [abs((v - mean) / max(std, 1e-8)) for _, v in self._buffer[metric_name]]
        if len(z_scores) >= 10:
            z_scores.sort()
            p80 = z_scores[int(len(z_scores) * 0.80)]
            p95 = z_scores[int(len(z_scores) * 0.95)]
            w_thresh = max(self._z_w, p80 * 0.9)
            c_thresh = max(self._z_c, p95 * 0.9)
        else:
            w_thresh, c_thresh = self._z_w, self._z_c

        if z >= c_thresh:
            return AnomalyPoint(ts, metric_name, value, mean, z, AnomalyLevel.CRITICAL)
        elif z >= w_thresh:
            return AnomalyPoint(ts, metric_name, value, mean, z, AnomalyLevel.WARNING)
        return None


# 多尺度残差分析 [KAN-AD 2024]: 多时间窗口残差比较

class MultiScaleResidualDetector:
    """多尺度残差异常检测.
    真正的结构性异常在多个时间尺度均表现高残差 [KAN-AD 2024].
    尺度: [short:5点, medium:20点, long:60点]
    """

    SCALES = [('short', 5), ('medium', 20), ('long', 60)]

    def __init__(self, consensus_threshold: int = 2):
        self._consensus = consensus_threshold
        self._buffers: Dict[str, Dict[str, deque]] = defaultdict(
            lambda: {s[0]: deque(maxlen=s[1] * 2) for s in self.SCALES})

    def detect(self, metric_name: str, value: float) -> Optional[Tuple[AnomalyLevel, Dict]]:
        scores = {}
        for scale_name, window in self.SCALES:
            buf = self._buffers[metric_name][scale_name]
            buf.append(value)
            if len(buf) < window:
                scores[scale_name] = 0.0; continue
            recent = list(buf)[-window:]
            mean = sum(recent) / window
            variance = sum((x - mean) ** 2 for x in recent) / max(window - 1, 1)
            std = math.sqrt(max(variance, 1e-10))
            scores[scale_name] = abs(value - mean) / std if std > 0 else 0.0

        # 共识: ≥2个尺度检测到异常
        w_flags = sum(1 for s in scores.values() if s >= 2.0)
        c_flags = sum(1 for s in scores.values() if s >= 4.0)

        if c_flags >= self._consensus:
            return AnomalyLevel.CRITICAL, {'scale_scores': scores, 'consensus': c_flags}
        elif w_flags >= self._consensus:
            return AnomalyLevel.WARNING, {'scale_scores': scores, 'consensus': w_flags}
        return None


# 集成检测管道

class MetricsAnomalyPipeline:
    # 顺序执行注册检测器, 任意触发→回调
    def __init__(self):
        self._detectors: List[Tuple[str, Callable]] = []
        self._history: deque = deque(maxlen=500)
        self._alert_callbacks: List[Callable] = []
        self._lk = threading.Lock()

    def add_detector(self, name: str, detector_fn: Callable[[str, float], Optional]):
        self._detectors.append((name, detector_fn))

    def on_alert(self, callback: Callable[[AnomalyPoint], None]):
        self._alert_callbacks.append(callback)

    def process(self, metric_name: str, value: float,
                timestamp: float = None) -> List[AnomalyPoint]:
        anomalies = []
        ts = timestamp or time.time()
        for dname, detector_fn in self._detectors:
            try:
                result = detector_fn(metric_name, value)
                if result:
                    ap = result if isinstance(result, AnomalyPoint) else AnomalyPoint(
                        ts, metric_name, value, 0.0, 0.0, AnomalyLevel.WARNING,
                        detail=str(result))
                    anomalies.append(ap)
            except Exception as _e:
                log.debug("detector %s failed: %s", dname, _e)

        with self._lk:
            for ap in anomalies:
                self._history.append(ap)
            for cb in self._alert_callbacks:
                for ap in anomalies:
                    try: cb(ap)
                    except Exception: pass
        return anomalies

    def get_recent(self, n: int = 50) -> List[AnomalyPoint]:
        with self._lk:
            items = list(self._history)
        return items[-n:]

    def get_summary(self) -> Dict:
        with self._lk:
            items = list(self._history)
        if not items: return {'total': 0, 'warning': 0, 'critical': 0}
        w = sum(1 for a in items if a.level == AnomalyLevel.WARNING)
        c = sum(1 for a in items if a.level == AnomalyLevel.CRITICAL)
        return {'total': len(items), 'warning': w, 'critical': c,
                'latest': str(items[-1]) if items else ''}

    @classmethod
    def create_default(cls, alpha: float = 0.15, period: int = 0) -> 'MetricsAnomalyPipeline':
        """创建AdaptiveThreshold+MultiScaleResidual默认管道."""
        pipe = cls()
        ad = AdaptiveThresholdDetector(alpha=alpha, period=period)
        pipe.add_detector('adaptive_threshold',
                          lambda n, v: ad.detect(n, v))
        ms = MultiScaleResidualDetector()
        pipe.add_detector('multiscale_residual',
                          lambda n, v: ms.detect(n, v))
        return pipe


# 批量指标分析，与MetricsRegistry集成

class BatchMetricAnalyzer:
    """MetricsRegistry批量异常扫描.
    输入: MetricsRegistry.collect()输出.
    """

    def __init__(self, pipeline: MetricsAnomalyPipeline = None):
        self.pipeline = pipeline or MetricsAnomalyPipeline.create_default()

    def analyze_collect_output(self, families: List,
                               ts: float = None) -> Dict[str, List[AnomalyPoint]]:
        """遍历MetricFamily列表, 每sample调用管道."""
        results: Dict[str, List[AnomalyPoint]] = defaultdict(list)
        for mf in families:
            for sample in mf.samples:
                anomalies = self.pipeline.process(sample.name, sample.value, ts)
                if anomalies:
                    results[sample.name].extend(anomalies)
        return dict(results)

    def analyze_dict(self, metrics: Dict[str, float]) -> List[AnomalyPoint]:
        """字典形式指标分析便捷方法."""
        all_anomalies = []
        for name, value in metrics.items():
            anomalies = self.pipeline.process(name, value)
            all_anomalies.extend(anomalies)
        return all_anomalies


# 全局默认管道
_default_pipeline: MetricsAnomalyPipeline = None

def get_anomaly_pipeline() -> MetricsAnomalyPipeline:
    global _default_pipeline
    if _default_pipeline is None:
        _default_pipeline = MetricsAnomalyPipeline.create_default()
    return _default_pipeline
