"""Serverless安全分析：枚举定义、数据结构与冷启动检测。

CloudProvider/TriggerType/FindingSeverity枚举、Finding/FunctionConfig数据结构、
ColdStartSideChannelDetector冷启动时序侧信道检测。
"""
import logging
from enum import Enum
from typing import Dict, Any, List

log = logging.getLogger(__name__)


class CloudProvider(Enum):
    """Serverless 平台标识枚举。"""
    AWS_LAMBDA = "aws_lambda"
    AZURE_FUNCTIONS = "azure_functions"
    GCP_CLOUD_FUNCTIONS = "gcp_cloud_functions"
    CLOUDFLARE_WORKERS = "cloudflare_workers"
    ALIBABA_FC = "alibaba_fc"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return self.value


class TriggerType(Enum):
    """Serverless 触发事件类型枚举。"""
    HTTP_API_GATEWAY = "http_api_gateway"
    EVENT_BRIDGE = "event_bridge"
    S3 = "s3"
    SNS = "sns"
    SQS = "sqs"
    DYNAMODB_STREAM = "dynamodb_stream"
    KINESIS = "kinesis"
    CLOUDWATCH_EVENTS = "cloudwatch_events"
    COGNITO = "cognito"
    SCHEDULED = "scheduled"
    QUEUE_STORAGE = "queue_storage"
    HTTP_WEBHOOK = "http_webhook"
    PUBSUB = "pubsub"
    FIRESTORE = "firestore"
    CLOUD_STORAGE = "cloud_storage"
    CUSTOM = "custom"

    def __str__(self) -> str:
        return self.value


class FindingSeverity(Enum):
    """发现严重等级枚举：CRITICAL/HIGH/MEDIUM/LOW/INFO。"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __str__(self) -> str:
        return self.value


class Finding:
    __slots__ = ('title', 'severity', 'category', 'provider', 'description',
                 'evidence', 'remediation', 'cvss_score', 'cwe_id',)

    def __init__(self, title, severity, category, provider=CloudProvider.UNKNOWN,
                 description="", evidence="", remediation="", cvss_score=0.0, cwe_id=""):
        self.title = title
        self.severity = severity
        self.category = category
        self.provider = provider
        self.description = description
        self.evidence = evidence
        self.remediation = remediation
        self.cvss_score = cvss_score
        self.cwe_id = cwe_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            'title': self.title, 'severity': self.severity.value,
            'category': self.category, 'provider': self.provider.value,
            'description': self.description, 'evidence': self.evidence,
            'remediation': self.remediation, 'cvss_score': self.cvss_score,
            'cwe_id': self.cwe_id,
        }


class FunctionConfig:
    __slots__ = ('name', 'provider', 'runtime', 'handler', 'memory_mb',
                 'timeout_seconds', 'triggers', 'env_vars', 'iam_policy',
                 'vpc_config', 'layers',)

    def __init__(self, name, provider=CloudProvider.UNKNOWN, runtime="",
                 handler="", memory_mb=128, timeout_seconds=3,
                 triggers=None, env_vars=None, iam_policy=None,
                 vpc_config=None, layers=None):
        self.name = name
        self.provider = provider
        self.runtime = runtime
        self.handler = handler
        self.memory_mb = memory_mb
        self.timeout_seconds = timeout_seconds
        self.triggers = triggers if triggers is not None else []
        self.env_vars = env_vars if env_vars is not None else {}
        self.iam_policy = iam_policy
        self.vpc_config = vpc_config
        self.layers = layers if layers is not None else []

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name, 'provider': self.provider.value,
            'runtime': self.runtime, 'handler': self.handler,
            'memory_mb': self.memory_mb, 'timeout_seconds': self.timeout_seconds,
            'triggers': [t.value for t in self.triggers],
            'env_var_count': len(self.env_vars),
            'iam_policy': self.iam_policy, 'vpc_config': self.vpc_config,
            'layers': self.layers,
        }


class ColdStartSideChannelDetector:
    THRESHOLD_MS = 500
    VARIANCE_RATIO = 2.5

    def __init__(self):
        self._timings: List[float] = []

    def feed(self, duration_ms: float) -> None:
        self._timings.append(duration_ms)

    def detect(self) -> List[Finding]:
        findings: List[Finding] = []
        if len(self._timings) < 3:
            return findings

        mean_t = sum(self._timings) / len(self._timings)
        max_t = max(self._timings)
        min_t = min(self._timings)
        ratio = max_t / max(min_t, 0.001)

        if mean_t > self.THRESHOLD_MS and ratio > self.VARIANCE_RATIO:
            findings.append(Finding(
                title="冷启动时序异常——潜在同驻主机探测",
                severity=FindingSeverity.MEDIUM,
                category="cold_start_side_channel",
                description=f"冷启动均值 {mean_t:.0f}ms，波动比 {ratio:.1f}x——攻击者可推断同驻函数活动。",
                evidence=f"时序采样={self._timings}, 均值={mean_t:.1f}, 波动比={ratio:.1f}",
                remediation="启用预置并发 / Always Ready；优先使用 ARM64 缩减侧信道面。",
                cvss_score=5.3, cwe_id="CWE-203",
            ))

        if len(self._timings) >= 6:
            diffs = [abs(self._timings[i] - self._timings[i - 1]) for i in range(1, len(self._timings))]
            if len(diffs) >= 4 and all(
                diffs[i] > diffs[i + 1] * 1.5 and diffs[i + 1] < diffs[i + 2] * 1.5
                for i in range(0, min(len(diffs) - 2, 4), 2)
            ):
                findings.append(Finding(
                    title="冷启动周期性噪声——疑似同租户指纹",
                    severity=FindingSeverity.LOW,
                    category="cold_start_co_tenancy",
                    description="初始化耗时差分呈交替振荡，与同驻函数噪声一致。",
                    evidence=f"差分序列={diffs[:10]}",
                    remediation="启用 SnapStart 或预置并发。",
                    cvss_score=3.1, cwe_id="CWE-203",
                ))

        return findings


__all__ = [
    "CloudProvider", "TriggerType", "FindingSeverity",
    "Finding", "FunctionConfig", "ColdStartSideChannelDetector",
]
