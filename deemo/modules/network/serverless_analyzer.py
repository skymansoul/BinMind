import logging
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


# fix: these used to have broken string/object mix — some attrs were
# strings, some were reassigned to objects at class level. now they're
# proper value objects with .value access everywhere, which is what the
# to_dict() methods and analyzer code already assumed.
class _ValueObj:
    """lightweight tagged value — cheaper than StrEnum, no enum overhead"""
    __slots__ = ('value',)
    def __init__(self, v): self.value = v
    def __str__(self): return self.value
    def __repr__(self): return f"{type(self).__name__}({self.value!r})"
    def __eq__(self, o): return isinstance(o, type(self)) and self.value == o.value
    def __hash__(self): return hash(self.value)

class CloudProvider:
    _vals: dict[str, '_ValueObj'] = {}
    @classmethod
    def _reg(cls, name, val):
        obj = _ValueObj(val); setattr(cls, name, obj); cls._vals[val] = obj

CloudProvider._reg("AWS_LAMBDA", "aws_lambda")
CloudProvider._reg("AZURE_FUNCTIONS", "azure_functions")
CloudProvider._reg("GCP_CLOUD_FUNCTIONS", "gcp_cloud_functions")
CloudProvider._reg("CLOUDFLARE_WORKERS", "cloudflare_workers")
CloudProvider._reg("ALIBABA_FC", "alibaba_fc")
CloudProvider._reg("UNKNOWN", "unknown")

class TriggerType:
    pass
TriggerType.HTTP_API_GATEWAY = _ValueObj("http_api_gateway")
TriggerType.EVENT_BRIDGE = _ValueObj("event_bridge")
TriggerType.S3 = _ValueObj("s3")
TriggerType.SNS = _ValueObj("sns")
TriggerType.SQS = _ValueObj("sqs")
TriggerType.DYNAMODB_STREAM = _ValueObj("dynamodb_stream")
TriggerType.KINESIS = _ValueObj("kinesis")
TriggerType.CLOUDWATCH_EVENTS = _ValueObj("cloudwatch_events")
TriggerType.COGNITO = _ValueObj("cognito")
TriggerType.SCHEDULED = _ValueObj("scheduled")
TriggerType.QUEUE_STORAGE = _ValueObj("queue_storage")
TriggerType.HTTP_WEBHOOK = _ValueObj("http_webhook")
TriggerType.PUBSUB = _ValueObj("pubsub")
TriggerType.FIRESTORE = _ValueObj("firestore")
TriggerType.CLOUD_STORAGE = _ValueObj("cloud_storage")
TriggerType.CUSTOM = _ValueObj("custom")

class FindingSeverity:
    pass
FindingSeverity.CRITICAL = _ValueObj("critical")
FindingSeverity.HIGH = _ValueObj("high")
FindingSeverity.MEDIUM = _ValueObj("medium")
FindingSeverity.LOW = _ValueObj("low")
FindingSeverity.INFO = _ValueObj("info")


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


class SharedEnvironmentEscapeDetector:
    GLOBAL_STATE_PATTERNS = {
        'python': [r'^(?!#|import|from|def|class|if|\s*$)\s*[A-Z_][A-Z0-9_]*\s*=',
                   r'global\s+\w+', r'@lru_cache', r'functools\.(?:lru_cache|cache)'],
        'nodejs': [r'(?:var|let|const)\s+\w+\s*=\s*.*require', r'module\.exports\.\w+\s*=',
                   r'global\.\w+\s*='],
        'go': [r'var\s+\w+\s+\w+\s*=', r'sync\.(?:Map|Pool|Once)', r'func\s+init\(\)'],
    }

    ESCAPE_INDICATORS = [
        (r'/proc/(?:self|\d+)/(?:maps|status|cmdline|environ)', 'procfs_access', 8.6),
        (r'(?:os\.(?:listdir|scandir)|fs\.readdirSync)\s*\(\s*[\'"]/proc', 'procfs_enum', 6.5),
        (r'(?:subprocess|os\.(?:system|popen|exec)|child_process\.exec)\s*\(', 'command_exec', 6.5),
        (r'(?:ctypes\.CDLL|ctypes\.cdll|ffi\.Library)\s*\(', 'native_library_load', 8.6),
        (r'__import__\s*\(\s*[\'"]os[\'"]', 'dynamic_import_os', 6.5),
    ]

    def detect(self, source_code: str, runtime: str = 'python') -> List[Finding]:
        findings: List[Finding] = []
        if not source_code:
            return findings

        for pattern in self.GLOBAL_STATE_PATTERNS.get(runtime, []):
            matches = re.findall(pattern, source_code, re.MULTILINE)
            if matches:
                snippet = (matches[0][:80] if isinstance(matches[0], str) else str(matches[0]))
                findings.append(Finding(
                    title="全局可变状态——跨调用数据泄漏向量",
                    severity=FindingSeverity.HIGH,
                    category="shared_env_global_state",
                    description=f"全局状态 `{snippet}` 在热容器调用间持久化——存在数据泄漏风险。",
                    evidence=f"匹配模式={pattern}, 命中数={len(matches)}",
                    remediation="将可变状态声明于 handler 内部；避免模块级可变变量。",
                    cvss_score=7.5, cwe_id="CWE-226",
                ))
                break

        for pattern, label, cvss in self.ESCAPE_INDICATORS:
            matches = re.findall(pattern, source_code, re.IGNORECASE)
            if matches:
                findings.append(Finding(
                    title=f"运行时逃逸指标：{label}",
                    severity=FindingSeverity.CRITICAL if cvss >= 8.0 else FindingSeverity.HIGH,
                    category=f"shared_env_escape_{label}",
                    description=f"检出 {label} 模式——服务端运行时沙箱边界穿越风险。",
                    evidence=f"匹配模式={pattern}, 出现次数={len(matches)}",
                    remediation="移除非必要系统调用；启用 SnapStart 加固初始化状态。",
                    cvss_score=cvss, cwe_id="CWE-668",
                ))

        return findings


class IamPermissionBoundaryAnalyzer:
    DANGEROUS: Set[str] = {
        'iam:*', 'iam:Create*', 'iam:Put*', 'iam:Attach*', 'iam:Update*',
        's3:*', 'dynamodb:*', 'lambda:*', 'kms:*', 'sts:AssumeRole*',
        'ec2:*', 'rds:*', 'secretsmanager:*', 'ssm:GetParameter*', 'sqs:*', 'sns:*',
    }

    def analyze(self, statements: List[Dict[str, Any]],
                provider: CloudProvider = CloudProvider.AWS_LAMBDA) -> List[Finding]:
        findings: List[Finding] = []

        for stmt in statements:
            effect = stmt.get('Effect', stmt.get('effect', 'Allow'))
            actions = self._list(stmt.get('Action', stmt.get('actions', [])))
            resources = self._list(stmt.get('Resource', stmt.get('resources', [])))
            w_actions = [a for a in actions if a.endswith('*') or a == '*']

            if w_actions and effect.lower() == 'allow':
                dangerous = [a for a in w_actions
                             if any(a.startswith(d.rstrip('*')) for d in self.DANGEROUS)]
                if dangerous or '*' in w_actions:
                    findings.append(Finding(
                        title="IAM 权限过度——通配符 Action 授予高危操作",
                        severity=FindingSeverity.CRITICAL if '*' in w_actions else FindingSeverity.HIGH,
                        category="iam_overly_permissive",
                        provider=provider,
                        description=f"Effect={effect}, 通配符Actions={w_actions[:5]}——违反最小权限原则。",
                        evidence=f"actions={w_actions}, resources={resources}",
                        remediation="替换通配符为显式 Action；添加 Condition 子句；设置 Permission Boundary。",
                        cvss_score=9.1 if '*' in w_actions else 7.8, cwe_id="CWE-285",
                    ))

            if (not resources or (len(resources) == 1 and resources[0] == '*')) and effect.lower() == 'allow' and actions:
                findings.append(Finding(
                    title="IAM 缺少资源约束",
                    severity=FindingSeverity.MEDIUM,
                    category="iam_no_resource_boundary",
                    provider=provider,
                    description=f"允许在 resource='*' 上执行 {actions[:3]}。",
                    evidence=f"actions={actions[:5]}, resources={resources}",
                    remediation="指定具体 ARN；使用资源级访问控制。",
                    cvss_score=5.5, cwe_id="CWE-862",
                ))

        return findings

    @staticmethod
    def _list(v: Any) -> List[str]:
        if isinstance(v, str): return [v]
        if isinstance(v, list): return [str(x) for x in v]
        return []


class EventInjectionScanner:
    """事件注入扫描——检测未校验的事件负载流向敏感汇点。"""

    PATTERNS: List[Tuple[str, str, str, FindingSeverity, str]] = [
        (r'os\.(?:system|popen)\s*\(\s*(?:event|body|params|query|payload|msg|message)', 'os_cmd_injection',
         '事件负载拼接入系统命令', FindingSeverity.CRITICAL, 'CWE-78'),
        (r'subprocess\.(?:run|call|Popen)\s*\([^)]*(?:event|body|payload)', 'subprocess_injection',
         '事件数据流入子进程调用', FindingSeverity.CRITICAL, 'CWE-78'),
        (r'(?:render_template|jinja2|Template|\.render)\s*\([^)]*(?:body|payload|request\.)', 'ssti',
         '事件数据传入模板引擎', FindingSeverity.CRITICAL, 'CWE-1336'),
        (r'(?:find|find_one|update_one|delete_one)\s*\(\s*\{\s*"?\$', 'nosql_injection',
         'MongoDB 查询以事件负载构造', FindingSeverity.HIGH, 'CWE-943'),
        (r'(?:scan|query|get_item)\s*\(\s*[^)]*(?:event|body|params|payload)', 'dynamodb_injection',
         'DynamoDB 表达式以事件数据构建', FindingSeverity.HIGH, 'CWE-943'),
        (r'(?:open|read|write|\.download)\s*\([^)]*(?:event|body|payload|key|path|filename)', 'path_traversal',
         '事件控制路径用于文件操作', FindingSeverity.HIGH, 'CWE-22'),
        (r'(?:etree\.(?:parse|fromstring)|lxml\.etree|xml2js\.parseString)\s*\([^)]*(?:body|payload|event)', 'xxe',
         'XML 解析器处理未校验事件负载', FindingSeverity.HIGH, 'CWE-611'),
        (r'(?:requests\.(?:get|post)|urllib|axios|fetch|got)\s*\([^)]*(?:event|body|url|endpoint)', 'ssrf',
         '事件负载控制 HTTP 请求目标', FindingSeverity.HIGH, 'CWE-918'),
        (r'(?:pickle\.(?:loads?|Unpickler)|yaml\.load\s*\(|json\.loads\s*\([^)]*(?:body|payload))', 'deserialization',
         '反序列化函数接收事件负载', FindingSeverity.CRITICAL, 'CWE-502'),
    ]

    def scan(self, source_code: str, trigger_type: Optional[TriggerType] = None) -> List[Finding]:
        findings: List[Finding] = []
        if not source_code:
            return findings
        seen: Set[str] = set()
        for pattern, cat, desc, severity, cwe in self.PATTERNS:
            if cat in seen:
                continue
            matches = re.findall(pattern, source_code, re.IGNORECASE)
            if matches:
                seen.add(cat)
                trigger_info = f"（触发器：{trigger_type.value}）" if trigger_type else ""
                findings.append(Finding(
                    title=f"事件注入：{cat}{trigger_info}", severity=severity,
                    category=f"event_injection_{cat}",
                    description=desc,
                    evidence=f"匹配模式={pattern}, 命中数={len(matches)}",
                    remediation="以 JSON Schema / Pydantic 校验输入；使用参数化命令；禁用 XML 外部实体。",
                    cvss_score=9.8 if severity == FindingSeverity.CRITICAL else 7.5, cwe_id=cwe,
                ))
        return findings


class EnvSecretExtractor:
    SECRETS: Dict[str, Tuple[str, str, FindingSeverity]] = {
        'aws_access': (r'(?:AWS|AMAZON)_?(?:ACCESS|SECRET)_?KEY[=:]\s*[\'"]?(?:AKIA|ASIA)[A-Z0-9]{16}', 'AWS 访问密钥', FindingSeverity.CRITICAL),
        'aws_secret': (r'(?:AWS|AMAZON)_?SECRET[=:]\s*[\'"](?:[A-Za-z0-9+/]{40})[\'"]', 'AWS 秘密密钥', FindingSeverity.CRITICAL),
        'aws_session': (r'AWS_SESSION_TOKEN[=:]\s*[\'"](?:[A-Za-z0-9/+=]{16,})', 'AWS 会话令牌', FindingSeverity.CRITICAL),
        'azure_conn': (r'(?:AZURE_)?CONNECTION_STRING[=:]\s*[\'"]DefaultEndpointsProtocol', 'Azure 连接字符串', FindingSeverity.CRITICAL),
        'azure_sas': (r'(?:AZURE_)?SAS_TOKEN[=:]\s*[\'"](?:sv=\d|sig=)', 'Azure SAS 令牌', FindingSeverity.CRITICAL),
        'gcp_sa': (r'(?:GCP_)?SERVICE_ACCOUNT[=:]\s*[\'"]\{[^}]*"type"\s*:\s*"service_account"', 'GCP 服务账号', FindingSeverity.CRITICAL),
        'gcp_api': (r'(?:GCP_|GOOGLE_)?API_KEY[=:]\s*[\'"](?:AIza)[A-Za-z0-9_\-]{35}', 'GCP API 密钥', FindingSeverity.CRITICAL),
        'cf_token': (r'(?:CF_|CLOUDFLARE_)?API_TOKEN[=:]\s*[\'"](?:[A-Za-z0-9_\-]{40})', 'Cloudflare API 令牌', FindingSeverity.CRITICAL),
        'generic': (r'(?:SECRET|PASSWORD|TOKEN|PRIVATE_KEY|API_KEY|AUTH_TOKEN)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]', '通用密钥', FindingSeverity.HIGH),
        'db_url': (r'(?:DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL)\s*[=:]\s*[\'"](?:\w+://[^\'"]*@)', '数据库连接字符串', FindingSeverity.HIGH),
        'jwt': (r'(?:JWT|JWT_SECRET|SECRET_KEY)\s*[=:]\s*[\'"](?:\w{16,})[\'"]', 'JWT/HMAC 密钥', FindingSeverity.HIGH),
        'slack': (r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24}', 'Slack Webhook', FindingSeverity.MEDIUM),
    }

    def extract(self, env_vars: Optional[Dict[str, str]] = None,
                config_text: str = "",
                provider: CloudProvider = CloudProvider.UNKNOWN) -> List[Finding]:
        findings: List[Finding] = []
        scan_text = config_text or ""
        if env_vars:
            for k, v in (env_vars or {}).items():
                scan_text += f"\n{k}={v}"
        if not scan_text.strip():
            return findings

        seen: Set[str] = set()
        for cat, (pattern, label, severity) in self.SECRETS.items():
            if cat in seen:
                continue
            matches = re.findall(pattern, scan_text, re.IGNORECASE)
            if matches:
                seen.add(cat)
                findings.append(Finding(
                    title=f"密钥暴露：{label}", severity=severity,
                    category="env_secret_leak", provider=provider,
                    description=f"检出 {label}（{len(matches)} 处）。密钥须通过 Secrets Manager 注入，禁止存储于配置。",
                    evidence=f"分类={cat}, 命中数={len(matches)}",
                    remediation="迁移至 Secrets Manager / Key Vault / Secret Manager；启用信封加密。",
                    cvss_score=9.1 if severity == FindingSeverity.CRITICAL else 7.5, cwe_id="CWE-798",
                ))

        if env_vars:
            suspicious = [k for k in env_vars if any(w in k.lower() for w in ('secret', 'password', 'key', 'token'))]
            if suspicious and not any('encrypted' in k.lower() or 'kms' in k.lower() for k in env_vars):
                findings.append(Finding(
                    title="疑似明文密钥无 KMS 集成",
                    severity=FindingSeverity.HIGH, category="env_plaintext_no_kms",
                    provider=provider, description=f"密钥 {suspicious[:5]} 明文存储，无加密。",
                    evidence=f"密钥={suspicious[:5]}",
                    remediation="迁移至 Secret Manager；使用 Lambda 环境加密辅助工具。",
                    cvss_score=7.8, cwe_id="CWE-312",
                ))

        return findings


class TmpPersistenceDetector:
    """/tmp 持久化滥用——检测热容器 /tmp 残留物在调用间存活。"""

    PATTERNS: List[Tuple[str, str, str, bool]] = [
        (r'(?:/tmp|tempfile\.gettempdir|os\.path\.join\s*\(\s*[\'"]/tmp)', 'tmp_write', '/tmp 写入操作', False),
        (r'chmod\s*\([^)]*/tmp', 'tmp_chmod', '/tmp 权限变更为可执行', False),
        (r'(?:/tmp\S*\.(?:so|dll|dylib)|dlopen\s*\([^)]*/tmp)', 'tmp_shared_lib', '从 /tmp 加载共享库', True),
        (r'os\.(?:exec[lv]?[pe]?|spawn|system)\s*\([^)]*/tmp', 'tmp_exec', '从 /tmp 执行二进制', True),
        (r'(?:importlib|__import__|imp\.load_source|spec_from_file_location)\s*\([^)]*/tmp', 'tmp_import', '从 /tmp 导入模块', True),
        (r'(?:eval|exec|compile)\s*\([^)]*/tmp', 'tmp_code_exec', '从 /tmp 执行代码', True),
    ]

    def detect(self, source_code: str, tmp_usage_bytes: int = 0) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[str] = set()
        for pattern, label, desc, is_crit in self.PATTERNS:
            if label in seen:
                continue
            matches = re.findall(pattern, source_code, re.IGNORECASE) if source_code else []
            if matches:
                seen.add(label)
                findings.append(Finding(
                    title=f"/tmp 持久化滥用：{label}",
                    severity=FindingSeverity.CRITICAL if is_crit else FindingSeverity.MEDIUM,
                    category=f"tmp_{label}",
                    description=f"{desc}——跨调用持久化：单次写入，后续调用均可执行。",
                    evidence=f"匹配模式={pattern}, 命中数={len(matches)}",
                    remediation="在 handler 入口清理 /tmp；启用 Lambda 代码签名；限制 /tmp 执行权限。",
                    cvss_score=9.3 if is_crit else 5.5, cwe_id="CWE-379" if is_crit else "CWE-459",
                ))

        if tmp_usage_bytes > 50 * 1024 * 1024:
            findings.append(Finding(
                title="/tmp 用量异常偏高",
                severity=FindingSeverity.MEDIUM, category="tmp_large_usage",
                description=f"/tmp 用量 {tmp_usage_bytes/1024/1024:.1f}MB——可能包含恶意载荷。",
                evidence=f"tmp_bytes={tmp_usage_bytes}",
                remediation="设置 /tmp 监控告警；验证内容不含可执行文件。",
                cvss_score=4.3, cwe_id="CWE-459",
            ))

        return findings


class ResourceExhaustionDetector:
    """检测并发资源耗尽攻击面 —— 无节流/无超时的外部调用链"""

    _UNBOUNDED_CALL_PATTERNS = [
        (r'(?:requests\.(?:get|post|put|delete)|urllib\.request)\s*\([^)]*\)\s*(?!.*timeout)', 'http_no_timeout'),
        (r'(?:boto3\.client|boto3\.resource)\s*\([^)]*\)\s*(?!.*config)', 'aws_sdk_no_retry_config'),
        (r'while\s+True\s*:\s*(?!.*break)', 'unbounded_loop'),
    ]

    def detect(self, source_code: str) -> List[Finding]:
        findings: List[Finding] = []
        for pattern, label in self._UNBOUNDED_CALL_PATTERNS:
            matches = re.findall(pattern, source_code, re.IGNORECASE | re.DOTALL) if source_code else []
            if matches:
                findings.append(Finding(
                    title=f"资源耗尽风险：{label}",
                    severity=FindingSeverity.MEDIUM,
                    category=f"resource_exhaustion_{label}",
                    description=f"无绑定或超时控制的调用模式（{len(matches)} 处）——可能导致并发耗尽计费。",
                    evidence=f"模式={pattern}",
                    remediation="为外部调用设置 timeout；使用指数退避；限制循环最大迭代。",
                    cvss_score=5.0, cwe_id="CWE-400",
                ))
        return findings


class FunctionChainAnalyzer:
    """函数链权限提升——构建调用图，检测环路与权限放大路径。"""

    _DANGEROUS: Set[str] = {
        'iam:*', 'iam:Create*', 's3:*', 'dynamodb:*', 'lambda:*', 'kms:*',
        'sts:AssumeRole*', 'ec2:*', 'rds:*', 'secretsmanager:*', 'ssm:GetParameter*', 'sqs:*', 'sns:*',
    }

    def __init__(self):
        self._funcs: Dict[str, FunctionConfig] = {}
        self._edges: List[Tuple[str, str, str]] = []

    def add_function(self, func: FunctionConfig) -> None:
        self._funcs[func.name] = func

    def add_invocation_edge(self, source: str, target: str, relation: str = "direct_invoke") -> None:
        self._edges.append((source, target, relation))

    def analyze(self) -> List[Finding]:
        findings: List[Finding] = []
        if not self._edges:
            return findings

        callees: Dict[str, List[str]] = {}
        callers: Dict[str, List[str]] = {}
        for s, t, _ in self._edges:
            callees.setdefault(s, []).append(t)
            callers.setdefault(t, []).append(s)

        def _dfs(node: str, path: List[str], visited: Set[str]) -> None:
            if node in path:
                cycle = path[path.index(node):] + [node]
                findings.append(Finding(
                    title="函数调用环路检出", severity=FindingSeverity.HIGH,
                    category="chain_cycle",
                    description=f"环路：{' -> '.join(cycle)}",
                    evidence=f"cycle={' -> '.join(cycle)}",
                    remediation="添加 max_retries / max_concurrency 限制；审计循环依赖。",
                    cvss_score=6.5, cwe_id="CWE-674",
                ))
                return
            if node in visited:
                return
            visited.add(node)
            path.append(node)
            for callee in callees.get(node, []):
                _dfs(callee, path, visited)
            path.pop()

        for name in list(self._funcs.keys()):
            _dfs(name, [], set())

        for s, t, _ in self._edges:
            sf = self._funcs.get(s)
            tf = self._funcs.get(t)
            if not sf or not tf:
                continue
            sd = self._count_danger(sf.iam_policy or [])
            td = self._count_danger(tf.iam_policy or [])
            if td > sd:
                findings.append(Finding(
                    title="函数链权限提升", severity=FindingSeverity.CRITICAL if td >= 3 else FindingSeverity.HIGH,
                    category="chain_priv_esc", provider=sf.provider,
                    description=f"'{s}'（{sd} 高危权限）-> '{t}'（{td} 高危权限）——可能逐步提权。",
                    evidence=f"source={s}({sd}), target={t}({td})",
                    remediation="按函数实施最小权限；在函数间传递限定凭证。",
                    cvss_score=9.1 if td >= 3 else 7.5, cwe_id="CWE-269",
                ))

        for name, caller_list in callers.items():
            if len(caller_list) > 3:
                findings.append(Finding(
                    title="函数入口面过大", severity=FindingSeverity.MEDIUM,
                    category="chain_blast_radius",
                    description=f"'{name}' 被 {len(caller_list)} 个调用方引用：{caller_list[:5]}。",
                    evidence=f"function={name}, callers={caller_list[:10]}",
                    remediation="缩减入口面；在各入口点强制认证。",
                    cvss_score=5.0, cwe_id="CWE-937",
                ))

        return findings

    def _count_danger(self, policy: List[Dict[str, Any]]) -> int:
        cnt = 0
        for stmt in policy:
            actions = stmt.get('Action', stmt.get('actions', []))
            if isinstance(actions, str):
                actions = [actions]
            for a in actions:
                if any(a.startswith(d.rstrip('*')) for d in self._DANGEROUS):
                    cnt += 1
        return cnt


class ServerlessAnalyzer:
    """Serverless 安全分析调度中枢——集成 8 个检测模块，执行云函数全面审计。"""

    def __init__(self):
        self.cold_start = ColdStartSideChannelDetector()
        self.env_escape = SharedEnvironmentEscapeDetector()
        self.iam = IamPermissionBoundaryAnalyzer()
        self.events = EventInjectionScanner()
        self.secrets = EnvSecretExtractor()
        self.tmp = TmpPersistenceDetector()
        self.chains = FunctionChainAnalyzer()
        self.resource_exhaust = ResourceExhaustionDetector()

    def analyze(self,
                source_code: str = "",
                runtime: str = "python",
                function_configs: Optional[List[Dict[str, Any]]] = None,
                env_vars: Optional[Dict[str, str]] = None,
                config_text: str = "",
                iam_statements: Optional[List[Dict[str, Any]]] = None,
                invocation_edges: Optional[List[Tuple[str, str, str]]] = None,
                init_timings: Optional[List[float]] = None,
                tmp_usage_bytes: int = 0,
                provider: CloudProvider = CloudProvider.AWS_LAMBDA,
                **kwargs) -> Dict[str, Any]:
        """运行完整 Serverless 安全分析流水线，涵盖全部可用模块。"""
        all_findings: List[Dict[str, Any]] = []
        stats: Dict[str, int] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        def _add(findings: List[Finding]):
            for f in findings:
                f.provider = provider
                all_findings.append(f.to_dict())
                stats[f.severity.value] += 1

        if init_timings:
            for t in init_timings:
                self.cold_start.feed(t)
            _add(self.cold_start.detect())

        if source_code:
            _add(self.env_escape.detect(source_code, runtime))

        if iam_statements:
            _add(self.iam.analyze(iam_statements, provider))

        if source_code:
            trigger = None
            if function_configs:
                for fc in function_configs:
                    tr = fc.get('triggers', fc.get('Triggers', []))
                    if tr:
                        try:
                            trigger = TriggerType(tr[0]) if isinstance(tr[0], str) else tr[0]
                        except (ValueError, TypeError):
                            pass
                        break
            _add(self.events.scan(source_code, trigger))

        if env_vars or config_text:
            _add(self.secrets.extract(env_vars, config_text, provider))

        if source_code or tmp_usage_bytes > 0:
            _add(self.tmp.detect(source_code, tmp_usage_bytes))

        if source_code:
            _add(self.resource_exhaust.detect(source_code))

        if function_configs:
            for fc in function_configs:
                func = FunctionConfig(
                    name=fc.get('name', fc.get('FunctionName', 'unknown')),
                    provider=provider,
                    runtime=fc.get('runtime', fc.get('Runtime', runtime)),
                    handler=fc.get('handler', fc.get('Handler', '')),
                    memory_mb=fc.get('memory_mb', fc.get('MemorySize', 128)),
                    timeout_seconds=fc.get('timeout_seconds', fc.get('Timeout', 3)),
                    env_vars=fc.get('env_vars', fc.get('Environment', {}).get('Variables', {})),
                    iam_policy=fc.get('iam_policy'),
                    vpc_config=fc.get('vpc_config', fc.get('VpcConfig')),
                    layers=fc.get('layers', fc.get('Layers', [])),
                )
                self.chains.add_function(func)
            if invocation_edges:
                for s, t, r in invocation_edges:
                    self.chains.add_invocation_edge(s, t, r)
            _add(self.chains.analyze())

        total = sum(stats.values())
        weights = {'critical': 10.0, 'high': 5.0, 'medium': 2.0, 'low': 0.5, 'info': 0.1}
        risk_score = min(round(sum(weights[k] * v for k, v in stats.items()), 1), 100.0)

        result: Dict[str, Any] = {
            'success': True, 'provider': provider.value,
            'total_findings': total, 'severity_counts': stats,
            'risk_score': risk_score, 'findings': all_findings,
        }
        logger.info(f"Serverless 分析完成：{provider.value}, 检出={total}, "
                    f"严重={stats['critical']}, 高危={stats['high']}, 风险分={risk_score}")
        return result


def analyze_serverless(source_code: str = "",
                       runtime: str = "python",
                       function_configs: Optional[List[Dict[str, Any]]] = None,
                       env_vars: Optional[Dict[str, str]] = None,
                       config_text: str = "",
                       iam_statements: Optional[List[Dict[str, Any]]] = None,
                       invocation_edges: Optional[List[Tuple[str, str, str]]] = None,
                       init_timings: Optional[List[float]] = None,
                       tmp_usage_bytes: int = 0,
                       provider: CloudProvider = CloudProvider.AWS_LAMBDA,
                       **kwargs) -> Dict[str, Any]:
    """单次 Serverless 安全分析入口。参数均可选——仅对已提供数据的模块执行检测。"""
    return ServerlessAnalyzer().analyze(
        source_code=source_code, runtime=runtime,
        function_configs=function_configs, env_vars=env_vars,
        config_text=config_text, iam_statements=iam_statements,
        invocation_edges=invocation_edges, init_timings=init_timings,
        tmp_usage_bytes=tmp_usage_bytes, provider=provider, **kwargs)


__all__ = [
    "ServerlessAnalyzer", "ColdStartSideChannelDetector",
    "SharedEnvironmentEscapeDetector", "IamPermissionBoundaryAnalyzer",
    "EventInjectionScanner", "EnvSecretExtractor", "TmpPersistenceDetector",
    "FunctionChainAnalyzer", "ResourceExhaustionDetector",
    "CloudProvider", "TriggerType",
    "FindingSeverity", "Finding", "FunctionConfig", "analyze_serverless",
]
