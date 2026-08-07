"""Serverless安全分析：6个检测器模块。

SharedEnvironmentEscapeDetector: 全局状态与运行时逃逸检测
IamPermissionBoundaryAnalyzer: IAM权限边界分析
EventInjectionScanner: 事件注入扫描
EnvSecretExtractor: 环境变量密钥提取
TmpPersistenceDetector: /tmp持久化滥用检测
ResourceExhaustionDetector: 资源耗尽检测
"""
import re
from typing import Dict, Any, List, Optional, Set, Tuple

from .serverless_types import (
    Finding, FindingSeverity, CloudProvider, TriggerType,
)


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


__all__ = [
    "SharedEnvironmentEscapeDetector", "IamPermissionBoundaryAnalyzer",
    "EventInjectionScanner", "EnvSecretExtractor",
    "TmpPersistenceDetector", "ResourceExhaustionDetector",
]
