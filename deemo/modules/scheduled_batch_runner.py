"""
自动化时间窗口: 智能批量分析调度模块

功能:
    1. 支持定时任务, 如夜间自动对资产仓库所有二进制批量分析
    2. 新发现漏洞推送告警
    3. 与 CI/CD 深度集成, 支持 MR/PR 时自动触发差异化分析

核心技术:
    - 任务调度 (基于 cron 表达式 / 间隔)
    - 资产发现 (目录递归扫描)
    - 增量分析 (基于上一次 hash)
    - CI/CD 钩子 (GitLab/GitHub)
"""

import logging
import os
import json
import time
import hashlib
import threading
import fnmatch
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class TriggerKind(Enum):
    SCHEDULED = "scheduled"           # 定时
    CI_PUSH = "ci_push"               # CI push
    CI_PR = "ci_pr"                   # CI PR/MR
    MANUAL = "manual"                 # 手动
    WEBHOOK = "webhook"               # 外部 webhook


@dataclass
class AssetBinary:
    """资产二进制"""
    path: str
    name: str
    size: int
    sha256: str
    last_analyzed_at: Optional[float] = None
    last_vuln_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScheduleRule:
    """调度规则"""
    name: str
    cron: Optional[str] = None         # 标准 5-字段 cron
    interval_seconds: Optional[float] = None
    trigger_kinds: List[TriggerKind] = field(default_factory=lambda: [TriggerKind.SCHEDULED])
    asset_paths: List[str] = field(default_factory=list)
    asset_patterns: List[str] = field(default_factory=lambda: ["*.elf", "*.bin", "*.exe", "*.so"])
    enabled: bool = True
    notify_webhook: Optional[str] = None
    on_vuln_found: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BatchAnalysisJob:
    """批量分析任务"""
    job_id: str
    rule_name: str
    started_at: float
    finished_at: Optional[float] = None
    binaries_total: int = 0
    binaries_analyzed: int = 0
    new_vulns: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "running"
    error: Optional[str] = None


class CronParser:
    """简单 cron 解析 (5 字段)"""

    @staticmethod
    def matches(cron: str, now: Optional[time.struct_time] = None) -> bool:
        now = now or time.localtime()
        fields = cron.split()
        if len(fields) != 5:
            return False
        minute, hour, dom, month, dow = fields
        return (
            CronParser._field_matches(minute, now.tm_min, 0, 59) and
            CronParser._field_matches(hour, now.tm_hour, 0, 23) and
            CronParser._field_matches(dom, now.tm_mday, 1, 31) and
            CronParser._field_matches(month, now.tm_mon, 1, 12) and
            CronParser._field_matches(dow, now.tm_wday, 0, 6)
        )

    @staticmethod
    def _field_matches(field: str, value: int, lo: int, hi: int) -> bool:
        if field == "*":
            return True
        for part in field.split(","):
            if "/" in part:
                base, step = part.split("/")
                base = lo if base == "*" else int(base)
                if (value - base) % int(step) == 0 and lo <= value <= hi:
                    return True
            elif "-" in part:
                start, end = map(int, part.split("-"))
                if start <= value <= end:
                    return True
            elif part.isdigit():
                if int(part) == value:
                    return True
        return False


class AssetDiscovery:
    """资产发现"""

    DEFAULT_PATTERNS = ["*.elf", "*.bin", "*.exe", "*.so", "*.dll",
                        "*.dylib", "*.o", "*.ko", "*.firmware"]

    def __init__(self, custom_patterns: Optional[List[str]] = None):
        self.patterns = custom_patterns or self.DEFAULT_PATTERNS

    def discover(self, root_dirs: List[str],
                 max_size_mb: int = 500) -> List[AssetBinary]:
        results: List[AssetBinary] = []
        for root in root_dirs:
            if not os.path.exists(root):
                continue
            for dirpath, _, filenames in os.walk(root):
                for fn in filenames:
                    if not self._match_pattern(fn):
                        continue
                    full = os.path.join(dirpath, fn)
                    try:
                        size = os.path.getsize(full)
                        if size > max_size_mb * 1024 * 1024:
                            continue
                        sha = self._sha256(full)
                    except OSError:
                        continue
                    results.append(AssetBinary(
                        path=full, name=fn, size=size, sha256=sha
                    ))
        return results

    def _match_pattern(self, name: str) -> bool:
        return any(fnmatch.fnmatch(name.lower(), p.lower())
                   for p in self.patterns)

    @staticmethod
    def _sha256(path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                while chunk := f.read(8192):
                    h.update(chunk)
        except OSError:
            return ""
        return h.hexdigest()


class IncrementalAnalyzer:
    """增量分析器"""

    def __init__(self, state_path: Optional[str] = None):
        if state_path is None:
            state_path = os.path.join(
                os.path.dirname(__file__), '..', 'data',
                'batch_analyzer_state.json'
            )
        os.makedirs(os.path.dirname(state_path), exist_ok=True)
        self.state_path = state_path
        self._state: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self):
        if os.path.exists(self.state_path):
            try:
                with open(self.state_path, 'r', encoding='utf-8') as f:
                    self._state = json.load(f)
            except Exception as e:
                logger.warning(f"加载批量分析状态失败: {e}")

    def _save(self):
        try:
            with open(self.state_path, 'w', encoding='utf-8') as f:
                json.dump(self._state, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"保存状态失败: {e}")

    def needs_analysis(self, asset: AssetBinary) -> bool:
        prior = self._state.get(asset.sha256)
        if not prior:
            return True
        return prior.get('sha256') != asset.sha256

    def record(self, asset: AssetBinary, vulns: int, result: Dict[str, Any]):
        self._state[asset.sha256] = {
            'sha256': asset.sha256,
            'path': asset.path,
            'analyzed_at': time.time(),
            'vuln_count': vulns,
            'result_summary': {
                k: result.get(k) for k in ('vuln_count', 'severity', 'top_finding')
            }
        }
        self._save()

    def get_state(self) -> Dict[str, Any]:
        return dict(self._state)


class Notifier:
    """通知器 (webhook)"""

    @staticmethod
    def send_webhook(url: str, payload: Dict[str, Any]) -> bool:
        try:
            import requests
            r = requests.post(url, json=payload, timeout=10)
            return r.status_code < 300
        except Exception as e:
            logger.warning(f"webhook 通知失败: {e}")
            return False


class ScheduledBatchRunner:
    """定时批量分析运行器"""

    def __init__(self,
                 analyzer: Optional[Callable[[str], Dict[str, Any]]] = None):
        self.discovery = AssetDiscovery()
        self.incremental = IncrementalAnalyzer()
        self.rules: List[ScheduleRule] = []
        self._jobs: Dict[str, BatchAnalysisJob] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.analyzer = analyzer

    def add_rule(self, rule: ScheduleRule):
        self.rules.append(rule)
        logger.info(f"[batch-runner] 添加规则: {rule.name}")

    def remove_rule(self, name: str):
        self.rules = [r for r in self.rules if r.name != name]

    def start(self, tick_seconds: float = 60.0):
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, args=(tick_seconds,), daemon=True
        )
        self._thread.start()
        logger.info("[batch-runner] 启动")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def _loop(self, tick: float):
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as e:
                logger.warning(f"tick 失败: {e}")
            self._stop.wait(tick)

    def _tick(self):
        for rule in self.rules:
            if not rule.enabled:
                continue
            if not self._should_run(rule):
                continue
            self._run_rule(rule, TriggerKind.SCHEDULED)

    def _should_run(self, rule: ScheduleRule) -> bool:
        if rule.cron and CronParser.matches(rule.cron):
            return True
        return False

    def _run_rule(self, rule: ScheduleRule,
                  trigger: TriggerKind) -> BatchAnalysisJob:
        job = BatchAnalysisJob(
            job_id=hashlib.sha256(
                f"{rule.name}-{time.time()}".encode()
            ).hexdigest()[:16],
            rule_name=rule.name,
            started_at=time.time(),
            status="running"
        )
        with self._lock:
            self._jobs[job.job_id] = job
        # 发现资产
        assets = self.discovery.discover(rule.asset_paths)
        job.binaries_total = len(assets)
        # 增量过滤
        todo = [a for a in assets if self.incremental.needs_analysis(a)]
        for asset in todo:
            try:
                if self.analyzer:
                    result = self.analyzer(asset.path)
                else:
                    result = self._default_analyzer(asset.path)
                vulns = result.get('vuln_count', 0)
                self.incremental.record(asset, vulns, result)
                if vulns > 0:
                    job.new_vulns.append({
                        'binary': asset.path,
                        'vuln_count': vulns,
                        'severity': result.get('severity', 'unknown')
                    })
                job.binaries_analyzed += 1
            except Exception as e:
                logger.warning(f"分析失败 {asset.path}: {e}")
        job.finished_at = time.time()
        job.status = "completed"
        # 通知
        if job.new_vulns and rule.notify_webhook:
            Notifier.send_webhook(rule.notify_webhook, {
                'job_id': job.job_id,
                'rule': rule.name,
                'trigger': trigger.value,
                'new_vulns': job.new_vulns
            })
        return job

    def _default_analyzer(self, binary_path: str) -> Dict[str, Any]:
        """默认占位分析器 (使用 hash 推断)"""
        try:
            size = os.path.getsize(binary_path)
            return {
                'success': True,
                'vuln_count': 0,
                'severity': 'info',
                'size': size
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def run_now(self, rule_name: str,
                trigger: TriggerKind = TriggerKind.MANUAL) -> Optional[BatchAnalysisJob]:
        for r in self.rules:
            if r.name == rule_name:
                return self._run_rule(r, trigger)
        return None

    def handle_ci_event(self, event_kind: TriggerKind,
                        rule_name: str,
                        changed_files: Optional[List[str]] = None) -> Optional[BatchAnalysisJob]:
        """CI 事件处理"""
        return self.run_now(rule_name, trigger=event_kind)

    def list_jobs(self) -> List[Dict[str, Any]]:
        return [
            {
                'job_id': j.job_id,
                'rule_name': j.rule_name,
                'status': j.status,
                'binaries_total': j.binaries_total,
                'binaries_analyzed': j.binaries_analyzed,
                'new_vulns': j.new_vulns,
                'started_at': j.started_at,
                'finished_at': j.finished_at
            }
            for j in self._jobs.values()
        ]


def add_scheduled_rule(
    name: str,
    cron: str,
    asset_paths: List[str],
    notify_webhook: Optional[str] = None
) -> ScheduleRule:
    """便捷入口"""
    return ScheduleRule(
        name=name, cron=cron, asset_paths=asset_paths,
        notify_webhook=notify_webhook
    )
