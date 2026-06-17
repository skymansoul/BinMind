import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class SyncIssueType(Enum):
    LOCK_CONTENTION = "lock_contention"
    DOUBLE_LOCK = "double_lock"
    UNLOCK_WITHOUT_LOCK = "unlock_without_lock"
    RACE_CONDITION = "race_condition"
    DEADLOCK = "deadlock"
    SEQUENCE_ERROR = "sequence_error"


@dataclass
class SyncIssue:
    issue_type: SyncIssueType
    lock_name: str
    address: int
    severity: str
    description: str
    stack_trace: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'issue_type': self.issue_type.value,
            'lock_name': self.lock_name,
            'address': hex(self.address),
            'severity': self.severity,
            'description': self.description,
            'stack_trace': self.stack_trace
        }


@dataclass
class SyncAnalysisResult:
    issues: List[SyncIssue]
    lock_acquisitions: int
    lock_releases: int
    deadlock_detected: bool
    recommendation: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'issues': [i.to_dict() for i in self.issues],
            'lock_acquisitions': self.lock_acquisitions,
            'lock_releases': self.lock_releases,
            'deadlock_detected': self.deadlock_detected,
            'recommendation': self.recommendation
        }


class KernelSyncDetector:
    
    def __init__(self):
        self.lock_functions = {
            'mutex_lock', 'mutex_unlock', 'mutex_lock_interruptible',
            'spin_lock', 'spin_unlock', 'spin_lock_irqsave',
            'rwlock_read_lock', 'rwlock_write_lock', 'rwlock_unlock',
            'sem_down', 'sem_up', 'down', 'up',
            'mutex_trylock', 'spin_trylock'
        }
        
        self.issue_patterns = {
            SyncIssueType.LOCK_CONTENTION: [
                r'mutex_lock.*blocked',
                r'spin_lock.*contention',
                r'lock.*held.*too.*long'
            ],
            SyncIssueType.DOUBLE_LOCK: [
                r'mutex_lock.*already.*held',
                r'double.*lock',
                r'recursive.*lock'
            ],
            SyncIssueType.UNLOCK_WITHOUT_LOCK: [
                r'mutex_unlock.*not.*held',
                r'unlock.*without.*lock',
                r'release.*unlocked'
            ],
            SyncIssueType.RACE_CONDITION: [
                r'data.*race',
                r'race.*condition',
                r'concurrent.*access'
            ],
            SyncIssueType.DEADLOCK: [
                r'deadlock',
                r'circular.*wait',
                r'lock.*order.*violation'
            ],
            SyncIssueType.SEQUENCE_ERROR: [
                r'lock.*order.*error',
                r'mutex.*order.*violation',
                r'wrong.*lock.*order'
            ]
        }
    
    def analyze(self, kernel_info: Dict[str, Any]) -> SyncAnalysisResult:
        issues = []
        lock_acquisitions = 0
        lock_releases = 0
        deadlock_detected = False
        
        strings = kernel_info.get('strings', '')
        
        for issue_type, patterns in self.issue_patterns.items():
            for pattern in patterns:
                if pattern.lower() in strings.lower():
                    issue = SyncIssue()
                        issue_type=issue_type,
                        lock_name='unknown',
                        address=0,
                        severity=self._get_severity(issue_type),
                        description=self._get_description(issue_type),
                        stack_trace=[]
                    
                    issues.append(issue)
                    
                    if issue_type == SyncIssueType.DEADLOCK:
                        deadlock_detected = True
        
        lock_acquisitions, lock_releases = self._count_locks(kernel_info)
        
        recommendation = self._generate_recommendation(issues, deadlock_detected)
        
        return SyncAnalysisResult(
            issues=issues,
            lock_acquisitions=lock_acquisitions,
            lock_releases=lock_releases,
            deadlock_detected=deadlock_detected,
            recommendation=recommendation)
        

    
    def _get_severity(self, issue_type: SyncIssueType) -> str:
        severity_map = {
            SyncIssueType.LOCK_CONTENTION: 'medium',
            SyncIssueType.DOUBLE_LOCK: 'high',
            SyncIssueType.UNLOCK_WITHOUT_LOCK: 'high',
            SyncIssueType.RACE_CONDITION: 'critical',
            SyncIssueType.DEADLOCK: 'critical',
            SyncIssueType.SEQUENCE_ERROR: 'medium'
        }
        return severity_map.get(issue_type, 'medium')
    
    def _get_description(self, issue_type: SyncIssueType) -> str:
        descriptions = {
            SyncIssueType.LOCK_CONTENTION: '检测到锁竞争，可能导致性能问题',
            SyncIssueType.DOUBLE_LOCK: '检测到重复加锁，可能导致死锁',
            SyncIssueType.UNLOCK_WITHOUT_LOCK: '检测到解锁未加锁的互斥量',
            SyncIssueType.RACE_CONDITION: '检测到数据竞争条件',
            SyncIssueType.DEADLOCK: '检测到死锁',
            SyncIssueType.SEQUENCE_ERROR: '检测到锁顺序错误'
        }
        return descriptions.get(issue_type, '未知同步问题')
    
    def _count_locks(self, kernel_info: Dict[str, Any]) -> tuple:
        acquisitions = 0
        releases = 0
        
        strings = kernel_info.get('strings', '')
        
        for func in self.lock_functions:
            if 'lock' in func.lower():
                acquisitions += strings.lower().count(func.lower(

            if 'unlock' in func.lower() or 'up' == func.lower():
                releases += strings.lower().count(func.lower(

        
        return acquisitions, releases
    
    def _generate_recommendation(self, issues: List[SyncIssue], deadlock_detected: bool) -> List[str]:
        recommendations = []
        
        if deadlock_detected:
            recommendations.append("检测到死锁，需要立即修复")
        
        race_conditions = [i for i in issues if i.issue_type == SyncIssueType.RACE_CONDITION]
        if race_conditions:
            recommendations.append("检测到数据竞争，建议添加适当的同步保护")
        
        double_locks = [i for i in issues if i.issue_type == SyncIssueType.DOUBLE_LOCK]
        if double_locks:
            recommendations.append("检测到重复加锁，建议检查锁的使用逻辑")
        
        return recommendations


def detect_kernel_sync_issues(kernel_info: Dict[str, Any]) -> SyncAnalysisResult:
    detector = KernelSyncDetector()
    return detector))))