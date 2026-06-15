import os
import logging
import pickle
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)

class ThreatCategory(Enum):
    """威胁类别枚举"""
    RANSOMWARE = 'ransomware'
    TROJAN = 'trojan'
    BACKDOOR = 'backdoor'
    MINER = 'miner'
    SPYWARE = 'spyware'
    ADWARE = 'adware'
    DOWNLOADER = 'downloader'
    DROPPER = 'dropper'
    WORM = 'worm'
    BENIGN = 'benign'
    UNKNOWN = 'unknown'

@dataclass
class SyscallSequence:
    """系统调用序列"""
    pid: int
    calls: List[str]
    timestamps: List[int] = None
    
    def __post_init__(self):
        if self.timestamps is None:
            self.timestamps = []

@dataclass
class ClassificationResult:
    """分类结果"""
    category: ThreatCategory
    confidence: float
    score: float
    features: Dict[str, float]
    explanation: str

@dataclass
class SyscallPattern:
    """系统调用模式"""
    name: str
    pattern: List[str]
    category: ThreatCategory
    weight: float = 1.0

class SyscallClassifier:
    """系统调用序列分类器"""
    
    # 恶意软件特征模式
    MALICIOUS_PATTERNS = [
        # 勒索软件模式
        SyscallPattern('ransomware_file_ops', 
            ['CreateFile', 'WriteFile', 'EncryptFile', 'DeleteFile', 'MoveFile'],
            ThreatCategory.RANSOMWARE, 1.5),
        SyscallPattern('ransomware_network', 
            ['Connect', 'Send', 'Recv', 'HttpSendRequest'],
            ThreatCategory.RANSOMWARE, 1.0),
        
        # 挖矿模式
        SyscallPattern('miner_cpu', 
            ['CreateThread', 'CreateRemoteThread', 'Sleep', 'QueryPerformanceCounter'],
            ThreatCategory.MINER, 1.2),
        SyscallPattern('miner_network', 
            ['Connect', 'Recv', 'Send', 'getaddrinfo'],
            ThreatCategory.MINER, 1.0),
        
        # 后门模式
        SyscallPattern('backdoor_listen', 
            ['socket', 'bind', 'listen', 'accept'],
            ThreatCategory.BACKDOOR, 1.5),
        SyscallPattern('backdoor_exec', 
            ['CreateProcess', 'WinExec', 'ShellExecute'],
            ThreatCategory.BACKDOOR, 1.3),
        
        # 间谍软件模式
        SyscallPattern('spyware_keyboard', 
            ['GetAsyncKeyState', 'GetKeyboardState', 'SetWindowsHookEx'],
            ThreatCategory.SPYWARE, 1.5),
        SyscallPattern('spyware_screenshot', 
            ['BitBlt', 'GetDC', 'CreateDC', 'PrintWindow'],
            ThreatCategory.SPYWARE, 1.2),
        
        # 下载器模式
        SyscallPattern('downloader_http', 
            ['HttpOpenRequest', 'HttpSendRequest', 'InternetReadFile', 'WriteFile'],
            ThreatCategory.DOWNLOADER, 1.5),
        SyscallPattern('downloader_file', 
            ['CreateFile', 'WriteFile', 'CreateProcess'],
            ThreatCategory.DOWNLOADER, 1.0),
        
        # 木马模式
        SyscallPattern('trojan_inject', 
            ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
            ThreatCategory.TROJAN, 1.5),
        SyscallPattern('trojan_persistence', 
            ['RegSetValue', 'CreateService', 'ScheduleJob'],
            ThreatCategory.TROJAN, 1.3),
        
        # 蠕虫模式
        SyscallPattern('worm_spread', 
            ['NetShareEnum', 'NetUseAdd', 'CopyFile', 'CreateProcess'],
            ThreatCategory.WORM, 1.5),
        
        # 良性模式
        SyscallPattern('benign_gui', 
            ['CreateWindow', 'ShowWindow', 'UpdateWindow', 'DispatchMessage'],
            ThreatCategory.BENIGN, 1.0),
        SyscallPattern('benign_file', 
            ['ReadFile', 'WriteFile', 'CloseHandle'],
            ThreatCategory.BENIGN, 0.8),
    ]
    
    # 危险系统调用列表
    DANGEROUS_SYSCALLS = [
        'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
        'OpenProcess', 'CreateProcess', 'WinExec', 'ShellExecute',
        'HttpSendRequest', 'InternetReadFile', 'URLDownloadToFile',
        'SetWindowsHookEx', 'GetAsyncKeyState', 'BitBlt',
        'RegSetValue', 'CreateService', 'ScheduleJob',
        'EncryptFile', 'DeleteFile', 'MoveFile',
        'socket', 'bind', 'listen', 'accept', 'connect',
    ]
    
    def __init__(self, model_path: str = None):
        """初始化系统调用分类器"""
        self.model_path = model_path
        self.patterns = self.MALICIOUS_PATTERNS
        self.scores: Dict[ThreatCategory, float] = {}
        self._init_scores()
    
    def _init_scores(self):
        """初始化各类别分数"""
        for category in ThreatCategory:
            self.scores[category] = 0.0
    
    def _calculate_pattern_match(self, syscalls: List[str], pattern: SyscallPattern) -> float:
        """计算模式匹配分数"""
        matched = 0
        for call in pattern.pattern:
            if call.lower() in [s.lower() for s in syscalls]:
                matched += 1
        
        if matched == 0:
            return 0.0
        
        return (matched / len(pattern.pattern)) * pattern.weight
    
    def _extract_features(self, syscalls: List[str]) -> Dict[str, float]:
        """提取特征"""
        features = {}
        
        # 危险调用计数
        dangerous_count = sum(1 for call in syscalls if call.lower() in [d.lower() for d in self.DANGEROUS_SYSCALLS])
        features['dangerous_call_ratio'] = dangerous_count / len(syscalls) if syscalls else 0.0
        
        # 网络调用计数
        network_calls = ['socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv',
                        'HttpOpenRequest', 'HttpSendRequest', 'InternetReadFile', 'getaddrinfo']
        features['network_call_ratio'] = sum(1 for call in syscalls if any(n in call.lower() for n in network_calls)) / len(syscalls) if syscalls else 0.0
        
        # 文件操作计数
        file_calls = ['CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile', 'MoveFile', 'CopyFile']
        features['file_call_ratio'] = sum(1 for call in syscalls if any(f in call.lower() for f in file_calls)) / len(syscalls) if syscalls else 0.0
        
        # 进程操作计数
        process_calls = ['CreateProcess', 'OpenProcess', 'CreateRemoteThread', 'TerminateProcess']
        features['process_call_ratio'] = sum(1 for call in syscalls if any(p in call.lower() for p in process_calls)) / len(syscalls) if syscalls else 0.0
        
        # 注册表操作计数
        reg_calls = ['RegOpenKey', 'RegSetValue', 'RegCreateKey', 'RegDeleteKey']
        features['reg_call_ratio'] = sum(1 for call in syscalls if any(r in call.lower() for r in reg_calls)) / len(syscalls) if syscalls else 0.0
        
        return features
    
    def _classify_by_patterns(self, syscalls: List[str]) -> Tuple[ThreatCategory, float]:
        """基于模式进行分类"""
        self._init_scores()
        
        for pattern in self.patterns:
            score = self._calculate_pattern_match(syscalls, pattern)
            if score > 0:
                self.scores[pattern.category] += score
        
        # 找到最高分的类别
        max_score = max(self.scores.values())
        if max_score == 0:
            return ThreatCategory.UNKNOWN, 0.0
        
        # 计算置信度
        total_score = sum(self.scores.values())
        confidence = max_score / total_score if total_score > 0 else 0.0
        
        # 确定类别
        top_category = max(self.scores, key=self.scores.get)
        
        return top_category, confidence
    
    def _generate_explanation(self, category: ThreatCategory, features: Dict[str, float]) -> str:
        """生成分类解释"""
        explanations = []
        
        if features['dangerous_call_ratio'] > 0.3:
            explanations.append(f"高危险系统调用比例 ({features['dangerous_call_ratio']:.2f})")
        
        if features['network_call_ratio'] > 0.2:
            explanations.append(f"频繁网络活动 ({features['network_call_ratio']:.2f})")
        
        if features['process_call_ratio'] > 0.1:
            explanations.append(f"频繁进程操作 ({features['process_call_ratio']:.2f})")
        
        if features['reg_call_ratio'] > 0.1:
            explanations.append(f"频繁注册表操作 ({features['reg_call_ratio']:.2f})")
        
        if not explanations:
            explanations.append("基于系统调用模式匹配")
        
        return f"分类为 {category.value}，原因: {'; '.join(explanations)}"
    
    def classify(self, syscalls: List[str]) -> ClassificationResult:
        """分类系统调用序列"""
        if not syscalls:
            return ClassificationResult(
                category=ThreatCategory.UNKNOWN,
                confidence=0.0,
                score=0.0,
                features={},
                explanation="无系统调用数据"
            )
        
        # 提取特征
        features = self._extract_features(syscalls)
        
        # 基于模式分类
        category, confidence = self._classify_by_patterns(syscalls)
        
        # 计算分数
        score = self.scores[category]
        
        # 生成解释
        explanation = self._generate_explanation(category, features)
        
        return ClassificationResult(
            category=category,
            confidence=confidence,
            score=score,
            features=features,
            explanation=explanation
        )
    
    def classify_sequence(self, sequence: SyscallSequence) -> ClassificationResult:
        """分类系统调用序列对象"""
        return self.classify(sequence.calls)
    
    def batch_classify(self, sequences: List[SyscallSequence]) -> List[ClassificationResult]:
        """批量分类"""
        results = []
        for seq in sequences:
            results.append(self.classify(seq.calls))
        return results
    
    def get_malicious_probability(self, syscalls: List[str]) -> float:
        """获取恶意概率"""
        result = self.classify(syscalls)
        
        malicious_categories = [
            ThreatCategory.RANSOMWARE,
            ThreatCategory.TROJAN,
            ThreatCategory.BACKDOOR,
            ThreatCategory.MINER,
            ThreatCategory.SPYWARE,
            ThreatCategory.DOWNLOADER,
            ThreatCategory.DROPPER,
            ThreatCategory.WORM,
        ]
        
        if result.category in malicious_categories:
            return result.confidence
        
        return 0.0
    
    def train(self, training_data: List[Tuple[List[str], ThreatCategory]]):
        """训练模型（简化实现）"""
        logger.info(f"训练数据: {len(training_data)} 样本")
        # 在实际实现中，这里会训练机器学习模型
        # 当前简化版本使用规则引擎
    
    def save_model(self, path: str):
        """保存模型"""
        try:
            with open(path, 'wb') as f:
                pickle.dump({
                    'patterns': self.patterns,
                    'dangerous_syscalls': self.DANGEROUS_SYSCALLS
                }, f)
            logger.info(f"模型已保存: {path}")
        except Exception as e:
            logger.error(f"保存模型失败: {e}")
    
    def load_model(self, path: str):
        """加载模型"""
        try:
            with open(path, 'rb') as f:
                data = pickle.load(f)
                self.patterns = data.get('patterns', self.patterns)
                # 保持内置的危险系统调用列表不变
            logger.info(f"模型已加载: {path}")
        except Exception as e:
            logger.error(f"加载模型失败: {e}")
    
    def get_analysis_summary(self, syscalls: List[str]) -> Dict[str, Any]:
        """获取分析摘要"""
        result = self.classify(syscalls)
        
        return {
            'category': result.category.value,
            'confidence': result.confidence,
            'score': result.score,
            'malicious_probability': self.get_malicious_probability(syscalls),
            'features': result.features,
            'explanation': result.explanation,
        }
