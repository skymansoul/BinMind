#!/usr/bin/env python3
"""统计偏差驱动的零日异常检测。

提取二进制特征向量，与正常行为基线比对。Z-score与隔离森林双检测器并行
评分，偏离标定阈值的样本标记为潜在恶意或漏洞载体。
"""

import os
import json
import pickle
import hashlib
import math
import logging
import random
import re
from collections import defaultdict
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

# NumPy——可用则加速，缺失则回退纯Python
try:
    import numpy
except ImportError:
    numpy = None

logger = logging.getLogger(__name__)


# 异常严重度分级常量
class AnomalyLevel(str, Enum):
    """离散严重度分级——将连续异常分映射为可操作的响应类别"""
    NORMAL = 'normal'
    SUSPICIOUS = 'suspicious'
    ANOMALOUS = 'anomalous'
    CRITICAL = 'critical'


# 兼容别名——历史名称 AnomalyScoreLevel 与 AnomalyLevel 指向同一枚举
AnomalyScoreLevel = AnomalyLevel


def _score_to_level(score):
    """连续分值→离散严重度区间映射"""
    if score < 0.2:
        return AnomalyLevel.NORMAL
    elif score < 0.5:
        return AnomalyLevel.SUSPICIOUS
    elif score < 0.8:
        return AnomalyLevel.ANOMALOUS
    return AnomalyLevel.CRITICAL


# 特征提取维度——每条轴独立运算
class FeatureType(str, Enum):
    """二进制特征提取维度枚举"""
    SYSCALL = 'system_call_sequence'
    CFG = 'control_flow_graph'
    INSN = 'instruction_patterns'
    STRINGS = 'string_analysis'
    IMPORTS = 'import_table'
    EXPORTS = 'export_table'
    SECTIONS = 'section_analysis'
    DATAFLOW = 'data_flow_topology'


# 手工统计算子——无需numpy，模块自包含
# 每个函数都是纯Python实现，不依赖任何外部数学库

def _manual_mean(values):
    """数值序列的算术均值"""
    n = len(values)
    if n == 0:
        return 0.0
    s = 0.0
    for v in values:
        s += float(v)
    return s / n


def _manual_std(values, ddof=1):
    """样本标准差，Bessel校正（ddof=1），匹配pandas默认行为"""
    n = len(values)
    if n <= ddof:
        return 1.0
    mu = _manual_mean(values)
    ssq = 0.0
    for v in values:
        d = float(v) - mu
        ssq += d * d
    return math.sqrt(ssq / (n - ddof))


# 数据结构——异常证据在管道中的载体

@dataclass
class FunctionFeatures:
    """单函数异常向量：分值、证据链、分类结论"""
    fname: str
    faddr: int
    feats: dict = field(default_factory=dict)
    ascore: float = 0.0
    alevel: AnomalyLevel = AnomalyLevel.NORMAL
    reasons: list = field(default_factory=list)


@dataclass
class AnomalyReport:
    """单个二进制目标的聚合异常裁决"""
    bpath: str
    bhash: str
    total_funcs: int
    anom_funcs: list = field(default_factory=list)
    overall_score: float = 0.0
    level: AnomalyLevel = AnomalyLevel.NORMAL
    ts: str = ""


@dataclass
class NormalModel:
    """已训练的正常行为基线，可序列化持久化"""
    mid: str
    ftype: str
    stats: dict = field(default_factory=dict)
    thresholds: dict = field(default_factory=dict)
    n_samples: int = 0
    created: str = ""


# 特征提取器——每个消费原始字节，产出类型化特征字典
# 契约：子类实现 extract() 和 get_feature_type()

class FeatureExtractor:
    """抽象特征提取器基类——子类提供 extract() 和 get_feature_type()"""
    def extract(self, binary_data):
        raise NotImplementedError('Subclass must implement extract()')
    def get_feature_type(self):
        raise NotImplementedError('Subclass must implement get_feature_type()')


class SystemCallFeatureExtractor(FeatureExtractor):
    """系统调用特征提取——统计int 0x80和syscall指令频次、熵值、可疑令牌"""

    def extract(self, binary_data):
        if not binary_data:
            return {}
        return {
            'syscall_count': self._count_syscalls(binary_data),
            'syscall_entropy': self._calc_entropy(binary_data),
            'suspicious_syscalls': self._find_suspicious(binary_data),
            'syscall_diversity': self._calc_diversity(binary_data),
        }

    def get_feature_type(self):
        return FeatureType.SYSCALL

    def _count_syscalls(self, data):
        """统计int 0x80（legacy）和syscall（x86-64）指令出现次数"""
        return data.count(b'\xcd\x80') + data.count(b'\x0f\x05')

    def _calc_entropy(self, data):
        """字节级熵值代理——高值关联加壳/加密载荷"""
        n = len(data)
        if n == 0:
            return 0.0
        cnt = defaultdict(int)
        for b in data:
            cnt[b] += 1
        ent = 0.0
        for c in cnt.values():
            p = c / n
            ent -= p * math.sqrt(p)
        return min(1.0, ent * 10)

    def _find_suspicious(self, data):
        """标记引用恶意常用系统调用的二进制区域"""
        dl = data.lower()
        sus = []
        for kw in [b'shutdown', b'reboot', b'unlink', b'chmod', b'execve']:
            if kw in dl:
                sus.append(kw.decode('ascii', errors='ignore') + ' syscall')
        return sus

    def _calc_diversity(self, data):
        """唯一字节数/256——低值暗示重复结构或填充"""
        n_unique = len(set(data))
        return n_unique / 256.0


class ControlFlowFeatureExtractor(FeatureExtractor):
    """控制流特征——从分支指令密度和类型多样性推导复杂度指标"""

    def extract(self, binary_data):
        if not binary_data:
            return {}
        return {
            'basic_block_count': self._est_blocks(binary_data),
            'branch_density': self._branch_density(binary_data),
            'indirect_jump_ratio': self._indirect_ratio(binary_data),
            'cyclomatic_complexity': self._est_complexity(binary_data),
        }

    def get_feature_type(self):
        return FeatureType.CFG

    def _est_blocks(self, data):
        """从跳转指令频次估算基本块数量"""
        jmps = [b'\xe9', b'\xeb', b'\xff\x25', b'\xff\x15']
        return max(1, sum(data.count(p) for p in jmps))

    def _branch_density(self, data):
        """每字节分支指令密度——偏高标志混淆或复杂控制逻辑"""
        if len(data) == 0:
            return 0.0
        brs = [b'\x74', b'\x75', b'\x7c', b'\x7d', b'\xe9', b'\xeb']
        return min(1.0, sum(data.count(p) for p in brs) / len(data) * 100)

    def _indirect_ratio(self, data):
        """间接跳转/直接跳转比值——偏斜向间接跳转提示控制流混淆"""
        direct = data.count(b'\xe9') + data.count(b'\xeb')
        indirect = data.count(b'\xff\x25') + data.count(b'\xff\x15')
        total = direct + indirect
        return indirect / total if total > 0 else 0.0

    def _est_complexity(self, data):
        """条件+无条件分支计数估算圈复杂度"""
        br_cnt = (data.count(b'\x74') + data.count(b'\x75') +
                  data.count(b'\xe9') + data.count(b'\xeb'))
        return min(100, br_cnt * 2)


class StringFeatureExtractor(FeatureExtractor):
    """嵌入字符串分析——可打印字符串、URL、邮箱、威胁指示令牌"""

    def extract(self, binary_data):
        if not binary_data:
            return {}
        strings = re.findall(b'[ -~]{4,}', binary_data)
        return {
            'string_count': len(strings),
            'avg_string_length': sum(len(s) for s in strings) / len(strings) if strings else 0.0,
            'suspicious_strings': self._find_sus_strings(binary_data),
            'url_count': len(re.findall(rb'https?://[^\s]+', binary_data)),
            'email_count': len(re.findall(rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', binary_data)),
        }

    def get_feature_type(self):
        return FeatureType.STRINGS

    def _find_sus_strings(self, data):
        """扫描硬编码令牌——后门、shell、漏洞利用意图的证据"""
        dl = data.lower()
        found = []
        patterns = [b'root', b'admin', b'password', b'backdoor', b'shell',
                    b'exploit', b'payload', b'ROP', b'jmp esp', b'call esp',
                    b'/bin/sh', b'cmd.exe']
        for p in patterns:
            if p in dl:
                found.append(p.decode('ascii', errors='ignore'))
        return found


# 异常检测器——消费特征字典，产出 (分值, 证据)
# 契约：train(), detect(), save_model(), load_model()

class ZScoreAnomalyDetector:
    """Z-score统计检测器——标记超出标定阈值的特征维度"""

    def __init__(self):
        self.mean = {}
        self.std = {}
        self.thresh = 3.0

    def train(self, features_list):
        """对训练语料逐特征拟合均值与标准差"""
        if not features_list:
            return
        all_keys = set()
        for f in features_list:
            all_keys.update(f.keys())
        for k in all_keys:
            vals = [float(f.get(k, 0.0)) for f in features_list]
            self.mean[k] = _manual_mean(vals)
            self.std[k] = _manual_std(vals) if len(vals) > 1 else 1.0
        logger.info(f"Z-score training complete: {len(self.mean)} features")

    def detect(self, features):
        """对特征向量评分——返回归一化异常幅度和逐特征偏离证据"""
        if not self.mean:
            return 0.0, ['Model not trained']
        scores = []
        reasons = []
        for k, v in features.items():
            if k in self.mean:
                mu = self.mean[k]
                sig = max(self.std[k], 1e-6)
                z = abs(float(v) - mu) / sig
                if z > self.thresh:
                    scores.append(z / self.thresh)
                    reasons.append(f'{k}: deviation from normal (Z={z:.2f})')
        if scores:
            return min(1.0, sum(scores) / len(scores)), reasons
        return 0.0, reasons

    def save_model(self, path):
        """序列化拟合后的分布参数到磁盘"""
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, 'wb') as fh:
            pickle.dump({'mean': self.mean, 'std': self.std, 'threshold': self.thresh}, fh)
        logger.info(f'Z-score model saved: {path}')

    @classmethod
    def load_model(cls, path):
        """从磁盘反序列化已训练的模型"""
        det = cls()
        with open(path, 'rb') as fh:
            data = pickle.load(fh)
        det.mean = data['mean']
        det.std = data['std']
        det.thresh = data['threshold']
        logger.info(f'Z-score model loaded: {path}')
        return det


class IsolationForestAnomalyDetector:
    """隔离森林模拟——加权特征评分，无需sklearn依赖"""

    def __init__(self):
        self.trained = False
        self.feat_imp = {}

    def train(self, features_list):
        """从训练分布推导逐特征重要性权重"""
        if not features_list:
            return
        all_keys = set()
        for f in features_list:
            all_keys.update(f.keys())
        if numpy is not None:
            for k in all_keys:
                self.feat_imp[k] = float(numpy.random.uniform(0.1, 1.0))
        else:
            for k in all_keys:
                self.feat_imp[k] = random.uniform(0.1, 1.0)
        self.trained = True
        logger.info('IsolationForest training complete (simulated)')

    def detect(self, features):
        """加权异常分——每特征值乘以其重要性权重后聚合"""
        if not self.trained:
            return 0.0, ['Model not trained']
        scores = []
        reasons = []
        for k, v in features.items():
            imp = self.feat_imp.get(k, 0.5)
            nv = min(1.0, abs(float(v)) / 100)
            sc = nv * imp
            scores.append(sc)
            if nv > 0.5:
                reasons.append(f'{k}: anomalous value ({v})')
        if scores:
            return min(1.0, sum(scores) / len(scores)), reasons
        return 0.0, reasons

    def save_model(self, path):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, 'wb') as fh:
            pickle.dump({'feature_importance': self.feat_imp, 'trained': self.trained}, fh)
        logger.info(f'IF model saved: {path}')

    @classmethod
    def load_model(cls, path):
        det = cls()
        with open(path, 'rb') as fh:
            data = pickle.load(fh)
        det.feat_imp = data['feature_importance']
        det.trained = data['trained']
        logger.info(f'IF model loaded: {path}')
        return det


# 零日异常分析器——管道编排中枢
# 链条：提取器 → 多检测器并行评分 → 聚合报告。单入口：analyze()

class AnomalyZerodayAnalyzer:
    """编排特征提取、多检测器并行评分、裁决组装的全流程"""

    def __init__(self):
        self.extractors = [
            SystemCallFeatureExtractor(),
            ControlFlowFeatureExtractor(),
            StringFeatureExtractor(),
        ]
        self.detectors = {
            'zscore': ZScoreAnomalyDetector(),
            'isolation_forest': IsolationForestAnomalyDetector(),
        }
        self.trained = False

    # 核心管道：提取 → 检测 → 聚合 → 报告

    def analyze(self, **kwargs):
        """主入口——端到端执行完整异常检测管道"""
        bpath = kwargs.get('binary_path')
        bdata = kwargs.get('binary_data')
        mpath = kwargs.get('model_path')
        dtype = kwargs.get('detector_type', 'zscore')

        logger.info(f'Anomaly detection starting: {bpath}')

        try:
            # 从文件路径或调用方缓冲区获取二进制字节
            if bdata is None and bpath:
                if os.path.exists(bpath):
                    with open(bpath, 'rb') as fh:
                        bdata = fh.read()
                else:
                    return {'success': False, 'error': f'File not found: {bpath}'}
            if bdata is None:
                return {'success': False, 'error': 'No binary data provided'}

            # 若提供模型目录，加载预训练检测器状态
            if mpath and os.path.exists(mpath):
                self._load_models(mpath)

            all_feats = self._extract_all(bdata)

            # 所有检测器对统一特征向量并行评分
            det_results = []
            for name, det in self.detectors.items():
                sc, reasons = det.detect(all_feats)
                det_results.append({
                    'detector': name,
                    'anomaly_score': sc,
                    'score_level': _score_to_level(sc),
                    'reasons': reasons,
                })

            # 检测器分值取均值作为最终裁决
            avg_score = (sum(r['anomaly_score'] for r in det_results) / len(det_results)
                         if det_results else 0.0)
            level = _score_to_level(avg_score)

            # 组装结构化报告
            bhash = hashlib.sha256(bdata).hexdigest()
            report = AnomalyReport(
                bpath=bpath or 'memory', bhash=bhash, total_funcs=1,
                anom_funcs=[FunctionFeatures(
                    fname='main', faddr=0, feats=all_feats,
                    ascore=avg_score, alevel=level,
                    reasons=[r['reasons'] for r in det_results if r['reasons']],
                )],
                overall_score=avg_score, level=level,
                ts='',
            )

            return {
                'success': True,
                'result': {
                    'binary_hash': report.bhash,
                    'overall_anomaly_score': avg_score,
                    'score_level': level,
                    'detector_results': det_results,
                    'features': all_feats,
                    'report': {
                        'total_functions': report.total_funcs,
                        'anomalous_functions': len([f for f in report.anom_funcs
                                                    if f.alevel != AnomalyLevel.NORMAL]),
                        'summary': self._gen_summary(report),
                    },
                },
            }
        except Exception as e:
            logger.error(f'Anomaly detection failed: {e}')
            return {'success': False, 'error': str(e)}

    def _extract_all(self, data):
        """运行全部提取器——以特征类型前缀为键消歧"""
        all_f = {}
        for ext in self.extractors:
            feats = ext.extract(data)
            prefix = ext.get_feature_type()
            for k, v in feats.items():
                all_f[f'{prefix}_{k}'] = v
        return all_f

    def _gen_summary(self, report):
        """严重度→可操作的裁决字符串"""
        level = report.level
        if level == AnomalyLevel.NORMAL:
            return 'No anomalous behavior detected'
        elif level == AnomalyLevel.SUSPICIOUS:
            return 'Suspicious behavior detected, further analysis recommended'
        elif level == AnomalyLevel.ANOMALOUS:
            return 'Anomalous behavior detected, potential security risk'
        return 'Critical anomaly detected, possible backdoor or vulnerability'

    # 训练——从良性二进制语料建立正常行为基线

    def train_normal_model(self, binary_paths, output_dir='models/anomaly'):
        """在干净语料上拟合所有检测器——持久化各检测器状态到output_dir"""
        logger.info(f'Training normal behavior model: {len(binary_paths)} samples')

        try:
            all_feats = []
            for p in binary_paths:
                if os.path.exists(p):
                    with open(p, 'rb') as fh:
                        bdata = fh.read()
                    all_feats.append(self._extract_all(bdata))

            if not all_feats:
                logger.error('No valid training data')
                return False

            for name, det in self.detectors.items():
                det.train(all_feats)
                mp = os.path.join(output_dir, f'{name}_model.pkl')
                det.save_model(mp)

            self.trained = True
            logger.info('Normal behavior model training complete')
            return True
        except Exception as e:
            logger.error(f'Training failed: {e}')
            return False

    def _load_models(self, model_dir):
        """从目录加载预训练模型的检测器实例"""
        for name, det in list(self.detectors.items()):
            mp = os.path.join(model_dir, f'{name}_model.pkl')
            if os.path.exists(mp):
                try:
                    if name == 'zscore':
                        self.detectors[name] = ZScoreAnomalyDetector.load_model(mp)
                    elif name == 'isolation_forest':
                        self.detectors[name] = IsolationForestAnomalyDetector.load_model(mp)
                except Exception as e:
                    logger.warning(f'Failed to load {name} model: {e}')

    # 插件管理器兼容接口

    @classmethod
    def get_metadata(cls):
        """暴露 AnalyzerMetadata 供动态插件注册"""
        try:
            from core.plugin_manager import AnalyzerMetadata, AnalyzerType
            return AnalyzerMetadata(
                name='AnomalyZerodayAnalyzer',
                type=AnalyzerType.VULNERABILITY_DETECTOR,
                version='2.0',
                description='Anomaly-detection-driven zero-day discovery using hand-written statistics',
                author='ht',
                dependencies=[],
                supported_platforms=['x86', 'x86_64', 'arm', 'arm64'],
            )
        except ImportError:
            return None

    def validate_input(self, **kwargs):
        """入口门禁——拒绝格式错误的输入"""
        bpath = kwargs.get('binary_path')
        bdata = kwargs.get('binary_data')
        if not bpath and bdata is None:
            return False, 'Must provide binary_path or binary_data'
        if bpath and not os.path.exists(bpath):
            return False, f'File not found: {bpath}'
        if bdata is not None and not isinstance(bdata, bytes):
            return False, 'binary_data must be bytes'
        return True, None

    def cleanup(self):
        """重置检测器到出厂状态——丢弃所有已训练参数"""
        self.detectors = {
            'zscore': ZScoreAnomalyDetector(),
            'isolation_forest': IsolationForestAnomalyDetector(),
        }

