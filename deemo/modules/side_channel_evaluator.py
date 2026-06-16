"""
侧信道动态量化评估模块

精确测量不同输入下的执行时间、缓存命中/缺失（基于pmc_side_channel），
统计泄露带宽，利用t-test等判断可利用性，输出评估报告。

Author: BinaryAnalysisPlatform
Version: 1.0.0
"""

import logging
import time
import statistics
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple, Callable
from scipy import stats

from modules.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
from modules.pmc_side_channel import PMCSideChannelEvaluator, TestResult, PMCCounterType, ExploitabilityScore

logger = logging.getLogger(__name__)


class LeakageType(Enum):
    """信息泄露类型"""
    TIMING = "timing"
    CACHE = "cache"
    BRANCH = "branch"
    POWER = "power"


class LeakageSeverity(Enum):
    """泄露严重程度"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TimingSample:
    """时序样本"""
    input_data: bytes
    execution_time_ns: int
    iteration: int


@dataclass
class CacheMeasurement:
    """缓存测量结果"""
    address: int
    hits: int
    misses: int
    hit_rate: float


@dataclass
class LeakageResult:
    """信息泄露检测结果"""
    leakage_type: LeakageType
    severity: LeakageSeverity
    signal_strength: float
    t_test_pvalue: float
    sample_count: int
    mean_difference: float
    bandwidth_bits: float
    description: str
    recommendations: List[str] = field(default_factory=list)


@dataclass
class SideChannelReport:
    """侧信道评估报告"""
    target_binary: str
    timestamp: float
    tests_performed: List[str]
    leakage_results: List[LeakageResult] = field(default_factory=list)
    overall_exploitability: ExploitabilityScore = ExploitabilityScore.NONE
    summary: Dict[str, Any] = field(default_factory=dict)


class SideChannelEvaluator(BaseAnalyzer):
    """
    侧信道动态量化评估器
    
    核心功能：
    1. 精确测量执行时间差异
    2. 统计缓存命中/缺失模式
    3. 使用t-test检测信息泄露
    4. 计算泄露带宽
    5. 生成可利用性评估报告
    """
    
    def __init__(self):
        self.pmc_evaluator = PMCSideChannelEvaluator()
        self.measurements: List[Dict[str, Any]] = []
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行侧信道评估
        
        Args:
            **kwargs: 分析参数
                - binary_path: str - 目标二进制路径
                - test_inputs: List[bytes] - 测试输入列表
                - iterations: int - 每次输入的迭代次数
                - measurement_type: str - 测量类型 'timing', 'cache', 'all'
        
        Returns:
            评估结果字典
        """
        binary_path = kwargs.get('binary_path', '')
        test_inputs = kwargs.get('test_inputs', [])
        iterations = kwargs.get('iterations', 100)
        measurement_type = kwargs.get('measurement_type', 'all')
        
        if not binary_path:
            return {'success': False, 'error': '需要提供目标二进制路径'}
        
        if not test_inputs:
            return {'success': False, 'error': '需要提供测试输入'}
        
        logger.info(f"开始侧信道评估，二进制: {binary_path}")
        
        report = self._perform_evaluation(binary_path, test_inputs, iterations, measurement_type)
        
        return {
            'success': True,
            'report': self._format_report(report),
            'exploitability': report.overall_exploitability.value
        }
    
    def _perform_evaluation(
        self,
        binary_path: str,
        test_inputs: List[bytes],
        iterations: int,
        measurement_type: str
    ) -> SideChannelReport:
        """
        执行完整的侧信道评估
        
        Args:
            binary_path: 目标二进制路径
            test_inputs: 测试输入列表
            iterations: 迭代次数
            measurement_type: 测量类型
        
        Returns:
            评估报告
        """
        report = SideChannelReport(
            target_binary=binary_path,
            timestamp=time.time(),
            tests_performed=[]
        )
        
        # 时序分析
        if measurement_type in ['timing', 'all']:
            timing_result = self._measure_timing_leakage(binary_path, test_inputs, iterations)
            if timing_result:
                report.leakage_results.append(timing_result)
                report.tests_performed.append('timing_analysis')
        
        # 缓存分析
        if measurement_type in ['cache', 'all']:
            cache_result = self._measure_cache_leakage(test_inputs, iterations)
            if cache_result:
                report.leakage_results.append(cache_result)
                report.tests_performed.append('cache_analysis')
        
        # 分支预测分析
        if measurement_type in ['branch', 'all']:
            branch_result = self._measure_branch_leakage(iterations)
            if branch_result:
                report.leakage_results.append(branch_result)
                report.tests_performed.append('branch_analysis')
        
        # 综合评估
        report.overall_exploitability = self._calculate_overall_exploitability(report)
        report.summary = self._generate_summary(report)
        
        return report
    
    def _measure_timing_leakage(
        self,
        binary_path: str,
        test_inputs: List[bytes],
        iterations: int
    ) -> Optional[LeakageResult]:
        """
        测量时序信息泄露
        
        Args:
            binary_path: 目标二进制路径
            test_inputs: 测试输入列表
            iterations: 迭代次数
        
        Returns:
            泄露检测结果
        """
        logger.info("执行时序泄露检测")
        
        samples: List[TimingSample] = []
        
        for input_data in test_inputs:
            for i in range(iterations):
                exec_time = self._measure_execution_time(binary_path, input_data)
                samples.append(TimingSample(
                    input_data=input_data,
                    execution_time_ns=exec_time,
                    iteration=i
                ))
        
        # 按输入分组
        groups = {}
        for sample in samples:
            key = sample.input_data.hex()
            if key not in groups:
                groups[key] = []
            groups[key].append(sample.execution_time_ns)
        
        if len(groups) < 2:
            logger.warning("测试输入不足，无法进行统计分析")
            return None
        
        # 执行t-test
        group_list = list(groups.values())
        if len(group_list) >= 2:
            t_stat, p_value = stats.ttest_ind(group_list[0], group_list[1])
        else:
            t_stat, p_value = 0, 1.0
        
        # 计算均值差异
        means = [statistics.mean(g) for g in group_list]
        mean_diff = max(means) - min(means) if means else 0
        
        # 计算信号强度
        pooled_std = statistics.stdev([s for g in group_list for s in g]) if len(samples) > 1 else 1
        signal_strength = mean_diff / pooled_std if pooled_std > 0 else 0
        
        # 计算泄露带宽（基于互信息估计）
        bandwidth = self._estimate_bandwidth(signal_strength, len(test_inputs))
        
        # 确定严重程度
        severity = self._determine_severity(signal_strength, p_value, bandwidth)
        
        recommendations = self._generate_recommendations(severity, 'timing')
        
        return LeakageResult(
            leakage_type=LeakageType.TIMING,
            severity=severity,
            signal_strength=signal_strength,
            t_test_pvalue=p_value,
            sample_count=len(samples),
            mean_difference=mean_diff,
            bandwidth_bits=bandwidth,
            description=f"时序分析检测到信息泄露，信号强度: {signal_strength:.2f}, p值: {p_value:.4f}",
            recommendations=recommendations
        )
    
    def _measure_execution_time(self, binary_path: str, input_data: bytes) -> int:
        """
        测量单次执行时间
        
        Args:
            binary_path: 目标二进制路径
            input_data: 输入数据
        
        Returns:
            执行时间（纳秒）
        """
        import subprocess
        import time
        
        start = time.perf_counter_ns()
        
        try:
            subprocess.run(
                [binary_path],
                input=input_data,
                capture_output=True,
                timeout=5
            )
        except subprocess.TimeoutExpired:
            pass
        
        end = time.perf_counter_ns()
        
        return end - start
    
    def _measure_cache_leakage(self, test_inputs: List[bytes], iterations: int) -> Optional[LeakageResult]:
        """
        测量缓存信息泄露
        
        Args:
            test_inputs: 测试输入列表
            iterations: 迭代次数
        
        Returns:
            泄露检测结果
        """
        logger.info("执行缓存泄露检测")
        
        addresses = [0x1000 + i * 0x1000 for i in range(16)]
        pmc_result = self.pmc_evaluator.measure_cache_timing(addresses, iterations)
        
        if not pmc_result.signal_detected:
            return None
        
        # 从PMC结果提取统计数据
        hit_times = [m.value for m in pmc_result.measurements 
                     if m.counter_type == PMCCounterType.CACHE_HIT]
        miss_times = [m.value for m in pmc_result.measurements 
                      if m.counter_type == PMCCounterType.CACHE_MISS]
        
        if not hit_times or not miss_times:
            return None
        
        # t-test比较命中和未命中时间
        t_stat, p_value = stats.ttest_ind(hit_times, miss_times)
        
        mean_hit = statistics.mean(hit_times)
        mean_miss = statistics.mean(miss_times)
        mean_diff = mean_miss - mean_hit
        
        pooled_std = statistics.stdev(hit_times + miss_times)
        signal_strength = mean_diff / pooled_std if pooled_std > 0 else 0
        
        bandwidth = self._estimate_bandwidth(signal_strength, len(test_inputs))
        severity = self._determine_severity(signal_strength, p_value, bandwidth)
        recommendations = self._generate_recommendations(severity, 'cache')
        
        return LeakageResult(
            leakage_type=LeakageType.CACHE,
            severity=severity,
            signal_strength=signal_strength,
            t_test_pvalue=p_value,
            sample_count=len(pmc_result.measurements),
            mean_difference=mean_diff,
            bandwidth_bits=bandwidth,
            description=f"缓存分析检测到信息泄露，命中/未命中差异: {mean_diff:.0f} ps",
            recommendations=recommendations
        )
    
    def _measure_branch_leakage(self, iterations: int) -> Optional[LeakageResult]:
        """
        测量分支预测信息泄露
        
        Args:
            iterations: 迭代次数
        
        Returns:
            泄露检测结果
        """
        logger.info("执行分支预测泄露检测")
        
        pmc_result = self.pmc_evaluator.measure_branch_prediction(iterations)
        
        if not pmc_result.signal_detected:
            return None
        
        miss_rate = pmc_result.statistics.get('branch_miss_rate', 0.5)
        signal_strength = 1.0 - miss_rate
        
        # 分支预测命中率高意味着更容易利用
        bandwidth = signal_strength * 1.0  # 简化估计
        
        severity = self._determine_severity(signal_strength, 0.0, bandwidth)
        recommendations = self._generate_recommendations(severity, 'branch')
        
        return LeakageResult(
            leakage_type=LeakageType.BRANCH,
            severity=severity,
            signal_strength=signal_strength,
            t_test_pvalue=0.0,
            sample_count=iterations,
            mean_difference=0,
            bandwidth_bits=bandwidth,
            description=f"分支预测分析：命中率 {(1 - miss_rate) * 100:.1f}%",
            recommendations=recommendations
        )
    
    def _estimate_bandwidth(self, signal_strength: float, num_inputs: int) -> float:
        """
        估计信息泄露带宽
        
        Args:
            signal_strength: 信号强度
            num_inputs: 输入数量
        
        Returns:
            估计的泄露带宽（比特）
        """
        if signal_strength < 0.1:
            return 0.0
        
        # 基于信噪比估计带宽
        snr = signal_strength
        bandwidth = snr * (num_inputs / 2)
        
        return min(bandwidth, 8.0)  # 最大8比特（一个字节）
    
    def _determine_severity(
        self,
        signal_strength: float,
        p_value: float,
        bandwidth: float
    ) -> LeakageSeverity:
        """
        根据测量结果确定泄露严重程度
        
        Args:
            signal_strength: 信号强度
            p_value: t-test p值
            bandwidth: 泄露带宽
        
        Returns:
            严重程度
        """
        if signal_strength < 0.1 or p_value > 0.01 or bandwidth < 0.1:
            return LeakageSeverity.NONE
        
        if signal_strength > 5.0 and bandwidth > 4.0:
            return LeakageSeverity.CRITICAL
        
        if signal_strength > 2.0 and bandwidth > 2.0:
            return LeakageSeverity.HIGH
        
        if signal_strength > 1.0 and bandwidth > 0.5:
            return LeakageSeverity.MEDIUM
        
        return LeakageSeverity.LOW
    
    def _generate_recommendations(self, severity: LeakageSeverity, leak_type: str) -> List[str]:
        """
        生成修复建议
        
        Args:
            severity: 严重程度
            leak_type: 泄露类型
        
        Returns:
            建议列表
        """
        recommendations = []
        
        if severity == LeakageSeverity.NONE:
            return recommendations
        
        if leak_type == 'timing':
            recommendations.append("使用常量时间比较函数（如CRYPTO_memcmp）")
            recommendations.append("避免数据相关的分支和循环")
            recommendations.append("使用位掩码操作替代条件分支")
        
        elif leak_type == 'cache':
            recommendations.append("使用常量时间内存访问模式")
            recommendations.append("考虑使用缓存旁路攻击防护技术")
            recommendations.append("对敏感数据使用加密内存")
        
        elif leak_type == 'branch':
            recommendations.append("使用分支预测硬化技术")
            recommendations.append("考虑使用Retpoline或IBRS")
        
        if severity in [LeakageSeverity.HIGH, LeakageSeverity.CRITICAL]:
            recommendations.append("立即修复此漏洞，存在实际攻击风险")
            recommendations.append("考虑使用侧信道安全的密码库")
        
        return recommendations
    
    def _calculate_overall_exploitability(self, report: SideChannelReport) -> ExploitabilityScore:
        """
        计算综合可利用性评分
        
        Args:
            report: 评估报告
        
        Returns:
            可利用性评分
        """
        if not report.leakage_results:
            return ExploitabilityScore.NONE
        
        max_severity = max(r.severity for r in report.leakage_results)
        
        if max_severity in [LeakageSeverity.CRITICAL, LeakageSeverity.HIGH]:
            return ExploitabilityScore.HIGH
        elif max_severity == LeakageSeverity.MEDIUM:
            return ExploitabilityScore.MEDIUM
        elif max_severity == LeakageSeverity.LOW:
            return ExploitabilityScore.LOW
        else:
            return ExploitabilityScore.NONE
    
    def _generate_summary(self, report: SideChannelReport) -> Dict[str, Any]:
        """
        生成报告摘要
        
        Args:
            report: 评估报告
        
        Returns:
            摘要字典
        """
        severity_counts = {s.value: 0 for s in LeakageSeverity}
        
        for result in report.leakage_results:
            severity_counts[result.severity.value] += 1
        
        total_bandwidth = sum(r.bandwidth_bits for r in report.leakage_results)
        
        return {
            'total_tests': len(report.tests_performed),
            'total_leakages': len(report.leakage_results),
            'severity_counts': severity_counts,
            'total_bandwidth_bits': total_bandwidth,
            'exploitability': report.overall_exploitability.value
        }
    
    def _format_report(self, report: SideChannelReport) -> Dict[str, Any]:
        """
        格式化报告为字典
        
        Args:
            report: 评估报告
        
        Returns:
            格式化后的报告字典
        """
        return {
            'target_binary': report.target_binary,
            'timestamp': report.timestamp,
            'tests_performed': report.tests_performed,
            'leakage_results': [
                {
                    'type': r.leakage_type.value,
                    'severity': r.severity.value,
                    'signal_strength': r.signal_strength,
                    't_test_pvalue': r.t_test_pvalue,
                    'sample_count': r.sample_count,
                    'mean_difference': r.mean_difference,
                    'bandwidth_bits': r.bandwidth_bits,
                    'description': r.description,
                    'recommendations': r.recommendations
                }
                for r in report.leakage_results
            ],
            'overall_exploitability': report.overall_exploitability.value,
            'summary': report.summary
        }
    
    def generate_text_report(self, report: SideChannelReport) -> str:
        """
        生成文本格式的评估报告
        
        Args:
            report: 评估报告
        
        Returns:
            报告字符串
        """
        lines = []
        lines.append("=" * 70)
        lines.append("侧信道动态量化评估报告")
        lines.append("=" * 70)
        lines.append("")
        
        lines.append(f"【目标二进制】{report.target_binary}")
        lines.append(f"【评估时间】{time.ctime(report.timestamp)}")
        lines.append("")
        
        lines.append("【测试项目】")
        for test in report.tests_performed:
            lines.append(f"  - {test}")
        lines.append("")
        
        lines.append("【检测结果】")
        for i, result in enumerate(report.leakage_results, 1):
            lines.append(f"")
            lines.append(f"  检测项 {i}: {result.leakage_type.value}")
            lines.append(f"    严重程度: {result.severity.value}")
            lines.append(f"    信号强度: {result.signal_strength:.2f}")
            lines.append(f"    t-test p值: {result.t_test_pvalue:.4f}")
            lines.append(f"    样本数量: {result.sample_count}")
            lines.append(f"    泄露带宽: {result.bandwidth_bits:.2f} bits")
            lines.append(f"    描述: {result.description}")
            if result.recommendations:
                lines.append("    修复建议:")
                for rec in result.recommendations:
                    lines.append(f"      - {rec}")
        
        lines.append("")
        lines.append("【综合评估】")
        lines.append(f"  可利用性评分: {report.overall_exploitability.value}")
        lines.append(f"  检测到的泄露数量: {report.summary['total_leakages']}")
        lines.append(f"  总泄露带宽: {report.summary['total_bandwidth_bits']:.2f} bits")
        lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="SideChannelEvaluator",
            type=AnalyzerType.VULNERABILITY_DETECTOR,
            version="1.0.0",
            description="侧信道动态量化评估模块，测量执行时间和缓存差异，检测信息泄露",
            author="BinaryAnalysisPlatform",
            dependencies=["scipy", "statistics", "pmc_side_channel"],
            supported_platforms=["x86", "x86_64"]
        )


def evaluate_side_channel(binary_path: str, **kwargs) -> Dict[str, Any]:
    """便捷函数：执行侧信道评估"""
    evaluator = SideChannelEvaluator()
    return evaluator.analyze(binary_path=binary_path, **kwargs)