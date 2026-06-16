#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI辅助的符号执行路径优先级模块

功能：
1. 使用LLM评估路径语义
2. 为符号执行提供探索优先级
3. 缓解路径爆炸问题

数据流：
1. 输入：符号执行路径列表（包含路径约束、执行轨迹、覆盖的代码）
2. 处理：LLM评估每条路径的"漏洞可能性"和"探索价值"
3. 输出：排序后的路径优先级列表

与其他模块的交互：
- 接收符号执行引擎的路径列表
- 返回优先级排序后的路径供符号执行引擎使用
"""

import logging
import os
import json
import time
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

# 尝试导入可选依赖
OPENAI_AVAILABLE = False

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    logger.warning("OpenAI SDK未安装，将使用模拟模式")


class PathPriority(Enum):
    """路径优先级枚举"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    IGNORE = "ignore"


class PathFeature(Enum):
    """路径特征枚举"""
    MEMORY_ACCESS = "memory_access"
    CONTROL_FLOW = "control_flow"
    SYSTEM_CALL = "system_call"
    NETWORK_OPERATION = "network_operation"
    CRYPTO_OPERATION = "crypto_operation"
    USER_INPUT = "user_input"
    PRIVILEGE_CHANGE = "privilege_change"


@dataclass
class SymbolicPath:
    """符号执行路径"""
    path_id: str
    constraints: List[str]
    instructions: List[str]
    registers: Dict[str, str]
    memory_access: List[Dict[str, Any]]
    reached_functions: List[str]
    depth: int
    coverage_ratio: float
    features: List[PathFeature] = field(default_factory=list)
    priority_score: float = 0.0
    priority_level: PathPriority = PathPriority.MEDIUM
    vulnerability_likelihood: float = 0.0
    exploration_value: float = 0.0


@dataclass
class PathAnalysisResult:
    """路径分析结果"""
    path_id: str
    priority_score: float
    priority_level: PathPriority
    vulnerability_likelihood: float
    exploration_value: float
    key_features: List[str]
    reasoning: str
    suggested_actions: List[str]


@dataclass
class PrioritizationResult:
    """优先级排序结果"""
    paths: List[PathAnalysisResult]
    total_paths: int
    prioritized_paths: int
    analysis_time: float
    summary: Dict[str, Any] = field(default_factory=dict)


class PathAnalyzer(ABC):
    """路径分析器抽象基类"""

    @abstractmethod
    def analyze_path(self, path: SymbolicPath) -> PathAnalysisResult:
        """
        分析单条路径
        
        Args:
            path: 符号执行路径
        
        Returns:
            路径分析结果
        """
        pass

    @abstractmethod
    def batch_analyze(self, paths: List[SymbolicPath]) -> List[PathAnalysisResult]:
        """
        批量分析路径
        
        Args:
            paths: 路径列表
        
        Returns:
            路径分析结果列表
        """
        pass


class LLMPathAnalyzer(PathAnalyzer):
    """基于LLM的路径分析器"""

    def __init__(self, api_key: str = None, model: str = "gpt-4o-mini"):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.model = model
        self._validate_api_key()

    def _validate_api_key(self):
        """验证API密钥"""
        if not self.api_key:
            logger.warning("OpenAI API密钥未设置，将使用模拟模式")
            self.use_mock = True
        else:
            self.use_mock = False
            openai.api_key = self.api_key

    def analyze_path(self, path: SymbolicPath) -> PathAnalysisResult:
        """分析单条路径"""
        if self.use_mock:
            return self._mock_analyze(path)

        try:
            path_context = self._build_path_context(path)
            
            prompt = f"""
            你是一名资深的二进制安全分析专家。请分析以下符号执行路径的安全性和探索价值。
            
            路径信息：
            {path_context}
            
            请评估：
            1. 该路径存在安全漏洞的可能性（0-100分）
            2. 该路径的探索价值（0-100分，考虑代码覆盖率、新颖性、潜在危险程度）
            3. 识别关键特征（内存访问、控制流、系统调用等）
            4. 给出优先级建议（CRITICAL/HIGH/MEDIUM/LOW/IGNORE）
            5. 提供简要推理和建议的下一步操作
            
            输出格式（JSON）：
            {{
                "priority_score": 数值,
                "priority_level": "CRITICAL/HIGH/MEDIUM/LOW/IGNORE",
                "vulnerability_likelihood": 0-100的数值,
                "exploration_value": 0-100的数值,
                "key_features": ["特征1", "特征2", ...],
                "reasoning": "推理说明",
                "suggested_actions": ["操作1", "操作2", ...]
            }}
            """

            response = openai.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是二进制安全分析专家，擅长评估符号执行路径的安全风险。"},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500,
                temperature=0.2
            )

            result = json.loads(response.choices[0].message.content.strip())
            return PathAnalysisResult(
                path_id=path.path_id,
                priority_score=result.get('priority_score', 50),
                priority_level=PathPriority(result.get('priority_level', 'MEDIUM')),
                vulnerability_likelihood=result.get('vulnerability_likelihood', 50),
                exploration_value=result.get('exploration_value', 50),
                key_features=result.get('key_features', []),
                reasoning=result.get('reasoning', ''),
                suggested_actions=result.get('suggested_actions', [])
            )

        except Exception as e:
            logger.error(f"LLM路径分析失败: {e}")
            return self._mock_analyze(path)

    def batch_analyze(self, paths: List[SymbolicPath]) -> List[PathAnalysisResult]:
        """批量分析路径"""
        results = []
        for path in paths:
            result = self.analyze_path(path)
            results.append(result)
        
        return results

    def _build_path_context(self, path: SymbolicPath) -> str:
        """构建路径上下文信息"""
        context = []
        
        context.append(f"路径ID: {path.path_id}")
        context.append(f"路径深度: {path.depth}")
        context.append(f"代码覆盖率: {path.coverage_ratio:.2%}")
        
        if path.constraints:
            context.append(f"\n约束条件 ({len(path.constraints)}):")
            for i, constraint in enumerate(path.constraints[:5], 1):
                context.append(f"  {i}. {constraint}")
        
        if path.reached_functions:
            context.append(f"\n到达的函数 ({len(path.reached_functions)}):")
            for func in path.reached_functions[:5]:
                context.append(f"  - {func}")
        
        if path.memory_access:
            context.append(f"\n内存访问操作 ({len(path.memory_access)}):")
            for access in path.memory_access[:5]:
                access_type = access.get('type', 'unknown')
                address = access.get('address', 'unknown')
                size = access.get('size', 0)
                context.append(f"  - {access_type} @ {hex(address) if isinstance(address, int) else address} (size: {size})")
        
        if path.features:
            context.append(f"\n路径特征: {[f.value for f in path.features]}")
        
        return "\n".join(context)

    def _mock_analyze(self, path: SymbolicPath) -> PathAnalysisResult:
        """模拟路径分析"""
        vulnerability_likelihood = 50
        exploration_value = 50
        key_features = []
        reasoning = ""
        
        # 基于特征计算分数
        has_dangerous_feature = False
        
        for feature in path.features:
            if feature == PathFeature.USER_INPUT:
                vulnerability_likelihood += 20
                key_features.append("用户输入处理")
                has_dangerous_feature = True
            elif feature == PathFeature.MEMORY_ACCESS:
                vulnerability_likelihood += 15
                key_features.append("内存访问")
                has_dangerous_feature = True
            elif feature == PathFeature.SYSTEM_CALL:
                exploration_value += 20
                key_features.append("系统调用")
            elif feature == PathFeature.PRIVILEGE_CHANGE:
                vulnerability_likelihood += 30
                exploration_value += 25
                key_features.append("权限变更")
                has_dangerous_feature = True
        
        # 基于约束条件
        for constraint in path.constraints:
            if '==' in constraint or '!=' in constraint:
                vulnerability_likelihood += 5
            if '>' in constraint or '<' in constraint:
                vulnerability_likelihood += 10
        
        # 基于覆盖率
        if path.coverage_ratio > 0.8:
            exploration_value += 15
        elif path.coverage_ratio < 0.2:
            exploration_value -= 10
        
        # 基于深度
        if path.depth > 50:
            exploration_value += 10
        
        # 基于到达的危险函数
        dangerous_functions = ['strcpy', 'strcat', 'sprintf', 'gets', 'system', 'exec']
        for func in path.reached_functions:
            if any(dangerous in func.lower() for dangerous in dangerous_functions):
                vulnerability_likelihood += 25
                key_features.append(f"调用危险函数: {func}")
                has_dangerous_feature = True
        
        # 计算优先级分数
        priority_score = (vulnerability_likelihood * 0.6 + exploration_value * 0.4) / 100
        
        # 确定优先级级别
        if priority_score >= 0.8:
            priority_level = PathPriority.CRITICAL
        elif priority_score >= 0.6:
            priority_level = PathPriority.HIGH
        elif priority_score >= 0.4:
            priority_level = PathPriority.MEDIUM
        elif priority_score >= 0.2:
            priority_level = PathPriority.LOW
        else:
            priority_level = PathPriority.IGNORE
        
        if has_dangerous_feature:
            reasoning = "路径包含潜在危险特征，建议优先探索"
        else:
            reasoning = "路径风险中等，按常规优先级处理"
        
        suggested_actions = []
        if priority_level in [PathPriority.CRITICAL, PathPriority.HIGH]:
            suggested_actions.append("优先探索此路径")
            suggested_actions.append("详细分析内存访问模式")
        if '用户输入' in key_features:
            suggested_actions.append("检查输入验证逻辑")
        
        return PathAnalysisResult(
            path_id=path.path_id,
            priority_score=priority_score,
            priority_level=priority_level,
            vulnerability_likelihood=min(100, vulnerability_likelihood),
            exploration_value=min(100, exploration_value),
            key_features=key_features,
            reasoning=reasoning,
            suggested_actions=suggested_actions
        )


class HeuristicPathAnalyzer(PathAnalyzer):
    """基于启发式规则的路径分析器"""

    def __init__(self):
        self.feature_weights = {
            PathFeature.USER_INPUT: 0.3,
            PathFeature.MEMORY_ACCESS: 0.25,
            PathFeature.SYSTEM_CALL: 0.15,
            PathFeature.NETWORK_OPERATION: 0.1,
            PathFeature.CRYPTO_OPERATION: 0.05,
            PathFeature.PRIVILEGE_CHANGE: 0.15
        }

    def analyze_path(self, path: SymbolicPath) -> PathAnalysisResult:
        """分析单条路径"""
        vulnerability_likelihood = self._calculate_vulnerability_likelihood(path)
        exploration_value = self._calculate_exploration_value(path)
        priority_score = (vulnerability_likelihood * 0.6 + exploration_value * 0.4) / 100
        
        priority_level = self._determine_priority_level(priority_score)
        key_features = self._extract_key_features(path)
        reasoning = self._generate_reasoning(path, key_features)
        suggested_actions = self._generate_actions(priority_level, key_features)
        
        return PathAnalysisResult(
            path_id=path.path_id,
            priority_score=priority_score,
            priority_level=priority_level,
            vulnerability_likelihood=vulnerability_likelihood,
            exploration_value=exploration_value,
            key_features=key_features,
            reasoning=reasoning,
            suggested_actions=suggested_actions
        )

    def batch_analyze(self, paths: List[SymbolicPath]) -> List[PathAnalysisResult]:
        """批量分析路径"""
        return [self.analyze_path(path) for path in paths]

    def _calculate_vulnerability_likelihood(self, path: SymbolicPath) -> float:
        """计算漏洞可能性"""
        score = 50
        
        # 特征权重
        for feature in path.features:
            score += self.feature_weights.get(feature, 0) * 30
        
        # 危险函数检测
        dangerous_funcs = ['strcpy', 'strcat', 'sprintf', 'gets', 'system', 'exec', 'memcpy']
        for func in path.reached_functions:
            if any(df in func.lower() for df in dangerous_funcs):
                score += 15
        
        # 约束复杂度
        constraint_complexity = sum(1 for c in path.constraints if any(op in c for op in ['>', '<', '>=', '<=', '&&', '||']))
        score += min(constraint_complexity * 5, 20)
        
        return min(100, score)

    def _calculate_exploration_value(self, path: SymbolicPath) -> float:
        """计算探索价值"""
        score = 50
        
        # 覆盖率奖励
        score += path.coverage_ratio * 20
        
        # 深度奖励
        if path.depth > 30:
            score += 10
        if path.depth > 50:
            score += 10
        
        # 新颖函数奖励
        if len(path.reached_functions) > 3:
            score += len(path.reached_functions) * 2
        
        return min(100, score)

    def _determine_priority_level(self, score: float) -> PathPriority:
        """确定优先级级别"""
        if score >= 0.8:
            return PathPriority.CRITICAL
        elif score >= 0.6:
            return PathPriority.HIGH
        elif score >= 0.4:
            return PathPriority.MEDIUM
        elif score >= 0.2:
            return PathPriority.LOW
        else:
            return PathPriority.IGNORE

    def _extract_key_features(self, path: SymbolicPath) -> List[str]:
        """提取关键特征"""
        return [f.value for f in path.features]

    def _generate_reasoning(self, path: SymbolicPath, key_features: List[str]) -> str:
        """生成推理说明"""
        reasons = []
        
        if 'user_input' in key_features:
            reasons.append("处理用户输入")
        if 'memory_access' in key_features:
            reasons.append("涉及内存操作")
        if 'privilege_change' in key_features:
            reasons.append("权限变更")
        
        if reasons:
            return f"路径包含{', '.join(reasons)}等特征"
        return "路径特征较为普通"

    def _generate_actions(self, priority_level: PathPriority, key_features: List[str]) -> List[str]:
        """生成建议操作"""
        actions = []
        
        if priority_level in [PathPriority.CRITICAL, PathPriority.HIGH]:
            actions.append("优先探索")
        if 'memory_access' in key_features:
            actions.append("检查内存边界")
        if 'user_input' in key_features:
            actions.append("验证输入处理")
        
        return actions


class AIPathPrioritizer:
    """
    AI辅助的路径优先级管理器
    
    功能：
    1. 接收符号执行路径列表
    2. 使用AI评估每条路径的优先级
    3. 返回排序后的路径供符号执行引擎使用
    4. 支持多种分析策略（LLM、启发式、混合）
    """

    def __init__(self, strategy: str = "hybrid"):
        """
        初始化路径优先级管理器
        
        Args:
            strategy: 分析策略 ("llm", "heuristic", "hybrid")
        """
        self.strategy = strategy
        self.llm_analyzer = LLMPathAnalyzer()
        self.heuristic_analyzer = HeuristicPathAnalyzer()
        self.analyzed_paths: Dict[str, PathAnalysisResult] = {}
        
        logger.info(f"使用路径优先级策略: {strategy}")

    def prioritize(self, paths: List[SymbolicPath], top_k: Optional[int] = None) -> PrioritizationResult:
        """
        对路径进行优先级排序
        
        Args:
            paths: 符号执行路径列表
            top_k: 返回前k条路径（默认返回全部）
        
        Returns:
            PrioritizationResult
        """
        start_time = time.time()
        
        if not paths:
            return PrioritizationResult(
                paths=[],
                total_paths=0,
                prioritized_paths=0,
                analysis_time=0,
                summary={'error': '路径列表为空'}
            )
        
        logger.info(f"开始分析 {len(paths)} 条路径")
        
        # 分析路径
        if self.strategy == "llm":
            results = self.llm_analyzer.batch_analyze(paths)
        elif self.strategy == "heuristic":
            results = self.heuristic_analyzer.batch_analyze(paths)
        else:
            # 混合策略：使用启发式快速筛选，再用LLM分析高优先级路径
            heuristic_results = self.heuristic_analyzer.batch_analyze(paths)
            high_priority_paths = [p for p, r in zip(paths, heuristic_results) 
                                  if r.priority_level in [PathPriority.CRITICAL, PathPriority.HIGH]]
            
            if high_priority_paths:
                llm_results = self.llm_analyzer.batch_analyze(high_priority_paths)
                llm_result_map = {r.path_id: r for r in llm_results}
            else:
                llm_result_map = {}
            
            # 合并结果
            results = []
            for path, heuristic_result in zip(paths, heuristic_results):
                if path.path_id in llm_result_map:
                    results.append(llm_result_map[path.path_id])
                else:
                    results.append(heuristic_result)
        
        # 保存分析结果
        for result in results:
            self.analyzed_paths[result.path_id] = result
        
        # 按优先级排序
        results.sort(key=lambda r: r.priority_score, reverse=True)
        
        # 截取top_k
        if top_k:
            results = results[:top_k]
        
        analysis_time = time.time() - start_time
        
        # 生成摘要
        summary = self._generate_summary(results, len(paths))
        
        logger.info(f"路径优先级分析完成，耗时 {analysis_time:.2f}秒")
        
        return PrioritizationResult(
            paths=results,
            total_paths=len(paths),
            prioritized_paths=len(results),
            analysis_time=analysis_time,
            summary=summary
        )

    def _generate_summary(self, results: List[PathAnalysisResult], total_paths: int) -> Dict[str, Any]:
        """生成分析摘要"""
        priority_counts = defaultdict(int)
        total_vulnerability = 0
        total_exploration = 0
        
        for result in results:
            priority_counts[result.priority_level.value] += 1
            total_vulnerability += result.vulnerability_likelihood
            total_exploration += result.exploration_value
        
        critical_count = priority_counts.get('critical', 0)
        high_count = priority_counts.get('high', 0)
        
        return {
            'total_paths': total_paths,
            'prioritized_count': len(results),
            'critical_paths': critical_count,
            'high_paths': high_count,
            'avg_vulnerability_likelihood': total_vulnerability / len(results) if results else 0,
            'avg_exploration_value': total_exploration / len(results) if results else 0,
            'priority_distribution': dict(priority_counts)
        }

    def get_path_analysis(self, path_id: str) -> Optional[PathAnalysisResult]:
        """
        获取单条路径的分析结果
        
        Args:
            path_id: 路径ID
        
        Returns:
            PathAnalysisResult或None
        """
        return self.analyzed_paths.get(path_id)

    def update_path_priority(self, path_id: str, priority_score: float, reason: str = ""):
        """
        手动更新路径优先级
        
        Args:
            path_id: 路径ID
            priority_score: 新的优先级分数
            reason: 更新原因
        """
        if path_id in self.analyzed_paths:
            result = self.analyzed_paths[path_id]
            result.priority_score = priority_score
            result.priority_level = self._score_to_priority(priority_score)
            if reason:
                result.reasoning += f" [手动调整: {reason}]"
            
            logger.info(f"路径 {path_id} 优先级已更新为 {priority_score}")

    def _score_to_priority(self, score: float) -> PathPriority:
        """将分数转换为优先级级别"""
        if score >= 0.8:
            return PathPriority.CRITICAL
        elif score >= 0.6:
            return PathPriority.HIGH
        elif score >= 0.4:
            return PathPriority.MEDIUM
        elif score >= 0.2:
            return PathPriority.LOW
        else:
            return PathPriority.IGNORE

    def export_prioritization_report(self, output_path: str) -> bool:
        """
        导出优先级分析报告
        
        Args:
            output_path: 输出路径
        
        Returns:
            是否成功
        """
        report = {
            'generated_at': time.time(),
            'strategy': self.strategy,
            'total_analyzed': len(self.analyzed_paths),
            'paths': []
        }
        
        for path_id, result in self.analyzed_paths.items():
            report['paths'].append({
                'path_id': path_id,
                'priority_score': result.priority_score,
                'priority_level': result.priority_level.value,
                'vulnerability_likelihood': result.vulnerability_likelihood,
                'exploration_value': result.exploration_value,
                'key_features': result.key_features,
                'reasoning': result.reasoning,
                'suggested_actions': result.suggested_actions
            })
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            logger.info(f"优先级报告已导出到: {output_path}")
            return True
        except Exception as e:
            logger.error(f"导出报告失败: {e}")
            return False


def prioritize_paths(paths: List[Dict[str, Any]], strategy: str = "hybrid", 
                     top_k: Optional[int] = None) -> PrioritizationResult:
    """
    便捷的路径优先级排序函数
    
    Args:
        paths: 路径列表（字典格式）
        strategy: 分析策略
        top_k: 返回前k条路径
    
    Returns:
        PrioritizationResult
    """
    # 转换为SymbolicPath对象
    symbolic_paths = []
    for path_data in paths:
        features = []
        if 'features' in path_data:
            for feature in path_data['features']:
                try:
                    features.append(PathFeature(feature))
                except ValueError:
                    pass
        
        symbolic_path = SymbolicPath(
            path_id=path_data.get('path_id', str(hash(time.time()))),
            constraints=path_data.get('constraints', []),
            instructions=path_data.get('instructions', []),
            registers=path_data.get('registers', {}),
            memory_access=path_data.get('memory_access', []),
            reached_functions=path_data.get('reached_functions', []),
            depth=path_data.get('depth', 0),
            coverage_ratio=path_data.get('coverage_ratio', 0.0),
            features=features
        )
        symbolic_paths.append(symbolic_path)
    
    prioritizer = AIPathPrioritizer(strategy=strategy)
    return prioritizer.prioritize(symbolic_paths, top_k)


def format_prioritization_report(result: PrioritizationResult) -> str:
    """
    格式化优先级报告
    
    Args:
        result: PrioritizationResult
    
    Returns:
        格式化的报告字符串
    """
    parts = [
        "# 路径优先级分析报告",
        "",
        f"分析路径总数: {result.total_paths}",
        f"优先级排序数: {result.prioritized_paths}",
        f"分析耗时: {result.analysis_time:.2f}秒",
        ""
    ]
    
    if result.summary:
        parts.append("## 摘要")
        parts.append(f"- 关键路径数: {result.summary.get('critical_paths', 0)}")
        parts.append(f"- 高优先级路径数: {result.summary.get('high_paths', 0)}")
        parts.append(f"- 平均漏洞可能性: {result.summary.get('avg_vulnerability_likelihood', 0):.1f}%")
        parts.append(f"- 平均探索价值: {result.summary.get('avg_exploration_value', 0):.1f}%")
        
        dist = result.summary.get('priority_distribution', {})
        if dist:
            parts.append(f"- 优先级分布: {', '.join([f'{k}: {v}' for k, v in dist.items()])}")
    
    if result.paths:
        parts.append("")
        parts.append("## 路径优先级列表")
        
        for i, path in enumerate(result.paths[:10], 1):  # 只显示前10条
            parts.extend([
                f"\n### {i}. 路径 {path.path_id}",
                f"- 优先级: {path.priority_level.value} ({path.priority_score:.2f})",
                f"- 漏洞可能性: {path.vulnerability_likelihood:.1f}%",
                f"- 探索价值: {path.exploration_value:.1f}%"
            ])
            
            if path.key_features:
                parts.append(f"- 关键特征: {', '.join(path.key_features)}")
            
            if path.reasoning:
                parts.append(f"- 推理: {path.reasoning}")
            
            if path.suggested_actions:
                parts.append(f"- 建议操作: {', '.join(path.suggested_actions)}")
    
    return "\n".join(parts)