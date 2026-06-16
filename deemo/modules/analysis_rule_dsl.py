"""
插件化分析管道与规则DSL模块

提供可扩展的分析管道框架和 YAML 规则 DSL，支持：
- 模块化分析管道
- YAML/JSON 规则编写
- 条件触发分析
- 自定义漏洞模式匹配

DSL Example:
    name: buffer_overflow_detector
    version: 1.0
    description: 检测缓冲区溢出漏洞
    
    rules:
      - id: strcpy_overflow
        pattern: strcpy(dest, src)
        condition:
          - dest.size < src.size
        severity: HIGH
        remediation: 使用 strncpy 替代 strcpy
    
    pipeline:
      - stage: parse
        module: binary_parser
      - stage: analyze
        module: data_flow
        input: parse.output
      - stage: detect
        module: rule_engine
        input: analyze.output
        rules: [strcpy_overflow]

Author: BinaryAnalysisPlatform
Version: 1.0.0
"""

import logging
import json
import yaml
import re
import os
import hashlib
from typing import Dict, List, Optional, Any, Set, Callable, Type, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from abc import ABC, abstractmethod
import subprocess

logger = logging.getLogger(__name__)


class StageStatus(Enum):
    """阶段状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Severity(Enum):
    """严重等级枚举"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNKNOWN = "Unknown"
    
    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """从字符串解析严重等级"""
        if not value:
            return cls.UNKNOWN
        value_lower = value.lower()
        for severity in cls:
            if severity.value.lower() == value_lower:
                return severity
        return cls.UNKNOWN


@dataclass
class RuleCondition:
    """规则条件"""
    field: str  # 字段名
    operator: str  # 操作符: ==, !=, >, <, in, not in, matches, contains
    value: Any  # 比较值
    

@dataclass 
class AnalysisRule:
    """分析规则定义"""
    rule_id: str
    name: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    conditions: List[RuleCondition] = field(default_factory=list)
    pattern: Optional[str] = None  # 正则模式
    metadata: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        """
        评估规则是否匹配
        
        Args:
            context: 评估上下文
        
        Returns:
            是否匹配
        """
        if not self.enabled:
            return False
        
        # 如果有正则模式
        if self.pattern:
            target = context.get('target', '')
            if isinstance(target, str):
                return bool(re.search(self.pattern, target))
            return False
        
        # 评估所有条件
        for cond in self.conditions:
            field_value = self._get_nested_field(context, cond.field)
            
            if cond.operator == '==':
                if field_value != cond.value:
                    return False
            elif cond.operator == '!=':
                if field_value == cond.value:
                    return False
            elif cond.operator == '>':
                if not (isinstance(field_value, (int, float)) and field_value > cond.value):
                    return False
            elif cond.operator == '<':
                if not (isinstance(field_value, (int, float)) and field_value < cond.value):
                    return False
            elif cond.operator == '>=':
                if not (isinstance(field_value, (int, float)) and field_value >= cond.value):
                    return False
            elif cond.operator == '<=':
                if not (isinstance(field_value, (int, float)) and field_value <= cond.value):
                    return False
            elif cond.operator == 'in':
                if field_value not in cond.value:
                    return False
            elif cond.operator == 'not in':
                if field_value in cond.value:
                    return False
            elif cond.operator == 'matches':
                if isinstance(field_value, str):
                    if not re.search(cond.value, field_value):
                        return False
                else:
                    return False
            elif cond.operator == 'contains':
                if isinstance(field_value, (str, list)):
                    if cond.value not in field_value:
                        return False
                else:
                    return False
        
        return True
    
    def _get_nested_field(self, data: Dict, path: str) -> Any:
        """获取嵌套字段值"""
        parts = path.split('.')
        value = data
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value


@dataclass
class PipelineStage:
    """分析管道阶段"""
    stage_id: str
    name: str
    module: str  # 模块名称
    input_refs: List[str] = field(default_factory=list)  # 输入引用
    output_key: str = ""  # 输出键名
    config: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)  # 依赖阶段
    rules: List[str] = field(default_factory=list)  # 应用的规则ID


@dataclass
class RuleMatch:
    """规则匹配结果"""
    rule_id: str
    rule_name: str
    severity: str
    matched_value: Any
    context: Dict[str, Any]
    confidence: float = 1.0
    location: Optional[str] = None
    description: str = ""


@dataclass
class StageResult:
    """阶段执行结果"""
    stage_id: str
    status: StageStatus
    output: Any = None
    error: Optional[str] = None
    matches: List[RuleMatch] = field(default_factory=list)
    execution_time: float = 0.0


@dataclass
class PipelineResult:
    """管道执行结果"""
    pipeline_id: str
    success: bool
    stages: Dict[str, StageResult] = field(default_factory=dict)
    total_matches: List[RuleMatch] = field(default_factory=list)
    execution_time: float = 0.0
    errors: List[str] = field(default_factory=list)


class RuleParser:
    """规则解析器"""
    
    def __init__(self):
        self.rules: Dict[str, AnalysisRule] = {}
    
    def parse_yaml(self, yaml_content: str) -> List[AnalysisRule]:
        """
        解析 YAML 规则
        
        Args:
            yaml_content: YAML 内容
        
        Returns:
            规则列表
        """
        try:
            data = yaml.safe_load(yaml_content)
            if not data or 'rules' not in data:
                return []
            
            rules = []
            for rule_data in data['rules']:
                rule = self._parse_rule(rule_data)
                if rule:
                    rules.append(rule)
                    self.rules[rule.rule_id] = rule
            
            return rules
        except Exception as e:
            logger.error(f"规则解析失败: {e}")
            return []
    
    def parse_json(self, json_content: str) -> List[AnalysisRule]:
        """解析 JSON 规则"""
        try:
            data = json.loads(json_content)
            if not data or 'rules' not in data:
                return []
            
            rules = []
            for rule_data in data['rules']:
                rule = self._parse_rule(rule_data)
                if rule:
                    rules.append(rule)
                    self.rules[rule.rule_id] = rule
            
            return rules
        except Exception as e:
            logger.error(f"JSON 规则解析失败: {e}")
            return []
    
    def load_from_file(self, file_path: str) -> List[AnalysisRule]:
        """从文件加载规则"""
        path = Path(file_path)
        if not path.exists():
            logger.error(f"规则文件不存在: {file_path}")
            return []
        
        content = path.read_text(encoding='utf-8')
        
        if path.suffix in ['.yaml', '.yml']:
            return self.parse_yaml(content)
        elif path.suffix == '.json':
            return self.parse_json(content)
        else:
            logger.error(f"不支持的规则文件格式: {path.suffix}")
            return []
    
    def _parse_rule(self, data: Dict) -> Optional[AnalysisRule]:
        """解析单条规则"""
        if 'id' not in data:
            logger.warning("规则缺少 ID，跳过")
            return None
        
        conditions = []
        for cond_data in data.get('conditions', []):
            cond = RuleCondition(
                field=cond_data.get('field', ''),
                operator=cond_data.get('operator', '=='),
                value=cond_data.get('value')
            )
            conditions.append(cond)
        
        return AnalysisRule(
            rule_id=data['id'],
            name=data.get('name', data['id']),
            description=data.get('description', ''),
            severity=data.get('severity', 'INFO'),
            category=data.get('category', 'general'),
            conditions=conditions,
            pattern=data.get('pattern'),
            metadata=data.get('metadata', {}),
            enabled=data.get('enabled', True),
            tags=data.get('tags', [])
        )
    
    def get_rule(self, rule_id: str) -> Optional[AnalysisRule]:
        """获取规则"""
        return self.rules.get(rule_id)
    
    def list_rules(self, category: Optional[str] = None,
                   enabled_only: bool = True) -> List[AnalysisRule]:
        """列出规则"""
        rules = list(self.rules.values())
        
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        
        if category:
            rules = [r for r in rules if r.category == category]
        
        return rules


class RuleEngine:
    """规则引擎"""
    
    def __init__(self, parser: Optional[RuleParser] = None):
        self.parser = parser or RuleParser()
        self.match_callbacks: List[Callable] = []
    
    def register_match_callback(self, callback: Callable[[RuleMatch], None]) -> None:
        """注册匹配回调"""
        self.match_callbacks.append(callback)
    
    def evaluate(self, context: Dict[str, Any],
                rule_ids: Optional[List[str]] = None) -> List[RuleMatch]:
        """
        评估规则
        
        Args:
            context: 评估上下文
            rule_ids: 规则ID列表（None 表示所有规则）
        
        Returns:
            匹配列表
        """
        matches = []
        
        rules = self.parser.list_rules()
        if rule_ids:
            rules = [r for r in rules if r.rule_id in rule_ids]
        
        for rule in rules:
            if rule.evaluate(context):
                match = RuleMatch(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    matched_value=context.get('target'),
                    context=context.copy(),
                    confidence=rule.metadata.get('confidence', 1.0),
                    location=context.get('location'),
                    description=rule.description
                )
                matches.append(match)
                
                # 调用回调
                for callback in self.match_callbacks:
                    try:
                        callback(match)
                    except Exception as e:
                        logger.error(f"匹配回调执行失败: {e}")
        
        return matches
    
    def evaluate_batch(self, contexts: List[Dict[str, Any]],
                       rule_ids: Optional[List[str]] = None) -> List[RuleMatch]:
        """批量评估"""
        all_matches = []
        for ctx in contexts:
            matches = self.evaluate(ctx, rule_ids)
            all_matches.extend(matches)
        return all_matches


class PipelineExecutor:
    """管道执行器"""
    
    def __init__(self, rule_engine: Optional[RuleEngine] = None):
        self.rule_engine = rule_engine or RuleEngine()
        self.stages: Dict[str, PipelineStage] = {}
        self.stage_handlers: Dict[str, Callable] = {}
        self._register_default_handlers()
    
    def _register_default_handlers(self) -> None:
        """注册默认处理器"""
        self.register_handler('rule_match', self._handle_rule_match)
        self.register_handler('filter', self._handle_filter)
        self.register_handler('transform', self._handle_transform)
        self.register_handler('aggregate', self._handle_aggregate)
    
    def register_handler(self, stage_type: str, 
                       handler: Callable[[Dict], Any]) -> None:
        """注册阶段处理器"""
        self.stage_handlers[stage_type] = handler
    
    def load_pipeline(self, pipeline_config: Union[str, Dict]) -> bool:
        """加载管道配置"""
        try:
            if isinstance(pipeline_config, str):
                path = Path(pipeline_config)
                if path.suffix in ['.yaml', '.yml']:
                    config = yaml.safe_load(path.read_text())
                elif path.suffix == '.json':
                    config = json.loads(path.read_text())
                else:
                    return False
            else:
                config = pipeline_config
            
            # 解析阶段
            for stage_data in config.get('pipeline', []):
                stage = PipelineStage(
                    stage_id=stage_data['id'],
                    name=stage_data.get('name', stage_data['id']),
                    module=stage_data['module'],
                    input_refs=stage_data.get('input', []),
                    output_key=stage_data.get('output', stage_data['id']),
                    config=stage_data.get('config', {}),
                    depends_on=stage_data.get('depends_on', []),
                    rules=stage_data.get('rules', [])
                )
                self.stages[stage.stage_id] = stage
            
            return True
        except Exception as e:
            logger.error(f"管道加载失败: {e}")
            return False
    
    def execute(self, initial_input: Any,
               pipeline_id: str = "default") -> PipelineResult:
        """
        执行管道
        
        Args:
            initial_input: 初始输入
            pipeline_id: 管道ID
        
        Returns:
            执行结果
        """
        import time
        start_time = time.time()
        
        result = PipelineResult(
            pipeline_id=pipeline_id,
            success=True,
            stages={}
        )
        
        # 执行拓扑排序的阶段
        executed = set()
        all_matches = []
        
        def execute_stage(stage: PipelineStage) -> StageResult:
            """执行单个阶段"""
            import time
            stage_start = time.time()
            
            # 检查依赖
            for dep_id in stage.depends_on:
                if dep_id not in executed:
                    return StageResult(
                        stage_id=stage.stage_id,
                        status=StageStatus.SKIPPED,
                        error=f"依赖阶段 {dep_id} 未完成"
                    )
            
            # 获取输入
            inputs = []
            for ref in stage.input_refs:
                if ref == 'initial':
                    inputs.append(initial_input)
                elif ref in result.stages:
                    inputs.append(result.stages[ref].output)
            
            # 执行处理器
            try:
                stage_type = stage.config.get('type', 'default')
                handler = self.stage_handlers.get(stage_type, self._handle_default)
                output = handler(stage, inputs)
                
                # 应用规则
                matches = []
                if stage.rules:
                    for item in (output if isinstance(output, list) else [output]):
                        if isinstance(item, dict):
                            matches.extend(
                                self.rule_engine.evaluate(item, stage.rules)
                            )
                
                all_matches.extend(matches)
                
                return StageResult(
                    stage_id=stage.stage_id,
                    status=StageStatus.COMPLETED,
                    output=output,
                    matches=matches,
                    execution_time=time.time() - stage_start
                )
                
            except Exception as e:
                return StageResult(
                    stage_id=stage.stage_id,
                    status=StageStatus.FAILED,
                    error=str(e),
                    execution_time=time.time() - stage_start
                )
        
        # 拓扑排序执行
        while len(executed) < len(self.stages):
            made_progress = False
            
            for stage_id, stage in self.stages.items():
                if stage_id in executed:
                    continue
                
                # 检查依赖是否满足
                deps_ready = all(dep in executed for dep in stage.depends_on)
                
                if deps_ready:
                    stage_result = execute_stage(stage)
                    result.stages[stage_id] = stage_result
                    executed.add(stage_id)
                    made_progress = True
                    
                    if stage_result.status == StageStatus.FAILED:
                        result.success = False
                        result.errors.append(
                            f"{stage_id}: {stage_result.error}"
                        )
            
            if not made_progress:
                break
        
        result.total_matches = all_matches
        result.execution_time = time.time() - start_time
        
        return result
    
    def _handle_default(self, stage: PipelineStage, 
                       inputs: List[Any]) -> Any:
        """默认处理器"""
        if not inputs:
            return None
        return inputs[0]
    
    def _handle_rule_match(self, stage: PipelineStage,
                          inputs: List[Any]) -> List[Dict]:
        """规则匹配处理器"""
        results = []
        for ctx in inputs:
            if isinstance(ctx, dict):
                matches = self.rule_engine.evaluate(ctx, stage.rules)
                for m in matches:
                    results.append({
                        'rule_id': m.rule_id,
                        'severity': m.severity,
                        'description': m.description,
                        'context': m.context
                    })
        return results
    
    def _handle_filter(self, stage: PipelineStage,
                      inputs: List[Any]) -> List[Any]:
        """过滤处理器"""
        filtered = []
        condition = stage.config.get('condition', {})
        
        for item in inputs:
            if isinstance(item, dict):
                keep = True
                for key, value in condition.items():
                    if item.get(key) != value:
                        keep = False
                        break
                if keep:
                    filtered.append(item)
        
        return filtered
    
    def _handle_transform(self, stage: PipelineStage,
                         inputs: List[Any]) -> List[Any]:
        """转换处理器"""
        transformed = []
        mapping = stage.config.get('mapping', {})
        
        for item in inputs:
            if isinstance(item, dict):
                new_item = {mapping.get(k, k): v for k, v in item.items()}
                transformed.append(new_item)
            else:
                transformed.append(item)
        
        return transformed
    
    def _handle_aggregate(self, stage: PipelineStage,
                         inputs: List[Any]) -> Dict[str, Any]:
        """聚合处理器"""
        aggregation = stage.config.get('aggregation', 'count')
        
        if aggregation == 'count':
            return {'count': len(inputs)}
        elif aggregation == 'sum':
            field = stage.config.get('field', 'value')
            return {'sum': sum(i.get(field, 0) for i in inputs if isinstance(i, dict))}
        elif aggregation == 'group_by':
            field = stage.config.get('group_by', 'type')
            groups = {}
            for i in inputs:
                if isinstance(i, dict):
                    key = i.get(field, 'unknown')
                    if key not in groups:
                        groups[key] = []
                    groups[key].append(i)
            return {'groups': groups}
        
        return {'items': inputs}


class AnalysisPipeline:
    """
    分析管道框架
    
    核心功能：
    1. YAML/JSON 规则解析
    2. 模块化管道执行
    3. 规则匹配引擎
    4. DAG 依赖调度
    """
    
    def __init__(self):
        self.rule_parser = RuleParser()
        self.rule_engine = RuleEngine(self.rule_parser)
        self.executor = PipelineExecutor(self.rule_engine)
        self.pipelines: Dict[str, Dict] = {}
    
    def load_rules(self, rule_files: List[str]) -> int:
        """加载规则文件"""
        total_rules = 0
        for file_path in rule_files:
            rules = self.rule_parser.load_from_file(file_path)
            total_rules += len(rules)
            logger.info(f"从 {file_path} 加载 {len(rules)} 条规则")
        return total_rules
    
    def load_rules_yaml(self, yaml_content: str) -> int:
        """从 YAML 内容加载规则"""
        rules = self.rule_parser.parse_yaml(yaml_content)
        return len(rules)
    
    def register_pipeline(self, pipeline_id: str,
                        pipeline_config: Union[str, Dict]) -> bool:
        """注册管道"""
        if self.executor.load_pipeline(pipeline_config):
            self.pipelines[pipeline_id] = pipeline_config
            return True
        return False
    
    def execute_pipeline(self, pipeline_id: str,
                        input_data: Any) -> PipelineResult:
        """执行管道"""
        if pipeline_id not in self.executor.stages:
            logger.error(f"管道未注册: {pipeline_id}")
            return PipelineResult(
                pipeline_id=pipeline_id,
                success=False,
                errors=[f"管道未注册: {pipeline_id}"]
            )
        
        return self.executor.execute(input_data, pipeline_id)
    
    def evaluate_rules(self, context: Dict[str, Any],
                     rule_ids: Optional[List[str]] = None) -> List[RuleMatch]:
        """直接评估规则"""
        return self.rule_engine.evaluate(context, rule_ids)
    
    def register_match_callback(self, 
                               callback: Callable[[RuleMatch], None]) -> None:
        """注册匹配回调"""
        self.rule_engine.register_match_callback(callback)
    
    def list_pipelines(self) -> List[str]:
        """列出已注册管道"""
        return list(self.pipelines.keys())
    
    def list_rules(self, category: Optional[str] = None) -> List[Dict]:
        """列出规则"""
        rules = self.rule_parser.list_rules(category)
        return [
            {
                'id': r.rule_id,
                'name': r.name,
                'description': r.description,
                'severity': r.severity,
                'category': r.category,
                'enabled': r.enabled,
                'tags': r.tags
            }
            for r in rules
        ]


# ============================================================================
# 内置规则模板
# ============================================================================

BUFFER_OVERFLOW_RULES = """
name: buffer_overflow_detector
version: 1.0
description: 检测缓冲区溢出漏洞

rules:
  - id: strcpy_no_size
    name: 不安全的字符串复制
    description: strcpy 不检查目标缓冲区大小
    severity: HIGH
    category: buffer_overflow
    pattern: "strcpy\\\\("
    tags: [cve, buffer]
    remediation: 使用 strncpy 或 memcpy 并指定长度

  - id: gets_usage
    name: 废弃的 gets 函数
    description: gets 函数已被废弃，容易造成缓冲区溢出
    severity: CRITICAL
    category: buffer_overflow
    pattern: "gets\\\\("
    tags: [deprecated, buffer]
    remediation: 使用 fgets 替代

  - id: sprintf_overflow
    name: 不安全的格式化字符串
    description: sprintf 不检查目标缓冲区大小
    severity: HIGH
    category: buffer_overflow
    pattern: "sprintf\\\\("
    tags: [format, buffer]
    remediation: 使用 snprintf 替代

  - id: scanf_no_width
    name: 不安全的 scanf
    description: scanf 未指定宽度限制
    severity: MEDIUM
    category: buffer_overflow
    pattern: "scanf\\\\([^%]*%[sdf]"
    tags: [format, input]
    remediation: 使用宽度说明符，如 %255s

  - id: memcpy_overflow
    name: 潜在 memcpy 溢出
    description: memcpy 大小参数可能为负数或超过目标大小
    severity: HIGH
    category: buffer_overflow
    conditions:
      - field: memcpy.size
        operator: '>'
        value: 0
      - field: memcpy.size
        operator: '>'
        value: "memcpy.dest_size"
    tags: [memory, buffer]
"""


def create_analysis_pipeline() -> AnalysisPipeline:
    """创建分析管道"""
    return AnalysisPipeline()


def load_builtin_rules(pipeline: AnalysisPipeline) -> None:
    """加载内置规则"""
    pipeline.load_rules_yaml(BUFFER_OVERFLOW_RULES)
