"""插件化分析流水线与 YAML 规则 DSL。

提供可扩展的分析流水线框架, 支持:
- 模块化流水线
- YAML/JSON 规则编写
- 条件触发分析
- 自定义漏洞模式匹配

DSL 示例:
    name: buffer_overflow_detector
    rules:
      - id: strcpy_overflow
        pattern: strcpy(dest, src)
        severity: HIGH
        remediation: 使用 strncpy 替代 strcpy

    pipeline:
      - stage: parse
        module: binary_parser
      - stage: detect
        module: rule_engine
        input: parse.output
        rules: [strcpy_overflow]
"""

import hashlib
import json
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

import yaml

logger = logging.getLogger(__name__)

# 严重度等级常量
SEV_CRITICAL = "Critical"
SEV_HIGH = "High"
SEV_MEDIUM = "Medium"
SEV_LOW = "Low"
SEV_UNKNOWN = "Unknown"

# 阶段状态常量
STAGE_PENDING = "pending"
STAGE_RUNNING = "running"
STAGE_COMPLETED = "completed"
STAGE_FAILED = "failed"
STAGE_SKIPPED = "skipped"

class StageStatus(str, Enum):
    """阶段状态枚举。"""
    PENDING = STAGE_PENDING
    RUNNING = STAGE_RUNNING
    COMPLETED = STAGE_COMPLETED
    FAILED = STAGE_FAILED
    SKIPPED = STAGE_SKIPPED


class Severity(str, Enum):
    """严重度枚举。"""
    CRITICAL = SEV_CRITICAL
    HIGH = SEV_HIGH
    MEDIUM = SEV_MEDIUM
    LOW = SEV_LOW
    UNKNOWN = SEV_UNKNOWN

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """按字符串解析严重度, 无法识别回退 UNKNOWN。"""
        if not value:
            return cls.UNKNOWN
        value_lower = value.lower()
        for severity in cls:
            if severity.value.lower() == value_lower:
                return severity
        return cls.UNKNOWN


@dataclass
class RuleConditionAr:
    """规则条件。"""
    field: str
    operator: str
    value: Any


@dataclass
class AnalysisRuleAr:
    """分析规则定义。"""
    rule_id: str
    name: str
    description: str
    severity: str
    category: str
    conditions: List[RuleConditionAr] = field(default_factory=list)
    pattern: Optional[str] = None
    metadata: Dict = field(default_factory=dict)
    enabled: bool = True
    tags: List[str] = field(default_factory=list)

    def evaluate(self, context: Dict[str, Any]) -> bool:
        """规则是否匹配上下文: 先模式匹配, 后逐条件全满足。"""
        if not self.enabled:
            return False

        # 模式匹配优先
        if self.pattern:
            target = context.get('target', '')
            if isinstance(target, str):
                return bool(re.search(self.pattern, target))
            return False

        # 全部条件满足才匹配
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
        """按点分路径取嵌套字段值。"""
        parts = path.split('.')
        value = data
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value


@dataclass
class PipelineStageAr:
    """分析流水线阶段。"""
    stage_id: str
    name: str
    module: str
    input_refs: List[str] = field(default_factory=list)
    output_key: str = ""
    config: Dict = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)
    rules: List[str] = field(default_factory=list)


@dataclass
class RuleMatchAr:
    """规则匹配结果。"""
    rule_id: str
    rule_name: str
    severity: str
    matched_value: Any
    context: Dict
    confidence: float = 1.0
    location: Optional[str] = None
    description: str = ""


@dataclass
class StageResultAr:
    """阶段执行结果。"""
    stage_id: str
    status: StageStatus
    output: Any = None
    error: Optional[str] = None
    matches: List = field(default_factory=list)
    execution_time: float = 0.0


@dataclass
class PipelineResultAr:
    """流水线执行结果。"""
    pipeline_id: str
    success: bool
    stages: Dict = field(default_factory=dict)
    total_matches: List = field(default_factory=list)
    execution_time: float = 0.0
    errors: List[str] = field(default_factory=list)


class RuleParserAr:
    """规则解析器 (YAML/JSON)。"""

    def __init__(self):
        self.rules: Dict[str, AnalysisRuleAr] = {}

    def parse_yaml(self, yaml_content: str) -> List[AnalysisRuleAr]:
        """解析 YAML 规则, 异常记日志并返回空表。"""
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
            logger.error(f"Rule parsing failed: {e}")
            return []

    def parse_json(self, json_content: str) -> List[AnalysisRuleAr]:
        """解析 JSON 规则。"""
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
            logger.error(f"JSON rule parsing failed: {e}")
            return []

    def load_from_file(self, file_path: str) -> List[AnalysisRuleAr]:
        """按扩展名从文件加载规则。"""
        path = Path(file_path)
        if not path.exists():
            logger.error(f"Rule file not found: {file_path}")
            return []

        content = path.read_text(encoding='utf-8')

        if path.suffix in ['.yaml', '.yml']:
            return self.parse_yaml(content)
        elif path.suffix == '.json':
            return self.parse_json(content)
        else:
            logger.error(f"Unsupported rule file format: {path.suffix}")
            return []

    def _parse_rule(self, data: Dict) -> Optional[AnalysisRuleAr]:
        """单条规则字典 → AnalysisRuleAr。"""
        if 'id' not in data:
            logger.warning("Rule missing ID, skipping")
            return None

        conditions = []
        for cond_data in data.get('conditions', []):
            cond = RuleConditionAr(
                field=cond_data.get('field', ''),
                operator=cond_data.get('operator', '=='),
                value=cond_data.get('value'))
            conditions.append(cond)

        return AnalysisRuleAr(
            rule_id=data['id'],
            name=data.get('name', data['id']),
            description=data.get('description', ''),
            severity=data.get('severity', 'INFO'),
            category=data.get('category', 'general'),
            conditions=conditions,
            pattern=data.get('pattern'),
            metadata=data.get('metadata', {}),
            enabled=data.get('enabled', True),
            tags=data.get('tags', []))

    def get_rule(self, rule_id: str) -> Optional[AnalysisRuleAr]:
        """按 ID 取规则。"""
        return self.rules.get(rule_id)

    def list_rules(self, category: Optional[str] = None, enabled_only: bool = True) -> List[AnalysisRuleAr]:
        """列出规则, 可按类别与启用状态过滤。"""
        rules = list(self.rules.values())

        if enabled_only:
            rules = [r for r in rules if r.enabled]

        if category:
            rules = [r for r in rules if r.category == category]

        return rules


class RuleEngineAr:
    """规则引擎。"""

    def __init__(self, parser: Optional[RuleParserAr] = None):
        self.parser = parser or RuleParserAr()
        self.match_callbacks: List[Callable] = []

    def register_match_callback(self, callback: Callable) -> None:
        """注册匹配回调。"""
        self.match_callbacks.append(callback)

    def evaluate(self, context: Dict[str, Any], rule_ids: Optional[List[str]] = None) -> List[RuleMatchAr]:
        """对上下文求值规则, 命中即构造结果并通知回调。"""
        matches = []

        rules = self.parser.list_rules()
        if rule_ids:
            rules = [r for r in rules if r.rule_id in rule_ids]

        for rule in rules:
            if rule.evaluate(context):
                match = RuleMatchAr(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    matched_value=context.get('target'),
                    context=context.copy(),
                    confidence=rule.metadata.get('confidence', 1.0),
                    location=context.get('location'),
                    description=rule.description)
                matches.append(match)

                # 通知回调, 异常不中断
                for callback in self.match_callbacks:
                    try:
                        callback(match)
                    except Exception as e:
                        logger.error(f"Match callback failed: {e}")

        return matches

    def evaluate_batch(self, contexts: List[Dict[str, Any]], rule_ids: Optional[List[str]] = None) -> List[RuleMatchAr]:
        """多上下文批量求值。"""
        all_matches = []
        for ctx in contexts:
            matches = self.evaluate(ctx, rule_ids)
            all_matches.extend(matches)
        return all_matches


class PipelineExecutorAr:
    """流水线执行器 (DAG 依赖调度)。"""

    def __init__(self, rule_engine: Optional[RuleEngineAr] = None):
        self.rule_engine = rule_engine or RuleEngineAr()
        self.stages: Dict[str, PipelineStageAr] = {}
        self.stage_handlers: Dict[str, Callable] = {}
        self._register_default_handlers()

    def _register_default_handlers(self) -> None:
        """注册内置阶段处理器。"""
        self.register_handler('rule_match', self._handle_rule_match)
        self.register_handler('filter', self._handle_filter)
        self.register_handler('transform', self._handle_transform)
        self.register_handler('aggregate', self._handle_aggregate)

    def register_handler(self, stage_type: str, handler: Callable) -> None:
        """注册阶段类型处理器。"""
        self.stage_handlers[stage_type] = handler

    def load_pipeline(self, pipeline_config: Union[str, Dict]) -> bool:
        """加载流水线配置 (文件路径或字典)。"""
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

            # 解析阶段配置
            for stage_data in config.get('pipeline', []):
                stage = PipelineStageAr(
                    stage_id=stage_data['id'],
                    name=stage_data.get('name', stage_data['id']),
                    module=stage_data['module'],
                    input_refs=stage_data.get('input', []),
                    output_key=stage_data.get('output', stage_data['id']),
                    config=stage_data.get('config', {}),
                    depends_on=stage_data.get('depends_on', []),
                    rules=stage_data.get('rules', []))
                self.stages[stage.stage_id] = stage

            return True
        except Exception as e:
            logger.error(f"Pipeline load failed: {e}")
            return False

    def execute(self, initial_input: Any, pipeline_id: str = "default") -> PipelineResultAr:
        """按拓扑序执行流水线, 依赖未就绪的阶段跳过, 全部就绪后返回结果。"""
        start_time = time.time()

        result = PipelineResultAr(
            pipeline_id=pipeline_id,
            success=True,
            stages={})

        # 按拓扑序执行
        executed: set = set()
        all_matches: list = []

        def execute_stage(stage: PipelineStageAr) -> StageResultAr:
            """执行单阶段: 依赖检查 → 收集输入 → 处理器 → 规则求值。"""
            stage_start = time.time()

            # 依赖未满足 → 跳过
            for dep_id in stage.depends_on:
                if dep_id not in executed:
                    return StageResultAr(
                        stage_id=stage.stage_id,
                        status=StageStatus.SKIPPED,
                        error=f"Dependency stage {dep_id} not complete")

            # 收集输入
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
                                self.rule_engine.evaluate(item, stage.rules))

                all_matches.extend(matches)

                return StageResultAr(
                    stage_id=stage.stage_id,
                    status=StageStatus.COMPLETED,
                    output=output,
                    matches=matches,
                    execution_time=time.time() - stage_start)

            except Exception as e:
                return StageResultAr(
                    stage_id=stage.stage_id,
                    status=StageStatus.FAILED,
                    error=str(e),
                    execution_time=time.time() - stage_start)

        # 循环直至全部阶段执行完毕或无法推进
        while len(executed) < len(self.stages):
            made_progress = False

            for stage_id, stage in self.stages.items():
                if stage_id in executed:
                    continue

                # 依赖全部满足才执行
                deps_ready = all(dep in executed for dep in stage.depends_on)

                if deps_ready:
                    stage_result = execute_stage(stage)
                    result.stages[stage_id] = stage_result
                    executed.add(stage_id)
                    made_progress = True

                    if stage_result.status == StageStatus.FAILED:
                        result.success = False
                        result.errors.append(
                            f"{stage_id}: {stage_result.error}")

            if not made_progress:
                break

        result.total_matches = all_matches
        result.execution_time = time.time() - start_time

        return result

    def _handle_default(self, stage: PipelineStageAr, inputs: List[Any]) -> Any:
        """默认处理器: 返回首个输入。"""
        if not inputs:
            return None
        return inputs[0]

    def _handle_rule_match(self, stage: PipelineStageAr, inputs: List[Any]) -> List[Dict]:
        """规则匹配处理器。"""
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

    def _handle_filter(self, stage: PipelineStageAr, inputs: List[Any]) -> List[Any]:
        """条件过滤处理器。"""
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

    def _handle_transform(self, stage: PipelineStageAr, inputs: List[Any]) -> List[Any]:
        """字段映射变换处理器。"""
        transformed = []
        mapping = stage.config.get('mapping', {})

        for item in inputs:
            if isinstance(item, dict):
                new_item = {mapping.get(k, k): v for k, v in item.items()}
                transformed.append(new_item)
            else:
                transformed.append(item)

        return transformed

    def _handle_aggregate(self, stage: PipelineStageAr, inputs: List[Any]) -> Dict[str, Any]:
        """聚合处理器 (count/sum/group_by)。"""
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


class AnalysisPipelineAr:
    """分析流水线框架: 规则解析 + 模块化执行 + 规则匹配引擎 + DAG 依赖调度。"""

    def __init__(self):
        self.rule_parser = RuleParserAr()
        self.rule_engine = RuleEngineAr(self.rule_parser)
        self.executor = PipelineExecutorAr(self.rule_engine)
        self.pipelines: Dict[str, Dict] = {}

    def load_rules(self, rule_files: List[str]) -> int:
        """从文件列表批量加载规则, 返回加载总数。"""
        total_rules = 0
        for file_path in rule_files:
            rules = self.rule_parser.load_from_file(file_path)
            total_rules += len(rules)
            logger.info(f"Loaded {len(rules)} rules from {file_path}")
        return total_rules

    def load_rules_yaml(self, yaml_content: str) -> int:
        """从 YAML 文本加载规则, 返回条数。"""
        rules = self.rule_parser.parse_yaml(yaml_content)
        return len(rules)

    def register_pipeline(self, pipeline_id: str, pipeline_config: Union[str, Dict]) -> bool:
        """注册流水线, 配置加载成功才记录。"""
        if self.executor.load_pipeline(pipeline_config):
            self.pipelines[pipeline_id] = pipeline_config
            return True
        return False

    def execute_pipeline(self, pipeline_id: str, input_data: Any) -> PipelineResultAr:
        """执行已注册流水线。"""
        if pipeline_id not in self.pipelines:
            logger.error(f"Pipeline not registered: {pipeline_id}")
            return PipelineResultAr(
                pipeline_id=pipeline_id,
                success=False,
                errors=[f"Pipeline not registered: {pipeline_id}"])

        return self.executor.execute(input_data, pipeline_id)

    def evaluate_rules(self, context: Dict[str, Any], rule_ids: Optional[List[str]] = None) -> List[RuleMatchAr]:
        """直接对上下文求值规则。"""
        return self.rule_engine.evaluate(context, rule_ids)

    def register_match_callback(self, callback: Callable) -> None:
        """注册匹配回调。"""
        self.rule_engine.register_match_callback(callback)

    def list_pipelines(self) -> List[str]:
        """列出已注册流水线 ID。"""
        return list(self.pipelines.keys())

    def list_rules(self, category: Optional[str] = None) -> List[Dict]:
        """列出规则概要。"""
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


# 内置规则模板

BUFFER_OVERFLOW_RULES = r"""
name: buffer_overflow_detector
version: 1.0
description: 检测缓冲区溢出漏洞

rules:
  - id: strcpy_no_size
    name: 不安全的字符串复制
    description: strcpy 不检查目标缓冲区大小
    severity: HIGH
    category: buffer_overflow
    pattern: 'strcpy\('
    tags: [cve, buffer]
    remediation: 使用 strncpy 或 memcpy 并指定长度

  - id: gets_usage
    name: 废弃的 gets 函数
    description: gets 函数已被废弃，容易造成缓冲区溢出
    severity: CRITICAL
    category: buffer_overflow
    pattern: 'gets\('
    tags: [deprecated, buffer]
    remediation: 使用 fgets 替代

  - id: sprintf_overflow
    name: 不安全的格式化字符串
    description: sprintf 不检查目标缓冲区大小
    severity: HIGH
    category: buffer_overflow
    pattern: 'sprintf\('
    tags: [format, buffer]
    remediation: 使用 snprintf 替代

  - id: scanf_no_width
    name: 不安全的 scanf
    description: scanf 未指定宽度限制
    severity: MEDIUM
    category: buffer_overflow
    pattern: 'scanf\([^%]*%[sdf]'
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


def create_analysis_pipeline() -> AnalysisPipelineAr:
    """创建分析流水线实例。"""
    return AnalysisPipelineAr()


def load_builtin_rules(pipeline: AnalysisPipelineAr) -> None:
    """把内置规则装载进流水线。"""
    pipeline.load_rules_yaml(BUFFER_OVERFLOW_RULES)

# 别名指向 AnalysisPipelineAr 而非 RuleEngineAr：后者缺少 rule_parser/
# executor 等管道属性，误指会导致管道测试全部失败。
AnalysisPipeline = AnalysisPipelineAr

RuleParser = RuleParserAr

RuleEngine = RuleEngineAr

PipelineExecutor = PipelineExecutorAr

AnalysisRule = AnalysisRuleAr

RuleCondition = RuleConditionAr

RuleMatch = RuleMatchAr
