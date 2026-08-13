"""
Plugin-based analysis pipeline and rule DSL module.

Provides an extensible analysis pipeline framework and YAML rule DSL supporting:
- Modular analysis pipelines
- YAML/JSON rule authoring
- Conditional trigger analysis
- Custom vulnerability pattern matching

DSL Example:
    name: buffer_overflow_detector
    version: 1.0
    description: Detect buffer overflow vulnerabilities

    rules:
      - id: strcpy_overflow
        pattern: strcpy(dest, src)
        condition:
          - dest.size < src.size
        severity: HIGH
        remediation: Use strncpy instead of strcpy

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
import re
import os
import time
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field

import yaml
import hashlib
import subprocess

logger = logging.getLogger(__name__)

# Severity level constants
SEV_CRITICAL = "Critical"
SEV_HIGH = "High"
SEV_MEDIUM = "Medium"
SEV_LOW = "Low"
SEV_UNKNOWN = "Unknown"

# Stage status constants
STAGE_PENDING = "pending"
STAGE_RUNNING = "running"
STAGE_COMPLETED = "completed"
STAGE_FAILED = "failed"
STAGE_SKIPPED = "skipped"

class StageStatus(str, Enum):
    """Stage status enumeration."""
    PENDING = STAGE_PENDING
    RUNNING = STAGE_RUNNING
    COMPLETED = STAGE_COMPLETED
    FAILED = STAGE_FAILED
    SKIPPED = STAGE_SKIPPED


class Severity(str, Enum):
    """Severity level enumeration."""
    CRITICAL = SEV_CRITICAL
    HIGH = SEV_HIGH
    MEDIUM = SEV_MEDIUM
    LOW = SEV_LOW
    UNKNOWN = SEV_UNKNOWN

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse severity level from string value."""
        if not value:
            return cls.UNKNOWN
        value_lower = value.lower()
        for severity in cls:
            if severity.value.lower() == value_lower:
                return severity
        return cls.UNKNOWN


@dataclass
class RuleConditionAr:
    """Rule condition."""
    field: str
    operator: str
    value: Any


@dataclass
class AnalysisRuleAr:
    """Analysis rule definition."""
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
        """Evaluate whether the rule matches the given context.

        Args:
            context: Evaluation context.

        Returns:
            True if the rule matches all conditions.
        """
        if not self.enabled:
            return False

        # Pattern-based matching takes priority
        if self.pattern:
            target = context.get('target', '')
            if isinstance(target, str):
                return bool(re.search(self.pattern, target))
            return False

        # Evaluate all conditions; all must match
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
        """Get nested field value by dot-separated path."""
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
    """Analysis pipeline stage."""
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
    """Rule match result."""
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
    """Stage execution result."""
    stage_id: str
    status: StageStatus
    output: Any = None
    error: Optional[str] = None
    matches: List = field(default_factory=list)
    execution_time: float = 0.0


@dataclass
class PipelineResultAr:
    """Pipeline execution result."""
    pipeline_id: str
    success: bool
    stages: Dict = field(default_factory=dict)
    total_matches: List = field(default_factory=list)
    execution_time: float = 0.0
    errors: List[str] = field(default_factory=list)


class RuleParserAr:
    """Rule parser."""

    def __init__(self):
        self.rules: Dict[str, AnalysisRuleAr] = {}

    def parse_yaml(self, yaml_content: str) -> List[AnalysisRuleAr]:
        """Parse YAML rules.

        Args:
            yaml_content: YAML content string.

        Returns:
            List of parsed rules.
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
            logger.error(f"Rule parsing failed: {e}")
            return []

    def parse_json(self, json_content: str) -> List[AnalysisRuleAr]:
        """Parse JSON rules."""
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
        """Load rules from a file."""
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
        """Parse a single rule from dict."""
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
        """Get a rule by ID."""
        return self.rules.get(rule_id)

    def list_rules(self, category: Optional[str] = None, enabled_only: bool = True) -> List[AnalysisRuleAr]:
        """List rules, optionally filtered by category and enabled status."""
        rules = list(self.rules.values())

        if enabled_only:
            rules = [r for r in rules if r.enabled]

        if category:
            rules = [r for r in rules if r.category == category]

        return rules


class RuleEngineAr:
    """Rule engine."""

    def __init__(self, parser: Optional[RuleParserAr] = None):
        self.parser = parser or RuleParserAr()
        self.match_callbacks: List[Callable] = []

    def register_match_callback(self, callback: Callable) -> None:
        """Register a match callback."""
        self.match_callbacks.append(callback)

    def evaluate(self, context: Dict[str, Any], rule_ids: Optional[List[str]] = None) -> List[RuleMatchAr]:
        """Evaluate rules against the given context.

        Args:
            context: Evaluation context.
            rule_ids: Optional list of rule IDs to evaluate.

        Returns:
            List of match results.
        """
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

                # Notify callbacks with exception protection
                for callback in self.match_callbacks:
                    try:
                        callback(match)
                    except Exception as e:
                        logger.error(f"Match callback failed: {e}")

        return matches

    def evaluate_batch(self, contexts: List[Dict[str, Any]], rule_ids: Optional[List[str]] = None) -> List[RuleMatchAr]:
        """Batch evaluation across multiple contexts."""
        all_matches = []
        for ctx in contexts:
            matches = self.evaluate(ctx, rule_ids)
            all_matches.extend(matches)
        return all_matches


class PipelineExecutorAr:
    """Pipeline executor."""

    def __init__(self, rule_engine: Optional[RuleEngineAr] = None):
        self.rule_engine = rule_engine or RuleEngineAr()
        self.stages: Dict[str, PipelineStageAr] = {}
        self.stage_handlers: Dict[str, Callable] = {}
        self._register_default_handlers()

    def _register_default_handlers(self) -> None:
        """Register default stage handlers."""
        self.register_handler('rule_match', self._handle_rule_match)
        self.register_handler('filter', self._handle_filter)
        self.register_handler('transform', self._handle_transform)
        self.register_handler('aggregate', self._handle_aggregate)

    def register_handler(self, stage_type: str, handler: Callable) -> None:
        """Register a stage handler."""
        self.stage_handlers[stage_type] = handler

    def load_pipeline(self, pipeline_config: Union[str, Dict]) -> bool:
        """Load pipeline configuration."""
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

            # Parse stage configuration
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
        """Execute the pipeline.

        Args:
            initial_input: Initial input data.
            pipeline_id: Pipeline identifier.

        Returns:
            Pipeline execution result.
        """
        start_time = time.time()

        result = PipelineResultAr(
            pipeline_id=pipeline_id,
            success=True,
            stages={})

        # Topological-order execution
        executed: set = set()
        all_matches: list = []

        def execute_stage(stage: PipelineStageAr) -> StageResultAr:
            """Execute a single pipeline stage."""
            stage_start = time.time()

            # Check dependency satisfaction
            for dep_id in stage.depends_on:
                if dep_id not in executed:
                    return StageResultAr(
                        stage_id=stage.stage_id,
                        status=StageStatus.SKIPPED,
                        error=f"Dependency stage {dep_id} not complete")

            # Gather inputs
            inputs = []
            for ref in stage.input_refs:
                if ref == 'initial':
                    inputs.append(initial_input)
                elif ref in result.stages:
                    inputs.append(result.stages[ref].output)

            # Execute the handler
            try:
                stage_type = stage.config.get('type', 'default')
                handler = self.stage_handlers.get(stage_type, self._handle_default)
                output = handler(stage, inputs)

                # Apply rules
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

        # Execute stages in topological order until all complete
        while len(executed) < len(self.stages):
            made_progress = False

            for stage_id, stage in self.stages.items():
                if stage_id in executed:
                    continue

                # Check dependency satisfaction
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
        """Default handler: return first input."""
        if not inputs:
            return None
        return inputs[0]

    def _handle_rule_match(self, stage: PipelineStageAr, inputs: List[Any]) -> List[Dict]:
        """Rule match handler."""
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
        """Filter handler."""
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
        """Transform handler."""
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
        """Aggregation handler."""
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
    """Analysis pipeline framework.

    Core functionality:
    1. YAML/JSON rule parsing
    2. Modular pipeline execution
    3. Rule matching engine
    4. DAG dependency scheduling
    """

    def __init__(self):
        self.rule_parser = RuleParserAr()
        self.rule_engine = RuleEngineAr(self.rule_parser)
        self.executor = PipelineExecutorAr(self.rule_engine)
        self.pipelines: Dict[str, Dict] = {}

    def load_rules(self, rule_files: List[str]) -> int:
        """Load rule files."""
        total_rules = 0
        for file_path in rule_files:
            rules = self.rule_parser.load_from_file(file_path)
            total_rules += len(rules)
            logger.info(f"Loaded {len(rules)} rules from {file_path}")
        return total_rules

    def load_rules_yaml(self, yaml_content: str) -> int:
        """Load rules from YAML content."""
        rules = self.rule_parser.parse_yaml(yaml_content)
        return len(rules)

    def register_pipeline(self, pipeline_id: str, pipeline_config: Union[str, Dict]) -> bool:
        """Register a pipeline."""
        if self.executor.load_pipeline(pipeline_config):
            self.pipelines[pipeline_id] = pipeline_config
            return True
        return False

    def execute_pipeline(self, pipeline_id: str, input_data: Any) -> PipelineResultAr:
        """Execute a registered pipeline."""
        if pipeline_id not in self.pipelines:
            logger.error(f"Pipeline not registered: {pipeline_id}")
            return PipelineResultAr(
                pipeline_id=pipeline_id,
                success=False,
                errors=[f"Pipeline not registered: {pipeline_id}"])

        return self.executor.execute(input_data, pipeline_id)

    def evaluate_rules(self, context: Dict[str, Any], rule_ids: Optional[List[str]] = None) -> List[RuleMatchAr]:
        """Directly evaluate rules."""
        return self.rule_engine.evaluate(context, rule_ids)

    def register_match_callback(self, callback: Callable) -> None:
        """Register a match callback."""
        self.rule_engine.register_match_callback(callback)

    def list_pipelines(self) -> List[str]:
        """List registered pipelines."""
        return list(self.pipelines.keys())

    def list_rules(self, category: Optional[str] = None) -> List[Dict]:
        """List rules."""
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


# Built-in rule templates

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
    """Create an analysis pipeline instance."""
    return AnalysisPipelineAr()


def load_builtin_rules(pipeline: AnalysisPipelineAr) -> None:
    """Load built-in rules into a pipeline."""
    pipeline.load_rules_yaml(BUFFER_OVERFLOW_RULES)

# 别名指向 AnalysisPipelineAr 而非 RuleEngineAr：后者缺少 rule_parser/
# executor 等管道属性，误指会导致管道测试全部失败。
AnalysisPipeline = AnalysisPipelineAr

RuleParser = RuleParserAr

RuleEngine = RuleEngineAr

PipelineExecutor = RuleEngineAr

AnalysisRule = AnalysisRuleAr

RuleCondition = RuleConditionAr

RuleCondition = RuleConditionAr

RuleMatch = RuleMatchAr
