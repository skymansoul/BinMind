"""
多目标分析任务管道模板模块

功能：
1. 预设模板（如"固件全面扫描"、"恶意软件快速分诊"）一键运行
2. 支持自定义模板
3. 管道编排与执行

核心组件：
- PipelineTemplate: 管道模板
- PipelineExecutor: 管道执行器
- TemplateManager: 模板管理器
"""

import os
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class PipelineType(Enum):
    FIRMWARE_FULL_SCAN = "firmware_full_scan"
    MALWARE_QUICK_TRIAGE = "malware_quick_triage"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    MEMORY_FORENSICS = "memory_forensics"
    CUSTOM = "custom"


class PipelineStage(Enum):
    LOAD = "load"
    DISASSEMBLE = "disassemble"
    ANALYZE = "analyze"
    DETECT = "detect"
    REPORT = "report"


@dataclass
class StageConfig:
    stage: PipelineStage
    enabled: bool = True
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineTemplate:
    name: str
    pipeline_type: PipelineType
    description: Optional[str] = None
    stages: List[StageConfig] = field(default_factory=list)
    default_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineResult:
    success: bool
    pipeline_name: str
    stage_results: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    execution_time: Optional[float] = None


class TemplateManager:

    _PREDEFINED_TEMPLATES = {
        PipelineType.FIRMWARE_FULL_SCAN: PipelineTemplate(
            name="固件全面扫描",
            pipeline_type=PipelineType.FIRMWARE_FULL_SCAN,
            description="完整的固件安全扫描流程",
            stages=[
                StageConfig(stage=PipelineStage.LOAD, params={"format": "auto"}),
                StageConfig(stage=PipelineStage.DISASSEMBLE, params={"arch": "auto"}),
                StageConfig(stage=PipelineStage.ANALYZE, params={"deep_analysis": True}),
                StageConfig(stage=PipelineStage.DETECT, params={"all_rules": True}),
                StageConfig(stage=PipelineStage.REPORT, params={"format": "html"})
            ],
            default_params={"timeout": 3600}
        ),
        PipelineType.MALWARE_QUICK_TRIAGE: PipelineTemplate(
            name="恶意软件快速分诊",
            pipeline_type=PipelineType.MALWARE_QUICK_TRIAGE,
            description="快速识别恶意软件基本特征",
            stages=[
                StageConfig(stage=PipelineStage.LOAD, params={"format": "auto"}),
                StageConfig(stage=PipelineStage.DISASSEMBLE, params={"quick_mode": True}),
                StageConfig(stage=PipelineStage.DETECT, params={"quick_scan": True}),
                StageConfig(stage=PipelineStage.REPORT, params={"format": "json"})
            ],
            default_params={"timeout": 120}
        ),
        PipelineType.VULNERABILITY_ANALYSIS: PipelineTemplate(
            name="漏洞深度分析",
            pipeline_type=PipelineType.VULNERABILITY_ANALYSIS,
            description="针对特定漏洞的深入分析",
            stages=[
                StageConfig(stage=PipelineStage.LOAD, params={"format": "binary"}),
                StageConfig(stage=PipelineStage.DISASSEMBLE, params={"detailed": True}),
                StageConfig(stage=PipelineStage.ANALYZE, params={"symbolic_exec": True}),
                StageConfig(stage=PipelineStage.DETECT, params={"vuln_only": True}),
                StageConfig(stage=PipelineStage.REPORT, params={"format": "detailed"})
            ],
            default_params={"timeout": 7200}
        )
    }

    def __init__(self):
        self._templates: Dict[str, PipelineTemplate] = {}
        self._load_predefined_templates()

    def _load_predefined_templates(self):
        for template in self._PREDEFINED_TEMPLATES.values():
            self._templates[template.name] = template

    def get_template(self, name_or_type: str) -> Optional[PipelineTemplate]:
        if name_or_type in self._templates:
            return self._templates[name_or_type]
        
        try:
            template_type = PipelineType[name_or_type.upper()]
            return self._PREDEFINED_TEMPLATES.get(template_type)
        except ValueError:
            return None

    def list_templates(self) -> List[PipelineTemplate]:
        return list(self._templates.values(

 def create_custom_template(self, name: str, stages: List[StageConfig], description: str = "") -> PipelineTemplate:
        template = PipelineTemplate(
            name=name,
            pipeline_type=PipelineType.CUSTOM,
            description=description,
            stages=stages
        )
        self._templates[name] = template
        return template

    def delete_template(self, name: str) -> bool:
        if name in self._templates and self._templates[name].pipeline_type == PipelineType.CUSTOM:
            del self._templates[name]
            return True
        return False


class PipelineExecutor:

    def __init__(self):
        self._template_manager = TemplateManager()
        self._stage_handlers: Dict[PipelineStage, Callable] = {}

    def register_stage_handler(self, stage: PipelineStage, handler: Callable):
        self._stage_handlers[stage] = handler

 def execute(self, template_name: str, input_data: Any, params: Optional[Dict[str, Any]] = None) -> PipelineResult:
        import time
        start_time = time.time()
        
        template = self._template_manager.get_template(template_name)
        if not template:
            return PipelineResult(
                success=False,
                pipeline_name=template_name,
                errors=[f"Template not found: {template_name}"]
            )
        
        stage_results = {}
        errors = []
        
        for stage_config in template.stages:
            if not stage_config.enabled:
                continue
            
            stage_name = stage_config.stage.value
            logger.info(f"Executing stage: {stage_name}")
            
            try:
                handler = self._stage_handlers.get(stage_config.stage)
                if handler:
                    result = handler(input_data, stage_config.params)
                else:
                    result = self._default_handler(stage_config.stage, input_data)
                
                stage_results[stage_name] = result
                input_data = result
            except Exception as e:
                errors.append(f"Stage {stage_name} failed: {e}")
                logger.error(f"Stage {stage_name} failed: {e}")
                break
        
        execution_time = time.time() - start_time
        
        return PipelineResult(
            success=len(errors) == 0,
            pipeline_name=template_name,
            stage_results=stage_results,
            errors=errors,
            execution_time=execution_time
        )

    def _default_handler(self, stage: PipelineStage, input_data: Any) -> Dict[str, Any]:
        return {
            "stage": stage.value,
            "processed": True,
            "input_size": len(str(input_data)) if input_data else 0
        }


def run_pipeline(template_name: str, input_path: str) -> PipelineResult:
    executor = PipelineExecutor()
    
    def load_handler(data, params):
        return {"loaded": True, "path": data}
    
    def disassemble_handler(data, params):
        return {"disassembled": True, "instructions": 1000}
    
    def analyze_handler(data, params):
        return {"analyzed": True, "functions": 50}
    
    def detect_handler(data, params):
        return {"detected": True, "vulnerabilities": 5}
    
    def report_handler(data, params):
        return {"reported": True, "path": "report.html"}
    
    executor.register_stage_handler(PipelineStage.LOAD, load_handler)
    executor.register_stage_handler(PipelineStage.DISASSEMBLE, disassemble_handler)
    executor.register_stage_handler(PipelineStage.ANALYZE, analyze_handler)
    executor.register_stage_handler(PipelineStage.DETECT, detect_handler)
    executor.register_stage_handler(PipelineStage.REPORT, report_handler)
    
    return executor.execute(template_name, input_path)))