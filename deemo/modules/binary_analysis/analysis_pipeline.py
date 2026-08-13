#!/usr/bin/env python3
from typing import Optional
"""Analysis pipeline module -- StageConfig, PipelineTemplate, PipelineResult classes."""

import os
import logging
import time
import json
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Pipeline type constants
PIPE_TYPES = {
    'firmware_full_scan': 'firmware_full_scan',
    'malware_quick_triage': 'malware_quick_triage',
    'vulnerability_analysis': 'vulnerability_analysis',
    'memory_forensics': 'memory_forensics',
    'custom': 'custom',
}

STAGES = {
    'load': 'load',
    'disassemble': 'disassemble',
    'analyze': 'analyze',
    'detect': 'detect',
    'report': 'report',
}


@dataclass
class StageConfig:
    """Pipeline stage configuration."""
    stage: str
    enabled: bool = True
    params: dict = field(default_factory=dict)

    def as_dict(self):
        return {'stage': self.stage, 'enabled': self.enabled, 'params': dict(self.params)}


@dataclass
class PipelineTemplate:
    """Pipeline template definition."""
    name: str
    pipe_type: str
    desc: str = ''
    stages: list = field(default_factory=list)
    defaults: dict = field(default_factory=dict)

    def active_stages(self):
        """Return only enabled stages for easy disabled-skipping iteration."""
        return [s for s in self.stages if s.enabled]


@dataclass
class PipelineResult:
    """Pipeline execution result."""
    success: bool
    pipeline_name: str
    stage_results: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    execution_time: typing.Optional[float] = None

    def ok(self):
        return self.success and len(self.errors) == 0

    def summary(self):
        return {
            'name': self.pipeline_name,
            'ok': self.ok(),
            'stages': list(self.stage_results.keys()),
            'errors': self.errors[:5],
            'time': round(self.execution_time, 3) if self.execution_time else None,
        }


def _build_default_stages(template_key):
    """Return stage list by template type -- centralized management for easy modification."""
    _m = {
        'firmware_full_scan': [
            StageConfig('load',        True, {'format': 'auto'}),
            StageConfig('disassemble', True, {'arch': 'auto'}),
            StageConfig('analyze',     True, {'deep_analysis': True}),
            StageConfig('detect',      True, {'all_rules': True}),
            StageConfig('report',      True, {'format': 'html'}),
        ],
        'malware_quick_triage': [
            StageConfig('load',        True, {'format': 'auto'}),
            StageConfig('disassemble', True, {'quick_mode': True}),
            StageConfig('detect',      True, {'quick_scan': True}),
            StageConfig('report',      True, {'format': 'json'}),
        ],
        'vulnerability_analysis': [
            StageConfig('load',        True, {'format': 'binary'}),
            StageConfig('disassemble', True, {'detailed': True}),
            StageConfig('analyze',     True, {'symbolic_exec': True}),
            StageConfig('detect',      True, {'vuln_only': True}),
            StageConfig('report',      True, {'format': 'detailed'}),
        ],
    }
    return _m.get(template_key, [])


_PREDEFINED = {
    'firmware_full_scan': PipelineTemplate(
        name='Firmware Full Scan', pipe_type='firmware_full_scan',
        desc='Complete firmware security scan pipeline',
        stages=_build_default_stages('firmware_full_scan'),
        defaults={'timeout': 3600},
    ),
    'malware_quick_triage': PipelineTemplate(
        name='Malware Quick Triage', pipe_type='malware_quick_triage',
        desc='Quick identification of basic malware characteristics',
        stages=_build_default_stages('malware_quick_triage'),
        defaults={'timeout': 120},
    ),
    'vulnerability_analysis': PipelineTemplate(
        name='Vulnerability Deep Analysis', pipe_type='vulnerability_analysis',
        desc='In-depth analysis for specific vulnerabilities',
        stages=_build_default_stages('vulnerability_analysis'),
        defaults={'timeout': 7200},
    ),
}


class TemplateManager:
    """Template manager supporting add/search/delete operations."""

    def __init__(self):
        self._store = {}
        self._load_defaults()

    def _load_defaults(self):
        for _k, _t in _PREDEFINED.items():
            self._store[_t.name] = _t
            self._store[_k] = _t

    def grab(self, key):
        """Look up template by name or type."""
        if not key:
            return None
        if key in self._store:
            return self._store[key]
        if key in PIPE_TYPES:
            pipe_key = PIPE_TYPES[key]
            if pipe_key in self._store:
                return self._store[pipe_key]
        return None

    def all_templates(self):
        seen = set()
        out = []
        for _t in self._store.values():
            if id(_t) not in seen:
                seen.add(id(_t))
                out.append(_t)
        return out

    def add_custom(self, name, stages, desc=''):
        """Create custom template -- CUSTOM type only."""
        if not name:
            return None
        _t = PipelineTemplate(name=name, pipe_type='custom', desc=desc, stages=stages)
        self._store[name] = _t
        return _t

    def remove(self, name):
        """Delete custom template (preset templates cannot be removed)."""
        _t = self._store.get(name)
        if _t is None:
            return False
        if _t.pipe_type == 'custom':
            to_del = [k for k, v in self._store.items() if v is _t]
            for k in to_del:
                del self._store[k]
            return True
        return False


class PipelineExecutor:
    """Pipeline executor with stage handler registration."""

    def __init__(self):
        self._tmpl_mgr = TemplateManager()
        self._handlers = {}

    def register(self, stage_name, handler_fn):
        """Register stage handler -- allows overwrites."""
        if stage_name not in STAGES:
            logger.warning(f'Unknown stage: {stage_name}, may be custom')
        self._handlers[stage_name] = handler_fn

    def run(self, template_key, input_data, extra_params=None):
        """Execute complete pipeline."""
        t0 = time.time()

        tmpl = self._tmpl_mgr.grab(template_key)
        if tmpl is None:
            return PipelineResult(False, template_key,
                                  errors=[f'Template not found: {template_key}'])

        results = {}
        errors = []
        current_data = input_data

        for sc in tmpl.active_stages():
            sn = sc.stage
            logger.info(f'[{tmpl.name}] -> {sn}')

            try:
                fn = self._handlers.get(sn)
                if fn is None:
                    logger.debug(f'  Stage {sn} has no registered handler, skipping')
                    results[sn] = {'skipped': True, 'reason': 'no handler'}
                    continue

                p = dict(sc.params) if sc.params else {}
                merged = {**tmpl.defaults, **p}
                if extra_params:
                    merged.update(extra_params)

                out = fn(current_data, merged)
                results[sn] = out
                current_data = out

            except Exception as e:
                msg = f'Stage {sn} failed: {e}'
                errors.append(msg)
                logger.error(msg)
                break

        elapsed = time.time() - t0
        return PipelineResult(
            success=len(errors) == 0,
            pipeline_name=tmpl.name,
            stage_results=results,
            errors=errors,
            execution_time=elapsed,
        )


def run_pipeline(template_name, input_path):
    """Quick pipeline runner -- for demo/testing."""
    executor = PipelineExecutor()

    if not input_path:
        logger.warning('Input path is empty')
        return PipelineResult(False, template_name, errors=['Input path is empty'])

    executor.register('load',        lambda d, p: {'loaded': True, 'path': str(d)})
    executor.register('disassemble', lambda d, p: {'disassembled': True, 'insns': 1000})
    executor.register('analyze',     lambda d, p: {'analyzed': True, 'funcs': 50})
    executor.register('detect',      lambda d, p: {'detected': True, 'vulns': 5})
    executor.register('report',      lambda d, p: {'reported': True, 'path': 'report.html'})

    return executor.run(template_name, input_path)
