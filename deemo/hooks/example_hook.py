# example_hook.py — hook script template
# Copy to hooks/ directory, rename, and implement needed hooks.
# Context is passed as dict for type safety — kwargs silently swallowed typos.

"""
Supported hook points (in execution order):
  pre_info_collect     — before info collection
  post_info_collect    — after info collection
  pre_decompile        — before decompilation
  post_decompile       — after decompilation
  pre_analysis         — before AI analysis
  post_analysis        — after AI analysis
  pre_exploit_generate — before exploit generation
  post_exploit_generate— after exploit generation
  pre_crash_analysis   — before crash analysis
  post_crash_analysis  — after crash analysis
  post_report          — after report generation

Each hook: func(context: dict) -> None
Remove unused hook definitions — hook manager uses hasattr to skip missing ones.
"""

import logging

_logger = logging.getLogger(__name__)


def _safe_get(ctx, key, default='unknown'):
    """Safe dict.get with null guard for context."""
    if ctx is None:
        return default
    val = ctx.get(key, default)
    return default if val is None else val


def pre_info_collect(context):
    bp = _safe_get(context, 'binary_path', 'unknown')
    _logger.info(f"[Example Hook] starting analysis: {bp}")


def post_decompile(context):
    n_func = _safe_get(context, 'functions_analyzed', 0)
    engine = _safe_get(context, 'decompiler_used', 'unknown')
    _logger.info(f"[Example Hook] decompile done — {n_func} functions, engine: {engine}")


def pre_exploit_generate(context):
    vt = _safe_get(context, 'vulnerability_type', 'unknown')
    if not vt or vt == 'unknown':
        _logger.warning("[Example Hook] vuln type unknown, exploit may fail")
    _logger.info(f"[Example Hook] generating exploit — type: {vt}")


def post_report(context):
    reports = _safe_get(context, 'reports', {})
    if not reports:
        _logger.warning("[Example Hook] no reports generated")
        return
    for fmt in reports:
        path = reports[fmt]
        if path:
            _logger.info(f"[Example Hook] report: {fmt} -> {path}")
