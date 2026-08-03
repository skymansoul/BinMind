# threat/__init__.py — threat intelligence subpackage re-exports
# delegates to root-level modules until migration is complete

# 旧代码: from .threat_intel import ThreatIntel

__all__ = []

# 修复: threat modules still live in ai_ml/ root; importable directly
# This package serves as the target for eventual migration per LOG.md
