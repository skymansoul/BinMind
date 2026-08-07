# search/__init__.py — search subpackage re-exports
# delegates to root-level modules until migration is complete

# 旧代码: from .deep_search import ...
# LAZY_SEARCH = {
# "deep_search": lambda: __import__("deep_search"),
# }

__all__ = []

# 修复: search modules still live in ai_ml/ root; importable directly
# This package serves as the target for eventual migration per LOG.md
