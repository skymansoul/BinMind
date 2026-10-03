# src/config.py - centralized config loader
# reads default.yaml, applies AIML_ env overrides, caches result

import logging as _logging
from copy import deepcopy as _deepcopy
import yaml as _yaml
import os
from typing import Any, Dict, Optional

__dbg = _logging.getLogger(__name__)
_DEFAULT_CFG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config', 'default.yaml')
_cfg_cache: Optional[Dict[str, Any]] = None
def _load_yaml(path: str) -> Dict[str, Any]:
	if not os.path.isfile(path):
		__dbg.warning(f"config file not found: {path}, using empty dict")
		return {}
	with open(path, 'r', encoding='utf-8') as fh:
		return _yaml.safe_load(fh) or {}
def _env_override(cfg: Dict[str, Any], prefix: str = "AIML_") -> Dict[str, Any]:
	# Depth-1 map: AIML_LOGGING_LEVEL -> cfg["日志"]["level"]
	res = _deepcopy(cfg)
	for key, val in os.environ.items():
		if not key.startswith(prefix):
			continue
		parts = key[len(prefix):].lower().split('_')
		if len(parts) < 2:
			res[parts[0]] = _coerce(val)
			continue
		section = parts[0]
		field = '_'.join(parts[1:])
		if section not in res:
			res[section] = {}
		res[section][field] = _coerce(val)
	return res
def _coerce(val: str):
	"""Try int/float/bool, fallback to str."""
	if val.lower() in ('true', 'yes', '1'):
		return True
	if val.lower() in ('false', 'no', '0'):
		return False
	try:
		return int(val)
	except ValueError:
		pass
	try:
		return float(val)
	except ValueError:
		pass
	return val
def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
	"""Load and cache config. Pass config_path to override default."""
	global _cfg_cache
	if _cfg_cache is not None and config_path is None:
		return _deepcopy(_cfg_cache)
	path = config_path or _DEFAULT_CFG_PATH
	raw = _load_yaml(path)
	cfg = _env_override(raw)
	if config_path is None:
		_cfg_cache = cfg
	__dbg.debug(f"config loaded from {path}: {list(cfg.keys())}")
	return _deepcopy(cfg)
def get(key: str, default: Any = None) -> Any:
	"""Convenience: get a dotted key from config."""
	cfg = load_config()
	parts = key.split('.')
	cur = cfg
	for p in parts:
		if isinstance(cur, dict) and p in cur:
			cur = cur[p]
		else:
			return default
	return cur
def reload_config():
	"""Invalidate cache; next load_config() will re-read from disk."""
	global _cfg_cache
	_cfg_cache = None
	__dbg.debug("config cache invalidated")

