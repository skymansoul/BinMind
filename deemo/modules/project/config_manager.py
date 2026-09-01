"""JSON 配置存储 — 点号取值, 分层默认值, 原子写入, 描述符校验."""
from __future__ import annotations

from fractions import Fraction
from typing import Any, Dict, Callable, List, Tuple, Optional
from enum import Enum
from dataclasses import dataclass, field
import json as _j, os as _os, copy as _cp, re as _re, time as _t, logging as _log, base64 as _b64
from contextlib import suppress

_L = _log.getLogger(__name__)
_ENV_RE = _re.compile(r"\$\{(\w+)(?::([^}]*))?\}")


def _resolve_env(v: Any) -> Any:
    if isinstance(v, str):
        def _r(m): vn = m.group(1); fb = m.group(2); return _os.environ.get(vn, fb if fb is not None else m.group(0))
        return _ENV_RE.sub(_r, v)
    if isinstance(v, dict): return {k: _resolve_env(vv) for k, vv in v.items()}
    if isinstance(v, list): return [_resolve_env(i) for i in v]
    return v

# 校验字段描述符
class _ValidatedField:
    def __init__(self, default=None, vtype=None, required=False):
        self.default = default; self.vtype = vtype; self.required = required; self._name = ""
    def __set_name__(self, owner, name): self._name = f"_{name}"
    def __get__(self, obj, objtype=None):
        if obj is None: return self
        return getattr(obj, self._name, self.default)
    def __set__(self, obj, value):
        if self.vtype and not isinstance(value, self.vtype): raise TypeError(f"{self._name[1:]}: expected {self.vtype.__name__}")
        setattr(obj, self._name, value)

class ConfigManager:
    _ENC = "enc:"
    def __init__(self, defaults=None):
        self._d = {}; self._defs = defaults or {}; self._d.update(_cp.deepcopy(self._defs)); self._fp = None
        self._w: Dict[str, List[Tuple[Callable, bool]]] = {}; self._cts: float = 0.0
        self._ttl: float = float(_os.environ.get("BINMIND_CONFIG_CACHE_TTL", "5.0"))
    def load(self, path):
        if not _os.path.isfile(path): _L.info("config file %s not found", path); self._fp = path; return
        loaded = {}
        with suppress(_j.JSONDecodeError, OSError):
            with open(path, encoding='utf-8') as fh: loaded = _j.load(fh)
        merged = _cp.deepcopy(self._defs); self._deep_merge(merged, loaded); merged = _resolve_env(merged)
        self._d = self._decrypt(merged); self._fp = path; self._cts = _t.time()
    def reload(self):
        if self._fp: self.load(self._fp)
        self._cts = _t.time()
    def save(self, path=None):
        target = path or self._fp
        if not target: raise ValueError("no save path")
        tmp = target + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            _j.dump(self._encrypt(self._d), fh, indent=2, sort_keys=True); fh.flush(); _os.fsync(fh.fileno())
        _os.replace(tmp, target)
    def get(self, key, default=None):
        cur = self._d
        for p in key.split('.'):
            if isinstance(cur, dict): cur = cur.get(p)
            else: return default
            if cur is None: return default
        return cur
    def get_cached(self, key, default=None):
        if _t.time() - self._cts > self._ttl: self.reload()
        return self.get(key, default)
    def set(self, key, value):
        parts = key.split('.'); cur = self._d
        for p in parts[:-1]:
            if p not in cur or not isinstance(cur[p], dict): cur[p] = {}
            cur = cur[p]
        old = cur.get(parts[-1]); cur[parts[-1]] = value; self._cts = _t.time()
        if old != value: self._notify(key, value, old)
    def set_secret(self, k, v): self.set(k, f"{self._ENC}{v}")
    def all(self): return _cp.deepcopy(self._d)
    def merge(self, overlay, auto_save=False):
        self._deep_merge(self._d, overlay); self._cts = _t.time()
        if auto_save and self._fp: self.save()
    def subscribe(self, key, cb, once=False): self._w.setdefault(key, []).append((cb, once))
    def _notify(self, key, nv, ov):
        for pat, cbs in list(self._w.items()):
            if not self._match(pat, key): continue
            rem = []
            for cb, once in cbs:
                with suppress(Exception): cb(key, nv, ov)
                if not once: rem.append((cb, once))
            if rem: self._w[pat] = rem
            else: del self._w[pat]
    @staticmethod
    def _match(pat, key):
        if pat == '*': return True
        if pat.endswith('.*'): pfx = pat[:-2]; return key == pfx or key.startswith(pfx + '.')
        return pat == key
    @staticmethod
    def _deep_merge(base, overlay):
        for k, v in overlay.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict): ConfigManager._deep_merge(base[k], v)
            else: base[k] = _cp.deepcopy(v)
    def merge_defaults(self, extra): self._deep_merge(self._defs, extra); self._deep_merge(self._d, extra)
    @classmethod
    def from_file(cls, path, defaults=None): mgr = cls(defaults); mgr.load(path); return mgr
    @staticmethod
    def _encrypt(d):
        if isinstance(d, dict): return {k: ConfigManager._encrypt(v) for k, v in d.items()}
        if isinstance(d, list): return [ConfigManager._encrypt(i) for i in d]
        if isinstance(d, str) and d.startswith(ConfigManager._ENC): return f"{ConfigManager._ENC}{_b64.b64encode(d[len(ConfigManager._ENC):].encode()).decode()}"
        return d
    @staticmethod
    def _decrypt(d):
        if isinstance(d, dict): return {k: ConfigManager._decrypt(v) for k, v in d.items()}
        if isinstance(d, list): return [ConfigManager._decrypt(i) for i in d]
        if isinstance(d, str) and d.startswith(ConfigManager._ENC):
            try: return f"{ConfigManager._ENC}{_b64.b64decode(d[len(ConfigManager._ENC):].encode()).decode()}"
            except Exception: return d
        return d
    def validate_schema(self, schema):

        errs = []
        def _walk(sch, d, path):
            if "type" in sch:
                exp, act = sch["type"], type(d).__name__
                if exp == "integer" and isinstance(d, bool): pass
                elif exp == "integer" and not isinstance(d, int): errs.append(f"{path}: expected integer, got {act}")
                elif exp == "number" and not isinstance(d, (int, float)): errs.append(f"{path}: expected number, got {act}")
                elif exp == "string" and not isinstance(d, str): errs.append(f"{path}: expected string, got {act}")
                elif exp == "boolean" and not isinstance(d, bool): errs.append(f"{path}: expected boolean, got {act}")
                elif exp == "array" and not isinstance(d, list): errs.append(f"{path}: expected array, got {act}")
                elif exp == "object" and not isinstance(d, dict): errs.append(f"{path}: expected object, got {act}")
            if "enum" in sch and d not in sch["enum"]: errs.append(f"{path}: value not in enum")
            if "minimum" in sch and isinstance(d, (int, float)) and d < sch["minimum"]: errs.append(f"{path}: {d} < min {sch['minimum']}")
            if "maximum" in sch and isinstance(d, (int, float)) and d > sch["maximum"]: errs.append(f"{path}: {d} > max {sch['maximum']}")
            if isinstance(d, dict):
                if "required" in sch:
                    for rk in sch["required"]:
                        if rk not in d: errs.append(f"{path}.{rk}: required key missing")
                if "properties" in sch:
                    for pk, ps in sch["properties"].items():
                        if pk in d: _walk(ps, d[pk], f"{path}.{pk}")
        _walk(schema, self._d, "$"); return errs

    def get_analyzer_config(self, name: str) -> AnalyzerConfig:
        """按名称返回分析器配置；未配置时返回该名称的默认配置。"""
        data = self.get(f"analyzers.{name}")
        if not isinstance(data, dict):
            data = {}
        return AnalyzerConfig(
            name=name,
            enabled=bool(data.get("enabled", True)),
            timeout=float(data.get("timeout", 300.0)),
            parameters=data.get("parameters", {}),
            options=data.get("options", {}),
        )

class ConfigSource(str, Enum):
    """配置来源优先级：default < yaml_file < environment < target"""
    DEFAULT = "default"
    FILE = "file"
    YAML_FILE = "yaml_file"
    ENV = "env"
    ENVIRONMENT = "environment"
    TARGET = "target"


@dataclass
class TargetConfig:
    """目标二进制配置封装。"""
    name: str = ''
    binary_path: str = ''
    arch: str = 'x86_64'
    os_type: str = 'linux'
    analysis_depth: int = 3
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "binary_path": self.binary_path,
            "arch": self.arch,
            "os_type": self.os_type,
            "analysis_depth": self.analysis_depth,
            "extra": self.extra,
        }


@dataclass
class AnalyzerConfig:
    """分析器配置封装。"""
    name: str = 'default'
    enabled: bool = True
    timeout: float = 300.0
    parameters: Dict[str, Any] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "timeout": self.timeout,
            "parameters": self.parameters,
            "options": self.options,
        }


def create_config_manager(defaults=None): return ConfigManager(defaults)
module: str = ""


def _debug_print(*a, **kw):
    if _os.environ.get("BINMIND_DEBUG"):
        print(*a, **kw)

