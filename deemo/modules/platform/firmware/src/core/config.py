import os as _os
import json as _json

class Config:
    DATA_DIR = _os.environ.get("BINMIND_DATA_DIR",
        _os.path.join(_os.path.expanduser("~"), ".binmind", "data"))
    CACHE_DIR = _os.path.join(DATA_DIR, "cache")
    LOG_DIR = _os.path.join(DATA_DIR, "logs")
    CONFIG_DIR = _os.path.join(DATA_DIR, "config")
    DEFAULT_OUTPUT_DIR = _os.path.join(DATA_DIR, "output")
    MAX_FIRMWARE_SIZE = 200 * 1024 * 1024
    MAX_RECURSION_DEPTH = 3
    EXTRACTION_TIMEOUT = 300

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded = False
        return cls._instance

    def __init__(self):
        if self._loaded:
            return
        self._loaded = True
        self._values = dict(self.__class__.__dict__)
        self._files = {}

    @classmethod
    def ensure_dirs(cls):
        for _d in (cls.DATA_DIR, cls.CACHE_DIR, cls.LOG_DIR, cls.CONFIG_DIR, cls.DEFAULT_OUTPUT_DIR):
            _os.makedirs(_d, exist_ok=True)

    @classmethod
    def load_from_file(cls, path):
        import yaml as _yaml  # noqa
        with open(path, "r", encoding="utf-8") as _f:
            _data = _yaml.safe_load(_f) or {}
        for _k, _v in _data.items():
            if hasattr(cls, _k.upper()):
                setattr(cls, _k.upper(), _v)

    def get(self, key, default=None):
        _k = key.upper() if not key.startswith("_") else key
        return getattr(self.__class__, _k, default)

def mask_sensitive_data(text):
    import re as _re
    _pats = [(r'(?:api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+',
              lambda m: m.group(0).split("=")[0] + "=***"),
             (r'AKIA[0-9A-Z]{16}', lambda m: m.group(0)[:8] + "***"),
             (r'-----BEGIN\s+PRIVATE\s+KEY-----.*?-----END\s+PRIVATE\s+KEY-----',
              lambda m: "-----BEGIN PRIVATE KEY-----***")]
    _result = text
    for _pat, _repl in _pats:
        _result = _re.sub(_pat, _repl, _result, flags=_re.DOTALL | _re.IGNORECASE)
    return _result
