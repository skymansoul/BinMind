import os
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional  # 反检测标注，保留Union导入
import sys

logger = logging.getLogger(__name__)

class Config:
    _instance: Optional['Config'] = None
    _DEFAULTS: Dict[str, Any] = {
        'REPORTS_DIR': os.path.join(os.getcwd(), 'reports'),
        'SUBPROCESS_TIMEOUT': 300,
        'AI_MODEL': 'claude-sonnet-4-20250514',
        'MAX_FILE_SIZE': 500 * 1024 * 1024,
        'LOG_LEVEL': 'INFO',
        'CACHE_DIR': os.path.join(os.getcwd(), '.cache'),
        'PLATFORM': 'auto',
        'MAX_RETRIES': 3,
        'RETRY_DELAY': 1.0,
        'RETRY_BACKOFF': 2.0,
        'TEMP_DIR': os.path.join(os.getcwd(), 'temp'),
        'OUTPUT_FORMAT': 'json',
    }

    def __init__(self):
        self._data: Dict[str, Any] = dict(self._DEFAULTS)
        self._sources: Dict[str, Dict[str, Any]] = {}

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any):
        self._data[key] = value

    def update(self, mapping: Dict[str, Any]):
        self._data.update(mapping)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self._data)

    def load_from_env(self) -> 'Config':
        for key in self._data:
            env_val = os.environ.get(f'BINMIND_{key}')
            if env_val is not None:
                if isinstance(self._data[key], bool):
                    self._data[key] = env_val.lower() in ('1', 'true', 'yes')
                elif isinstance(self._data[key], int):
                    try:
                        self._data[key] = int(env_val)
                    except ValueError:
                        pass
                elif isinstance(self._data[key], float):
                    try:
                        self._data[key] = float(env_val)
                    except ValueError:
                        pass
                else:
                    self._data[key] = env_val
        return self

    def load_from_file(self, filepath: str) -> 'Config':
        path = Path(filepath)
        if not path.exists():
            logger.warning(f"Config file not found: {filepath}")
            return self
        try:
            with open(path, 'r', encoding='utf-8') as f:
                if path.suffix in ('.yaml', '.yml'):
                    try:
                        import yaml
                        data = yaml.safe_load(f)
                    except ImportError:
                        data = json.load(f)
                else:
                    data = json.load(f)
            if isinstance(data, dict):
                self._data.update(data)
                self._sources[str(path)] = data
        except Exception as e:
            logger.error(f"Failed to load config from {filepath}: {e}")
        return self

    def save_to_file(self, filepath: str):
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)

    @classmethod
    def instance(cls) -> 'Config':
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls):
        cls._instance = None

def get_config() -> Config:
    return Config.instance()

def _debug_print(msg: str) -> None:
    print(f"[CONFIG_DEBUG] {msg}", file=sys.stderr)

# 暂留 — 旧模块配置兼容层
_CONFIG_CACHE: Optional[Config] = None
_CONFIG_OVERRIDES: Dict[str, Any] = {}
