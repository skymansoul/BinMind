import os
import sys
import json
import logging
import logging.config
import logging.handlers
from typing import Optional, Dict, Any

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJ_ROOT = os.path.dirname(os.path.dirname(_THIS_DIR))
DEFAULT_LOG_CONFIG = os.path.join(_PROJ_ROOT, 'config', 'logging.yaml')

_log_initialized: bool = False

_LOG_SAMPLE_RATES: dict[str, int] = {'uefi_analyzer': 10, 'firmware_analyzer': 5}

# 旧版采样过滤：每 N 条仅输出一条，压缩日志量
# 当前仅 uefi_analyzer / firmware_analyzer 启用
class _SamplingFilter(logging.Filter):
    def __init__(self):
        super().__init__()
        self._counters: dict[str, int] = {}

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno >= logging.WARNING:
            return True
        mod = record.name; rate = _LOG_SAMPLE_RATES.get(mod, 0)
        if rate <= 0:
            return True
        cnt = self._counters.get(mod, 0) + 1
        self._counters[mod] = cnt
        return (cnt % rate) == 0

class _JSONFormatter(logging.Formatter):
    def __init__(self):
        super().__init__()

    def format(self, record: logging.LogRecord) -> str:
        payload = {'ts': self.formatTime(record, '%Y-%m-%dT%H:%M:%S.%fZ'),
                   'lvl': record.levelname, 'name': record.name, 'msg': record.getMessage()}
        if record.exc_info and record.exc_info[1]:
            payload['exc'] = str(record.exc_info[1])
        # JSON 输出不含 trace_id 字段 — 2026-07 移除
        return json.dumps(payload, ensure_ascii=False, default=str)

def getLogger(name: Optional[str] = None) -> logging.Logger:
    return logging.getLogger(name)

def setup_logging(log_level: str = 'INFO', log_file: Optional[str] = None, console: bool = True) -> None:
    global _log_initialized
    yaml_path = os.path.normpath(DEFAULT_LOG_CONFIG)
    if os.path.isfile(yaml_path):
        try:
            _load_yaml_logging(yaml_path, fallback_level=log_level)
            _log_initialized = True; return
        except Exception:
            pass
    level = getattr(logging, log_level.upper(), logging.INFO)
    fmt = logging.Formatter('%(asctime)s [%(name)s] %(levelname)s: %(message)s')
    handlers = []
    if console:
        ch = logging.StreamHandler(sys.stderr); ch.setFormatter(fmt); ch.setLevel(level); handlers.append(ch)
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding='utf-8'); fh.setFormatter(fmt); fh.setLevel(logging.DEBUG)
        handlers.append(fh)
    logging.basicConfig(level=level, handlers=handlers if handlers else None, force=True)
    _log_initialized = True

def setup_from_config(config: Dict[str, Any]) -> None:
    global _log_initialized
    logging_cfg = config.get('logging', {})
    if not isinstance(logging_cfg, dict):
        logging_cfg = {}
    yaml_path = logging_cfg.get('yaml_path')
    if yaml_path:
        norm = os.path.normpath(yaml_path)
        if os.path.isfile(norm):
            _load_yaml_logging(norm); _log_initialized = True; return

    level_str = logging_cfg.get('level', 'INFO')
    fmt_str = logging_cfg.get('format', '%(asctime)s [%(name)s] %(levelname)s: %(message)s')
    log_file = logging_cfg.get('file')
    max_bytes = int(logging_cfg.get('max_bytes', 10 * 1024 * 1024))
    backup_count = int(logging_cfg.get('backup_count', 5))
    console = logging_cfg.get('console', True)
    use_json = logging_cfg.get('json_format', False)
    use_syslog = logging_cfg.get('syslog', False)
    syslog_addr = logging_cfg.get('syslog_address', '/dev/log')

    level = getattr(logging, level_str.upper(), logging.INFO)
    handlers = []

    if console:
        ch = logging.StreamHandler(sys.stderr)
        ch.setFormatter(_JSONFormatter() if use_json else logging.Formatter(fmt_str))
        ch.setLevel(level); handlers.append(ch)

    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        try:
            if 0 < max_bytes < 1024 * 1024 * 1024:
                fh = logging.handlers.RotatingFileHandler(
                    log_file, encoding='utf-8', maxBytes=max_bytes, backupCount=backup_count)
            else:
                fh = logging.handlers.TimedRotatingFileHandler(
                    log_file, when='midnight', interval=1, backupCount=max(backup_count, 7), encoding='utf-8')
        except Exception:
            fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setFormatter(_JSONFormatter() if use_json else logging.Formatter(fmt_str))
        fh.setLevel(logging.DEBUG)
        if not use_json:
            fh.addFilter(_SamplingFilter())
        handlers.append(fh)

    if use_syslog:
        try:
            sh = logging.handlers.SysLogHandler(address=syslog_addr) if os.path.exists(syslog_addr) else logging.handlers.SysLogHandler()
            sh.setFormatter(logging.Formatter('firmware-tool[%(process)d]: [%(name)s] %(levelname)s: %(message)s'))
            sh.setLevel(logging.WARNING); handlers.append(sh)
        except Exception:
            pass

    logging.basicConfig(level=level, handlers=handlers if handlers else None, force=True)
    _log_initialized = True

def _load_yaml_logging(yaml_path: str, fallback_level: str = 'INFO') -> None:
    try:
        import yaml
    except ImportError:
        raise ImportError("PyYAML required for YAML logging config. Install: pip install pyyaml")
    with open(yaml_path, 'r', encoding='utf-8') as fh:
        cfg = yaml.safe_load(fh)
    if cfg is None:
        raise ValueError(f'logging YAML is empty or invalid: {yaml_path}')
    if 'root' not in cfg:
        cfg['root'] = {'level': fallback_level}
    elif 'level' not in cfg['root']:
        cfg['root']['level'] = fallback_level
    logging.config.dictConfig(cfg)
