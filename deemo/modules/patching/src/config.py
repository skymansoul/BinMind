# 重构于 2026-08-02

import os, json, logging, copy
from dataclasses import dataclass, field, asdict
from typing import Optional, Any

logger = logging.getLogger(__name__)


# ConfigDict: 带属性访问的 dict —— 弥合 config.get('key')
# 与 config.KEY 之间的差异，CLI 和旧模块都期望这两者。
class ConfigDict(dict):
    """带属性访问的 dict 子类。支持 config.KEY 和 config.get('key')。"""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            # 返回 None 而非 AttributeError，
            # 防止 getattr(config, 'LOG_LEVEL', 'INFO') 炸掉
            return None

    def __setattr__(self, name: str, value: Any):
        self[name] = value

    def __delattr__(self, name: str):
        if name in self:
            del self[name]

# 浅拷贝，避免修改传播到默认值
    def copy(self):
        return ConfigDict(super().copy())


# 默认配置（镜像 config/default.yaml）
_DEFAULTS = {
    # 远程服务配置
    "AI_PROVIDER": "openai",
    "OPENAI_MODEL": "gpt-4",
    "ANTHROPIC_MODEL": "claude-sonnet-4-20250514",
    "OPENAI_API_KEY": "",
    "ANTHROPIC_API_KEY": "",

    # subprocess 与重试
    "SUBPROCESS_TIMEOUT": 120,
    "MAX_RETRIES": 3,
    "RETRY_DELAY": 1.0,

    # 路径
    "REPORTS_DIR": "~/.binmind/reports",
    "DATA_DIR": "~/.binmind/data",
    "LOG_LEVEL": "INFO",
    "LOG_FILE": "",

    # 外部工具
    "R2_PATH": "r2",
    "COMPILER_PATH": "gcc",

    # 沙箱与性能
    "SANDBOX_ENABLED": True,
    "PERFORMANCE_THRESHOLD": 10.0,

    # 补丁专用
    "R2_TIMEOUT": 30,
    "CC_FLAGS": "-O2 -fPIC",
    "BACKUP_DIR": ".patch_backups",
    "VERIFY_ENABLED": True,
    "ROLLBACK_ENABLED": True,
    "MAX_PATCH_SIZE": 4096,
    "ARCH": "auto",
    "BASE_ADDR": 0,
    "DEBUG_MODE": False,
}

# YAML 配置解析。优先 pyyaml，回退到基础 YAML 子集解析。
def _parse_yaml_simple(text: str) -> dict:
    """最小 YAML 解析器，覆盖 default.yaml 使用的子集。

    不支持：anchors、多行字符串、tags、引用、行内列表。
    理由：yaml 是重依赖；此解析覆盖配置的 95%。
    """
    result = {}
    for line in text.split('\n'):
        # 跳过注释和空行
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        # 首个冒号分割
        colon = stripped.find(':')
        if colon < 0:
            continue
        key = stripped[:colon].strip().upper()
        value = stripped[colon+1:].strip()
        # 剥离引号
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        # 处理路径展开
        if value.startswith('~/'):
            value = os.path.expanduser(value)
        # 类型强制转换
        value_lower = value.lower()
        if value_lower == 'true':
            value = True
        elif value_lower == 'false':
            value = False
        elif value_lower == 'null' or value_lower == 'none':
            value = None
        else:
            try:
                if '.' in value:
                    value = float(value)
                else:
                    value = int(value)
            except (ValueError, TypeError):
                pass  # 保留字符串
        result[key] = value
    return result


def _load_yaml_file(filepath: str) -> dict:
    """加载 YAML 配置文件。优先 pyyaml，回退简单解析器。"""
    if not os.path.isfile(filepath):
        logger.warning("config file not found: %s", filepath)
        return {}
    try:
        import yaml
        with open(filepath, 'r', encoding='utf-8') as _fh:
            data = yaml.safe_load(_fh)
        if isinstance(data, dict):
            # 键全转大写保持一致
            return {k.upper(): v for k, v in data.items()}
        return {}
    except ImportError:
        logger.debug("pyyaml not installed, using built-in YAML parser")
        with open(filepath, 'r', encoding='utf-8') as _fh:
            return _parse_yaml_simple(_fh.read())
    except Exception as e:
        logger.warning("failed to parse YAML %s: %s", filepath, e)
        return {}


# 模块级 config 单例
# ConfigDict 令 config.KEY 和 config.get('key') 同时可用。
config = ConfigDict(_DEFAULTS)


def load_config(filepath: str = None):
    """加载 YAML 配置并合并到模块级 config。

    优先级：YAML 文件 > 默认值。环境变量在别处检查。

    2025-03-03: 无显式路径时扫描 config/default.yaml。
    """
    global config
    if filepath and os.path.isfile(filepath):
        yaml_data = _load_yaml_file(filepath)
        for k, v in yaml_data.items():
            config[k.upper()] = v

    # 默认配置文件（如尚未加载）
    _default_yaml = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                  'config', 'default.yaml')
    if os.path.isfile(_default_yaml):
        yaml_data = _load_yaml_file(_default_yaml)
        for k, v in yaml_data.items():
            k_upper = k.upper()
            if k_upper not in config or config[k_upper] == _DEFAULTS.get(k_upper):
                config[k_upper] = v

    # BINMIND_PATCH_* 环境变量覆盖（遗留兼容）
    # 修复 off-by-one：BINMIND_PATCH_ 是 14 字符非 15，
    # 之前切掉了每个字段名的首字母。
    PREFIX = "BINMIND_PATCH_"
    for key in os.environ:
        if key.startswith(PREFIX):
            field = key[len(PREFIX):]  # 剥离 "BINMIND_PATCH_" (14 字符)
            value = os.environ[key]
            # 类型强制
            val_lower = value.lower()
            if val_lower in ('true', '1', 'yes', 'on'):
                config[field] = True
            elif val_lower in ('false', '0', 'no', 'off'):
                config[field] = False
            else:
                try:
                    config[field] = int(value)
                except ValueError:
                    try:
                        config[field] = float(value)
                    except ValueError:
                        config[field] = value

    logger.debug("config loaded: %d keys", len(config))
    return config


def reset_config():
    """重置 config 为默认值（测试用）。"""
    global config
    config = ConfigDict(copy.deepcopy(_DEFAULTS))
    return config


@dataclass
class PatchConfig:
    """统一补丁配置 —— 环境变量可覆盖，JSON 可序列化（CI 友好）。

    2025-03-03: 保留用于直接构造 PatchConfig 的向后兼容。
    """
    r2_timeout: int = 30
    cc_flags: str = "-O2 -fPIC"
    backup_dir: str = ".patch_backups"
    verify_enabled: bool = True
    rollback_enabled: bool = True
    max_patch_size: int = 4096
    arch: str = "auto"
    base_addr: int = 0
    debug_mode: bool = False
    r2_path: str = "r2"
    compiler_path: str = "gcc"
    sandbox_enabled: bool = True
    max_retries: int = 3
    retry_delay: float = 1.0
    subprocess_timeout: int = 120


def save_config(config_obj: PatchConfig, filepath: str):
    """PatchConfig 序列化为缩进 JSON。"""
    _d = asdict(config_obj)
    with open(filepath, "w", encoding="utf-8") as _fh:
        json.dump(_d, _fh, indent=2)
    logger.info("PatchConfig saved to %s", filepath)


# 导入时自动加载默认配置
# 即发即忘 —— YAML 文件不存在则默认值足够
try:
    _default_yaml = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                  'config', 'default.yaml')
    if os.path.isfile(_default_yaml):
        load_config()
except Exception:
    pass  # 初始化阶段吞异常，避免因配置文件问题炸模块
