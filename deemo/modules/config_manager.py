import os
import json
from typing import Dict, Any, Optional, Union
from pathlib import Path

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    import toml
    TOML_AVAILABLE = True
except ImportError:
    TOML_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

ENCRYPTION_KEY_ENV = "BINARY_ANALYZER_ENCRYPTION_KEY"
ENCRYPTED_FIELD_PREFIX = "_encrypted_"


def generate_encryption_key() -> str:
    """生成加密密钥"""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography 库不可用")
    return Fernet.generate_key().decode()


def get_encryption_key() -> bytes:
    """获取加密密钥"""
    key = os.environ.get(ENCRYPTION_KEY_ENV)
    if key:
        return key.encode()
    raise RuntimeError(f"加密密钥环境变量 {ENCRYPTION_KEY_ENV} 未设置")


def encrypt_value(value: str) -> str:
    """加密敏感值"""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography 库不可用")
    f = Fernet(get_encryption_key())
    return f.encrypt(value.encode()).decode()


def decrypt_value(encrypted_value: str) -> str:
    """解密敏感值"""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography 库不可用")
    f = Fernet(get_encryption_key())
    return f.decrypt(encrypted_value.encode()).decode()


class ConfigParser:
    """配置解析器 - 支持YAML/TOML/JSON格式"""
    
    @staticmethod
    def parse_file(file_path: Union[str, Path]) -> Dict[str, Any]:
        """解析配置文件"""
        path = Path(file_path)
        
        if not path.exists():
            return {}
        
        ext = path.suffix.lower()
        
        try:
            if ext in ['.yaml', '.yml']:
                if not YAML_AVAILABLE:
                    raise ImportError("PyYAML 库不可用")
                with open(path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f) or {}
            elif ext == '.toml':
                if not TOML_AVAILABLE:
                    raise ImportError("toml 库不可用")
                with open(path, 'r', encoding='utf-8') as f:
                    return toml.load(f)
            elif ext == '.json':
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                raise ValueError(f"不支持的配置文件格式: {ext}")
        except Exception as e:
            print(f"解析配置文件 {file_path} 失败: {e}")
            return {}
    
    @staticmethod
    def dump_to_file(data: Dict[str, Any], file_path: Union[str, Path], format: str = 'yaml') -> bool:
        """将配置写入文件"""
        path = Path(file_path)
        
        try:
            if format == 'yaml':
                if not YAML_AVAILABLE:
                    raise ImportError("PyYAML 库不可用")
                with open(path, 'w', encoding='utf-8') as f:
                    yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
            elif format == 'toml':
                if not TOML_AVAILABLE:
                    raise ImportError("toml 库不可用")
                with open(path, 'w', encoding='utf-8') as f:
                    toml.dump(data, f)
            elif format == 'json':
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            else:
                raise ValueError(f"不支持的配置格式: {format}")
            return True
        except Exception as e:
            print(f"写入配置文件 {file_path} 失败: {e}")
            return False


class EnvironmentOverride:
    """环境变量覆盖处理器"""
    
    @staticmethod
    def apply_overrides(config: Dict[str, Any], prefix: str = "BA_") -> Dict[str, Any]:
        """应用环境变量覆盖"""
        result = config.copy()
        
        for key, value in os.environ.items():
            if key.startswith(prefix):
                config_key = key[len(prefix):].lower().replace('_', '.')
                EnvironmentOverride._set_nested_value(result, config_key, value)
        
        return result
    
    @staticmethod
    def _set_nested_value(config: Dict[str, Any], key_path: str, value: str) -> None:
        """设置嵌套配置值"""
        keys = key_path.split('.')
        current = config
        
        for i, key in enumerate(keys[:-1]):
            if key not in current:
                current[key] = {}
            current = current[key]
        
        final_key = keys[-1]
        try:
            if value.lower() == 'true':
                current[final_key] = True
            elif value.lower() == 'false':
                current[final_key] = False
            elif value.isdigit():
                current[final_key] = int(value)
            elif '.' in value and value.replace('.', '').isdigit():
                current[final_key] = float(value)
            else:
                current[final_key] = value
        except:
            current[final_key] = value


class SensitiveFieldHandler:
    """敏感字段处理器"""
    
    @staticmethod
    def decrypt_config(config: Dict[str, Any]) -> Dict[str, Any]:
        """解密配置中的敏感字段"""
        result = {}
        
        for key, value in config.items():
            if key.startswith(ENCRYPTED_FIELD_PREFIX):
                try:
                    decrypted = decrypt_value(value)
                    result[key[len(ENCRYPTED_FIELD_PREFIX):]] = decrypted
                except Exception as e:
                    print(f"解密字段 {key} 失败: {e}")
                    result[key] = value
            elif isinstance(value, dict):
                result[key] = SensitiveFieldHandler.decrypt_config(value)
            else:
                result[key] = value
        
        return result
    
    @staticmethod
    def encrypt_config(config: Dict[str, Any], sensitive_keys: Optional[list] = None) -> Dict[str, Any]:
        """加密配置中的敏感字段"""
        sensitive_keys = sensitive_keys or ['api_key', 'password', 'secret', 'token']
        result = {}
        
        for key, value in config.items():
            if isinstance(value, dict):
                result[key] = SensitiveFieldHandler.encrypt_config(value, sensitive_keys)
            elif isinstance(value, str):
                key_lower = key.lower()
                if any(sk in key_lower for sk in sensitive_keys):
                    result[ENCRYPTED_FIELD_PREFIX + key] = encrypt_value(value)
                else:
                    result[key] = value
            else:
                result[key] = value
        
        return result


class ConfigManager:
    """配置管理器 - 支持分层配置、环境变量覆盖、敏感字段加密"""
    
    _instance = None
    
    def __new__(cls, config_dir: Optional[str] = None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
            cls._instance._config_dir = config_dir
        return cls._instance
    
    def initialize(self, config_dir: Optional[str] = None):
        """初始化配置管理器"""
        if self._initialized:
            return
        
        self._config_dir = Path(config_dir) if config_dir else Path(__file__).parent.parent / "config"
        self._config_data: Dict[str, Any] = {}
        self._load_config()
        self._initialized = True
    
    def _load_config(self):
        """加载配置（分层加载）"""
        config_sources = [
            self._config_dir / "defaults.yaml",
            self._config_dir / "config.yaml",
            self._config_dir / "secrets.yaml",
            Path(os.environ.get("BA_CONFIG_FILE", "")),
        ]
        
        for source in config_sources:
            if source and source.exists():
                self._merge_config(ConfigParser.parse_file(source))
        
        self._config_data = EnvironmentOverride.apply_overrides(self._config_data)
        self._config_data = SensitiveFieldHandler.decrypt_config(self._config_data)
    
    def _merge_config(self, new_config: Dict[str, Any]):
        """递归合并配置"""
        for key, value in new_config.items():
            if key in self._config_data and isinstance(self._config_data[key], dict) and isinstance(value, dict):
                self._merge_config_nested(self._config_data[key], value)
            else:
                self._config_data[key] = value
    
    def _merge_config_nested(self, existing: Dict[str, Any], new: Dict[str, Any]):
        """嵌套合并配置"""
        for key, value in new.items():
            if key in existing and isinstance(existing[key], dict) and isinstance(value, dict):
                self._merge_config_nested(existing[key], value)
            else:
                existing[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值（支持点分隔的嵌套路径）"""
        keys = key.split('.')
        current = self._config_data
        
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
        
        return current
    
    def set(self, key: str, value: Any) -> bool:
        """设置配置值（支持点分隔的嵌套路径）"""
        keys = key.split('.')
        current = self._config_data
        
        for i, k in enumerate(keys[:-1]):
            if k not in current:
                current[k] = {}
            current = current[k]
        
        current[keys[-1]] = value
        return True
    
    def save_config(self, file_path: Union[str, Path], format: str = 'yaml', encrypt: bool = False) -> bool:
        """保存配置到文件"""
        data = self._config_data
        if encrypt:
            data = SensitiveFieldHandler.encrypt_config(data)
        return ConfigParser.dump_to_file(data, file_path, format)
    
    def reload(self):
        """重新加载配置"""
        self._config_data = {}
        self._load_config()
    
    @property
    def config_data(self) -> Dict[str, Any]:
        """获取完整配置数据"""
        return self._config_data
    
    @property
    def is_initialized(self) -> bool:
        """检查是否已初始化"""
        return self._initialized


def get_config_manager() -> ConfigManager:
    """获取全局配置管理器实例"""
    return ConfigManager()


def init_config(config_dir: Optional[str] = None):
    """初始化配置"""
    manager = ConfigManager()
    manager.initialize(config_dir)


def create_default_config(config_dir: str):
    """创建默认配置目录和文件"""
    dir_path = Path(config_dir)
    dir_path.mkdir(parents=True, exist_ok=True)
    
    defaults = {
        "logging": {
            "level": "INFO",
            "format": "json",
            "file": "logs/binary_analyzer.log"
        },
        "paths": {
            "data": "data",
            "temp": "temp",
            "results": "results",
            "cache": "cache",
            "reports": "reports"
        },
        "analysis": {
            "timeout": 300,
            "max_iterations": 5,
            "default_decompiler": "auto",
            "enable_symbolic_execution": True
        },
        "ai": {
            "provider": "openai",
            "timeout": 60,
            "max_tokens": 4096,
            "temperature": 0.7
        },
        "resource": {
            "memory_limit_mb": 4096,
            "cpu_cores": 4
        }
    }
    
    ConfigParser.dump_to_file(defaults, dir_path / "defaults.yaml")
    
    if not (dir_path / "config.yaml").exists():
        ConfigParser.dump_to_file({}, dir_path / "config.yaml")
    
    if not (dir_path / "secrets.yaml").exists():
        ConfigParser.dump_to_file({}, dir_path / "secrets.yaml")


# ---------------------------------------------------------------------------
# 兼容性别名与扩展类 (Compatible aliases & extension classes)
# 下面的定义为兼容 __init__.py 的导出而添加, 遵循"只增加代码不删除"原则。
# ---------------------------------------------------------------------------

class ConfigSource:
    """配置来源标识 (兼容性别名)"""

    FILE = "file"
    ENV = "env"
    DEFAULT = "default"
    RUNTIME = "runtime"
    REMOTE = "remote"

    def __init__(self, source_type: str = "file", path: Optional[str] = None):
        self.source_type = source_type
        self.path = path

    def __repr__(self) -> str:
        return f"ConfigSource(type={self.source_type}, path={self.path})"


class TargetConfig:
    """目标二进制/分析目标的配置封装"""

    def __init__(
        self,
        name: str = "",
        path: str = "",
        arch: str = "x86_64",
        os_type: str = "linux",
        analysis_depth: int = 3,
        extra: Optional[Dict[str, Any]] = None,
    ):
        self.name = name
        self.path = path
        self.arch = arch
        self.os_type = os_type
        self.analysis_depth = analysis_depth
        self.extra = extra or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "arch": self.arch,
            "os_type": self.os_type,
            "analysis_depth": self.analysis_depth,
            "extra": self.extra,
        }


class AnalyzerConfig:
    """分析器配置封装"""

    def __init__(
        self,
        name: str = "default",
        enabled: bool = True,
        timeout: float = 300.0,
        options: Optional[Dict[str, Any]] = None,
    ):
        self.name = name
        self.enabled = enabled
        self.timeout = timeout
        self.options = options or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "timeout": self.timeout,
            "options": self.options,
        }


def create_config_manager(config_dir: Optional[str] = None) -> ConfigManager:
    """创建并初始化配置管理器 (便捷入口)"""
    manager = ConfigManager(config_dir=config_dir)
    manager.initialize(config_dir)
    return manager