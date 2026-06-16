"""
层次化配置管理系统

支持：
1. YAML 层次化配置
2. 环境变量覆盖
3. Per-target 配置
4. 敏感信息加密存储
"""

import os
import yaml
import json
import logging
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

CRYPTO_AVAILABLE = False
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    CRYPTO_AVAILABLE = True
except ImportError:
    logger.warning("cryptography 模块未安装，加密功能不可用")


class ConfigSource(Enum):
    """配置来源枚举"""
    DEFAULT = "default"
    YAML_FILE = "yaml_file"
    ENVIRONMENT = "environment"
    TARGET = "target"
    COMMAND_LINE = "command_line"
    ENCRYPTED = "encrypted"


class SensitiveData:
    """敏感数据包装器"""
    
    def __init__(self, value: str, encrypted: bool = False):
        self.value = value
        self.encrypted = encrypted
        self._masked = None
    
    @property
    def masked(self) -> str:
        """返回掩码形式（用于日志）"""
        if self._masked is None:
            if len(self.value) <= 4:
                self._masked = "****"
            else:
                self._masked = self.value[:2] + "*" * (len(self.value) - 4) + self.value[-2:]
        return self._masked


@dataclass
class TargetConfig:
    """目标特定配置"""
    name: str
    binary_path: str
    settings: Dict[str, Any] = field(default_factory=dict)
    analyzers: List[str] = field(default_factory=list)
    timeout: Optional[int] = None
    memory_limit: Optional[int] = None


@dataclass
class AnalyzerConfig:
    """分析器配置"""
    name: str
    enabled: bool = True
    parameters: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)


class ConfigManager:
    """
    层次化配置管理器
    
    配置优先级（从低到高）：
    1. 默认配置
    2. YAML 文件配置
    3. 环境变量覆盖
    4. Per-target 配置
    5. 命令行参数
    6. 加密配置文件
    """
    
    def __init__(
        self,
        config_dir: str = "config",
        target_config_dir: str = "config/targets",
        encryption_key: Optional[bytes] = None
    ):
        """
        初始化配置管理器
        
        Args:
            config_dir: 配置目录
            target_config_dir: Per-target配置目录
            encryption_key: 加密密钥
        """
        self.config_dir = Path(config_dir)
        self.target_config_dir = Path(target_config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.target_config_dir.mkdir(parents=True, exist_ok=True)
        
        self._encryption_key = encryption_key
        self._cipher = None
        if encryption_key and CRYPTO_AVAILABLE:
            self._cipher = Fernet(self._derive_key(encryption_key))
        elif encryption_key and not CRYPTO_AVAILABLE:
            logger.warning("cryptography 模块不可用，加密功能将被禁用")
        
        self._config_cache: Dict[str, Any] = {}
        self._configs_by_source: Dict[str, Dict[str, Any]] = {}
        self._target_configs: Dict[str, TargetConfig] = {}
        self._analyzer_configs: Dict[str, AnalyzerConfig] = {}
        
        self._load_default_config()
        self._load_yaml_configs()
        self._load_environment_overrides()
    
    def _derive_key(self, password: bytes) -> bytes:
        """从密码派生加密密钥"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'binary_analysis_platform_salt',
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def _encrypt_value(self, value: str) -> str:
        """加密敏感值"""
        if not self._cipher:
            logger.warning("加密密钥未设置，跳过加密")
            return value
        
        encrypted = self._cipher.encrypt(value.encode())
        return base64.b64encode(encrypted).decode()
    
    def _decrypt_value(self, encrypted_value: str) -> str:
        """解密敏感值"""
        if not self._cipher:
            logger.warning("加密密钥未设置，尝试直接解码")
            return encrypted_value
        
        try:
            decoded = base64.b64decode(encrypted_value.encode())
            decrypted = self._cipher.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"解密失败: {e}")
            return encrypted_value
    
    def _load_default_config(self) -> None:
        """加载默认配置"""
        self._configs_by_source[ConfigSource.DEFAULT.value] = {
            "analysis": {
                "max_workers": 4,
                "timeout": 300,
                "memory_limit": 2048,
                "incremental": True,
                "cache_dir": "data/cache"
            },
            "symbolic_execution": {
                "max_steps": 1000,
                "max_memory": 1024,
                "timeout": 600,
                "enable_simulation": True
            },
            "fuzzing": {
                "max_iterations": 10000,
                "timeout": 3600,
                "corpus_dir": "data/corpus",
                "use_sandbox": True
            },
            "reporting": {
                "format": "markdown",
                "output_dir": "data/reports",
                "include_source": True
            },
            "security": {
                "sandbox_enabled": True,
                "max_file_size": 104857600,
                "max_network_connections": 10
            },
            "plugins": {
                "plugins_dir": "plugins",
                "auto_load": True
            }
        }
        self._config_cache.update(self._configs_by_source[ConfigSource.DEFAULT.value])
    
    def _load_yaml_configs(self) -> None:
        """加载 YAML 配置文件"""
        config_files = [
            self.config_dir / "default.yaml",
            self.config_dir / "analysis.yaml",
            self.config_dir / "security.yaml"
        ]
        
        for config_file in config_files:
            if config_file.exists():
                try:
                    with open(config_file, 'r', encoding='utf-8') as f:
                        config_data = yaml.safe_load(f)
                    
                    if config_data:
                        self._configs_by_source[ConfigSource.YAML_FILE.value] = config_data
                        self._merge_config(config_data)
                        logger.info(f"加载YAML配置: {config_file}")
                except Exception as e:
                    logger.error(f"加载YAML配置失败 {config_file}: {e}")
    
    def _load_environment_overrides(self) -> None:
        """从环境变量加载配置覆盖"""
        env_prefix = "BINARY_ANALYSIS_"
        
        env_configs = {}
        for key, value in os.environ.items():
            if key.startswith(env_prefix):
                config_key = key[len(env_prefix):].lower()
                
                parts = config_key.split("_")
                current = env_configs
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                
                current[parts[-1]] = self._parse_env_value(value)
        
        if env_configs:
            self._configs_by_source[ConfigSource.ENVIRONMENT.value] = env_configs
            self._merge_config(env_configs)
            logger.info(f"从环境变量加载 {len(env_configs)} 个配置项")
    
    def _parse_env_value(self, value: str) -> Any:
        """解析环境变量值"""
        if value.lower() == "true":
            return True
        elif value.lower() == "false":
            return False
        elif value.lower() == "none":
            return None
        
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            return value
    
    def _merge_config(self, new_config: Dict[str, Any], priority: str = "override") -> None:
        """合并配置"""
        def deep_merge(base: Dict, override: Dict) -> Dict:
            result = base.copy()
            for key, value in override.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = deep_merge(result[key], value)
                else:
                    result[key] = value
            return result
        
        self._config_cache = deep_merge(self._config_cache, new_config)
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        获取配置值
        
        Args:
            key: 配置键（支持点号分隔，如 'analysis.max_workers'）
            default: 默认值
            
        Returns:
            配置值
        """
        keys = key.split(".")
        value = self._config_cache
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any, source: ConfigSource = ConfigSource.DEFAULT) -> None:
        """
        设置配置值
        
        Args:
            key: 配置键
            value: 配置值
            source: 配置来源
        """
        keys = key.split(".")
        current = self._config_cache
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        current[keys[-1]] = value
        
        if source.value not in self._configs_by_source:
            self._configs_by_source[source.value] = {}
        
        target = self._configs_by_source[source.value]
        for k in keys[:-1]:
            if k not in target:
                target[k] = {}
            target = target[k]
        target[keys[-1]] = value
    
    def get_sensitive(self, key: str) -> Optional[str]:
        """
        获取敏感配置值（解密后）
        
        Args:
            key: 配置键
            
        Returns:
            解密后的值，如果不存在返回 None
        """
        encrypted_value = self.get(f"sensitive.{key}")
        if encrypted_value:
            return self._decrypt_value(encrypted_value)
        return None
    
    def set_sensitive(self, key: str, value: str) -> None:
        """
        设置敏感配置值（加密存储）
        
        Args:
            key: 配置键
            value: 明文值
        """
        encrypted = self._encrypt_value(value)
        self.set(f"sensitive.{key}", encrypted, ConfigSource.ENCRYPTED)
    
    def load_target_config(self, target_name: str) -> Optional[TargetConfig]:
        """
        加载目标特定配置
        
        Args:
            target_name: 目标名称
            
        Returns:
            TargetConfig 对象
        """
        if target_name in self._target_configs:
            return self._target_configs[target_name]
        
        target_file = self.target_config_dir / f"{target_name}.yaml"
        if not target_file.exists():
            return None
        
        try:
            with open(target_file, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            target_config = TargetConfig(
                name=config_data.get("name", target_name),
                binary_path=config_data.get("binary_path", ""),
                settings=config_data.get("settings", {}),
                analyzers=config_data.get("analyzers", []),
                timeout=config_data.get("timeout"),
                memory_limit=config_data.get("memory_limit")
            )
            
            self._target_configs[target_name] = target_config
            self._configs_by_source[f"target:{target_name}"] = config_data
            
            logger.info(f"加载目标配置: {target_name}")
            return target_config
            
        except Exception as e:
            logger.error(f"加载目标配置失败 {target_name}: {e}")
            return None
    
    def save_target_config(self, target_config: TargetConfig) -> bool:
        """
        保存目标特定配置
        
        Args:
            target_config: 目标配置对象
            
        Returns:
            是否成功保存
        """
        target_file = self.target_config_dir / f"{target_config.name}.yaml"
        
        try:
            with open(target_file, 'w', encoding='utf-8') as f:
                yaml.dump(asdict(target_config), f, default_flow_style=False)
            
            self._target_configs[target_config.name] = target_config
            logger.info(f"保存目标配置: {target_config.name}")
            return True
            
        except Exception as e:
            logger.error(f"保存目标配置失败 {target_config.name}: {e}")
            return False
    
    def get_analyzer_config(self, analyzer_name: str) -> AnalyzerConfig:
        """
        获取分析器配置
        
        Args:
            analyzer_name: 分析器名称
            
        Returns:
            AnalyzerConfig 对象
        """
        if analyzer_name in self._analyzer_configs:
            return self._analyzer_configs[analyzer_name]
        
        config = self.get(f"analyzers.{analyzer_name}", {})
        
        analyzer_config = AnalyzerConfig(
            name=analyzer_name,
            enabled=config.get("enabled", True),
            parameters=config.get("parameters", {}),
            dependencies=config.get("dependencies", [])
        )
        
        self._analyzer_configs[analyzer_name] = analyzer_config
        return analyzer_config
    
    def set_analyzer_config(self, analyzer_config: AnalyzerConfig) -> None:
        """设置分析器配置"""
        self._analyzer_configs[analyzer_config.name] = analyzer_config
        self.set(
            f"analyzers.{analyzer_config.name}",
            {
                "enabled": analyzer_config.enabled,
                "parameters": analyzer_config.parameters,
                "dependencies": analyzer_config.dependencies
            }
        )
    
    def save_to_yaml(self, path: Optional[str] = None) -> bool:
        """
        保存当前配置到 YAML 文件
        
        Args:
            path: 文件路径
            
        Returns:
            是否成功保存
        """
        save_path = Path(path) if path else self.config_dir / "current.yaml"
        
        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                yaml.dump(self._config_cache, f, default_flow_style=False)
            
            logger.info(f"配置已保存到: {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"保存配置失败: {e}")
            return False
    
    def load_from_yaml(self, path: str) -> bool:
        """
        从 YAML 文件加载配置
        
        Args:
            path: 文件路径
            
        Returns:
            是否成功加载
        """
        config_path = Path(path)
        
        if not config_path.exists():
            logger.error(f"配置文件不存在: {path}")
            return False
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            if config_data:
                self._configs_by_source[ConfigSource.YAML_FILE.value] = config_data
                self._merge_config(config_data)
                logger.info(f"从YAML加载配置: {path}")
            
            return True
            
        except Exception as e:
            logger.error(f"加载YAML配置失败: {e}")
            return False
    
    def export_config_sources(self) -> Dict[str, Any]:
        """
        导出各来源配置（用于调试）
        
        Returns:
            按来源分类的配置字典
        """
        return {
            "sources": list(self._configs_by_source.keys()),
            "current": self._config_cache,
            "by_source": self._configs_by_source
        }
    
    def create_encrypted_config(self, output_path: str, keys_to_encrypt: List[str]) -> bool:
        """
        创建加密配置文件
        
        Args:
            output_path: 输出路径
            keys_to_encrypt: 需要加密的配置键列表
            
        Returns:
            是否成功创建
        """
        if not self._cipher:
            logger.error("加密密钥未设置")
            return False
        
        try:
            config_to_export = self._config_cache.copy()
            
            sensitive_section = {}
            for key in keys_to_encrypt:
                value = self.get(key)
                if value:
                    sensitive_section[key] = self._encrypt_value(str(value))
            
            if sensitive_section:
                config_to_export["sensitive"] = sensitive_section
            
            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.dump(config_to_export, f, default_flow_style=False)
            
            logger.info(f"加密配置已保存到: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"创建加密配置失败: {e}")
            return False


def create_config_manager(
    config_dir: str = "config",
    env_prefix: str = "BINARY_ANALYSIS_"
) -> ConfigManager:
    """
    创建配置管理器的工厂函数
    
    Args:
        config_dir: 配置目录
        env_prefix: 环境变量前缀
        
    Returns:
        ConfigManager 实例
    """
    encryption_key = os.environ.get("CONFIG_ENCRYPTION_KEY", "").encode()
    
    manager = ConfigManager(
        config_dir=config_dir,
        encryption_key=encryption_key if encryption_key else None
    )
    
    return manager


class EnvironmentConfigSource:
    """
    环境变量配置源
    
    便捷类，用于从环境变量快速读取配置
    """
    
    @staticmethod
    def get(key: str, default: Any = None, prefix: str = "BINARY_ANALYSIS_") -> Any:
        """
        获取环境变量配置
        
        Args:
            key: 配置键
            default: 默认值
            prefix: 环境变量前缀
            
        Returns:
            配置值
        """
        env_key = f"{prefix}{key.upper().replace('.', '_')}"
        value = os.environ.get(env_key)
        
        if value is None:
            return default
        
        if value.lower() == "true":
            return True
        elif value.lower() == "false":
            return False
        
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            return value
    
    @staticmethod
    def set(key: str, value: Any, prefix: str = "BINARY_ANALYSIS_") -> None:
        """
        设置环境变量配置
        
        Args:
            key: 配置键
            value: 配置值
            prefix: 环境变量前缀
        """
        env_key = f"{prefix}{key.upper().replace('.', '_')}"
        os.environ[env_key] = str(value)
