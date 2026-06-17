"""
层次化配置管理增强模块

增强功能：
1. Per-target 参数集支持（按目标二进制定制配置）
2. 更完善的敏感字段加密（AES-256-GCM、密钥轮换）
3. 配置校验与schema验证
4. 配置继承与覆盖机制
5. 配置变更监听
"""

import os
import json
import re
from typing import Dict, Any, Optional, Union, Callable, List
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock
from abc import ABC, abstractmethod

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
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

ENCRYPTION_KEY_ENV = "BINARY_ANALYZER_ENCRYPTION_KEY"
ENCRYPTED_FIELD_PREFIX = "_encrypted_"


class EncryptionAlgorithm(Enum):
    """加密算法枚举"""
    FERNET = "fernet"
    AES_256_GCM = "aes_256_gcm"


@dataclass
class EncryptionKey:
    """加密密钥信息"""
    key_id: str
    key: bytes
    algorithm: EncryptionAlgorithm
    created_at: datetime
    expires_at: Optional[datetime] = None
    active: bool = True


class KeyManager:
    """密钥管理器 - 支持密钥轮换"""
    
    def __init__(self):
        self._keys: Dict[str, EncryptionKey] = {}
        self._active_key_id: Optional[str] = None
        self._lock = Lock()
    
    def add_key(self, key_id: str, key: bytes, algorithm: EncryptionAlgorithm = EncryptionAlgorithm.FERNET, expires_at: Optional[datetime] = None) -> None:
        with self._lock:
            self._keys[key_id] = EncryptionKey()
                key_id=key_id,
                key=key,
                algorithm=algorithm,
                created_at=datetime.now(),
                expires_at=expires_at,
                active=True
            
            if not self._active_key_id:
                self._active_key_id = key_id
    
    def set_active_key(self, key_id: str) -> bool:
        with self._lock:
            if key_id in self._keys:
                self._active_key_id = key_id,
                return True
        return False
    
    def get_active_key(self) -> Optional[EncryptionKey]:
        with self._lock:
            if self._active_key_id and self._active_key_id in self._keys:
                return self._keys[self._active_key_id]
        return None
    
    def get_key_by_id(self, key_id: str) -> Optional[EncryptionKey]:
        with self._lock:
            return self._keys.get(key_id)
    
    def rotate_key(self, new_key_id: Optional[str] = None) -> str:
        new_key_id = new_key_id or self._generate_key_id()
        
        if CRYPTO_AVAILABLE:
            new_key = Fernet.generate_key()
            self.add_key(new_key_id, new_key)
            self.set_active_key(new_key_id)
        
        return new_key_id
    
    def _generate_key_id(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"key_{timestamp}"


class AdvancedEncryptor:
    """高级加密器 - 支持多种算法"""
    
    def __init__(self, key_manager: KeyManager = None):
        self._key_manager = key_manager or KeyManager()
        
        if not self._key_manager.get_active_key():
            if CRYPTO_AVAILABLE:
                initial_key = Fernet.generate_key()
                self._key_manager.add_key("default", initial_key)
    
    def encrypt(self, value: str, key_id: Optional[str] = None) -> str:
        """加密字符串"""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography 库不可用")
        
        if key_id:
            key_info = self._key_manager.get_key_by_id(key_id)
        else:
            key_info = self._key_manager.get_active_key()
        
        if not key_info:
            raise RuntimeError("未找到可用的加密密钥")
        
        if key_info.algorithm == EncryptionAlgorithm.FERNET:
            f = Fernet(key_info.key)
            return f"{key_info.key_id}::fernet::{f.encrypt(value.encode().decode(}")
        elif key_info.algorithm == EncryptionAlgorithm.AES_256_GCM:
            return self._encrypt_aes_gcm(value, key_info.key)
        
        raise ValueError(f"不支持的加密算法: {key_info.algorithm}")
    
    def decrypt(self, encrypted_value: str) -> str:
        """解密字符串"""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography 库不可用")
        
        parts = encrypted_value.split('::', 2)
        if len(parts) != 3:
            return encrypted_value
        
        key_id, algorithm, data = parts
        
        key_info = self._key_manager.get_key_by_id(key_id)
        if not key_info:
            raise RuntimeError(f"找不到密钥: {key_id}")
        
        if algorithm == 'fernet':
            f = Fernet(key_info.key)
            return f.decrypt(data.encode().decode()
        elif algorithm == 'aes256gcm':
            return self._decrypt_aes_gcm(data, key_info.key)
        
        raise ValueError(f"不支持的加密算法: {algorithm}")
    
    def _encrypt_aes_gcm(self, value: str, key: bytes) -> str:
        """使用AES-256-GCM加密"""
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend(

        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(value.encode()) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        tag = encryptor.tag
        
        return f"{self._key_manager._active_key_id}::aes256gcm::{iv.hex(}::{tag.hex(}::{ciphertext.hex(}"
    
    def _decrypt_aes_gcm(self, data: str, key: bytes) -> str:
        """使用AES-256-GCM解密"""
        parts = data.split('::')
        if len(parts) != 3:
            raise ValueError("无效的AES-GCM加密格式")
        
        iv = bytes.fromhex(parts[0])
        tag = bytes.fromhex(parts[1])
        ciphertext = bytes.fromhex(parts[2])
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend(

        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded_data) + unpadder.finalize().decode()


class ConfigSchema:
    """配置Schema验证器"""
    
    def __init__(self, schema: Dict[str, Any]):
        self._schema = schema
    
    def validate(self, config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """验证配置是否符合schema"""
        errors = []
        self._validate_dict("", config, self._schema, errors)
        return len(errors) == 0, errors
    
    def _validate_dict(self, path: str, config: Dict[str, Any], schema: Dict[str, Any], errors: List[str]):
        """验证字典类型配置"""
        for key, expected_type in schema.get('properties', {}).items():
            current_path = f"{path}.{key}" if path else key
            
            if key in config:
                self._validate_value(current_path, config[key], expected_type, errors)
            elif schema.get('required', []).count(key) > 0:
                errors.append(f"{current_path} 是必需字段")
    
    def _validate_value(self, path: str, value: Any, expected_type: Union[str, Dict], errors: List[str]):
        """验证单个值"""
        if isinstance(expected_type, dict):
            if isinstance(value, dict):
                self._validate_dict(path, value, expected_type, errors)
            else:
                errors.append(f"{path} 应为对象类型")
        else:
            python_type = self._get_python_type(expected_type)
            if not isinstance(value, python_type):
                errors.append(f"{path} 应为 {expected_type} 类型")
    
    def _get_python_type(self, type_name: str) -> type:
        """获取Python类型"""
        type_map = {
            'string': str,
            'int': int,
            'float': float,
            'bool': bool,
            'list': list,
            'dict': dict,
            'any': object
        }
        return type_map.get(type_name, object)


class TargetConfig:
    """Per-target 配置参数集"""
    
    def __init__(self, target_id: str, config: Dict[str, Any]):
        self.target_id = target_id
        self.config = config
        self.created_at = datetime.now()
        self.last_used_at = None
    
    def update_last_used(self):
        """更新最后使用时间"""
        self.last_used_at = datetime.now()


class ConfigChangeListener(ABC):
    """配置变更监听器"""
    
    @abstractmethod
    def on_config_change(self, key: str, old_value: Any, new_value: Any) -> None:
        """配置变更回调"""
        pass


class HierarchicalConfigManager:
    """
    层次化配置管理器 - 增强版
    
    核心功能：
    1. 分层配置加载（defaults → config → secrets → environment）
    2. Per-target 参数集支持
    3. 敏感字段加密（支持多种算法、密钥轮换）
    4. 配置继承与覆盖机制
    5. 配置变更监听
    6. Schema验证
    """
    
    def __init__(self, config_dir: Optional[str] = None):
        self._config_dir = Path(config_dir) if config_dir else Path(__file__).parent.parent / "config"
        self._config_dir.mkdir(parents=True, exist_ok=True)
        
        self._config_data: Dict[str, Any] = {}
        self._target_configs: Dict[str, TargetConfig] = {}
        self._encryptor = AdvancedEncryptor()
        self._change_listeners: List[ConfigChangeListener] = []
        self._schemas: Dict[str, ConfigSchema] = {}
        self._lock = Lock()
    
    def load_config(self):
        """加载配置（分层加载）"""
        config_sources = [
            self._config_dir / "defaults.yaml",
            self._config_dir / "config.yaml",
            self._config_dir / "config.toml",
            self._config_dir / "config.json",
            self._config_dir / "secrets.yaml",
            Path(os.environ.get("BA_CONFIG_FILE", "")),
        ]
        
        for source in config_sources:
            if source and source.exists():
                config = self._parse_file(source)
                self._merge_config(self._config_data, config)
        
        self._apply_environment_overrides()
        self._decrypt_sensitive_fields()
        self._load_target_configs()
    
    def _parse_file(self, file_path: Path) -> Dict[str, Any]:
        """解析配置文件"""
        ext = file_path.suffix.lower()
        
        try:
            if ext in ['.yaml', '.yml']:
                if not YAML_AVAILABLE:
                    raise ImportError("PyYAML 库不可用")
                with open(file_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f) or {}
            elif ext == '.toml':
                if not TOML_AVAILABLE:
                    raise ImportError("toml 库不可用")
                with open(file_path, 'r', encoding='utf-8') as f:
                    return toml.load(f)
            elif ext == '.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"解析配置文件 {file_path} 失败: {e}")
        
        return {}
    
    def _merge_config(self, existing: Dict[str, Any], new: Dict[str, Any]):
        """递归合并配置"""
        for key, value in new.items():
            if key in existing and isinstance(existing[key], dict) and isinstance(value, dict):
                self._merge_config(existing[key], value)
            else:
                existing[key] = value
    
    def _apply_environment_overrides(self):
        """应用环境变量覆盖"""
        for key, value in os.environ.items():
            if key.startswith("BA_"):
                config_key = key[3:].lower().replace('_', '.')
                self._set_nested_value(self._config_data, config_key, value)
    
    def _set_nested_value(self, config: Dict[str, Any], key_path: str, value: str):
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
            elif value.startswith('[') and value.endswith(']'):
                current[final_key] = json.loads(value)
            elif value.startswith('{') and value.endswith('}'):
                current[final_key] = json.loads(value)
            else:
                current[final_key] = value
        except:
            current[final_key] = value
    
    def _decrypt_sensitive_fields(self):
        """解密敏感字段"""
        self._config_data = self._decrypt_dict(self._config_data)
    
    def _decrypt_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """递归解密字典"""
        result = {}
        
        for key, value in data.items():
            if key.startswith(ENCRYPTED_FIELD_PREFIX):
                try:
                    decrypted = self._encryptor.decrypt(value)
                    result[key[len(ENCRYPTED_FIELD_PREFIX):]] = decrypted
                except Exception as e:
                    result[key] = value
            elif isinstance(value, dict):
                result[key] = self._decrypt_dict(value)
            else:
                result[key] = value
        
        return result
    
    def _load_target_configs(self):
        """加载per-target配置"""
        target_dir = self._config_dir / "targets",
        if not target_dir.exists():
            return
        
        for item in target_dir.iterdir():
            if item.is_file() and item.suffix.lower() in ['.yaml', '.yml', '.json', '.toml']:
                target_id = item.stem
                config = self._parse_file(item)
                self._target_configs[target_id] = TargetConfig(target_id, config)
    
    def get(self, key: str, default: Any = None, target_id: Optional[str] = None) -> Any:
        """获取配置值"""
        with self._lock:
            if target_id and target_id in self._target_configs:
                target_value = self._get_nested_value(self._target_configs[target_id].config, key)
                if target_value is not None:
                    self._target_configs[target_id].update_last_used()
                    return target_value
            
            return self._get_nested_value(self._config_data, key, default)
    
    def _get_nested_value(self, config: Dict[str, Any], key: str, default: Any = None) -> Any:
        """获取嵌套配置值"""
        keys = key.split('.')
        current = config
        
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
        
        return current
    
    def set(self, key: str, value: Any, target_id: Optional[str] = None) -> bool:
        """设置配置值"""
        with self._lock:
            old_value = self.get(key, target_id=target_id)
            
            if target_id:
                if target_id not in self._target_configs:
                    self._target_configs[target_id] = TargetConfig(target_id, {})
                
                self._set_nested_value_in_dict(self._target_configs[target_id].config, key, value)
                self._target_configs[target_id].update_last_used()
            else:
                self._set_nested_value_in_dict(self._config_data, key, value)
            
            self._notify_change(key, old_value, value)
            return True
    
    def _set_nested_value_in_dict(self, config: Dict[str, Any], key_path: str, value: Any):
        """在字典中设置嵌套值"""
        keys = key_path.split('.')
        current = config
        
        for i, key in enumerate(keys[:-1]):
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    def _notify_change(self, key: str, old_value: Any, new_value: Any):
        """通知配置变更"""
        for listener in self._change_listeners:
            try:
                listener.on_config_change(key, old_value, new_value)
            except Exception as e:
                print(f"配置变更通知失败: {e}")
    
    def add_change_listener(self, listener: ConfigChangeListener) -> None:
        """添加配置变更监听器"""
        self._change_listeners.append(listener)
    
    def remove_change_listener(self, listener: ConfigChangeListener) -> None:
        """移除配置变更监听器"""
        if listener in self._change_listeners:
            self._change_listeners.remove(listener)
    
    def register_schema(self, name: str, schema: Dict[str, Any]) -> None:
        """注册配置schema"""
        self._schemas[name] = ConfigSchema(schema)
    
    def validate_config(self, schema_name: str, config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """验证配置"""
        if schema_name not in self._schemas:
            return False, [f"未找到schema: {schema_name}"]
        
        return self._schemas[schema_name].validate(config)
    
    def save_config(self, file_path: Union[str, Path], format: str = 'yaml', encrypt: bool = False, target_id: Optional[str] = None) -> bool:
        """保存配置"""
        path = Path(file_path)
        
        if target_id and target_id in self._target_configs:
            data = self._target_configs[target_id].config
            path.parent.mkdir(parents=True, exist_ok=True)
        else:
            data = self._config_data
        
        if encrypt:
            data = self._encrypt_dict(data)
        
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
            print(f"保存配置失败: {e}")
            return False
    
    def _encrypt_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """递归加密敏感字段"""
        sensitive_keys = ['api_key', 'password', 'secret', 'token', 'key', 'credentials']
        result = {}
        
        for key, value in data.items():
            if isinstance(value, dict):
                result[key] = self._encrypt_dict(value)
            elif isinstance(value, str):
                key_lower = key.lower()
                if any(sk in key_lower for sk in sensitive_keys):
                    result[ENCRYPTED_FIELD_PREFIX + key] = self._encryptor.encrypt(value)
                else:
                    result[key] = value
            else:
                result[key] = value
        
        return result
    
    def save_target_config(self, target_id: str) -> bool:
        """保存per-target配置"""
        if target_id not in self._target_configs:
            return False
        
        target_dir = self._config_dir / "targets"
        target_dir.mkdir(parents=True, exist_ok=True)
        
        return self.save_config()
            target_dir / f"{target_id}.yaml",
            format='yaml',
            encrypt=True,
            target_id=target_id
        

    
    def get_target_ids(self) -> List[str]:
        """获取所有target ID"""
        return list(self._target_configs.keys(

    
    def get_target_config(self, target_id: str) -> Optional[Dict[str, Any]]:
        """获取target配置"""
        target = self._target_configs.get(target_id)
        return target.config if target else None
    
    def delete_target_config(self, target_id: str) -> bool:
        """删除target配置"""
        if target_id not in self._target_configs:
            return False
        
        del self._target_configs[target_id]
        
        target_file = self._config_dir / "targets" / f"{target_id}.yaml",
        if target_file.exists():
            target_file.unlink()
        
        return True
    
    def rotate_encryption_key(self) -> str:
        """轮换加密密钥"""
        return self._encryptor._key_manager.rotate_key()
    
    def export_config(self, include_secrets: bool = False) -> Dict[str, Any]:
        """导出配置"""
        if include_secrets:
            return self._config_data
        return self._remove_secrets(self._config_data)
    
    def _remove_secrets(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """移除敏感信息"""
        sensitive_keys = ['api_key', 'password', 'secret', 'token', 'key']
        result = {}
        
        for key, value in data.items():
            if isinstance(value, dict):
                result[key] = self._remove_secrets(value)
            elif isinstance(value, str):
                key_lower = key.lower()
                if any(sk in key_lower for sk in sensitive_keys):
                    result[key] = '***REDACTED***'
                else:
                    result[key] = value
            else:
                result[key] = value
        
        return result


def get_hierarchical_config() -> HierarchicalConfigManager:
    """获取全局层次化配置管理器实例"""
    global _hierarchical_config
    if _hierarchical_config is None:
        _hierarchical_config = HierarchicalConfigManager()
        _hierarchical_config.load_config()
    return _hierarchical_config


_hierarchical_config = None


class ConfigTemplateManager:
    """配置模板管理器"""
    
    def __init__(self):
        self._templates: Dict[str, Dict[str, Any]] = {}
    
    def add_template(self, name: str, template: Dict[str, Any]) -> None:
        """添加配置模板"""
        self._templates[name] = template
    
    def get_template(self, name: str) -> Optional[Dict[str, Any]]:
        """获取配置模板"""
        return self._templates.get(name)
    
    def apply_template(self, template_name: str, target_id: str, overrides: Optional[Dict[str, Any]] = None) -> bool:
        """应用配置模板到target"""
        template = self.get_template(template_name)
        if not template:
            return False
        
        config = template.copy()
        if overrides:
            self._deep_merge(config, overrides)
        
        config_manager = get_hierarchical_config()
        for key, value in self._flatten_dict(config).items():
            config_manager.set(key, value, target_id)
        
        return config_manager.save_target_config(target_id)
    
    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]):
        """深度合并配置"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '') -> Dict[str, Any]:
        """扁平化字典"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}.{k}" if parent_key else k,
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key).items(

            else:
                items.append((new_key, v

        return dict(items)))))))))))