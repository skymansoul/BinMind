# 序列化辅助逻辑 (mixin)
# 分离动机: 字典化输出与检测逻辑解耦

from .ble_radio_types import BLEVulnerability


class BLESerializerMixin:
    """分析结果序列化混入。

    将内部数据对象字典化, 供 analyze() 直接返回。
    """

    def _security_config_to_dict(self):
        return {
            "encryption_enabled": self.security_config.encryption_enabled,
            "encryption_algorithm": self.security_config.encryption_algorithm,
            "mitm_protection": self.security_config.mitm_protection,
            "secure_connections": self.security_config.secure_connections,
            "bonding_enabled": self.security_config.bonding_enabled,
            "maximum_encryption_key_size": self.security_config.maximum_encryption_key_size,
        }

    def _service_to_dict(self, s):
        return {
            "uuid": s.uuid,
            "name": s.name,
            "start_handle": hex(s.start_handle),
            "end_handle": hex(s.end_handle),
            "characteristic_count": len(s.characteristics),
            "characteristics": [self._char_to_dict(c) for c in s.characteristics],
        }

    def _char_to_dict(self, ch):
        return {
            "uuid": ch.uuid,
            "name": ch.name,
            "properties": hex(ch.properties),
            "permissions": hex(ch.permissions),
            "handle": hex(ch.handle),
            "value_handle": hex(ch.value_handle),
        }

    def _vuln_to_dict(self, v: BLEVulnerability):
        return {
            "type": v.type,
            "severity": v.severity,
            "description": v.description,
            "affected_layer": v.affected_layer.value,
            "cvss_score": v.cvss_score,
            "related_characteristics": v.related_characteristics,
        }
