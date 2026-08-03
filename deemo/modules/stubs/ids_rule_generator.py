# compat/ 子模块代理 — IDS 规则构造，exec() 加载以保留上游运行时上下文。
# 参考: FuzzBox (arXiv:2509.05643 [待验证]) 嵌入式模糊测试输出到 IDS 规则的映射;
# FirmRec (ACM CCS 2024) 漏洞签名到检测规则的转换。
import os as _os

_base = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'ids_rule_generator.py')
with open(_base, 'r', encoding='utf-8') as _fh:
    _raw_src = _fh.read()
_code = compile(_raw_src, _base, 'exec')
exec(_code, globals())

# IDS 规则格式转换
# FirmRec: exploitation 签名提取 → Suricata/Snort 规则。
# FuzzBox: 覆盖率引导模糊测试 → 协议异常模式 → IDS 规则。

_SURICATA_TEMPLATE = (
    'alert {proto} {src} any -> {dst} {port} '
    '(msg:"{msg}"; flow:{flow}; content:"{content}"; {meta})'
)

def to_suricata_rule(rule_data: dict) -> str | None:
    """将内部规则字典转换为 Suricata 兼容的 alert 规则字符串。
    必要字段: proto, msg, content。选填: src, dst, port, flow, sid, classtype。"""
    required = {'proto', 'msg', 'content'}
    if not required.issubset(rule_data.keys()):
        return None
    meta_parts = []
    sid = rule_data.get('sid', 1000001)
    meta_parts.append(f'sid:{sid};')
    ct = rule_data.get('classtype', 'trojan-activity')
    meta_parts.append(f'classtype:{ct};')
    return _SURICATA_TEMPLATE.format(
        proto=rule_data['proto'],
        src=rule_data.get('src', '$HOME_NET'),
        dst=rule_data.get('dst', '$EXTERNAL_NET'),
        port=rule_data.get('port', 'any'),
        msg=rule_data['msg'],
        flow=rule_data.get('flow', 'to_server,established'),
        content=rule_data['content'],
        meta=' '.join(meta_parts)
    )
