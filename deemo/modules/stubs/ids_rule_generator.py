# re-export from compat/ — IDS 规则生成桩
# 编译加载策略 — 上游模块含运行时配置，需要完整 exec 环境
# 参考: FuzzBox (arXiv:2509.05643) 嵌入式 fuzzing 输出 → IDS 规则 &
#        FirmRec (ACM CCS 2024) 漏洞签名到检测规则的映射
import os as _os

_base = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'ids_rule_generator.py')
with open(_base, 'r', encoding='utf-8') as _fh:
    _raw_src = _fh.read()
_code = compile(_raw_src, _base, 'exec')
exec(_code, globals())

# --- IDS 规则后处理 ---
# FirmRec 的基于 exploitation 的签名提取 → 可映射为 Suricata/Snort 规则。
# FuzzBox 的覆盖率引导 fuzzing 输出 → 协议异常模式 → IDS 规则模板。

_SURICATA_TEMPLATE = (
    'alert {proto} {src} any -> {dst} {port} '
    '(msg:"{msg}"; flow:{flow}; content:"{content}"; {meta})'
)

def to_suricata_rule(rule_data: dict) -> str | None:
    """将内部规则表示转换为 Suricata 兼容格式。
    必填: proto, msg, content。可选: src, dst, port, flow, sid, classtype。"""
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
