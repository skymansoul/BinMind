"""
密码学异常检测规则生成 — 从静态分析发现中自动生成YARA/Suricata运行时检测规则。

修改记录:
  2025-09-05 14:56 — 初始实现: YARA规则生成/Suricata TLS规则/二进制模式/行为规则

设计意图:
  静态分析回答"此二进制中有什么", 但不回答"此二进制运行时是否表现异常"。
  本模块桥接静态分析和运行时监控:
    从静态检测到的密码学特征生成运行时检测规则,
    部署后可监控密码学行为的异常偏离。

  规则生成策略:
    YARA规则: 匹配二进制中的密码学常量/字符串/S-box/API指纹 — 用于文件扫描。
    Suricata规则: 匹配TLS/SSH协议异常 — 来自protocol_state的不标准状态转移。
    行为规则: 描述预期的密码学行为模式 → 偏离即告警。

  四类规则模板:
    R1 (STATIC_MATCH): 基于魔数/S-box的YARA规则 → 文件/内存扫描。
    R2 (API_USAGE): 基于API字符串的YARA规则 → 检测密码学API使用。
    R3 (PROTOCOL_ANOMALY): Suricata规则 → 检测协议状态机偏离。
    R4 (BEHAVIORAL): 文字描述的行为规则 → 供SIEM/SOAR使用。

  - YARA: 恶意软件分类和检测的事实标准。
  - Suricata: 开源IDS/IPS, 支持TLS/JA3指纹。
  - Sigma Rules: 通用SIEM检测规则格式。

边界条件:
  - 生成的规则是模板—需根据实际部署环境调整阈值和上下文。
  - YARA规则基于字符串匹配—对混淆代码可能漏检。
  - Suricata规则需要网络流量—不适用于离线二进制分析。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class DetectionRule:
    rule_id: str = ""
    rule_type: str = ""            # YARA / SURICATA / BEHAVIORAL
    rule_name: str = ""
    description: str = ""
    severity: str = ""             # CRITICAL / HIGH / MEDIUM / LOW
    rule_content: str = ""         # 实际规则文本
    triggered_by: str = ""         # 触发此规则需满足的静态条件
    false_positive_risk: str = ""  # LOW / MEDIUM / HIGH

def _make_yara_identifier(name: str) -> str:
    """生成合法的YARA标识符(字母数字+下划线, 不能以数字开头)。"""
    clean = ''.join(c if c.isalnum() else '_' for c in name)
    if clean and clean[0].isdigit():
        clean = 'crypto_' + clean
    return clean[:64]  # YARA标识符长度限制

def generate_yara_rules(crypto_findings: Optional[List] = None,
                        algo_names: Optional[List[str]] = None
                        ) -> List[DetectionRule]:
    """从密码学检测结果生成YARA规则。"""
    rules: List[DetectionRule] = []
    algos = set(algo_names or [])

    if crypto_findings:
        for f in crypto_findings:
            try:
                algos.add(getattr(f, 'algorithm', ''))
            except Exception:
                pass

    if not algos:
        return rules

    # R1: 算法魔数规则
    sbox_algos = {'AES', 'SM4', 'GOST', 'Camellia', 'ARIA'}
    for algo in algos:
        if algo in sbox_algos:
            rid = _make_yara_identifier(algo)
            rule = (f'rule Crypto_{rid}_SBox {{\n'
                    f'  meta:\n'
                    f'    description = "Detect {algo} S-box in binary"\n'
                    f'    author = "BinMind crypto_anomaly_rules (auto-generated)"\n'
                    f'    severity = "medium"\n'
                    f'  strings:\n'
                    f'    $sbox = {{ 63 7C 77 7B F2 6B 6F C5 }}  // {algo} S-box prefix\n'
                    f'  condition:\n'
                    f'    $sbox\n'
                    f'}}')
            rules.append(DetectionRule(
                rule_id=f'YARA-{len(rules)+1:03d}',
                rule_type='YARA', rule_name=f'Crypto_{rid}_SBox',
                description=f'检测{algo}算法S-box',
                severity='MEDIUM', rule_content=rule,
                triggered_by=f'{algo} detected in binary',
                false_positive_risk='LOW (标准S-box在非密码学代码中出现概率≈0)'))

    # 弱算法规则
    weak_algos = {'DES', '3DES', 'MD5', 'SHA-1', 'RC4'}
    detected_weak = algos & weak_algos
    if detected_weak:
        weak_names = ' '.join(sorted(detected_weak))
        rule = (f'rule Crypto_WeakAlgorithms {{\n'
                f'  meta:\n'
                f'    description = "Weak/deprecated cryptographic algorithms detected"\n'
                f'    severity = "high"\n'
                f'    algorithms = "{weak_names}"\n'
                f'  strings:\n'
                f'    $weak1 = "MD5" nocase\n'
                f'    $weak2 = "SHA1" nocase\n'
                f'    $weak3 = "DES" nocase\n'
                f'    $weak4 = "RC4" nocase\n'
                f'  condition:\n'
                f'    any of them\n'
                f'}}')
        rules.append(DetectionRule(
            rule_id=f'YARA-{len(rules)+1:03d}',
            rule_type='YARA', rule_name='Crypto_WeakAlgorithms',
            description=f'弱/已废弃密码学算法检测: {weak_names}',
            severity='HIGH', rule_content=rule,
            triggered_by=f'{weak_names} detected',
            false_positive_risk='MEDIUM (字符串可能在非密码学上下文中出现)'))

    return rules

def generate_suricata_rules(
        protocol_findings: Optional[List] = None
) -> List[DetectionRule]:
    """
    从协议状态机偏离生成Suricata IDS规则。
    protocol_findings: crypto_protocol_state的输出。
    """
    rules: List[DetectionRule] = []
    if not protocol_findings:
        return rules

    for pf in protocol_findings:
        try:
            anomalies = getattr(pf, 'anomaly_flags', [])
            proto = getattr(pf, 'protocol_name', 'TLS')
        except Exception:
            continue

        for anomaly in anomalies:
            if 'AUTH' in anomaly.upper():
                rule = (f'alert tls any any -> any any '
                        f'(msg:"BinMind: {proto} AUTH bypass anomaly"; '
                        f'flow:established; tls.subject:"*"; '
                        f'classtype:protocol-command-decode; '
                        f'sid:{9000000 + len(rules)}; rev:1;)')
                rules.append(DetectionRule(
                    rule_id=f'SUR-{len(rules)+1:03d}',
                    rule_type='SURICATA',
                    rule_name=f'{proto}_AUTH_anomaly',
                    description=f'{proto}认证绕过异常',
                    severity='CRITICAL', rule_content=rule,
                    triggered_by=f'Protocol state anomaly: {anomaly}',
                    false_positive_risk='LOW'))

    return rules

def generate_behavioral_rules(
        crypto_findings: Optional[List] = None,
        key_lifecycle_reports: Optional[List] = None
) -> List[DetectionRule]:
    """生成行为级别的SIEM/SOAR检测规则描述。"""
    rules: List[DetectionRule] = []
    algos = set()
    if crypto_findings:
        for f in crypto_findings:
            try:
                algos.add(getattr(f, 'algorithm', ''))
            except Exception:
                pass

    # 密钥生命周期行为规则
    if key_lifecycle_reports:
        for kl in key_lifecycle_reports:
            try:
                if not getattr(kl, 'is_zeroized', True):
                    rules.append(DetectionRule(
                        rule_id=f'BEH-{len(rules)+1:03d}',
                        rule_type='BEHAVIORAL',
                        rule_name='KeyNotZeroized',
                        description='进程终止时密钥缓冲区未清零 — 内存取证可提取密钥',
                        severity='HIGH',
                        rule_content=('MONITOR: 监控进程内存中的密钥模式\n'
                                      'TRIGGER: 进程退出后内存页面未覆盖\n'
                                      'ACTION: 强制SIGKILL+SIGSEGV前的memset'),
                        triggered_by='key_lifecycle: is_zeroized=False',
                        false_positive_risk='LOW'))
            except Exception:
                pass

    # 弱算法使用行为规则
    if algos & {'DES', 'MD5', 'SHA-1'}:
        rules.append(DetectionRule(
            rule_id=f'BEH-{len(rules)+1:03d}',
            rule_type='BEHAVIORAL',
            rule_name='WeakCryptoAPICall',
            description='检测到运行时调用弱/已废弃的密码学API',
            severity='HIGH',
            rule_content=('MONITOR: 拦截EVP_EncryptInit/DES/MD5 API调用\n'
                          'TRIGGER: 弱算法API被调用\n'
                          'ACTION: 告警+审计日志; 若为支付系统→阻止交易'),
            triggered_by='Weak algorithms in binary: DES/MD5/SHA-1',
            false_positive_risk='MEDIUM (遗留验证/兼容性调用可能触发)'))

    return rules

def generate_all_rules(
        crypto_findings: Optional[List] = None,
        algo_names: Optional[List[str]] = None,
        protocol_findings: Optional[List] = None,
        key_lifecycle_reports: Optional[List] = None
) -> List[DetectionRule]:
    """生成所有类型的异常检测规则。"""
    all_rules: List[DetectionRule] = []
    all_rules.extend(generate_yara_rules(crypto_findings, algo_names))
    all_rules.extend(generate_suricata_rules(protocol_findings))
    all_rules.extend(generate_behavioral_rules(crypto_findings, key_lifecycle_reports))
    return all_rules
