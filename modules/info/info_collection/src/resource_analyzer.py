# resource_analyzer — 嵌入式资源安全分析器
# 提取并安全分析二进制中嵌入的资源 (PE/DLL, 清单, 脚本, 证书)
# 区别于 Resource Hacker/pestudio (仅展示): 对每个嵌入资源做独立安全评估

import struct, hashlib
from typing import Dict, List, Optional, Set


def _find_embedded_pe(raw: bytes) -> List[Dict]:
    """扫描原始字节中的嵌入 PE 文件 (MZ + PE签名)。"""
    _found = []
    _off = 0
    while True:
        _pos = raw.find(b'MZ', _off)
        if _pos == -1: break
        if _pos + 0x40 < len(raw):
            try:
                _pe_off = struct.unpack_from('<I', raw, _pos + 0x3C)[0]
                if _pos + _pe_off + 4 < len(raw):
                    _sig = struct.unpack_from('<I', raw, _pos + _pe_off)[0]
                    if _sig == 0x00004550:
                        _machine = struct.unpack_from('<H', raw, _pos + _pe_off + 4)[0]
                        _ts = struct.unpack_from('<I', raw, _pos + _pe_off + 8)[0]
                        _sz = _estimate_pe_size(raw, _pos + _pe_off)
                        _found.append({
                            "type": "embedded_pe",
                            "offset": _pos,
                            "machine": _machine,
                            "timestamp": _ts,
                            "estimated_size": _sz,
                            "sha256": hashlib.sha256(
                                raw[_pos:_pos + min(_sz, len(raw) - _pos)]).hexdigest(),
                        })
            except Exception:
                pass
        _off = _pos + 1
        if len(_found) > 20: break
    return _found


def _estimate_pe_size(raw: bytes, pe_offset: int) -> int:
    """从 PE 头估算文件大小。取最后一个节区末尾或文件末尾。"""
    try:
        _num_sec = struct.unpack_from('<H', raw, pe_offset + 6)[0]
        _opt_size = struct.unpack_from('<H', raw, pe_offset + 20)[0]
        _sec_off = pe_offset + 24 + _opt_size
        _max_end = 0
        for _i in range(min(_num_sec, 96)):
            _so = _sec_off + _i * 40
            if _so + 40 > len(raw): break
            _raw_ptr = struct.unpack_from('<I', raw, _so + 20)[0]
            _raw_size = struct.unpack_from('<I', raw, _so + 16)[0]
            _max_end = max(_max_end, _raw_ptr + _raw_size)
        return max(_max_end, 512)
    except Exception:
        return 4096


def _find_embedded_scripts(raw: bytes) -> List[Dict]:
    """扫描嵌入脚本 (VBS/JS/PS1/BAT)。"""
    _patterns = {
        "vbs": [b'On Error Resume Next', b'CreateObject(', b'WScript.',
                b'MsgBox ', b'ExecuteGlobal'],
        "js": [b'eval(', b'ActiveXObject(', b'WScript.', b'new Function('],
        "ps1": [b'Invoke-Expression', b'PowerShell', b'-EncodedCommand',
                b'FromBase64String', b'IEX('],
        "bat": [b'@echo off', b'cmd /c', b'%TEMP%', b'reg add'],
    }
    _found = []
    for _lang, _sigs in _patterns.items():
        for _sig in _sigs:
            _off = 0
            while True:
                _pos = raw.find(_sig, _off)
                if _pos == -1: break
                _found.append({
                    "type": "embedded_script",
                    "language": _lang,
                    "offset": _pos,
                    "signature": _sig.decode('ascii', errors='replace'),
                })
                _off = _pos + 1
                if len(_found) > 50: break
    return _found


def _find_manifest_issues(raw: bytes, imports: Dict = None) -> List[Dict]:
    """检测嵌入 XML manifest 中的安全问题。"""
    _issues = []
    # 搜索 manifest XML 片段
    _manifest_regions = []
    _off = 0
    while True:
        _pos = raw.find(b'<assembly', _off)
        if _pos == -1: break
        _end = raw.find(b'</assembly>', _pos)
        if _end == -1: break
        _manifest_regions.append(raw[_pos:_end + 12])
        _off = _end + 1

    for _mr in _manifest_regions:
        _text = _mr.decode('utf-8', errors='replace').lower()
        # COM 劫持风险: clrClass / comInterfaceExternalProxyStub
        if 'cominterfaceexternalproxystub' in _text:
            _issues.append({
                "type": "manifest_com_hijack_risk",
                "detail": "COM 代理存根重定向 — 可能的 DLL 劫持路径",
                "severity": "HIGH",
            })
        # 不安全执行级别
        if 'requireadministrator' in _text:
            _issues.append({
                "type": "manifest_admin_required",
                "detail": "清单请求管理员权限 — 若被劫持影响更大",
                "severity": "MEDIUM",
            })
        # DPI 感知绕过
        if 'dpiaware' in _text and 'false' in _text:
            _issues.append({
                "type": "manifest_dpi_unaware",
                "detail": "非 DPI 感知 — 可能被 UI 重定向攻击利用",
                "severity": "LOW",
            })

    return _issues


def _find_certificate_issues(raw: bytes) -> List[Dict]:
    """检测嵌入证书/签名块的安全问题。"""
    _issues = []
    # PKCS#7 / DER 证书标记
    _cert_markers = [
        b'\x30\x82',  # DER SEQUENCE (证书 TLV 结构前缀)
        b'BEGIN CERTIFICATE',
        b'BEGIN RSA PRIVATE KEY',
        b'BEGIN PRIVATE KEY',
    ]
    _cert_count = 0
    for _marker in _cert_markers:
        _off = 0
        while True:
            _pos = raw.find(_marker, _off)
            if _pos == -1: break
            _cert_count += 1
            _off = _pos + 1
            if _cert_count > 20: break

    if _cert_count >= 1:
        _issues.append({
            "type": "embedded_certificates",
            "detail": f"检测到 {_cert_count} 个证书 — 验证有效期和签名链",
            "severity": "MEDIUM" if _cert_count > 3 else "LOW",
        })
    if b'BEGIN RSA PRIVATE KEY' in raw or b'BEGIN PRIVATE KEY' in raw:
        _issues.append({
            "type": "embedded_private_key",
            "detail": "嵌入私钥 — 严重密钥泄露风险",
            "severity": "CRITICAL",
        })

    return _issues


def analyze_resources(
    raw: bytes = None,
    filepath: str = None,
    imports: Dict = None,
    sections: List[Dict] = None,
) -> Dict:
    """嵌入式资源安全分析主入口。

    返回:
    - embedded_pe: 嵌入 PE/DLL 列表及安全评估
    - embedded_scripts: 嵌入脚本检测
    - manifest_issues: 清单安全问题
    - certificate_issues: 证书安全问题
    - resource_bloat: 资源膨胀检测
    - overall_risk: 综合风险评估
    - findings: 所有安全发现的汇总列表
    """
    if raw is None and filepath:
        with open(filepath, 'rb') as _fh:
            raw = _fh.read()
    if raw is None:
        return {"error": "no_data_provided"}

    _fsize = len(raw)
    _findings = []
    _risk_score = 0.0

    # 1. 嵌入 PE
    _embedded_pe = _find_embedded_pe(raw)
    _pe_issues = []
    if _embedded_pe:
        # 多个嵌入 PE → 可疑
        if len(_embedded_pe) > 1:
            _pe_issues.append({
                "type": "multiple_embedded_pe",
                "detail": f"检测到 {len(_embedded_pe)} 个嵌入 PE — 可能的 DLL sideloading 或捆绑",
                "severity": "HIGH",
            })
            _risk_score += 0.25
        # 嵌入 PE 占文件体积过大
        _total_pe_sz = sum(p.get("estimated_size", 0) for p in _embedded_pe)
        if _total_pe_sz > _fsize * 0.6:
            _pe_issues.append({
                "type": "embedded_pe_dominant",
                "detail": f"嵌入 PE 占总文件 {_total_pe_sz/_fsize:.0%}",
                "severity": "MEDIUM",
            })
            _risk_score += 0.10

    for _pe in _embedded_pe:
        _pe["security_issues"] = _pe_issues

    # 2. 嵌入脚本
    _embedded_scripts = _find_embedded_scripts(raw)
    if _embedded_scripts:
        _langs = set(s["language"] for s in _embedded_scripts)
        _findings.append({
            "type": "embedded_scripts_detected",
            "detail": f"检测到嵌入脚本: {', '.join(_langs)} ({len(_embedded_scripts)} 处)",
            "severity": "HIGH",
            "evidence": _embedded_scripts[:5],
        })
        _risk_score += 0.20

    # 3. 清单问题
    _manifest_issues = _find_manifest_issues(raw, imports)
    for _mi in _manifest_issues:
        _findings.append(_mi)
        if _mi["severity"] == "HIGH":
            _risk_score += 0.15
        elif _mi["severity"] == "MEDIUM":
            _risk_score += 0.05

    # 4. 证书问题
    _cert_issues = _find_certificate_issues(raw)
    for _ci in _cert_issues:
        _findings.append(_ci)
        if _ci["severity"] == "CRITICAL":
            _risk_score += 0.35
        elif _ci["severity"] == "MEDIUM":
            _risk_score += 0.10

    # 5. 资源膨胀: 非代码段占文件体积比过高
    _code_sz = sum(
        s.get("size", s.get("vmsize", s.get("filesz", 0)))
        for s in (sections or [])
        if isinstance(s, dict) and s.get("name", "") in (".text", "CODE", "__TEXT")
    )
    if _code_sz > 0 and _fsize > 0:
        _code_ratio = _code_sz / _fsize
        if _code_ratio < 0.15:
            _findings.append({
                "type": "resource_bloat",
                "detail": f"代码段仅占 {_code_ratio:.1%} — 可能资源膨胀或载荷隐藏",
                "severity": "MEDIUM",
            })
            _risk_score += 0.10

    # 综合风险评估
    _risk_score = min(_risk_score, 1.0)
    if _risk_score > 0.50:
        _overall = "HIGH_RISK"
    elif _risk_score > 0.25:
        _overall = "MEDIUM_RISK"
    elif _risk_score > 0.10:
        _overall = "LOW_RISK"
    else:
        _overall = "CLEAN"

    return {
        "embedded_pe_count": len(_embedded_pe),
        "embedded_pe": _embedded_pe,
        "embedded_scripts_count": len(_embedded_scripts),
        "embedded_scripts": _embedded_scripts[:10],
        "manifest_issues": _manifest_issues,
        "certificate_issues": _cert_issues,
        "findings": _findings,
        "risk_score": round(_risk_score, 4),
        "overall_risk": _overall,
        "recommendations": _generate_recommendations(_findings),
    }


def _generate_recommendations(findings: List[Dict]) -> List[str]:
    _rec_map = {
        "multiple_embedded_pe": "验证所有嵌入DLL的签名一致性; 使用KnownDLLs防止DLL劫持",
        "embedded_scripts_detected": "提取并审计嵌入脚本; 确认非恶意dropper行为",
        "manifest_com_hijack_risk": "审查COM代理重定向; 移除不必要的comInterfaceExternalProxyStub",
        "embedded_private_key": "立即替换泄露私钥; 重新签名所有受影响二进制",
        "resource_bloat": "用binwalk/foremost扫描资源段; 确认无隐藏载荷",
    }
    _types = {f["type"] for f in findings}
    return [_rec_map[t] for t in _types if t in _rec_map] or ["未检测到嵌入式资源安全问题"]
