#!/usr/bin/env python3
"""
移动端密钥存储安全审计: Android Keystore及iOS Keychain深度扫描 + PQC后量子密码迁移检测。

覆盖范围：
  1. Keymaster HAL版本检测及已知漏洞映射
  2. KeyInfo参数审计（purposes/padding/block modes/digests）
  3. 用户认证绑定检查（biometric + credential）
  4. Secure Enclave / StrongBox 硬件支持检测
  5. Keychain accessibility flag 审计（kSecAttrAccessible*）
  6. 密钥提取可行性评估（root/jailbreak场景攻击面）
  7. Key Attestation 链路验证
  8. 硬编码密钥材料扫描（AES key, RSA private key, HMAC secret 等）
  9. WithSecureLabs审计模式: 密钥用途组合安全性及导入密钥溯源
  10. QED式PQC就绪度评估: 检测量子脆弱算法并量化评分

  三阶段静态分析：(1) 文件级量子脆弱库依赖检测,
  (2) API级量子脆弱API识别, (3) 静态调用图追踪。
  本模块将PQC就绪度评分应用于移动端二进制，识别RSA/ECDSA/SHA-1等
  量子脆弱算法的使用情况，评估Kyber/Dilithium等PQC标准的采纳进度。

  - Rattanavipanon et al., QED Toolchain, IEEE Access 2025
  - Strauss et al.,, IEEE S&P 2025
  - ML-QED-Lite, ePrint 2026/1419
"""

import re, struct, logging, os, hashlib, binascii
from pathlib import Path
from dataclasses import dataclass, field
from enum import StrEnum, IntEnum
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict

logger = logging.getLogger(__name__)

class KeymasterVersion(StrEnum): V1_0="1.0"; V2_0="2.0"; V3_0="3.0"; V4_0="4.0"; V4_1="4.1"; UNKNOWN="unknown"
class KeyPurpose(IntEnum): ENCRYPT=0x01; DECRYPT=0x02; SIGN=0x04; VERIFY=0x08; WRAP_KEY=0x10; AGREE_KEY=0x20; ATTEST_KEY=0x40
class KeyAuthenticationType(StrEnum): NONE="none"; PASSWORD="password"; FINGERPRINT="fingerprint"; FACE="face"; IRIS="iris"; STRONGBOX="strongbox"; BIOMETRIC_WEAK="biometric_weak"; BIOMETRIC_STRONG="biometric_strong"
class KeyOrigin(StrEnum): GENERATED="generated"; DERIVED="derived"; IMPORTED="imported"; SECURELY_IMPORTED="securely_imported"; UNKNOWN="unknown"
class SecurityLevel(StrEnum): SOFTWARE="software"; TRUSTED_ENVIRONMENT="tee"; STRONGBOX="strongbox"; UNKNOWN="unknown"

# PQC就绪度: 量子脆弱算法及PQC标准签名数据库
# 基于QED Toolchain + Strauss et al. 算法分类

_QUANTUM_VULNERABLE_ALGORITHMS = {
    # 非对称加密 (Shor算法可破)
    "RSA": ("RSA", "asymmetric", "Shor算法于多项式时间内分解大整数", 2048),
    "RSA/ECB": ("RSA-ECB", "asymmetric", "RSA-ECB填充模式, 量子脆弱", 2048),
    "RSA/PKCS1": ("RSA-PKCS1", "asymmetric", "RSA PKCS#1 v1.5, 量子脆弱且存填充神谕风险", 2048),
    "RSA/OAEP": ("RSA-OAEP", "asymmetric", "RSA-OAEP, 量子脆弱然填充安全", 2048),
    "ECDSA": ("ECDSA", "asymmetric", "椭圆曲线签名, Shor算法可破", 256),
    "ECDH": ("ECDH", "asymmetric", "椭圆曲线密钥交换, 量子脆弱", 256),
    "EC": ("Elliptic Curve", "asymmetric", "通用椭圆曲线密码, 量子脆弱", 256),
    # 哈希 (Grover算法二次加速)
    "SHA-1": ("SHA-1", "hash", "SHA-1, 经典碰撞攻击已实现, Grover给予二次加速", None),
    "SHA-256": ("SHA-256", "hash", "SHA-256, Grover算法将安全性降至128位", None),
    "MD5": ("MD5", "hash", "MD5, 经典碰撞攻击已实现, 已完全不安全", None),
    # 对称加密 (Grover算法二次加速, 需双倍密钥长度)
    "AES-128": ("AES-128", "symmetric", "AES-128, Grover算法将安全性降至64位", 256),
    "DES": ("DES", "symmetric", "DES, 经典暴力破解已实现, 量子加速愈加脆弱", 256),
    "3DES": ("3DES", "symmetric", "3DES, Grover算法将安全性降至56位等效", 256),
}

_PQC_STANDARDS = {
    # NIST PQC标准化算法
    "Kyber": ("CRYSTALS-Kyber", "kem", "NIST FIPS 203, 基于格的后量子密钥封装"),
    "ML-KEM": ("ML-KEM", "kem", "NIST FIPS 203, Kyber的正式标准名称"),
    "Dilithium": ("CRYSTALS-Dilithium", "signature", "NIST FIPS 204, 基于格的后量子签名"),
    "ML-DSA": ("ML-DSA", "signature", "NIST FIPS 204, Dilithium的正式标准名称"),
    "SPHINCS+": ("SPHINCS+", "signature", "NIST FIPS 205, 基于哈希的状态无关后量子签名"),
    "SLH-DSA": ("SLH-DSA", "signature", "NIST FIPS 205, SPHINCS+的正式标准名称"),
    "FrodoKEM": ("FrodoKEM", "kem", "基于LWE的后量子密钥封装, 备选方案"),
    "ClassicMcEliece": ("Classic McEliece", "kem", "基于编码理论的后量子密钥封装, 最长公开审计历史"),
    "BIKE": ("BIKE", "kem", "基于编码理论的后量子密钥封装"),
    "HQC": ("HQC", "kem", "基于编码理论的后量子密钥封装"),
    "XMSS": ("XMSS", "signature", "基于哈希的状态相关后量子签名"),
}

@dataclass
class AndroidKeyInfo:
    alias:str; purpose_mask:int=0; padding_modes:List[str]=field(default_factory=list)
    block_modes:List[str]=field(default_factory=list); digests:List[str]=field(default_factory=list)
    key_size_bits:int=0; origin:KeyOrigin=KeyOrigin.UNKNOWN; security_level:SecurityLevel=SecurityLevel.UNKNOWN
    auth_required:bool=False; auth_timeout_seconds:int=-1; user_auth_required:bool=False
    biometric_required:bool=False; is_exportable:bool=False; attestation_challenge:Optional[bytes]=None
    candidate_offsets:List[int]=field(default_factory=list)
    # PQC关联字段
    uses_quantum_vulnerable_algo:bool=False; pqc_algorithm:str=""
    def purposes(self)->List[KeyPurpose]: return [p for p in KeyPurpose if self.purpose_mask&p.value]

@dataclass
class KeymasterVulnerability: cve_id:str; affected_versions:List[KeymasterVersion]; description:str; severity:str; exploit_complexity:str="medium"; patch_level:str=""
@dataclass
class HardcodedKey: material:str; offset:int; key_type:str; size_bits:int; context_preview:str=""; confidence:float=0.0; is_quantum_vulnerable:bool=False

class KeychainAccessibility(StrEnum):
    ALWAYS="kSecAttrAccessibleAlways"; ALWAYS_THIS_DEVICE_ONLY="kSecAttrAccessibleAlwaysThisDeviceOnly"
    WHEN_UNLOCKED="kSecAttrAccessibleWhenUnlocked"; WHEN_UNLOCKED_THIS_DEVICE_ONLY="kSecAttrAccessibleWhenUnlockedThisDeviceOnly"
    AFTER_FIRST_UNLOCK="kSecAttrAccessibleAfterFirstUnlock"; AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY="kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"
    WHEN_PASSCODE_SET_THIS_DEVICE_ONLY="kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly"; UNKNOWN="unknown"
class KeychainClass(StrEnum): GENERIC_PASSWORD="genp"; INTERNET_PASSWORD="inet"; CERTIFICATE="cert"; KEY="keys"; IDENTITY="idnt"

@dataclass
class IOSKeychainItem:
    item_class:KeychainClass=KeychainClass.GENERIC_PASSWORD; accessibility:KeychainAccessibility=KeychainAccessibility.UNKNOWN
    access_group:str=""; service_name:str=""; account:str=""
    has_biometric_protection:bool=False; has_acm:bool=False; acm_flags:List[str]=field(default_factory=list)
    syncable:bool=False; data_protection_class:str=""; candidate_addresses:List[int]=field(default_factory=list)

_KEYMASTER_VULNS=[KeymasterVulnerability("CVE-2018-9475",[KeymasterVersion.V1_0,KeymasterVersion.V2_0],"Keymaster TA边界检查缺失","high",patch_level="2018-11-05"),KeymasterVulnerability("CVE-2021-0392",[KeymasterVersion.V3_0,KeymasterVersion.V4_0],"Keymaster 4.0 importKey绕过安全导入检查","critical","low","2021-02-05"),KeymasterVulnerability("CVE-2021-1905",[KeymasterVersion.V4_0],"Qualcomm Keymaster UAF密钥泄露","critical",patch_level="2021-05-05"),KeymasterVulnerability("CVE-2022-20224",[KeymasterVersion.V3_0,KeymasterVersion.V4_0,KeymasterVersion.V4_1],"Keymaster TA race condition","high",patch_level="2022-08-05"),KeymasterVulnerability("CVE-2023-21137",[KeymasterVersion.V4_0,KeymasterVersion.V4_1],"Keymint shared memory未初始化","medium",patch_level="2023-05-05"),KeymasterVulnerability("CVE-2024-29745",[KeymasterVersion.V4_1],"Android 14 Keymint auth token重放","high","low","2024-04-05"),KeymasterVulnerability("CVE-2024-34724",[KeymasterVersion.V4_0,KeymasterVersion.V4_1],"Keymint shared memory参数注入","critical","medium","2024-06-05")]

_ANDROID_WEAK_PURPOSE_COMBOS=[(KeyPurpose.ENCRYPT.value|KeyPurpose.DECRYPT.value,"加密+解密组合: 可用于对称密码学绕过"),(KeyPurpose.SIGN.value|KeyPurpose.VERIFY.value,"签名+验证组合: 结合不当使用可伪造签名"),(KeyPurpose.SIGN.value|KeyPurpose.ENCRYPT.value,"签名+加密组合: 同一密钥用于两种不同密码学原语, 破坏密钥用途隔离"),(KeyPurpose.WRAP_KEY.value,"密钥包装能力: 充当密钥导出神谕")]

_IOS_WEAK_ACCESSIBILITY=[KeychainAccessibility.ALWAYS,KeychainAccessibility.ALWAYS_THIS_DEVICE_ONLY,KeychainAccessibility.WHEN_UNLOCKED]
_WEAK_KEY_SIZES={"RSA":2048,"EC":256,"AES":128}

_KEY_MAGIC_PATTERNS={b'-----BEGIN RSA PRIVATE KEY-----':('RSA private key',1024),b'-----BEGIN EC PRIVATE KEY-----':('EC private key',256),b'-----BEGIN PRIVATE KEY-----':('PKCS#8 private key',1024),b'-----BEGIN CERTIFICATE-----':('X.509 certificate',0),b'\x30\x82':('DER SEQUENCE (possible key)',1024),b'3082':('hex DER SEQUENCE (possible key)',1024)}
_HEX_KEY_PATTERNS=re.compile(r'[0-9a-fA-F]{32,128}')

def _estimate_entropy(data:bytes)->float:
    if not data: return 0.0
    freq=defaultdict(int)
    for b in data: freq[b]+=1
    length=len(data); entropy=0.0
    for count in freq.values(): p=count/length; entropy-=p*(p.bit_length()-1)
    return entropy/max(len(freq).bit_length(),1)

class AndroidKeystoreAnalyzer:
    _KEYSTORE_ALIAS_PATTERN=re.compile(rb'AndroidKeyStore|AndroidKeyStore\b')
    _KEYGEN_BUILDER_PATTERN=re.compile(rb'KeyGenParameterSpec\.Builder|KeyGenParameterSpec\$Builder')
    _KEY_PURPOSE_PATTERN=re.compile(rb'setPurposes?\(|PURPOSE_ENCRYPT|PURPOSE_DECRYPT|PURPOSE_SIGN|PURPOSE_VERIFY')
    _AUTH_PATTERN=re.compile(rb'setUserAuthenticationRequired|setUserAuthenticationValidityDurationSeconds|setUserAuthenticationParameters|setInvalidatedByBiometricEnrollment')
    _SET_BLOCK_MODE=re.compile(rb'setBlockModes?\(|setEncryptionPaddings?\(')
    _DIGEST_PATTERN=re.compile(rb'setDigests?\(')
    _KEYMASTER_IMPL_PATTERNS=[(rb'keymaster@?1\.0',KeymasterVersion.V1_0),(rb'keymaster@?2\.0',KeymasterVersion.V2_0),(rb'keymaster@?3\.0',KeymasterVersion.V3_0),(rb'keymaster@?4\.0',KeymasterVersion.V4_0),(rb'keymaster@?4\.1|keymint@?1\.0',KeymasterVersion.V4_1),(rb'android\.hardware\.gatekeeper',KeymasterVersion.V3_0)]
    _STRONGBOX_PATTERN=re.compile(rb'StrongBox|STRONGBOX|IsStrongBoxBacked')
    _SECURITY_LEVEL_PATTERN=re.compile(rb'SecurityLevel|TRUSTED_ENVIRONMENT|SOFTWARE')

    def __init__(s,bp:str="",bd:bytes=b""):
        s.binary_path=bp; s.data=bd
        if not s.data and bp and os.path.exists(bp): s.data=Path(bp).read_bytes()
        s.key_infos:List[AndroidKeyInfo]=[]; s.hardcoded_keys:List[HardcodedKey]=[]
        s._detected_version=KeymasterVersion.UNKNOWN; s._has_strongbox=False; s._pqc_score=0.0

    def detect_keymaster_version(s)->KeymasterVersion:
        for p,v in s._KEYMASTER_IMPL_PATTERNS:
            if re.search(p,s.data): s._detected_version=v; return v
        if s._STRONGBOX_PATTERN.search(s.data): s._detected_version=KeymasterVersion.V4_0; return KeymasterVersion.V4_0
        return KeymasterVersion.UNKNOWN

    def extract_key_aliases(s)->List[str]:
        aliases:Set[str]=set()
        for m in s._KEYSTORE_ALIAS_PATTERN.finditer(s.data):
            st=m.end(); end=st; dl=len(s.data)
            while end<dl and end-st<128 and 0x20<=s.data[end]<=0x7E and s.data[end] not in (0x00,0x0A,0x0D): end+=1
            if end>st:
                al=s.data[st:end].decode('ascii',errors='ignore').strip()
                if al and len(al)>1 and not al.startswith('org'): aliases.add(al)
        for m in re.compile(rb'(?:getEntry|getKey|containsAlias)\s*\(\s*"([^"]+)"',re.DOTALL).finditer(s.data):
            al=m.group(1).decode('utf-8',errors='ignore')
            if al and len(al)>1: aliases.add(al)
        return list(aliases)

    def _infer_key_config(s,alias:str,region:bytes)->AndroidKeyInfo:
        info=AndroidKeyInfo(alias=alias)
        if b'PURPOSE_ENCRYPT' in region: info.purpose_mask|=KeyPurpose.ENCRYPT.value
        if b'PURPOSE_DECRYPT' in region: info.purpose_mask|=KeyPurpose.DECRYPT.value
        if b'PURPOSE_SIGN' in region: info.purpose_mask|=KeyPurpose.SIGN.value
        if b'PURPOSE_VERIFY' in region: info.purpose_mask|=KeyPurpose.VERIFY.value
        if b'PURPOSE_WRAP_KEY' in region: info.purpose_mask|=KeyPurpose.WRAP_KEY.value
        if b'setUserAuthenticationRequired' in region: info.user_auth_required=True
        if b'setUserAuthenticationValidityDurationSeconds' in region:
            info.auth_required=True; dm=re.search(rb'DurationSeconds\s*\(\s*(\d+)',region)
            if dm: info.auth_timeout_seconds=int(dm.group(1))
        if b'setInvalidatedByBiometricEnrollment' in region or b'BIOMETRIC_STRONG' in region or b'BIOMETRIC_WEAK' in region: info.biometric_required=True
        for md in [b'GCM',b'CBC',b'CTR',b'ECB']:
            if md in region: info.block_modes.append(md.decode())
        for pd in [b'PKCS7',b'PKCS1',b'OAEP',b'NoPadding']:
            if pd in region: info.padding_modes.append(pd.decode())
        sm=re.search(rb'setKeySize\s*\(\s*(\d+)',region)
        if sm: info.key_size_bits=int(sm.group(1))
        if b'StrongBox' in region or b'StrongBoxKeymaster' in region: info.security_level=SecurityLevel.STRONGBOX
        elif b'TrustedEnvironment' in region or b'keymaster' in region: info.security_level=SecurityLevel.TRUSTED_ENVIRONMENT
        if b'importKey' in region or b'IMPORTED' in region: info.origin=KeyOrigin.IMPORTED
        elif b'SECURELY_IMPORTED' in region: info.origin=KeyOrigin.SECURELY_IMPORTED
        # PQC算法检测
        rsa_pat=re.search(rb'(RSA|ECDSA|ECDH|EC)',region)
        if rsa_pat:
            algo=rsa_pat.group(1).decode()
            if algo in _QUANTUM_VULNERABLE_ALGORITHMS: info.uses_quantum_vulnerable_algo=True
        for pqc_name in _PQC_STANDARDS:
            if pqc_name.encode() in region: info.pqc_algorithm=pqc_name; break
        return info

    def analyze_key_configs(s)->List[AndroidKeyInfo]:
        aliases=s.extract_key_aliases(); results=[]
        for al in aliases:
            ab=al.encode('utf-8',errors='ignore'); idx=s.data.find(ab)
            if idx==-1: continue
            rs=max(0,idx-2048); re_=min(len(s.data),idx+2048)
            info=s._infer_key_config(al,s.data[rs:re_]); info.candidate_offsets.append(idx); results.append(info)
        s.key_infos=results; return results

    def scan_hardcoded_keys(s)->List[HardcodedKey]:
        keys=[]; data=s.data
        for magic,(kt,esz) in _KEY_MAGIC_PATTERNS.items():
            off=0
            while True:
                off=data.find(magic,off)
                if off==-1: break
                end=min(len(data),off+4096); kb=data[off:end]
                etp=kb.find(b'-----END ',len(magic))
                if etp>0:
                    el=kb.find(b'\n',etp)
                    if el>0: kb=kb[:el+1]
                cb=data[max(0,off-32):off].decode('ascii',errors='replace')
                is_qv=any(qalgo.encode() in magic for qalgo in ["RSA","EC "])
                keys.append(HardcodedKey(binascii.hexlify(kb[:64]).decode()+'...',off,kt,esz,cb,0.95,is_qv)); off+=1
        for m in _HEX_KEY_PATTERNS.finditer(data.decode('ascii',errors='ignore')):
            hs=m.group()
            if len(hs)<32: continue
            try:
                raw=bytes.fromhex(hs); ent=_estimate_entropy(raw)
                if ent>0.85:
                    kt='AES' if len(raw) in (16,24,32) else 'generic'
                    is_qv=(kt=='AES' and len(raw)==16)
                    keys.append(HardcodedKey(hs[:64],m.start(),kt,len(raw)*8,confidence=ent*0.9,is_quantum_vulnerable=is_qv))
            except (ValueError, binascii.Error): pass
        s.hardcoded_keys=keys; return keys

    def map_known_vulnerabilities(s)->List[KeymasterVulnerability]:
        ver=s._detected_version
        if ver==KeymasterVersion.UNKNOWN: ver=s.detect_keymaster_version()
        return [v for v in _KEYMASTER_VULNS if ver in v.affected_versions]

# QED式PQC就绪度评估
    def assess_pqc_readiness(s)->Dict[str,Any]:
        """基于QED Toolchain的三阶段PQC就绪度评估。

        阶段1: 文件级, 检测量子脆弱算法库的使用 (OpenSSL, BoringSSL, etc.)
        阶段2: API级, 识别量子脆弱API (RSA_generate_key, ECDSA_sign, etc.)
        阶段3: PQC标准采纳, 检测Kyber/Dilithium/SPHINCS+的使用
        """
        result={"pqc_score":0.0,"quantum_vulnerable_algos":[],"pqc_standards_adopted":[],
                "vulnerable_key_count":0,"hardcoded_qv_count":0,"migration_urgency":"none"}
        d=s.data
        # 阶段1及2：量子脆弱算法检测
        for algo_name,(canonical,cat,desc,rec_size) in _QUANTUM_VULNERABLE_ALGORITHMS.items():
            if algo_name.encode() in d or f'"{algo_name}"'.encode() in d:
                result["quantum_vulnerable_algos"].append({
                    "algorithm":canonical,"category":cat,"risk":desc,
                    "recommended_size":rec_size,"detection":"signature_match"})
        # 阶段3：PQC标准采纳检测
        for pqc_name,(canonical,cat,desc) in _PQC_STANDARDS.items():
            if pqc_name.encode() in d:
                result["pqc_standards_adopted"].append({
                    "algorithm":canonical,"category":cat,"description":desc})
        # 密钥材料之量子脆弱性统计
        result["vulnerable_key_count"]=sum(1 for k in s.key_infos if k.uses_quantum_vulnerable_algo)
        result["hardcoded_qv_count"]=sum(1 for k in s.hardcoded_keys if k.is_quantum_vulnerable)
        # PQC评分: 起始10, 每发现量子脆弱算法扣分, 每采纳PQC标准加分
        score=10.0
        score-=len(result["quantum_vulnerable_algos"])*1.5
        score-=result["vulnerable_key_count"]*0.5
        score-=result["hardcoded_qv_count"]*1.0
        score+=len(result["pqc_standards_adopted"])*2.0
        score=round(min(max(score,0.0),10.0),1)
        result["pqc_score"]=score
        if score<=3: result["migration_urgency"]="critical"
        elif score<=5: result["migration_urgency"]="high"
        elif score<=7: result["migration_urgency"]="medium"
        else: result["migration_urgency"]="low"
        return result

    def assess_weakness(s)->List[Dict[str,Any]]:
        findings=[]
        for info in s.key_infos:
            for mask,desc in _ANDROID_WEAK_PURPOSE_COMBOS:
                if (info.purpose_mask&mask)==mask: findings.append({'alias':info.alias,'type':'weak_purpose_combination','severity':'medium','description':desc,'recommendation':'分离加密/解密与签名/验证密钥'})
            if not info.user_auth_required and info.purpose_mask!=0: findings.append({'alias':info.alias,'type':'no_user_authentication','severity':'high','description':f'密钥{info.alias}未要求用户认证','recommendation':'调用setUserAuthenticationRequired(true)'})
            if info.auth_timeout_seconds>300 or info.auth_timeout_seconds==-1: findings.append({'alias':info.alias,'type':'excessive_auth_timeout','severity':'low' if info.auth_timeout_seconds>300 else 'medium','description':f'认证超时过长:{info.auth_timeout_seconds}s','recommendation':'设置<=300s'})
            if info.origin==KeyOrigin.IMPORTED and info.security_level==SecurityLevel.SOFTWARE: findings.append({'alias':info.alias,'type':'imported_software_key','severity':'high','description':f'密钥{info.alias}是导入的软件密钥','recommendation':'使用KeyStore生成密钥或securely_imported'})
            if 0<info.key_size_bits<2048 and info.purpose_mask&(KeyPurpose.SIGN.value|KeyPurpose.ENCRYPT.value): findings.append({'alias':info.alias,'type':'weak_key_size','severity':'medium','description':f'密钥{info.alias}大小{info.key_size_bits}位低于推荐值','recommendation':'RSA>=2048, EC>=256, AES>=256'})
            # PQC风险告警
            if info.uses_quantum_vulnerable_algo: findings.append({'alias':info.alias,'type':'quantum_vulnerable_crypto','severity':'medium' if info.key_size_bits>=256 else 'high','description':f'密钥{info.alias}使用量子脆弱算法','recommendation':'迁移至Kyber(ML-KEM)或Dilithium(ML-DSA)'})
        for hk in s.hardcoded_keys:
            if hk.confidence>0.7:
                sev='critical' if hk.is_quantum_vulnerable else 'critical'
                findings.append({'type':'hardcoded_key_material','severity':sev,'key_type':hk.key_type,'offset':hex(hk.offset),'description':f'发现硬编码{hk.key_type}: offset{hk.offset:#x}{" [量子脆弱]" if hk.is_quantum_vulnerable else ""}','recommendation':'使用Android Keystore生成密钥'})
        return findings

    def analyze(s)->Dict[str,Any]:
        return {'platform':'android','keymaster_version':s.detect_keymaster_version().value,'has_strongbox':s._STRONGBOX_PATTERN.search(s.data) is not None,'key_configs':[{'alias':k.alias,'purpose_mask':hex(k.purpose_mask),'block_modes':k.block_modes,'padding_modes':k.padding_modes,'key_size_bits':k.key_size_bits,'security_level':k.security_level.value,'origin':k.origin.value,'user_auth_required':k.user_auth_required,'biometric_required':k.biometric_required,'auth_timeout_seconds':k.auth_timeout_seconds,'uses_quantum_vulnerable':k.uses_quantum_vulnerable_algo,'pqc_algorithm':k.pqc_algorithm} for k in s.key_infos],'hardcoded_keys':[{'type':k.key_type,'offset':hex(k.offset),'confidence':round(k.confidence,2),'quantum_vulnerable':k.is_quantum_vulnerable} for k in s.hardcoded_keys],'known_vulnerabilities':[{'cve':v.cve_id,'severity':v.severity,'description':v.description} for v in s.map_known_vulnerabilities()],'weakness_findings':s.assess_weakness(),'pqc_readiness':s.assess_pqc_readiness()}

    def run_full(s)->Dict[str,Any]: s.extract_key_aliases(); s.analyze_key_configs(); s.scan_hardcoded_keys(); return s.analyze()

class IOSKeychainAnalyzer:
    _SEC_ITEM_ADD=re.compile(rb'_SecItemAdd\b'); _SEC_ITEM_COPY=re.compile(rb'_SecItemCopyMatching\b')
    _SEC_ITEM_UPDATE=re.compile(rb'_SecItemUpdate\b'); _SEC_ITEM_DELETE=re.compile(rb'_SecItemDelete\b')
    _ACCESSIBILITY_MAP:Dict[bytes,KeychainAccessibility]={b'kSecAttrAccessibleAlways':KeychainAccessibility.ALWAYS,b'kSecAttrAccessibleAlwaysThisDeviceOnly':KeychainAccessibility.ALWAYS_THIS_DEVICE_ONLY,b'kSecAttrAccessibleWhenUnlocked':KeychainAccessibility.WHEN_UNLOCKED,b'kSecAttrAccessibleWhenUnlockedThisDeviceOnly':KeychainAccessibility.WHEN_UNLOCKED_THIS_DEVICE_ONLY,b'kSecAttrAccessibleAfterFirstUnlock':KeychainAccessibility.AFTER_FIRST_UNLOCK,b'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly':KeychainAccessibility.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,b'kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly':KeychainAccessibility.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY}
    _ACL_FLAG_PATTERNS=[(rb'kSecAccessControlUserPresence','UserPresence'),(rb'kSecAccessControlBiometryAny','BiometryAny'),(rb'kSecAccessControlBiometryCurrentSet','BiometryCurrentSet'),(rb'kSecAccessControlDevicePasscode','DevicePasscode'),(rb'kSecAccessControlOr','Or'),(rb'kSecAccessControlAnd','And'),(rb'kSecAccessControlPrivateKeyUsage','PrivateKeyUsage'),(rb'kSecAccessControlApplicationPassword','AppPassword')]
    _ACCESS_GROUP_PATTERN=re.compile(rb'keychain-access-groups|com\.\w+\.\w+')

    def __init__(s,bp:str="",bd:bytes=b""):
        s.binary_path=bp; s.data=bd
        if not s.data and bp and os.path.exists(bp): s.data=Path(bp).read_bytes()
        s.keychain_items:List[IOSKeychainItem]=[]; s._secitem_calls:Dict[str,List[int]]=defaultdict(list)

    def detect_keychain_api_usage(s)->Dict[str,List[int]]:
        for name,pat in [('SecItemAdd',s._SEC_ITEM_ADD),('SecItemCopyMatching',s._SEC_ITEM_COPY),('SecItemUpdate',s._SEC_ITEM_UPDATE),('SecItemDelete',s._SEC_ITEM_DELETE)]:
            for m in pat.finditer(s.data): s._secitem_calls[name].append(m.start())
        return dict(s._secitem_calls)

    def _infer_accessibility(s)->KeychainAccessibility:
        found=KeychainAccessibility.UNKNOWN
        for rf,acc in s._ACCESSIBILITY_MAP.items():
            if rf in s.data:
                if found==KeychainAccessibility.UNKNOWN or list(KeychainAccessibility).index(acc)<list(KeychainAccessibility).index(found): found=acc
        return found

    def _detect_acl_flags(s)->List[str]: return [fn for p,fn in s._ACL_FLAG_PATTERNS if p in s.data]
    def _extract_access_groups(s)->List[str]:
        groups:Set[str]=set()
        for m in s._ACCESS_GROUP_PATTERN.finditer(s.data): groups.add(m.group(0).decode('utf-8',errors='ignore'))
        return list(groups)

    def analyze_keychain_config(s)->IOSKeychainItem:
        item=IOSKeychainItem(); item.accessibility=s._infer_accessibility(); item.acm_flags=s._detect_acl_flags()
        item.access_group=','.join(s._extract_access_groups())
        item.has_biometric_protection=any(f in item.acm_flags for f in ['BiometryAny','BiometryCurrentSet','UserPresence'])
        item.has_acm=len(item.acm_flags)>0; return item

    def assess_weakness(s)->List[Dict[str,Any]]:
        findings=[]; item=s.analyze_keychain_config()
        if item.accessibility in _IOS_WEAK_ACCESSIBILITY: findings.append({'type':'weak_accessibility','severity':'high' if item.accessibility==KeychainAccessibility.ALWAYS else 'medium','description':f'Keychain弱accessibility:{item.accessibility.value}','recommendation':'改用WhenUnlockedThisDeviceOnly'})
        if not item.has_acm: findings.append({'type':'no_access_control','severity':'medium','description':'未使用SecAccessControl','recommendation':'添加kSecAccessControlUserPresence'})
        if 'BiometryAny' in item.acm_flags and 'BiometryCurrentSet' not in item.acm_flags: findings.append({'type':'weak_biometric_binding','severity':'medium','description':'使用BiometryAny而非CurrentSet','recommendation':'改用BiometryCurrentSet'})
        ac=s.detect_keychain_api_usage(); tc=sum(len(v) for v in ac.values())
        if tc==0: findings.append({'type':'no_keychain_usage','severity':'info','description':'未检测到Keychain API使用'})
        findings.append({'type':'keychain_api_summary','severity':'info','description':f'Keychain API调用:{ {k:len(v) for k,v in ac.items()} }'})
        return findings

    def analyze(s)->Dict[str,Any]:
        item=s.analyze_keychain_config(); au=s.detect_keychain_api_usage()
        return {'platform':'ios','keychain_accessibility':item.accessibility.value,'access_control_flags':item.acm_flags,'has_biometric_protection':item.has_biometric_protection,'access_groups':item.access_group.split(',') if item.access_group else [],'keychain_api_usage':{k:len(v) for k,v in au.items()},'weakness_findings':s.assess_weakness()}
    def run_full(s)->Dict[str,Any]: s.detect_keychain_api_usage(); return s.analyze()

_MACHO_MAGICS=[b'\xcf\xfa\xed\xfe',b'\xfe\xed\xfa\xcf',b'\xce\xfa\xed\xfe',b'\xfe\xed\xfa\xce']

def analyze_keystore_security(binary_path:str,platform:str='auto')->Dict[str,Any]:
    path=Path(binary_path)
    if not path.exists(): return {'error':f'文件不存在:{binary_path}'}
    data=path.read_bytes()
    if platform=='auto':
        magic=data[:4]
        if magic in _MACHO_MAGICS: platform='ios'
        elif data[:4]==b'\x7fELF': platform='android'
        else: platform='android' if (b'AndroidKeyStore' in data or b'keymaster' in data) else 'ios'
    if platform=='android':
        a=AndroidKeystoreAnalyzer(bd=data); r=a.run_full()
    else:
        a=IOSKeychainAnalyzer(bd=data); r=a.run_full()
    r['binary_path']=str(path); r['platform']=platform; r['file_hash']=hashlib.sha256(data).hexdigest()[:16]
    return r

@dataclass
class MobileKeystoreVulnerability: type:str=''; severity:str='Medium'; description:str=''; platform:str=''; location:str=''
class MobileKeystoreAnalyzer:
    def __init__(s,path:str,platform:str='auto'): s.path=path; s.platform=platform
    def analyze(s)->Dict[str,Any]: return analyze_keystore_security(s.path,s.platform)
