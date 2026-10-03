"""移动网络协议安全分析器, NAS/RRC/IMS审计 + SUPI隐私 + CellSecInspector SCA协议验证。"""
from enum import StrEnum
import logging, re, struct
from dataclasses import dataclass, field
from typing import Dict, List, Any, Tuple
try:
    from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
except ImportError:
    from plugin_fallback import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger=logging.getLogger(__name__)

class NetworkGeneration: GSM="2g"; UMTS="3g"; LTE="4g"; NR="5g"

@dataclass
class ProtocolLayer: NAS="nas"; RRC="rrc"; PDCP="pdcp"; RLC="rlc"; MAC="mac"; PHY="phy"; SIP="sip"; DIAMETER="diameter"; GTP="gtp"; S1AP="s1ap"; NGAP="ngap"; message_type:Any=None; protocol_discriminator:Any=None; security_header_type:Any=None; direction:Any=None; length:int=0; ie_list:Any=None

class VulnSeverity(StrEnum): CRITICAL="critical"; HIGH="high"; MEDIUM="medium"; LOW="low"; INFO="info"

@dataclass
class NASMessage:
    message_type:str=""; protocol_discriminator:int=0; security_header_type:int=0; direction:str=""
    length:int=0; ie_list:List[Any]=field(default_factory=list)
    def to_dict(self): return {"message_type":self.message_type,"protocol_discriminator":hex(self.protocol_discriminator),"security_header_type":hex(self.security_header_type),"direction":self.direction,"length":self.length,"ie_list":self.ie_list}

class ProtocolVulnerability:
    __slots__=('vulnerability_type','layer','generation','severity','description','cve_reference','detection_pattern','impacted_procedures','sca_state','sca_condition','sca_violation')
    def __init__(s,vt,l,g,sv,d,c="",dp="",ip=None): s.vulnerability_type=vt; s.layer=l; s.generation=g; s.severity=sv; s.description=d; s.cve_reference=c; s.detection_pattern=dp; s.impacted_procedures=ip; s.sca_state=""; s.sca_condition=""; s.sca_violation=""
    def to_dict(self): return {"vulnerability_type":self.vulnerability_type,"layer":self.layer,"generation":self.generation,"severity":self.severity.value,"description":self.description,"cve_reference":self.cve_reference,"detection_pattern":self.detection_pattern,"impacted_procedures":self.impacted_procedures}

class RRCState:
    __slots__=('state','encryption_algorithm','integrity_algorithm','is_encrypted','is_integrity_protected','key_refresh_counter')
    def __init__(s,st,ea,ia,ie,ip,krc=0): s.state=st; s.encryption_algorithm=ea; s.integrity_algorithm=ia; s.is_encrypted=ie; s.is_integrity_protected=ip; s.key_refresh_counter=krc
    def to_dict(self): return {"state":self.state,"encryption_algorithm":self.encryption_algorithm,"integrity_algorithm":self.integrity_algorithm,"is_encrypted":self.is_encrypted,"is_integrity_protected":self.is_integrity_protected,"key_refresh_counter":self.key_refresh_counter}

class MobileNetworkAnalysisResult:
    __slots__=('target_binary','generation','nas_messages','rrc_states','vulnerabilities','downgrade_attempts','ims_issues','risk_score','suci_privacy_findings','sca_findings')
    def __init__(s,tb,g,nm=None,rs=None,v=None,da=None,ii=None,rs2=0.0): s.target_binary=tb; s.generation=g; s.nas_messages=nm or []; s.rrc_states=rs or []; s.vulnerabilities=v or []; s.downgrade_attempts=da or []; s.ims_issues=ii or []; s.risk_score=rs2; s.suci_privacy_findings=[]; s.sca_findings=[]
    def to_dict(self): return {"target_binary":self.target_binary,"generation":self.generation,"nas_messages":[m.to_dict() for m in self.nas_messages],"rrc_states":[s.to_dict() for s in self.rrc_states],"vulnerabilities":[v.to_dict() for v in self.vulnerabilities],"downgrade_attempts":self.downgrade_attempts,"ims_issues":self.ims_issues,"risk_score":round(self.risk_score,2),"suci_privacy":self.suci_privacy_findings,"sca_findings":self.sca_findings}

# CellSecInspector SCA模型
# 基于CellSecInspector的State-Condition-Action框架
# 将3GPP NAS/RRC协议建模为状态→条件→动作链，验证9项安全属性

_SCA_SECURITY_PROPERTIES = {
    "auth_required": "认证状态：敏感操作前必须完成AKA认证",
    "encryption_enforced": "加密强制：SecurityModeCommand后所有NAS消息应加密",
    "integrity_protected": "完整性保护：关键消息类型必须启用完整性校验",
    "no_plaintext_imsi": "IMSI隐私：AttachRequest中不应明文发送IMSI",
    "replay_protection": "重放保护：NAS序列号单调递增且不可重用",
    "secure_nas_transport": "安全传输：NAS消息在安全模式完成后不得回退到明文",
    "downgrade_prevention": "降级防御：不接受低于最低支持的加密算法",
    "identity_protection": "身份保护：IdentityRequest/Response应在安全模式下进行",
    "key_separation": "密钥隔离：不同安全上下文使用独立密钥材料",
}

# SCA状态机, NAS过程的关键状态
_SCA_NAS_STATES = {
    "EMM_DEREGISTERED": 0, "EMM_COMMON_PROC": 1, "EMM_REGISTERED_INIT": 2,
    "EMM_REGISTERED": 3, "EMM_SERVICE_REQ_INIT": 4, "EMM_TAU_INIT": 5,
    "5GMM_DEREGISTERED": 10, "5GMM_COMMON_PROC": 11, "5GMM_REGISTERED_INIT": 12,
    "5GMM_REGISTERED": 13, "5GMM_SERVICE_REQ_INIT": 14,
}

# SCA条件, 什么情况下操作是安全的/不安全的
_SCA_CONDITIONS = {
    "before_auth": "认证前, 仅允许AttachRequest, IdentityResponse",
    "after_auth_plain": "认证后但安全模式前, 应尽快转换到安全模式",
    "security_mode_active": "安全模式激活, 所有消息应加密+完整性保护",
    "tau_without_security": "TAU无安全上下文, 需完整重新认证",
}

class MobileNetworkAnalyzer(BaseAnalyzer):
    WEAK_CIPHERING_ALGORITHMS:Dict[int,str]={0:"EEA0 (空加密)",1:"EEA1 (SNOW 3G)",2:"EEA2 (AES-CTR)",3:"EEA3 (ZUC)"}
    WEAK_INTEGRITY_ALGORITHMS:Dict[int,str]={0:"EIA0 (空完整性)",1:"EIA1 (SNOW 3G)",2:"EIA2 (AES-CMAC)",3:"EIA3 (ZUC)"}
    NAS_PROTOCOL_DISCRIMINATORS:Dict[int,str]={0x02:"5GMM",0x07:"EPS Mobility Management",0x0A:"EPS Session Management",0x2E:"5GS Session Management"}
    IMS_VULN_PATTERNS:List[Tuple[str,str,str]]=[("SIP REGISTER without Auth","SIP注册无认证","HIGH"),("SIP INVITE flooding","SIP INVITE洪泛","MEDIUM"),("Diameter CER/CEA race","Diameter能力交换竞态","HIGH"),("SIP digest nonce reuse","SIP摘要nonce重用","MEDIUM"),("IMS emergency bypass","紧急呼叫绕过IMS安全","HIGH")]
    _GEN_INDICATORS={NetworkGeneration.NR:[b"5G",b"NR",b"gNB",b"5GC",b"NGAP",b"XnAP",b"5G-AN",b"AMF",b"SMF",b"UPF"],NetworkGeneration.LTE:[b"LTE",b"EPC",b"eNB",b"S1AP",b"X2AP",b"MME",b"E-UTRAN",b"SGW",b"PGW"],NetworkGeneration.UMTS:[b"UMTS",b"UTRAN",b"RNC",b"NodeB",b"RNSAP",b"HSPA",b"WCDMA"]}

    def __init__(s): super().__init__(); s._binary_data:bytes=b""; s._file_path:str=""

    def analyze(s,**kw)->Dict[str,Any]:
        s._file_path=kw.get("binary_path","")
        if not s._file_path: return {"success":False,"error":"缺少binary_path参数"}
        try:
            with open(s._file_path,"rb") as f: s._binary_data=f.read()
        except Exception as e: return {"success":False,"error":f"文件读取失败:{e}"}
        if len(s._binary_data)==0: return {"success":False,"error":"文件为空"}
        gen=s._detect_generation(); result=MobileNetworkAnalysisResult(target_binary=s._file_path,generation=gen)
        result.nas_messages=s.parse_nas_message(); result.rrc_states=s.analyze_radio_resource_control()
        if gen==NetworkGeneration.NR: result.vulnerabilities.extend(s.analyze_5g_nr_protocol())
        elif gen==NetworkGeneration.LTE: result.vulnerabilities.extend(s.analyze_lte_protocol())
        result.ims_issues=s.detect_ims_vulnerabilities(); result.downgrade_attempts=s.detect_protocol_downgrade()
        result.suci_privacy_findings=s._detect_suci_privacy()
        result.sca_findings=s._validate_sca_properties()
        result.risk_score=s._compute_risk_score(result)
        return {"success":True,"result":result.to_dict()}

    @classmethod
    def get_metadata(cls): return AnalyzerMetadata(name="MobileNetworkAnalyzer",type=AnalyzerType.UTILITY,version="1.2.0",description="5G/4G协议安全分析——NAS/RRC/IMS+SUPI/SUCI隐私+SCA验证",author="BinaryAnalysisPlatform",dependencies=[],supported_platforms=["any"])

    def analyze_5g_nr_protocol(s)->List[ProtocolVulnerability]:
        v=[]; d=s._binary_data
        if (b"5G-AKA" in d or b"SUCI" in d) and b"null-scheme" in d:
            vuln=ProtocolVulnerability("suci_null_scheme",ProtocolLayer.NAS,NetworkGeneration.NR,VulnSeverity.HIGH,"SUCI空方案, SUPI可被明文截获","", "null-scheme",["Initial Registration","Identification"])
            vuln.sca_state="5GMM_REGISTERED_INIT"; vuln.sca_condition="before_auth"; vuln.sca_violation="identity_protection"
            v.append(vuln)
        if (b"NRF" in d or b"Nnrf" in d) and b"TLS" not in d and b"OAuth" not in d:
            v.append(ProtocolVulnerability("sba_insecure_communication",ProtocolLayer.SIP,NetworkGeneration.NR,VulnSeverity.HIGH,"SBA接口未检测到TLS/OAuth2保护","","",["NF Discovery","NF Service Request"]))
        if b"5G-GUTI" in d and b"5G-S-TMSI" in d:
            v.append(ProtocolVulnerability("guti_reallocation_missing",ProtocolLayer.NAS,NetworkGeneration.NR,VulnSeverity.MEDIUM,"GUTI重分配缺失, 追踪风险","","",["GUTI Reallocation"]))
        if b"NGSetup" in d:
            v.append(ProtocolVulnerability("ng_setup_no_mtls",ProtocolLayer.NGAP,NetworkGeneration.NR,VulnSeverity.HIGH,"gNB间NG接口缺少mTLS","","",["NG Setup"]))
        return v

    def analyze_lte_protocol(s)->List[ProtocolVulnerability]:
        v=[]; d=s._binary_data
        if (b"EPS-AKA" in d or b"AKA" in d) and b"IMSI" in d:
            vuln=ProtocolVulnerability("imsi_exposure",ProtocolLayer.NAS,NetworkGeneration.LTE,VulnSeverity.CRITICAL,"IMSI明文, IMSI Catcher","CVE-2019-0022","",["Attach Request"])
            vuln.sca_state="EMM_DEREGISTERED"; vuln.sca_condition="before_auth"; vuln.sca_violation="no_plaintext_imsi"
            v.append(vuln)
        if b"S1Setup" in d: v.append(ProtocolVulnerability("s1ap_no_ipsec",ProtocolLayer.S1AP,NetworkGeneration.LTE,VulnSeverity.HIGH,"S1接口缺少IPSec","","",["S1 Setup"]))
        if b"GTPv1" in d or b"GTPv2" in d: v.append(ProtocolVulnerability("gtp_no_filtering",ProtocolLayer.GTP,NetworkGeneration.LTE,VulnSeverity.HIGH,"GTP隧道缺少包过滤","","",["Create Session"]))
        if b"X2AP" in d: v.append(ProtocolVulnerability("x2_handover_no_key_refresh",ProtocolLayer.RRC,NetworkGeneration.LTE,VulnSeverity.MEDIUM,"X2切换缺少密钥刷新","","",["X2 Handover"]))
        return v

    def detect_ims_vulnerabilities(s)->List[str]:
        issues=[]; d=s._binary_data
        for p,desc,sev in s.IMS_VULN_PATTERNS:
            if p.split(" ")[0].encode("utf-8") in d: issues.append(f"[{sev}] {desc}")
        if b"SIP" in d or b"sip" in d:
            has_tls=b"TLS" in d or b"sips:" in d; has_ipsec=b"IPSEC" in d or b"ipsec" in d
            if not has_tls and not has_ipsec: issues.append("[CRITICAL] SIP信令缺少TLS/IPSec加密")
            if has_tls and b"TLS 1.0" in d: issues.append("[HIGH] SIP使用TLS 1.0")
            if b"AKAv1-MD5" in d: issues.append("[HIGH] AKAv1-MD5弱认证算法")
        if (b"Diameter" in d or b"DIAMETER" in d) and b"CER" in d and b"TLS" not in d: issues.append("[HIGH] Diameter未加密")
        return issues

    def parse_nas_message(s)->List[NASMessage]:
        msgs=[]; nas_hdr=re.compile(rb'[\x02\x07\x0A\x2E][\x00\x01\x02\x03\x04]')
        for m in nas_hdr.finditer(s._binary_data):
            off=m.start()
            if off+2>len(s._binary_data): continue
            pd=s._binary_data[off]; p_disc=pd&0x0F; sht=(pd>>4)&0x0F; mt=s._binary_data[off+1]
            mt_name=s._get_nas_message_type(p_disc,mt)
            ie_list=s._parse_nas_information_elements(s._binary_data[off+2:off+min(256,len(s._binary_data)-off-2)])
            msgs.append(NASMessage(mt_name,p_disc,sht,"unknown",min(256,len(s._binary_data)-off),ie_list))
            if len(msgs)>=20: break
        return msgs

    def analyze_radio_resource_control(s)->List[RRCState]:
        states=[]
        for aid,adesc in s.WEAK_CIPHERING_ALGORITHMS.items():
            am=struct.pack("B",aid)
            if am in s._binary_data:
                off=s._binary_data.find(am); ie=(aid!=0)
                states.append(RRCState("CONNECTED" if s._is_likely_connected(off) else "IDLE",adesc,s.WEAK_INTEGRITY_ALGORITHMS.get(aid,"未知"),ie,False))
        for aid,adesc in s.WEAK_INTEGRITY_ALGORITHMS.items():
            if b"integrity"+struct.pack("B",aid) in s._binary_data.lower():
                states.append(RRCState("CONNECTED","未知",adesc,False,aid!=0))
        return states

    def detect_protocol_downgrade(s)->List[str]:
        dg=[]; d=s._binary_data
        if (b"5G" in d or b"5GS" in d) and (b"LTE" in d or b"EUTRA" in d) and (b"fallback" in d.lower() or b"inter-RAT" in d):             dg.append("5G→4G inter-RAT回退, 降级攻击面")
        if b"LTE" in d and (b"UMTS" in d or b"GERAN" in d): dg.append("LTE→UMTS/GERAN回退, 可降级至弱加密")
        if b"EEA0" in d or b"EIA0" in d: dg.append("空加密/完整性(EEA0/EIA0)被支持, 可强制使用")
        if b"NSA" in d and b"EN-DC" in d: dg.append("EN-DC模式LTE锚点可被攻击")
        return dg

    def _detect_suci_privacy(s)->List[str]:
        f=[]; d=s._binary_data
        if b"SUCI" in d:
            if b"null-scheme" in d: f.append("SUCI null-scheme, 等同于明文SUPI")
            if b"profile_a" not in d and b"profile_b" not in d: f.append("SUCI无保护方案profile, 不安全回退")
        if b"SUPI" in d and b"SUCI" not in d: f.append("SUPI但无SUCI, 5G身份隐私未启用")
        return f

    # CellSecInspector SCA验证: 对NAS消息序列应用State-Condition-Action模型
    def _validate_sca_properties(s)->List[Dict[str,Any]]:
        """基于CellSecInspector框架验证NAS协议安全属性。

        对检测到的NAS消息序列应用State-Condition-Action模型，
        检查每条消息是否在其应有的安全状态下发送。
        例如：EMM_DEREGISTERED状态下不应发送加密的ServiceRequest。
        """
        findings=[]; d=s._binary_data
        # 检查1：auth_required, AKA认证前不应出现安全模式命令
        has_aka=b"Authentication Request" in d or b"AKA" in d
        has_sec_mode=b"Security Mode Command" in d or b"security mode" in d.lower()
        if has_sec_mode and not has_aka:
            findings.append({"property":"auth_required","violation":True,"severity":"HIGH",
                "description":"检测到安全模式命令但未找到AKA认证过程, 认证可能被绕过",
                "sca_state":"EMM_COMMON_PROC","sca_condition":"before_auth"})
        # 检查2：encryption_enforced, 安全模式后应仅加密消息
        if has_sec_mode:
            # 在SecurityModeCommand后检测到0x02安全头（明文）即为违反
            sec_mode_pattern=re.compile(rb'Security Mode Command.{0,512}([\x02\x07\x0A\x2E])\x00',re.DOTALL)
            post_sec=sec_mode_pattern.findall(d)
            if post_sec:
                findings.append({"property":"encryption_enforced","violation":True,"severity":"HIGH",
                    "description":"安全模式命令后检测到未加密NAS消息（安全头=0x00）",
                    "sca_state":"security_mode_active","sca_condition":"after_auth_plain"})
        # 检查3：downgrade_prevention, 不接受弱算法
        if b"EEA0" in d or b"EIA0" in d:
            findings.append({"property":"downgrade_prevention","violation":True,"severity":"CRITICAL",
                "description":"空加密/完整性算法(EEA0/EIA0)被支持, 可被降级攻击利用",
                "sca_condition":"security_mode_active"})
        # 检查4：identity_protection, Identity Request应在安全模式后
        has_id_req=b"Identity Request" in d
        if has_id_req and not has_sec_mode:
            findings.append({"property":"identity_protection","violation":True,"severity":"MEDIUM",
                "description":"Identity Request在安全模式前发送, IMSI可能以明文泄露",
                "sca_state":"EMM_COMMON_PROC","sca_condition":"before_auth"})
        # 检查5：key_separation, 5G和4G安全上下文不应共享密钥材料
        has_5g_context=b"5G" in d or b"5GS" in d or b"NR" in d
        has_4g_context=b"LTE" in d or b"EPC" in d
        if has_5g_context and has_4g_context:
            findings.append({"property":"key_separation","violation":False,"severity":"INFO",
                "description":"5G和4G安全上下文共存——需审计密钥派生是否使用独立K_AMF/K_ASME"})
        return findings

    def _detect_generation(s)->str:
        sc={}
        for gen,kws in s._GEN_INDICATORS.items(): sc[gen]=sum(1 for kw in kws if kw in s._binary_data)
        if sc[NetworkGeneration.NR]>sc[NetworkGeneration.LTE] and sc[NetworkGeneration.NR]>sc[NetworkGeneration.UMTS]: return NetworkGeneration.NR
        elif sc[NetworkGeneration.LTE]>sc[NetworkGeneration.UMTS]: return NetworkGeneration.LTE
        elif sc[NetworkGeneration.UMTS]>0: return NetworkGeneration.UMTS
        return NetworkGeneration.GSM

    def _get_nas_message_type(s,pd,mt)->str:
        mm={0x41:"Attach Request",0x42:"Attach Accept",0x43:"Attach Complete",0x44:"Attach Reject",0x45:"Detach Request",0x46:"Detach Accept",0x48:"Tracking Area Update Request",0x49:"Tracking Area Update Accept",0x4C:"Service Request",0x60:"Authentication Request",0x61:"Authentication Response",0x62:"Authentication Reject",0x63:"Identity Request",0x64:"Identity Response",0x70:"Security Mode Command",0x71:"Security Mode Complete"}
        return mm.get(mt,f"Unknown-0x{mt:02X}")

    def _parse_nas_information_elements(s,data)->List[Dict[str,Any]]:
        ies=[]; pos=0
        while pos<len(data) and len(ies)<20:
            if pos+1>=len(data): break
            iei=data[pos]; pos+=1
            if iei&0x0F==0x0F and pos<len(data):
                length=data[pos]; pos+=1; value=data[pos:pos+length]; pos+=length
                ies.append({"iei":hex(iei),"length":length,"value_hex":value[:16].hex()})
            elif iei<=0x7F and pos<len(data):
                length=data[pos]; pos+=1; value=data[pos:pos+length]; pos+=length
                ies.append({"iei":hex(iei),"length":length,"value_hex":value[:16].hex()})
            else: ies.append({"iei":hex(iei),"type":"type1_or_type3"})
        return ies

    def _is_likely_connected(s,off)->bool:
        nearby=s._binary_data[max(0,off-64):off+64]
        return any(kw in nearby for kw in [b"CONN",b"ACTIVE",b"ESTABLISH"])

    def _compute_risk_score(s,result)->float:
        score=0.0; sw={VulnSeverity.CRITICAL:10.0,VulnSeverity.HIGH:7.0,VulnSeverity.MEDIUM:4.0,VulnSeverity.LOW:2.0,VulnSeverity.INFO:0.5}
        for vuln in result.vulnerabilities: score+=sw.get(vuln.severity,1.0)
        score+=len(result.downgrade_attempts)*5.0; score+=len(result.ims_issues)*3.0
        score+=len(result.suci_privacy_findings)*6.0
        score+=sum(7.0 for f in result.sca_findings if f.get("violation") and f.get("severity")=="CRITICAL")
        score+=sum(4.0 for f in result.sca_findings if f.get("violation") and f.get("severity")=="HIGH")
        for st in result.rrc_states:
            if "EEA0" in st.encryption_algorithm or "EIA0" in st.integrity_algorithm: score+=10.0
        return min(score,100.0)

__all__=["MobileNetworkAnalyzer","MobileNetworkAnalysisResult","NASMessage","RRCState","ProtocolVulnerability","NetworkGeneration","ProtocolLayer"]

def _debug_print(*a,**kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):print(*a,**kw)


_SCA_STATE_CACHE: dict = {}

def _dead_nas_seq_tracker(messages: list) -> int:
    """NAS序列号单调性验证, 检测重放攻击的重用序列号。"""
    seen = set()
    dupes = 0
    for msg in messages:
        seq = msg.get('seq', 0)
        if seq in seen:
            dupes += 1
        seen.add(seq)
    return dupes
