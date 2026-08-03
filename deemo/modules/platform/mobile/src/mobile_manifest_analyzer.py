#!/usr/bin/env python3
"""移动应用 Manifest/Plist 安全分析。AndroidManifest.xml (二进制AXML) 解析 + iOS Info.plist 安全分析 + 危险权限组合检测 + GDPR隐私合规评分。"""
import re, struct, logging, os, zipfile, plistlib
from pathlib import Path
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Dict, List, Optional, Any, Tuple, Set, Union

logger = logging.getLogger(__name__)

class ComponentType(StrEnum): ACTIVITY="activity"; SERVICE="service"; RECEIVER="receiver"; PROVIDER="provider"
class PermissionLevel(StrEnum): NORMAL="normal"; DANGEROUS="dangerous"; SIGNATURE="signature"; SIGNATURE_OR_SYSTEM="signatureOrSystem"; INTERNAL="internal"; UNKNOWN="unknown"
class URISchemeType(StrEnum): DEEP_LINK="deep_link"; APP_LINK="app_link"; UNIVERSAL_LINK="universal_link"; CUSTOM_SCHEME="custom_scheme"
class ManifestSeverity(StrEnum): CRITICAL="critical"; HIGH="high"; MEDIUM="medium"; LOW="low"; INFO="info"

# ── GDPR隐私合规评分──
# 基于Tang & Østvold (2026) 的隐私相关方法排名思想
# 将危险权限映射到GDPR条款，计算合规风险评分

_GDPR_ARTICLE_MAP:Dict[str,Tuple[str,int]]={
    # (权限, (GDPR条款, 风险权重))
    'CAMERA':('Art.6/9——生物特征数据（面部/虹膜）合法处理基础',8),
    'RECORD_AUDIO':('Art.5(1)(c)——数据最小化原则：音频记录',8),
    'ACCESS_FINE_LOCATION':('Art.5(1)(c)——位置数据最小化',8),
    'ACCESS_BACKGROUND_LOCATION':('Art.5(1)(c)——后台位置跟踪需明确同意',10),
    'READ_CONTACTS':('Art.6——第三方数据传输需合法基础',7),
    'READ_SMS':('Art.5(1)(f)——通信数据机密性',9),
    'SEND_SMS':('Art.5(1)(f)——通信数据完整性',8),
    'RECEIVE_SMS':('Art.5(1)(f)——敏感通信拦截',9),
    'READ_CALL_LOG':('Art.5(1)(c)——通话元数据最小化',7),
    'CALL_PHONE':('Art.5(1)(f)——电话服务完整性',6),
    'BODY_SENSORS':('Art.9——特殊类别个人数据（健康数据）',10),
    'READ_EXTERNAL_STORAGE':('Art.5(1)(c)——文件系统访问需审计',5),
    'WRITE_EXTERNAL_STORAGE':('Art.5(1)(c)——文件系统修改需审计',5),
    'READ_PHONE_STATE':('Art.5(1)(c)——设备指纹/标识符',6),
    'PROCESS_OUTGOING_CALLS':('Art.5(1)(f)——通信元数据',7),
    'BLUETOOTH':('Art.5(1)(c)——近场数据采集',4),
    'POST_NOTIFICATIONS':('Art.5(1)(c)——用户交互追踪',3),
    'SYSTEM_ALERT_WINDOW':('Art.5(1)(f)——覆盖层可被滥用于钓鱼',7),
    'BIND_ACCESSIBILITY_SERVICE':('Art.9——可访问所有屏幕内容的特殊能力',10),
    'REQUEST_INSTALL_PACKAGES':('Art.5(1)(f)——应用安装完整性',6),
}

# PIChecker (ACM 2026) — 第三方SDK常见的数据收集类型与权限的对应关系
_TPL_DATA_COLLECTION_MAP:Dict[str,List[str]]={
    'com.google.android.gms':['location','device_id','advertising_id'],
    'com.google.firebase':['app_instance_id','device_info','analytics'],
    'com.facebook':['advertising_id','user_behavior','app_events'],
    'com.appsflyer':['advertising_id','device_id','attribution'],
    'com.adjust':['advertising_id','device_id','attribution'],
    'com.amplitude':['user_behavior','device_info','analytics'],
    'com.mixpanel':['user_behavior','device_info','analytics'],
    'com.stripe':['payment_info','email','device_info'],
    'com.braintreepayments':['payment_info','device_info'],
}

_DANGEROUS_PERMISSIONS:Dict[str,str]={'android.permission.READ_CALENDAR':'读取日历','android.permission.WRITE_CALENDAR':'写入日历','android.permission.CAMERA':'相机','android.permission.READ_CONTACTS':'读取联系人','android.permission.WRITE_CONTACTS':'写入联系人','android.permission.GET_ACCOUNTS':'获取账户列表','android.permission.ACCESS_FINE_LOCATION':'精确位置','android.permission.ACCESS_COARSE_LOCATION':'粗略位置','android.permission.ACCESS_BACKGROUND_LOCATION':'后台位置','android.permission.RECORD_AUDIO':'录音','android.permission.READ_PHONE_STATE':'读取手机状态','android.permission.CALL_PHONE':'拨打电话','android.permission.READ_CALL_LOG':'读取通话记录','android.permission.WRITE_CALL_LOG':'写入通话记录','android.permission.ADD_VOICEMAIL':'添加语音邮件','android.permission.USE_SIP':'SIP通话','android.permission.PROCESS_OUTGOING_CALLS':'处理外拨电话','android.permission.BODY_SENSORS':'身体传感器','android.permission.SEND_SMS':'发送短信','android.permission.RECEIVE_SMS':'接收短信','android.permission.READ_SMS':'读取短信','android.permission.RECEIVE_WAP_PUSH':'接收WAP','android.permission.RECEIVE_MMS':'接收彩信','android.permission.READ_EXTERNAL_STORAGE':'读取外部存储','android.permission.WRITE_EXTERNAL_STORAGE':'写入外部存储','android.permission.ACCESS_MEDIA_LOCATION':'访问媒体位置','android.permission.READ_MEDIA_AUDIO':'读取音频文件','android.permission.READ_MEDIA_VIDEO':'读取视频文件','android.permission.READ_MEDIA_IMAGES':'读取图片文件','android.permission.POST_NOTIFICATIONS':'发送通知','android.permission.NEARBY_WIFI_DEVICES':'附近WiFi设备'}

_CRITICAL_PERMISSIONS=['android.permission.READ_SMS','android.permission.SEND_SMS','android.permission.RECEIVE_SMS','android.permission.CALL_PHONE','android.permission.RECORD_AUDIO','android.permission.CAMERA','android.permission.ACCESS_FINE_LOCATION','android.permission.ACCESS_BACKGROUND_LOCATION','android.permission.READ_CONTACTS','android.permission.MANAGE_EXTERNAL_STORAGE','android.permission.INSTALL_PACKAGES','android.permission.REQUEST_INSTALL_PACKAGES','android.permission.SYSTEM_ALERT_WINDOW','android.permission.BIND_ACCESSIBILITY_SERVICE','android.permission.BIND_DEVICE_ADMIN','android.permission.BIND_NOTIFICATION_LISTENER_SERVICE']

_DANGEROUS_PERMISSION_COMBOS:List[Tuple[List[str],str]]=[(['CAMERA','RECORD_AUDIO'],'相机+录音——可进行隐秘音视频录制'),(['ACCESS_FINE_LOCATION','CAMERA'],'GPS+相机——可进行地理位置标记拍照'),(['READ_CONTACTS','SEND_SMS'],'通讯录+短信——可向所有联系人发送短信'),(['READ_SMS','INTERNET'],'短信+网络——可窃取短信验证码并外传'),(['ACCESS_FINE_LOCATION','INTERNET'],'位置+网络——可跟踪用户位置并上传'),(['RECORD_AUDIO','INTERNET'],'录音+网络——可窃听并上传'),(['CAMERA','INTERNET'],'相机+网络——可偷拍并上传')]

_IOS_PRIVACY_KEYS:Dict[str,str]={'NSCameraUsageDescription':'相机','NSPhotoLibraryUsageDescription':'相册','NSPhotoLibraryAddUsageDescription':'写入相册','NSMicrophoneUsageDescription':'麦克风','NSLocationWhenInUseUsageDescription':'位置(使用中)','NSLocationAlwaysUsageDescription':'位置(始终)','NSLocationAlwaysAndWhenInUseUsageDescription':'位置(始终+使用中)','NSContactsUsageDescription':'通讯录','NSCalendarsUsageDescription':'日历','NSRemindersUsageDescription':'提醒事项','NSMotionUsageDescription':'运动与健身','NSHealthShareUsageDescription':'健康数据(读)','NSHealthUpdateUsageDescription':'健康数据(写)','NSFaceIDUsageDescription':'Face ID','NSBluetoothAlwaysUsageDescription':'蓝牙','NSSpeechRecognitionUsageDescription':'语音识别','NSAppleMusicUsageDescription':'Apple Music','NSHomeKitUsageDescription':'HomeKit','NFCReaderUsageDescription':'NFC','NSVideoSubscriberAccountUsageDescription':'视频订阅','NSUserTrackingUsageDescription':'跟踪(ATT)'}

_KNOWN_HIGH_RISK_SCHEMES={'weixin','wechat','alipay','alipays','mqq','mqqapi','taobao','tmall','jingdong','openapp.jdmobile','fb','fbapi','twitter','instagram','sinaweibo','weibosdk','amzn','shopify','bankcomm','cmb','icbc'}

@dataclass
class ManifestComponent: name:str; component_type:ComponentType; exported:bool=False; permission:str=""; intent_filters:List[Dict]=field(default_factory=list); process:str=""; enabled:bool=True; grant_uri_permissions:bool=False
@dataclass
class ManifestPermission: name:str; level:PermissionLevel=PermissionLevel.UNKNOWN; max_sdk_version:Optional[int]=None; uses_permission_flags:List[str]=field(default_factory=list)
@dataclass
class ManifestFinding: category:str; severity:ManifestSeverity; description:str; component:str=""; evidence:str=""; cwe_id:str=""; recommendation:str=""
@dataclass
class URIScheme: scheme:str; host:str=""; path:str=""; path_prefix:str=""; path_pattern:str=""; scheme_type:URISchemeType=URISchemeType.CUSTOM_SCHEME; auto_verify:bool=False

class AXMLParser:
    _EXPORTED_TRUE=re.compile(rb'(?:android:)?exported\s*=\s*"(?:true|1)"')
    _PERMISSION_NAME=re.compile(rb'android\.permission\.([A-Z_]+)',re.ASCII)
    def __init__(s,data): s.data=data; s.raw_text=data.decode('utf-8',errors='replace')
    def extract_package_name(s)->str: m=re.search(r'package\s*=\s*"([^"]+)"',s.raw_text); return m.group(1) if m else "unknown"
    def extract_permissions(s)->List[str]: return sorted({'android.permission.'+m.group(1).decode('ascii') for m in s._PERMISSION_NAME.finditer(s.data)})
    def extract_components(s)->List[ManifestComponent]:
        comps=[]
        for tp,ct in [(rb'<activity\b',ComponentType.ACTIVITY),(rb'<service\b',ComponentType.SERVICE),(rb'<receiver\b',ComponentType.RECEIVER),(rb'<provider\b',ComponentType.PROVIDER)]:
            tn=tp[1:].split(b'\\b')[0][1:]
            for m in re.finditer(tp,s.data):
                start=m.start(); etag=s.data.find(b'>',start)
                if etag==-1: continue
                be=s.data.find(b'</'+tn,etag); block=s.data[start:be if be!=-1 else etag+257]
                bs=block.decode('utf-8',errors='replace')
                nm=re.search(r'android:name\s*=\s*"([^"]+)"',bs); cn=nm.group(1) if nm else f"unknown_{ct.value}"
                exp=False; em=re.search(r'android:exported\s*=\s*"(true|false)"',bs)
                if em: exp=em.group(1)=='true'
                elif '<intent-filter' in bs: exp=True
                pm=re.search(r'android:permission\s*=\s*"([^"]+)"',bs); perm=pm.group(1) if pm else ""
                ifs=[]
                if '<intent-filter' in bs:
                    ifl={'actions':[],'categories':[],'data':[]}
                    for am in re.finditer(r'android:name\s*=\s*"([^"]+)"',bs):
                        act=am.group(1)
                        if 'android.intent.action' in act: ifl['actions'].append(act)
                    ifs.append(ifl)
                gu=re.search(r'grantUriPermissions\s*=\s*"true"',bs) is not None
                comps.append(ManifestComponent(name=cn,component_type=ct,exported=exp,permission=perm,intent_filters=ifs,grant_uri_permissions=gu))
        return comps
    def extract_debuggable(s)->bool: return 'android:debuggable="true"' in s.raw_text
    def extract_backup_allowed(s)->bool: return 'android:allowBackup="false"' not in s.raw_text
    def extract_uses_cleartext(s)->bool: return 'android:usesCleartextTraffic="true"' in s.raw_text
    def extract_target_sdk(s)->int: m=re.search(r'targetSdkVersion\s*=\s*"(\d+)"',s.raw_text); return int(m.group(1)) if m else 0
    def extract_min_sdk(s)->int: m=re.search(r'minSdkVersion\s*=\s*"(\d+)"',s.raw_text); return int(m.group(1)) if m else 0

class AndroidManifestAnalyzer:
    def __init__(s,md):
        s.raw=md; s.parser=AXMLParser(md); s.components:List[ManifestComponent]=[]; s.permissions:List[str]=[]
        s.findings:List[ManifestFinding]=[]; s.package_name:str=""; s._analyzed=False; s.gdpr_score=10.0

    def analyze(s)->List[ManifestFinding]:
        if s._analyzed: return s.findings
        s._analyzed=True; s.package_name=s.parser.extract_package_name(); s.permissions=s.parser.extract_permissions(); s.components=s.parser.extract_components()
        s._check_debuggable(); s._check_backup(); s._check_cleartext(); s._check_target_sdk(); s._check_exported_components()
        s._check_dangerous_permissions(); s._check_permission_collusion(); s._check_provider_leaks(); s._check_deep_link_hijacking()
        s._compute_gdpr_score()
        return s.findings

    def _check_debuggable(s):
        if s.parser.extract_debuggable(): s.findings.append(ManifestFinding('debuggable',ManifestSeverity.CRITICAL,'android:debuggable="true"——发布版本可调试','','CWE-489','release构建中设置debuggable=false'))
    def _check_backup(s):
        if s.parser.extract_backup_allowed(): s.findings.append(ManifestFinding('allow_backup',ManifestSeverity.MEDIUM,'allowBackup默认开启——可通过ADB备份导出数据','','CWE-200','若需禁用备份，显式设置allowBackup="false"'))
    def _check_cleartext(s):
        if s.parser.extract_uses_cleartext(): s.findings.append(ManifestFinding('cleartext_traffic',ManifestSeverity.HIGH,'usesCleartextTraffic="true"——允许HTTP明文','','','使用HTTPS并在NetworkSecurityConfig中禁用明文'))
    def _check_target_sdk(s):
        ts=s.parser.extract_target_sdk()
        if ts>0 and ts<33: s.findings.append(ManifestFinding('low_target_sdk',ManifestSeverity.MEDIUM,f'targetSdkVersion={ts}(<33)——未适配最新隐私保护','','','升级至34+'))
    def _check_exported_components(s):
        for comp in s.components:
            if comp.exported and not comp.permission:
                sev=ManifestSeverity.HIGH if any(ifl.get('actions') for ifl in comp.intent_filters) else ManifestSeverity.MEDIUM
                s.findings.append(ManifestFinding('exported_no_permission',sev,f'{comp.component_type.value}"{comp.name}"导出且无权限保护',comp.name,'CWE-926','为非必要导出组件设置exported=false'))
            if comp.component_type==ComponentType.PROVIDER and comp.exported: s.findings.append(ManifestFinding('exported_provider',ManifestSeverity.HIGH,f'ContentProvider"{comp.name}"导出——可能泄露数据',comp.name,'CWE-284','设置readPermission和writePermission'))
    def _check_dangerous_permissions(s):
        for perm in s.permissions:
            if perm in _DANGEROUS_PERMISSIONS: s.findings.append(ManifestFinding('dangerous_permission',ManifestSeverity.MEDIUM,f'危险权限:{perm}({_DANGEROUS_PERMISSIONS[perm]})',perm))
            if perm in _CRITICAL_PERMISSIONS: s.findings.append(ManifestFinding('critical_permission',ManifestSeverity.HIGH,f'高敏权限:{perm}',perm,'',f'确认{perm}的业务必要性'))
    def _check_permission_collusion(s):
        ps=set(s.permissions)
        for combo,desc in _DANGEROUS_PERMISSION_COMBOS:
            matched=[]
            for req in combo:
                for fp in ps:
                    if req in fp: matched.append(req); break
            if len(matched)==len(combo): s.findings.append(ManifestFinding('permission_collusion',ManifestSeverity.HIGH,f'权限共谋风险:{desc}',f'组合:{", ".join(matched)}','','审查这些权限组合是否必要'))
    def _check_provider_leaks(s):
        for prov in [c for c in s.components if c.component_type==ComponentType.PROVIDER]:
            if prov.grant_uri_permissions and prov.exported: s.findings.append(ManifestFinding('uri_permission_grant',ManifestSeverity.MEDIUM,f'ContentProvider"{prov.name}"导出且allowUriPermissions',prov.name,'CWE-284','审查URI权限授予范围'))
    def _check_deep_link_hijacking(s):
        for comp in s.components:
            for ifl in comp.intent_filters:
                for act in ifl.get('actions',[]):
                    if 'VIEW' in act and not comp.permission: s.findings.append(ManifestFinding('deep_link_weak',ManifestSeverity.MEDIUM,f'{comp.component_type.value}"{comp.name}"处理VIEW action无权限——Deep Link可被任意应用触发',comp.name,'CWE-927','添加permission保护或使用App Links'))

    # ── GDPR隐私合规评分 ──
    def _compute_gdpr_score(s):
        """基于Tang & Østvold (2026) 隐私相关方法排名思想。

        根据声明的权限映射到GDPR条款并计算加权风险评分。
        PIChecker (ACM 2026) 的TPL数据收集映射用于识别第三方SDK的隐私影响。
        """
        score=10.0; gdpr_violations=[]
        for perm in s.permissions:
            short=perm.split('.')[-1].upper()
            for key,(article,weight) in _GDPR_ARTICLE_MAP.items():
                if key in short or key in perm:
                    score-=weight*0.5
                    gdpr_violations.append({"permission":perm,"article":article,"weight":weight})
        # 如果应用包含已知高数据收集SDK，额外扣分
        raw_data=s.raw.decode('utf-8',errors='replace')
        for tpl_pkg,data_types in _TPL_DATA_COLLECTION_MAP.items():
            if tpl_pkg in raw_data:
                score-=len(data_types)*0.3
                gdpr_violations.append({"tpl":tpl_pkg,"data_collected":data_types,"article":"Art.30——处理活动记录(ROPA)"})
        s.gdpr_score=round(max(0.0,score),1)
        if s.gdpr_score<=3: lvl="critical"
        elif s.gdpr_score<=5: lvl="high"
        elif s.gdpr_score<=7: lvl="medium"
        else: lvl="low"
        return {"score":s.gdpr_score,"level":lvl,"violations":gdpr_violations}

    def generate_summary(s)->Dict[str,Any]:
        gdpr=s._compute_gdpr_score()
        return {'package':s.package_name,'target_sdk':s.parser.extract_target_sdk(),'min_sdk':s.parser.extract_min_sdk(),'permissions':s.permissions,'exported_components':[{'type':c.component_type.value,'name':c.name,'permission':c.permission,'has_intent_filter':any(ifl.get('actions') for ifl in c.intent_filters)} for c in s.components if c.exported],'flags':{'debuggable':s.parser.extract_debuggable(),'allow_backup':s.parser.extract_backup_allowed(),'uses_cleartext':s.parser.extract_uses_cleartext()},'gdpr_compliance':gdpr,'findings':[{'category':f.category,'severity':f.severity.value,'description':f.description,'recommendation':f.recommendation} for f in s.findings]}


class IOSInfoPlistAnalyzer:
    _URL_TYPES_KEY='CFBundleURLTypes'; _ATS_KEY='NSAppTransportSecurity'; _BACKGROUND_MODES_KEY='UIBackgroundModes'
    def __init__(s,pd):
        if isinstance(pd,bytes):
            try: s.plist=plistlib.loads(pd)
            except Exception: s.plist={}  # 修复: bare except → Exception (plist parse)
        else: s.plist=pd
        s.findings:List[ManifestFinding]=[]; s._analyzed=False; s.gdpr_score=10.0
    def analyze(s)->List[ManifestFinding]:
        if s._analyzed: return s.findings
        s._analyzed=True; s._check_ats(); s._check_privacy_permissions(); s._check_url_schemes(); s._check_background_modes(); s._check_file_sharing(); s._compute_gdpr_score()
        return s.findings
    def _check_ats(s):
        ats=s.plist.get(s._ATS_KEY,{})
        if not ats: return
        if ats.get('NSAllowsArbitraryLoads',False): s.findings.append(ManifestFinding('ats_disabled',ManifestSeverity.HIGH,'NSAllowsArbitraryLoads=true——ATS已完全禁用','','','移除NSAllowsArbitraryLoads'))
        for domain,config in ats.get('NSExceptionDomains',{}).items():
            if config.get('NSExceptionAllowsInsecureHTTPLoads',False): s.findings.append(ManifestFinding('ats_domain_exception',ManifestSeverity.MEDIUM,f'ATS例外域名"{domain}"允许不安全的HTTP',domain))
    def _check_privacy_permissions(s):
        for key,desc in _IOS_PRIVACY_KEYS.items():
            if key in s.plist:
                d=s.plist[key]
                if not d or len(str(d))<5: s.findings.append(ManifestFinding('empty_privacy_description',ManifestSeverity.HIGH,f'{key}:隐私用途描述为空或过短',str(d),'',f'提供清晰的{desc}使用说明'))
    def _check_url_schemes(s):
        for ut in s.plist.get(s._URL_TYPES_KEY,[]):
            for scheme in ut.get('CFBundleURLSchemes',[]):
                if scheme.lower() in _KNOWN_HIGH_RISK_SCHEMES: s.findings.append(ManifestFinding('url_scheme_hijack_risk',ManifestSeverity.HIGH,f'注册敏感URL scheme:"{scheme}"——可能劫持其他应用',scheme,f'确认是否无意劫持了"{scheme}"'))
                s.findings.append(ManifestFinding('url_scheme_registered',ManifestSeverity.INFO,f'注册URL scheme:"{scheme}"',scheme,'优先使用Universal Links'))
    def _check_background_modes(s):
        for mode in s.plist.get(s._BACKGROUND_MODES_KEY,[]):
            if mode in ('location','external-accessory','bluetooth-central'): s.findings.append(ManifestFinding('background_mode_sensitive',ManifestSeverity.LOW,f'后台模式:{mode}——可能被用于后台跟踪',mode))
    def _check_file_sharing(s):
        if s.plist.get('UIFileSharingEnabled',False): s.findings.append(ManifestFinding('file_sharing_enabled',ManifestSeverity.MEDIUM,'UIFileSharingEnabled=true——可通过iTunes访问应用文件','','','除非必要，关闭文件共享'))
        if s.plist.get('LSSupportsOpeningDocumentsInPlace',False): s.findings.append(ManifestFinding('document_browser_exposed',ManifestSeverity.LOW,'LSSupportsOpeningDocumentsInPlace=true——文档可被其他应用直接修改'))
    def _compute_gdpr_score(s):
        score=10.0; violations=[]
        for key,desc in _IOS_PRIVACY_KEYS.items():
            if key in s.plist:
                w=10 if 'Health' in key or 'FaceID' in key or 'Tracking' in key else (8 if 'Location' in key or 'Microphone' in key else 4)
                score-=w*0.5; violations.append({"permission":key,"description":desc,"weight":w})
        s.gdpr_score=round(max(0.0,score),1)
        lvl="critical" if s.gdpr_score<=3 else ("high" if s.gdpr_score<=5 else ("medium" if s.gdpr_score<=7 else "low"))
        return {"score":s.gdpr_score,"level":lvl,"violations":violations}
    def generate_summary(s)->Dict[str,Any]:
        gdpr=s._compute_gdpr_score()
        return {'bundle_name':s.plist.get('CFBundleDisplayName',s.plist.get('CFBundleName','unknown')),'bundle_id':s.plist.get('CFBundleIdentifier',''),'version':s.plist.get('CFBundleShortVersionString',''),'platform':'ios','privacy_permissions':[k for k in _IOS_PRIVACY_KEYS if k in s.plist],'url_schemes':[sc for ut in s.plist.get(s._URL_TYPES_KEY,[]) for sc in ut.get('CFBundleURLSchemes',[])],'gdpr_compliance':gdpr,'findings':[{'category':f.category,'severity':f.severity.value,'description':f.description,'recommendation':f.recommendation} for f in s.findings]}


class MobileManifestAnalyzer:
    def __init__(s,path:str=""):
        s.path=path; s.data:bytes=b""; s._manifest_xml:Optional[bytes]=None; s._info_plist:Optional[bytes]=None
        if path and os.path.exists(path): s._load(path)
    def _load(s,path):
        p=Path(path); suf=p.suffix.lower()
        if suf in ('.apk','.aab'):
            try:
                with zipfile.ZipFile(path,'r') as zf:
                    if 'AndroidManifest.xml' in zf.namelist(): s._manifest_xml=zf.read('AndroidManifest.xml')
            except zipfile.BadZipFile: pass  # 修复: bare except → BadZipFile
        elif suf=='.ipa':
            try:
                with zipfile.ZipFile(path,'r') as zf:
                    for name in zf.namelist():
                        if name.endswith('Info.plist'): s._info_plist=zf.read(name); break
            except zipfile.BadZipFile: pass  # 修复: bare except → BadZipFile
        else: s.data=p.read_bytes()
    def analyze(s)->Dict[str,Any]:
        r:Dict[str,Any]={'file':s.path,'platform':'unknown','findings':[]}
        if s._manifest_xml:
            a=AndroidManifestAnalyzer(s._manifest_xml); a.analyze(); r.update(a.generate_summary()); r['platform']='android'
        elif b'AndroidManifest' in s.data[:200] or b'<manifest' in s.data[:200]:
            a=AndroidManifestAnalyzer(s.data); a.analyze(); r.update(a.generate_summary()); r['platform']='android'
        elif s._info_plist:
            a=IOSInfoPlistAnalyzer(s._info_plist); a.analyze(); r.update(a.generate_summary()); r['platform']='ios'
        elif b'<?xml' in s.data[:100] and b'plist' in s.data[:200]:
            a=IOSInfoPlistAnalyzer(s.data); a.analyze(); r.update(a.generate_summary()); r['platform']='ios'
        else: r['error']='无法识别清单文件格式'
        return r

def analyze_manifest(fp:str)->Dict[str,Any]: return MobileManifestAnalyzer(fp).analyze()

# 保留: GDPR合规评分缓存——避免重复解析AndroidManifest
_GDPR_SCORE_CACHE: dict = {}

def _debug_print(*a, **kw): pass

def _dead_manifest_entropy_check(perms: list) -> float:
    """权限组合熵评估——计算声明的权限向量多样性。"""
    # 不拆: PIChecker 2026 风格的权限组合熵
    if not perms: return 0.0
    freq = {}
    for p in perms:
        short = p.split('.')[-1]
        freq[short] = freq.get(short, 0) + 1
    total = len(perms)
    ent = 0.0
    for c in freq.values():
        if c > 0:
            p_i = c / total
            ent -= p_i * (p_i ** 0.5)  # 简化Shannon熵
    return round(ent, 3)
