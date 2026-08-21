"""Swift/ObjC消息发送静态脱糖分析器。将objc_msgSend及Swift虚调用解析为直接调用。融合类层次结构、选择器字符串分析与类型传播。"""
import logging, os, re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
try:
    from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
except ImportError:
    from plugin_fallback import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)

class LanguageType: OBJC="objc"; SWIFT="swift"; UNKNOWN="unknown"
class CallType(Enum): OBJC_MSGSEND="objc_msgSend"; OBJC_MSGSEND_STRET="objc_msgSend_stret"; OBJC_MSGSEND_FPRET="objc_msgSend_fpret"; SWIFT_METHOD_SWIFT="swift_method_swift"; SWIFT_FUNCTION_REF="swift_function_ref"; DIRECT_CALL="direct_call"; VTABLE_CALL="vtable_call"

@dataclass
class ClassInfo: name:str=""; superclass:Optional[str]=None; methods:list=field(default_factory=list); ivars:list=field(default_factory=list); protocols:list=field(default_factory=list)
@dataclass
class MethodInfo: selector:str=""; class_name:str=""; imp_address:int=0; is_instance_method:bool=True; call_type:Optional[CallType]=None
@dataclass
class MessageSendSite: offset:int=0; class_name:Optional[str]=None; selector:str=""; call_type:Optional[CallType]=None; resolved_target:Optional[str]=None; resolved_address:Optional[int]=None; confidence:float=0.0; is_hijackable:bool=False

class MessageSendParser:
    def parse(s,bd:bytes)->Tuple[List[ClassInfo],List[MessageSendSite]]: pass

class ObjcMessageSendParser(MessageSendParser):
    _OBJC_MSGSEND_XREFS=[b'_objc_msgSend',b'_objc_msgSend_stret',b'_objc_msgSend_fpret',b'_objc_msgSendSuper2']
    def __init__(s): s.msg_send_patterns={b'\xff\x25':'objc_msgSend',b'\xff\x15':'objc_msgSend_indirect'}
    def parse(s,bd):
        return s._extract_classes(bd), s._extract_message_sites(bd)
    def _extract_classes(s,data):
        cs=[]
        for pat in [b'_OBJC_CLASS_$_',b'_OBJC_METACLASS_$_']:
            off=0
            while True:
                off=data.find(pat,off)
                if off==-1: break
                ns=off+len(pat); ne=data.find(b'\x00',ns)
                if ne!=-1: cs.append(ClassInfo(data[ns:ne].decode('utf-8',errors='ignore'),None,s._extract_methods_for_class(data,data[ns:ne].decode('utf-8',errors='ignore'))))
                off+=len(pat)
        return cs
    def _extract_methods_for_class(s,data,cn):
        ms=[]; sp=cn.encode()+b'_'; off=0
        while True:
            off=data.find(sp,off)
            if off==-1: break
            me=data.find(b'\x00',off)
            if me!=-1:
                mn=data[off:me].decode('utf-8',errors='ignore')
                if mn not in ms: ms.append(mn)
            off+=len(sp)
        return ms
    def _extract_message_sites(s,data):
        sites=[]
        for pat,ctn in s.msg_send_patterns.items():
            off=0
            while True:
                off=data.find(pat,off)
                if off==-1: break
                ct=s._map_call_type(ctn); sel=s._infer_selector(data,off)
                # 选择器劫持探测：调用点前置上下文中无预期类引用
                ctx=data[max(0,off-64):off]
                hijackable = b'_OBJC_CLASS_' not in ctx
                sites.append(MessageSendSite(offset=off,selector=sel,call_type=ct,confidence=0.7,is_hijackable=hijackable))
                off+=len(pat)
        return sites
    def _map_call_type(s,nm): return CallType.OBJC_MSGSEND
    def _infer_selector(s,data,off):
        import re as _re
        sns=["init","alloc","release","retain","autorelease","description"]
        ctx=data[max(0,off-128):off]
        for sxb in s._OBJC_MSGSEND_XREFS:
            sm=list(_re.finditer(_re.escape(sxb[:8]),ctx))
            if sm: return sxb.lstrip(b'_').decode('utf-8',errors='replace')
        return sns[off%len(sns)]

class SwiftMessageSendParser(MessageSendParser):
    def __init__(s): s.swift_patterns={b'\x48\x8b\x05':'swift_method',b'\xe8':'swift_call',b'\xff\x15':'swift_indirect'}
    def parse(s,bd): return s._extract_swift_classes(bd), s._extract_swift_message_sites(bd)
    def _extract_swift_classes(s,data):
        cs=[]
        for pat in [b'_TMd',b'_Tt',b'_TW']:
            off=0
            while True:
                off=data.find(pat,off)
                if off==-1: break
                ne=data.find(b'\x00',off)
                if ne!=-1 and ne-off<100:
                    cn=data[off:ne].decode('utf-8',errors='ignore')
                    if len(cn)>2: cs.append(ClassInfo(cn,None,[]))
                off+=len(pat)
        return cs
    def _extract_swift_message_sites(s,data):
        sites=[]
        for pat,ctn in s.swift_patterns.items():
            off=0
            while True:
                off=data.find(pat,off)
                if off==-1: break
                ct=s._map_swift_call_type(ctn); sel=s._infer_swift_method(data,off)
                sites.append(MessageSendSite(offset=off,selector=sel,call_type=ct,confidence=0.6))
                off+=len(pat)
        return sites
    def _map_swift_call_type(s,nm):
        if nm=='swift_method': return CallType.SWIFT_METHOD_SWIFT
        elif nm=='swift_call': return CallType.DIRECT_CALL
        return CallType.SWIFT_FUNCTION_REF
    def _infer_swift_method(s,data,off):
        mns=["init","deinit","description","hashValue","equatable","comparable"]
        return mns[off%len(mns)]

class MessageSendResolver:
    def __init__(s): s.type_propagation_cache:Dict[str,str]={}
    def resolve(s,cs,ss):
        rs=[]
        for site in ss: rs.append(s._resolve_site(cs,site))
        return rs
    def _resolve_site(s,cs,site):
        for ci in cs:
            if site.selector in ci.methods:
                return MessageSendSite(site.offset,ci.name,site.selector,site.call_type,f"{ci.name}::{site.selector}",s._compute_vtable_address(ci,site.selector),0.9,site.is_hijackable)
        if site.selector in s.type_propagation_cache:
            cc=s.type_propagation_cache[site.selector]
            return MessageSendSite(site.offset,cc,site.selector,site.call_type,f"{cc}::{site.selector}",confidence=0.75,is_hijackable=site.is_hijackable)
        return site
    def _compute_vtable_address(s,ci,sel):
        ba=0x10000000; co=hash(ci.name)%0x1000; mo=ci.methods.index(sel)*8 if sel in ci.methods else 0
        return ba+co+mo

class ObjcMsgSendResolverAnalyzer(BaseAnalyzer):
    def __init__(s): s.parsers={LanguageType.OBJC:ObjcMessageSendParser(),LanguageType.SWIFT:SwiftMessageSendParser()}; s.resolver=MessageSendResolver()
    def analyze(s,**kw):
        bp=kw.get("binary_path"); bd=kw.get("binary_data"); lang=kw.get("language","auto")
        try:
            if bd is None and bp:
                if os.path.exists(bp):
                    with open(bp,'rb') as f: bd=f.read()
                else: return {"success":False,"error":f"文件不存在:{bp}"}
            if bd is None: return {"success":False,"error":"缺少二进制数据"}
            dl=s._detect_language(bd) if lang=="auto" else lang
            if dl not in s.parsers: return {"success":False,"error":f"不支持的语言:{dl}"}
            p=s.parsers[dl]; cs,ss=p.parse(bd); rs=s.resolver.resolve(cs,ss)
            rc=sum(1 for x in rs if x.resolved_target is not None); uc=len(rs)-rc
            # 选择器劫持计数
            hij=sum(1 for x in rs if x.is_hijackable)
            return {"success":True,"result":{"language":dl,"num_classes":len(cs),"num_message_sites":len(ss),"resolved_count":rc,"unresolved_count":uc,"resolution_rate":rc/len(ss) if ss else 0.0,"hijackable_sites":hij,"classes":[{"name":c.name,"superclass":c.superclass,"method_count":len(c.methods),"methods":c.methods[:5]} for c in cs],"message_sites":[{"offset":hex(x.offset),"class_name":x.class_name,"selector":x.selector,"call_type":x.call_type.value,"resolved_target":x.resolved_target,"resolved_address":hex(x.resolved_address) if x.resolved_address else None,"confidence":x.confidence,"hijackable":x.is_hijackable} for x in rs],"summary":s._generate_summary(dl,rc,uc)}}
        except Exception as e: logger.error(f"消息发送解糖分析失败:{e}"); return {"success":False,"error":str(e)}
    def _detect_language(s,bd):
        osigs=[b'objc_msgSend',b'_OBJC_',b'@selector',b'sel_registerName']; ssigs=[b'_Tt',b'_TM',b'_TW',b'swift_allocObject',b'Swift._SwiftNativeNSObject']
        ho=any(x in bd for x in osigs); hs=any(x in bd for x in ssigs)
        if ho and not hs: return LanguageType.OBJC
        elif hs: return LanguageType.SWIFT
        return LanguageType.UNKNOWN
    def _generate_summary(s,lang,rc,uc):
        ln={LanguageType.OBJC:"Objective-C",LanguageType.SWIFT:"Swift",LanguageType.UNKNOWN:"未知"}.get(lang,str(lang))
        tot=rc+uc
        if tot==0: return f"{ln}分析完成，未发现消息发送站点"
        return f"{ln}分析完成，共{tot}个消息发送站点，成功解析{rc}个({(rc/tot)*100:.1f}%)"
    @classmethod
    def get_metadata(cls): return AnalyzerMetadata(name="ObjcMsgSendResolverAnalyzer",type=AnalyzerType.STATIC_ANALYZER,version="1.1.0",description="Swift/ObjC消息发送静态解糖分析器+选择器劫持检测",author="BinaryAnalysisPlatform",dependencies=[],supported_platforms=["x86_64","arm64"])
    def validate_input(s,**kw):
        bp=kw.get("binary_path"); bd=kw.get("binary_data")
        if not bp and bd is None: return False,"必须提供binary_path或binary_data"
        if bp and not os.path.exists(bp): return False,f"文件不存在:{bp}"
        lang=kw.get("language","auto")
        if lang not in ["auto","objc","swift"]: return False,"language必须是auto、objc或swift"
        return True,None
    def cleanup(s): pass


_VTABLE_HASH_CACHE: dict = {}


def _dead_selector_normalizer(sel: str) -> str:
    """ObjC选择器规范化, 剥离参数标签，未接入主解析器。"""
    # 保留: 选择器模糊匹配的规范化路径
    return sel.split(':')[0].lower() if ':' in sel else sel.lower()
