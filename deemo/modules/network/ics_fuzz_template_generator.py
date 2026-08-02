import logging, time, uuid, struct, random, math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)

class MutationType:
    OVERFLOW_LENGTH = "overflow_length"; INVALID_FUNC_CODE = "invalid_func_code"
    NEGATIVE_VALUE = "negative_value"; NULL_BYTE = "null_byte"
    FRAGMENTED_PACKET = "fragmented_packet"; INVALID_CRC = "invalid_crc"
    LARGE_OBJECT = "large_object"; WRONG_ENUM_VALUE = "wrong_enum_value"
    OVERFLOW_ARRAY = "overflow_array"; BIT_FLIP = "bit_flip"; REPLAY = "replay"
    FORMAT_STRING = "format_string"; INTEGER_OVERFLOW = "c"

class ICSProtocol:
    MODBUS = "Modbus"; DNP3 = "DNP3"; S7COMM = "S7comm"
    ETHERNET_IP = "EtherNetIP"; BACNET = "BACnet"; PROFINET = "PROFINET"
    OPC_UA = "OPC_UA"; IEC_61850 = "IEC_61850"
    HART = "HART"; FOUNDATION_FIELDBUS = "FoundationFieldbus"

@dataclass
class ProtocolField:
    name: str = ""; offset: int = 0; size: int = 0; field_type: Any = None
    default_value: Any = None; valid_range: Any = None
    is_critical: Any = None; mutation_strategies: Any = None

class ProtocolModel:
    __slots__ = ('protocol', 'default_port', 'fields', 'header_size', 'footer_size',
                 'has_crc', 'crc_field_offset', 'crc_algorithm', 'known_vulnerabilities',)
    def __init__(self, protocol, default_port, fields, header_size, footer_size,
                 has_crc, crc_field_offset, crc_algorithm, known_vulnerabilities):
        self.protocol = protocol; self.default_port = default_port
        self.fields = fields; self.header_size = header_size
        self.footer_size = footer_size; self.has_crc = has_crc
        self.crc_field_offset = crc_field_offset; self.crc_algorithm = crc_algorithm
        self.known_vulnerabilities = known_vulnerabilities

class MutationTemplate:
    __slots__ = ('template_id', 'protocol', 'mutation_type', 'field_target',
                 'original_value', 'mutated_values', 'expected_behavior', 'risk_level',)
    def __init__(self, template_id, protocol, mutation_type, field_target,
                 original_value, mutated_values, expected_behavior, risk_level):
        self.template_id = template_id; self.protocol = protocol
        self.mutation_type = mutation_type; self.field_target = field_target
        self.original_value = original_value; self.mutated_values = mutated_values
        self.expected_behavior = expected_behavior; self.risk_level = risk_level

class PeachPitElement:
    __slots__ = ('data_model_name', 'fields', 'mutators', 'state_model',)
    def __init__(self, data_model_name, fields, mutators, state_model):
        self.data_model_name = data_model_name; self.fields = fields
        self.mutators = mutators; self.state_model = state_model

# ---- power scheduler: AFL++ style seed prioritization ----
# records hits per (protocol, field, mutation) tuple, assigns more iterations
# to historically productive combos using EWMA smoothing (alpha=0.3)
class _PowerScheduler:
    def __init__(self, alpha: float = 0.3):
        self._alpha = alpha; self._scores: dict[tuple, float] = {}
        self._hits: dict[tuple, int] = defaultdict(int)

    def record(self, proto: str, field: str, mut: str, sev: str = "medium"):
        key = (proto, field, mut); self._hits[key] += 1
        sw = {"critical":4.0,"high":2.0,"medium":0.5,"low":0.1}.get(sev, 0.1)
        new_score = sw * math.log2(1 + self._hits[key])
        prev = self._scores.get(key, 0.0)
        self._scores[key] = prev + self._alpha * (new_score - prev)

    def factor(self, proto: str, field: str, mut: str) -> float:
        key = (proto, field, mut)
        if key not in self._scores: return 1.0
        return min(16.0, max(1.0, self._scores[key]))

class ICSFuzzTemplateGenerator(BaseAnalyzer):
    """ICS/SCADA fuzz template generator — protocol-specific mutations + Peach Pit XML"""
    PROTOCOLS: Dict[str, Dict[str, Any]] = {
        "Modbus": {"ports": [502], "func_codes": list(range(1, 128)),
            "mutations": ["overflow_length","invalid_func_code","negative_value","null_byte","bit_flip"],
            "known_vulns": ["功能码注入","线圈地址越界","保持寄存器溢出","ASCII模式注入","异常码信息泄漏"]},
        "DNP3": {"ports": [20000],
            "mutations": ["fragmented_packet","invalid_crc","large_object","replay","bit_flip"],
            "known_vulns": ["链路层帧分片攻击","CRC校验绕过","对象头解析错误","应用层ACK风暴","时间同步攻击"]},
        "S7comm": {"ports": [102],
            "mutations": ["overflow_length","wrong_enum_value","integer_overflow","null_byte","large_object"],
            "known_vulns": ["CVE-2020-15782 越界写入","功能码0xF0未授权操作","Job/ACK反序列化错误","TPKT长度解析漏洞"]},
        "EtherNetIP": {"ports": [44818],
            "mutations": ["overflow_length","wrong_enum_value","fragmented_packet","replay","format_string"],
            "known_vulns": ["CIP路径穿越","会话注册拒绝服务","ForwardOpen资源耗尽","隐式消息注入","连接ID预测"]},
        "BACnet": {"ports": [47808],
            "mutations": ["wrong_enum_value","overflow_array","large_object","null_byte"],
            "known_vulns": ["Who-Is放大攻击","属性数组越界","BVLL消息注入","ConfirmedCOV订阅劫持"]},
    }

    MODBUS_FIELDS: List[ProtocolField] = [
        ProtocolField("transaction_id",0,2,"uint16",0x0001,(0,0xFFFF),False,[MutationType.OVERFLOW_LENGTH,MutationType.BIT_FLIP]),
        ProtocolField("protocol_id",2,2,"uint16",0x0000,(0,0),False,[MutationType.OVERFLOW_LENGTH]),
        ProtocolField("length",4,2,"uint16",6,(0,0xFFFF),True,[MutationType.OVERFLOW_LENGTH,MutationType.INTEGER_OVERFLOW,MutationType.NULL_BYTE]),
        ProtocolField("unit_id",6,1,"uint8",1,(0,255),False,[MutationType.OVERFLOW_LENGTH,MutationType.BIT_FLIP]),
        ProtocolField("function_code",7,1,"uint8",3,(1,127),True,[MutationType.INVALID_FUNC_CODE,MutationType.BIT_FLIP,MutationType.NULL_BYTE]),
        ProtocolField("data",8,0,"bytes",b"",(0,252),True,[MutationType.OVERFLOW_LENGTH,MutationType.LARGE_OBJECT,MutationType.NULL_BYTE]),
    ]
    DNP3_FIELDS: List[ProtocolField] = [
        ProtocolField("start_bytes",0,2,"uint16",0x0564,(0x0564,0x0564),True,[MutationType.BIT_FLIP]),
        ProtocolField("length",2,1,"uint8",5,(5,255),True,[MutationType.OVERFLOW_LENGTH,MutationType.INTEGER_OVERFLOW]),
        ProtocolField("control",3,1,"uint8",0xC0,(0,0xFF),False,[MutationType.BIT_FLIP,MutationType.REPLAY]),
        ProtocolField("destination",4,2,"uint16",0x0001,(0,0xFFFF),False,[MutationType.OVERFLOW_LENGTH]),
        ProtocolField("source",6,2,"uint16",0x0000,(0,0xFFFF),False,[MutationType.OVERFLOW_LENGTH]),
        ProtocolField("crc",8,2,"uint16",0x0000,(0,0xFFFF),True,[MutationType.INVALID_CRC]),
        ProtocolField("user_data",10,0,"bytes",b"",(0,249),True,[MutationType.FRAGMENTED_PACKET,MutationType.LARGE_OBJECT]),
    ]
    S7COMM_FIELDS: List[ProtocolField] = [
        ProtocolField("tpkt_version",0,1,"uint8",3,(3,3),False,[MutationType.BIT_FLIP]),
        ProtocolField("tpkt_reserved",1,1,"uint8",0,(0,0),False,[MutationType.OVERFLOW_LENGTH]),
        ProtocolField("tpkt_length",2,2,"uint16",0,(7,65535),True,[MutationType.OVERFLOW_LENGTH,MutationType.INTEGER_OVERFLOW]),
        ProtocolField("cotp_length",4,1,"uint8",2,(2,254),True,[MutationType.OVERFLOW_LENGTH]),
        ProtocolField("cotp_pdu_type",5,1,"uint8",0xF0,(0,0xFF),False,[MutationType.WRONG_ENUM_VALUE,MutationType.BIT_FLIP]),
        ProtocolField("s7_header",6,4,"bytes",b"\x32\x01\x00\x00",(0,0xFFFFFFFF),True,[MutationType.OVERFLOW_LENGTH,MutationType.BIT_FLIP]),
        ProtocolField("s7_data",10,0,"bytes",b"",(0,65535),True,[MutationType.LARGE_OBJECT,MutationType.NULL_BYTE]),
    ]

    def __init__(self):
        self._templates: List[MutationTemplate] = []
        self._proto_models: Dict[str, ProtocolModel] = {}
        self._power = _PowerScheduler()
        self._build_models()

    def analyze(self, **kwargs) -> Dict[str, Any]:
        ok, err = self.validate_input(**kwargs)
        if not ok: return {"success": False, "error": err}
        try:
            protos = kwargs.get("protocols", []) or list(self.PROTOCOLS.keys())
            mut_types = kwargs.get("mutation_types", [])
            gen_peach = kwargs.get("generate_peach_pit", False)
            all_tmpl: List[MutationTemplate] = []
            stats: Dict[str, Dict[str, Any]] = {}

            for pn in protos:
                if pn in self.PROTOCOLS:
                    tmpl = self._gen_templates(pn, mut_types)
                    all_tmpl.extend(tmpl)
                    stats[pn] = {"mutations": len(tmpl),
                        "known_vulns": self.PROTOCOLS[pn].get("known_vulns", []),
                        "default_ports": self.PROTOCOLS[pn].get("ports", [])}

            peach = self.generate_peach_pit_xml(protos) if gen_peach else None
            return {"success": True, "total_templates": len(all_tmpl),
                "protocols": stats,
                "templates": [self._tmpl_to_dict(t) for t in all_tmpl[:50]],
                "peach_pit_xml": peach,
                "mutation_types_available": [m for m in dir(MutationType)
                    if not m.startswith("_") and isinstance(getattr(MutationType,m),str)]}
        except Exception as e:
            logger.error(f"ICS template gen failed: {e}")
            return {"success": False, "error": str(e)}

    def generate_modbus_template(self, mt=None): return self._gen_templates("Modbus", mt)
    def generate_dnp3_template(self, mt=None): return self._gen_templates("DNP3", mt)
    def generate_s7comm_template(self, mt=None): return self._gen_templates("S7comm", mt)
    def generate_ethernet_ip_template(self, mt=None): return self._gen_templates("EtherNetIP", mt)
    def protocol_field_modeling(self, pn: str) -> Optional[ProtocolModel]: return self._proto_models.get(pn)

    def mutation_strategy_for_ics(self, proto: ICSProtocol, field: ProtocolField) -> List[MutationType]:
        strategies = list(field.mutation_strategies)
        if proto == ICSProtocol.MODBUS:
            if field.name == "function_code": strategies.append(MutationType.INVALID_FUNC_CODE)
            elif field.name == "length": strategies.append(MutationType.INTEGER_OVERFLOW)
        elif proto == ICSProtocol.DNP3:
            if field.name == "crc": strategies.append(MutationType.INVALID_CRC)
            elif field.name == "user_data": strategies.append(MutationType.FRAGMENTED_PACKET)
        elif proto == ICSProtocol.S7COMM:
            if field.name == "tpkt_length": strategies.append(MutationType.INTEGER_OVERFLOW)
            elif field.name == "cotp_pdu_type": strategies.append(MutationType.WRONG_ENUM_VALUE)
        return list(set(strategies))

    def feedback_hit(self, proto: str, field: str, mut: str, sev: str = "medium"):
        """external feedback hook — fuzz engine reports a crash/coverage gain"""
        self._power.record(proto, field, mut, sev)

    def generate_peach_pit_xml(self, protos: List[str]) -> str:
        parts = ['<?xml version="1.0" encoding="utf-8"?>',
            '<Peach xmlns="http://peachfuzzer.com/2012/Peach">',
            f'  <!-- generated by ICSFuzzTemplateGenerator -->',
            f'  <!-- {time.strftime("%Y-%m-%d %H:%M:%S")} -->', '']
        for pn in protos:
            if pn not in self.PROTOCOLS: continue
            info = self.PROTOCOLS[pn]; fields = self._get_fields(pn); port = info["ports"][0]
            parts.append(f'  <DataModel name="{pn}Data">')
            for f in fields:
                bt = self._field_to_peach_type(f.field_type, f.size)
                parts.append(f'    <Block name="{f.name}"><{bt} size="{f.size*8}" value="{f.default_value}" valueType="hex"/></Block>')
            parts.append(f'  </DataModel>')
            parts.append(f'  <StateModel name="{pn}State" initialState="Initial"><State name="Initial"><Action type="output"><DataModel ref="{pn}Data"/></Action></State></StateModel>')
            parts.append(f'  <Agent name="{pn}Agent"><Monitor class="tcp.TcpMonitor"><Param name="host" value="127.0.0.1"/><Param name="port" value="{port}"/></Monitor>')
            for mt in info.get("mutations", []): parts.append(f'    <Mutator class="{self._mut_to_peach(mt)}"/>')
            parts.append(f'  </Agent>')
            parts.append(f'  <Test name="{pn}Test"><Agent ref="{pn}Agent"/><StateModel ref="{pn}State"/><Publisher class="tcp.TcpPublisher"><Param name="host" value="127.0.0.1"/><Param name="port" value="{port}"/></Publisher></Test>')
        parts.append('</Peach>'); return '\n'.join(parts)

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(name="ICSFuzzTemplateGenerator", type=AnalyzerType.UTILITY,
            version="1.0.0", description="ICS/SCADA fuzz template gen — Modbus/DNP3/S7comm/EtherNetIP/BACnet",
            author="BinaryAnalysisPlatform", dependencies=[], supported_platforms=["x86_64"])

    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]: return True, None
    def cleanup(self) -> None: self._templates.clear()

    def _build_models(self) -> None:
        fm = {"Modbus":self.MODBUS_FIELDS,"DNP3":self.DNP3_FIELDS,"S7comm":self.S7COMM_FIELDS}
        for pn, info in self.PROTOCOLS.items():
            fields = fm.get(pn, [])
            pe = ICSProtocol(pn) if pn in (p.value for p in ICSProtocol) else ICSProtocol.MODBUS
            self._proto_models[pn] = ProtocolModel(protocol=pe, default_port=info["ports"][0],
                fields=fields, header_size=sum(f.size for f in fields if f.size>0 and f.offset<10),
                footer_size=2 if pn in ("DNP3","Modbus") else 0,
                has_crc=pn in ("DNP3","Modbus"),
                crc_field_offset=8 if pn=="DNP3" else 0,
                crc_algorithm="CRC-16" if pn=="DNP3" else "N/A",
                known_vulnerabilities=info.get("known_vulns",[]))

    def _gen_templates(self, pn, mt=None) -> List[MutationTemplate]:
        info = self.PROTOCOLS.get(pn, {}); fields = self._get_fields(pn)
        tmpls: List[MutationTemplate] = []
        muts = mt if mt else info.get("mutations", [])
        for mn in muts:
            try: mut = MutationType(mn)
            except ValueError: continue
            af = [f for f in fields if mut in f.mutation_strategies]
            if not af:
                cf = [f for f in fields if f.is_critical]
                af = cf[:1] if cf else fields[:1]
            for field in af[:3]:
                power = self._power.factor(pn, field.name, mn)
                cnt = max(1, min(5, int(power / 3.0)))
                for _ in range(cnt):
                    mvals = self._gen_mutated_values(field, mut, pn)
                    t = MutationTemplate(
                        template_id=f"{pn}_{mut.value}_{field.name}_{uuid.uuid4().hex[:4]}",
                        protocol=ICSProtocol(pn) if pn in (p.value for p in ICSProtocol) else ICSProtocol.MODBUS,
                        mutation_type=mut, field_target=field.name,
                        original_value=field.default_value, mutated_values=mvals,
                        expected_behavior=self._predict(pn, mut, field.name),
                        risk_level=self._risk(mut, field))
                    tmpls.append(t); self._templates.append(t)
        return tmpls

    def _get_fields(self, pn: str) -> List[ProtocolField]:
        fm = {"Modbus":self.MODBUS_FIELDS,"DNP3":self.DNP3_FIELDS,"S7comm":self.S7COMM_FIELDS}
        return fm.get(pn, [])

    def _gen_mutated_values(self, field, mut, pn) -> List[Any]:
        vals: List[Any] = []
        if field.field_type in ("uint8","uint16","uint32"):
            d = field.default_value if isinstance(field.default_value,int) else 0
            mx = 0xFF if field.field_type=="uint8" else 0xFFFF if field.field_type=="uint16" else 0xFFFFFFFF
            if mut==MutationType.OVERFLOW_LENGTH: vals.extend([mx,mx+1,0xFFFF if field.field_type!="uint32" else 0xFFFFFFFF])
            elif mut==MutationType.NULL_BYTE: vals.extend([0,0x00])
            elif mut==MutationType.NEGATIVE_VALUE: vals.extend([-1,-32768])
            elif mut==MutationType.INTEGER_OVERFLOW: vals.extend([mx,mx*2+1])
            elif mut==MutationType.BIT_FLIP: vals.extend([d^0xFF if field.field_type=="uint8" else d^0xFFFF,d^0x01,d^0x80])
            elif mut==MutationType.INVALID_FUNC_CODE: vals.extend([0,128,255])
            else: vals.append(d)
        elif field.field_type in ("bytes","string"):
            if mut==MutationType.OVERFLOW_LENGTH: vals.extend([b"A"*1024,b"A"*4096])
            elif mut==MutationType.NULL_BYTE: vals.append(b"\x00"*16)
            elif mut==MutationType.LARGE_OBJECT: vals.extend([b"\xff"*1024,b"\x00"*65536])
            elif mut==MutationType.FORMAT_STRING: vals.extend([b"%s%s%s%s",b"%n%n%n%n"])
            elif mut==MutationType.FRAGMENTED_PACKET: vals.extend([b"\x01\x00\x00\x00",b"\x00"*8+b"\xff"*8])
            else: vals.append(b"\x00"*8)
        return vals if vals else [field.default_value]

    def _predict(self, pn, mut, fn) -> str:
        preds = {MutationType.OVERFLOW_LENGTH:"缓冲区溢出或解析器崩溃",
            MutationType.INVALID_FUNC_CODE:"未定义功能码行为或拒绝服务",
            MutationType.NULL_BYTE:"字符串过早截断或长度计算错误",
            MutationType.BIT_FLIP:"异常路径触发或校验和验证失败",
            MutationType.INTEGER_OVERFLOW:"整数溢出或异常内存分配",
            MutationType.FRAGMENTED_PACKET:"重组缓冲区溢出",
            MutationType.INVALID_CRC:"校验和拒绝—测试错误处理路径",
            MutationType.LARGE_OBJECT:"内存耗尽或处理超时",
            MutationType.WRONG_ENUM_VALUE:"非预期状态转换"}
        return preds.get(mut, "行为未知")

    def _risk(self, mut, field) -> str:
        if field.is_critical and mut in (MutationType.OVERFLOW_LENGTH,
            MutationType.INTEGER_OVERFLOW, MutationType.LARGE_OBJECT): return "high"
        elif field.is_critical: return "medium"
        return "low"

    @staticmethod
    def _field_to_peach_type(ft: str, sz: int) -> str:
        return {"uint8":"Number","uint16":"Number","uint32":"Number","bytes":"Blob","string":"String"}.get(ft,"Blob")

    @staticmethod
    def _mut_to_peach(mn: str) -> str:
        return {"overflow_length":"StringMutator","invalid_func_code":"NumericalMutator",
            "null_byte":"StringMutator","bit_flip":"BitFlipperMutator",
            "fragmented_packet":"BlobMutator","invalid_crc":"NumericalMutator",
            "large_object":"BlobMutator","replay":"StringMutator",
            "wrong_enum_value":"NumericalMutator","overflow_array":"ArrayMutator",
            "negative_value":"NumericalMutator","format_string":"StringMutator",
            "integer_overflow":"NumericalMutator"}.get(mn,"StringMutator")

    @staticmethod
    def _tmpl_to_dict(t: MutationTemplate) -> Dict[str, Any]:
        return {"template_id":t.template_id,"protocol":t.protocol.value,
            "mutation_type":t.mutation_type.value,"field_target":t.field_target,
            "original_value":str(t.original_value),"mutated_values_count":len(t.mutated_values),
            "expected_behavior":t.expected_behavior,"risk_level":t.risk_level}

def generate_ics_fuzz_templates(protocols: List[str]) -> Dict[str, Any]:
    return ICSFuzzTemplateGenerator().analyze(protocols=protocols)
