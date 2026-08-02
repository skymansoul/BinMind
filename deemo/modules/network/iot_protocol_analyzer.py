import logging, struct
from dataclasses import dataclass
from enum import StrEnum

logger = logging.getLogger(__name__)

class IoTProtocol(StrEnum):
    MQTT = "mqtt"; COAP = "coap"; MODBUS = "modbus"
    ZIGBEE = "zigbee"; OPC_UA = "opc_ua"; BACNET = "bacnet"
    CAN_BUS = "can_bus"; DNP3 = "dnp3"

@dataclass
class ProtocolField:
    name: str; value: str; offset: int; byte_len: int
    description: str = ""; is_dangerous: bool = False

@dataclass
class ProtocolVulnerability:
    vuln_id: str; protocol: IoTProtocol; field_name: str; severity: str
    description: str; cwe_id: str = ""; exploit_scenario: str = ""; remediation: str = ""

MAX_PROTO_NAME_LEN = 20

_OPCUA_MSG_TYPES = {0x48454c46: "HEL", 0x41434b46: "ACK", 0x52524552: "ERR",
    0x4f504e46: "OPN", 0x4d534746: "MSG", 0x434c4f46: "CLO"}

class MQTTAnalyzer:
    MQTT_PACKET_TYPES = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC",
        6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK", 10: "UNSUBSCRIBE",
        11: "UNSUBACK", 12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT", 15: "AUTH"}

    def analyze(self, packet_bytes):
        data_len = len(packet_bytes)
        if data_len < 2: return {'error': 'packet too short'}
        packet_type = (packet_bytes[0] >> 4) & 0x0F; flags = packet_bytes[0] & 0x0F
        remaining_length, rl_len = self._decode_remaining_length(packet_bytes[1:])
        findings = []
        if packet_type == 1: self._analyze_connect(packet_bytes, findings)
        if packet_type == 15: self._analyze_auth_v5(packet_bytes, findings)
        findings.extend(self._check_generic(packet_bytes, packet_type, flags))
        return {'packet_type': self.MQTT_PACKET_TYPES.get(packet_type, "UNKNOWN(" + str(packet_type) + ")"),
                'flags': flags, 'remaining_length': remaining_length, 'findings': findings}

    def _decode_remaining_length(self, data):
        value = 0; multiplier = 0; idx = 0; max_len = min(len(data), 4)
        while idx < max_len:
            byte = data[idx]; value += (byte & 0x7F) << (7 * multiplier); multiplier += 1
            if (byte & 0x80) == 0: return value, idx + 1
            idx += 1
        return 0, 0

    def _analyze_connect(self, data, findings):
        try:
            proto_name_len = (data[2] << 8) | data[3]
            if proto_name_len > MAX_PROTO_NAME_LEN:
                findings.append(ProtocolVulnerability("MQTT-001", IoTProtocol.MQTT, "protocol_name_length",
                    "high", "Abnormal protocol name length: " + str(proto_name_len), "CWE-120", "Buffer overflow", "Limit max protocol name length"))
            if len(data) > 10 and (data[7] & 0x80) and (data[7] & 0x40):
                findings.append(ProtocolVulnerability("MQTT-002", IoTProtocol.MQTT, "credentials",
                    "medium", "MQTT username/password transmitted in cleartext", "CWE-319", "Credential sniffing", "Enable TLS encryption"))
        except (IndexError, ValueError): pass

    def _analyze_auth_v5(self, data, findings):
        if len(data) < 4: return
        try:
            pos = 3; _, rl_len = self._decode_remaining_length(data[1:]); pos = 1 + rl_len
            if pos + 1 >= len(data): return
            prop_len = data[pos]; pos += 1; end = pos + prop_len
            while pos + 1 < min(end, len(data)):
                prop_id = data[pos]
                if prop_id == 0x22 and pos + 3 < len(data):
                    auth_len = (data[pos + 1] << 8) | data[pos + 2]
                    if auth_len > 256:
                        findings.append(ProtocolVulnerability("MQTT-004", IoTProtocol.MQTT, "auth_data",
                            "medium", f"Excessive AUTH data: {auth_len} bytes", "CWE-770", "DoS via oversized auth data", "Cap AUTH data at 256 bytes"))
                pos += 1
                if pos + 2 < end:
                    prop_val_len = (data[pos] << 8) | data[pos + 1]; pos += 2 + prop_val_len
                else: break
        except (IndexError, ValueError): pass

    @staticmethod
    def _check_generic(data, ptype, flags):
        findings = []
        if ptype == 3 and (flags & 0x6):
            findings.append(ProtocolVulnerability("MQTT-003", IoTProtocol.MQTT, "qos", "medium",
                "PUBLISH uses reserved QoS value 3", "CWE-1164", "Protocol parser may crash", "Reject QoS=3 packets"))
        return findings

class ModbusAnalyzer:
    DANGEROUS_FUNCTIONS = {5: "Write Single Coil", 6: "Write Single Register", 15: "Write Multiple Coils", 16: "Write Multiple Registers"}
    READ_FUNCTIONS = {1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers", 4: "Read Input Registers"}

    def analyze(self, data):
        if len(data) < 8: return {'error': 'packet too short'}
        func_code = data[7]; findings = []
        if func_code in self.DANGEROUS_FUNCTIONS:
            start_addr = (data[8] << 8) | data[9]; quantity = (data[10] << 8) | data[11]
            risk = 'high' if func_code in (15, 16) else 'medium'
            findings.append({'function': self.DANGEROUS_FUNCTIONS[func_code], 'start_address': start_addr,
                'quantity': quantity, 'risk': risk,
                'description': f"Modbus write: {self.DANGEROUS_FUNCTIONS[func_code]} addr={start_addr} quantity={quantity}"})
        func_name = self.DANGEROUS_FUNCTIONS.get(func_code) or self.READ_FUNCTIONS.get(func_code) or f"UNKNOWN({func_code})"
        return {'unit_id': data[6], 'function_code': func_code, 'function_name': func_name, 'findings': findings}

class CoAPAnalyzer:
    def analyze(self, data):
        if len(data) < 4: return {'error': 'packet too short'}
        version = (data[0] >> 6) & 0x03; msg_type = (data[0] >> 4) & 0x03
        token_len = data[0] & 0x0F; code = data[1]; msg_id = (data[2] << 8) | data[3]
        findings = []
        if version != 1: findings.append({'field': 'version', 'issue': f'Non-standard CoAP version: {version}', 'severity': 'low'})
        if token_len > 8: findings.append({'field': 'token_length', 'issue': f'Excessive token length: {token_len}', 'severity': 'medium'})
        type_map = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}
        return {'version': version, 'type': type_map.get(msg_type, "?"), 'code': code,
                'message_id': msg_id, 'token_len': token_len, 'findings': findings}

class OPCUABinaryAnalyzer:
    def analyze(self, data):
        if len(data) < 12: return {'error': 'packet too short for OPC-UA Binary'}
        msg_type_raw = struct.unpack("<I", data[0:4])[0]
        msg_type = _OPCUA_MSG_TYPES.get(msg_type_raw, f"0x{msg_type_raw:08X}")
        msg_size = struct.unpack("<I", data[4:8])[0]; secure_channel_id = struct.unpack("<I", data[8:12])[0]
        findings = []
        if secure_channel_id == 0 and msg_type in ("OPN", "MSG"):
            findings.append(ProtocolVulnerability("OPCUA-001", IoTProtocol.OPC_UA, "secure_channel",
                "high", "OPC-UA 未建立安全通道——明文传输", "CWE-319", "Traffic interception", "Enforce SecureChannel"))
        return {'message_type': msg_type, 'message_size': msg_size, 'secure_channel_id': secure_channel_id, 'findings': findings}

class IoTProtocolAnalyzer:
    def __init__(self):
        self.mqtt = MQTTAnalyzer(); self.modbus = ModbusAnalyzer()
        self.coap = CoAPAnalyzer(); self.opcua = OPCUABinaryAnalyzer()
        self._findings = []

    def analyze(self, protocol=None, raw_data=None, **kwargs):
        results = {'success': True, 'findings': []}
        if raw_data is not None and protocol is not None:
            protocol_lower = protocol.lower()
            if protocol_lower == 'mqtt': result = self.mqtt.analyze(raw_data); results.update(result); results['protocol'] = 'mqtt'
            elif protocol_lower == 'modbus': result = self.modbus.analyze(raw_data); results.update(result); results['protocol'] = 'modbus'
            elif protocol_lower == 'coap': result = self.coap.analyze(raw_data); results.update(result); results['protocol'] = 'coap'
            elif protocol_lower in ('opc_ua', 'opcua', 'opc-ua'): result = self.opcua.analyze(raw_data); results.update(result); results['protocol'] = 'opc_ua'
            else: results['error'] = 'Unsupported protocol: ' + str(protocol)
            self._findings.extend(results.get('findings', []))
        return results

    def fuzz_template(self, protocol):
        templates = {
            IoTProtocol.MQTT: [{'field': 'protocol_name', 'mutation': 'overflow_256'}, {'field': 'client_id', 'mutation': 'format_string'}, {'field': 'will_topic', 'mutation': 'null_byte'}],
            IoTProtocol.MODBUS: [{'field': 'function_code', 'mutation': 'invalid_range'}, {'field': 'address', 'mutation': 'overflow'}, {'field': 'quantity', 'mutation': 'zero'}],
            IoTProtocol.COAP: [{'field': 'option_delta', 'mutation': 'overflow'}, {'field': 'uri_path', 'mutation': 'path_traversal'}, {'field': 'token', 'mutation': 'overflow'}],
            IoTProtocol.OPC_UA: [{'field': 'message_size', 'mutation': 'overflow'}, {'field': 'secure_channel_id', 'mutation': 'zero'}, {'field': 'node_id', 'mutation': 'path_traversal'}],
        }
        return templates.get(protocol, {})

def analyze_iot_protocol(protocol, raw_data, **kwargs):
    return IoTProtocolAnalyzer().analyze(protocol=protocol, raw_data=raw_data)

__all__ = ["IoTProtocolAnalyzer", "MQTTAnalyzer", "ModbusAnalyzer", "CoAPAnalyzer",
           "OPCUABinaryAnalyzer", "IoTProtocol", "ProtocolVulnerability", "analyze_iot_protocol"]
