import os
import re
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class WirelessProtocolAnalyzer:
    """
    嵌入式无线协议栈分析器
    
    针对物联网固件中的无线通信协议栈（如蓝牙HCI、L2CAP、Wi-Fi管理帧处理）进行分析，
    识别可能的缓冲区溢出、解析错误、配对认证绕过等漏洞，并生成针对性的模糊测试用例。
    
    Attributes:
        firmware_path: 固件文件路径
        protocol_functions: 检测到的协议相关函数
        vulnerabilities: 发现的漏洞列表
        fuzz_cases: 生成的模糊测试用例
    """
    
    def __init__(self, firmware_path: str = None):
        """
        初始化无线协议栈分析器
        
        Args:
            firmware_path: 固件文件路径
        """
        self.firmware_path = firmware_path
        self.protocol_functions: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.fuzz_cases: List[Dict[str, Any]] = []
    
    def analyze(self) -> Dict[str, Any]:
        """
        执行完整的无线协议栈分析
        
        Returns:
            分析结果字典
        """
        logger.info("开始无线协议栈分析")
        
        # 识别协议栈函数
        self._identify_protocol_functions()
        
        # 分析帧解析逻辑
        self._analyze_frame_parsing()
        
        # 检测漏洞
        self._detect_vulnerabilities()
        
        # 生成模糊测试用例
        self._generate_fuzz_cases()
        
        result = {
            'protocol_functions': self.protocol_functions,
            'vulnerabilities': self.vulnerabilities,
            'fuzz_cases': self.fuzz_cases,
            'risk_level': self._calculate_risk_level()
        }
        
        return result
    
    def _identify_protocol_functions(self):
        """识别协议栈相关函数"""
        if not self.firmware_path:
            return
        
        try:
            from modules.decomp_ai import DecompilerAI
            
            decompiler = DecompilerAI(self.firmware_path, client=None)
            functions = decompiler.list_functions()
            
            # 蓝牙相关函数模式
            bluetooth_patterns = [
                r'hci_.*',
                r'l2cap_.*',
                r'sdp_.*',
                r'a2dp_.*',
                r'rfcomm_.*',
                r'smp_.*',
                r'bnep_.*',
                r'hidp_.*'
            ]
            
            # Wi-Fi相关函数模式
            wifi_patterns = [
                r'ieee80211_.*',
                r'wlan_.*',
                r'wifi_.*',
                r'ath_.*',
                r'mac80211_.*',
                r'cfg80211_.*',
                r'hostap_.*',
                r'wpa_.*',
                r'eapol_.*'
            ]
            
            for func_name in functions:
                # 检测蓝牙函数
                for pattern in bluetooth_patterns:
                    if re.match(pattern, func_name.lower()):
                        self.protocol_functions.append({)
                            'name': func_name,
                            'protocol': 'bluetooth',
                            'layer': self._infer_bluetooth_layer(func_name),
                            'pattern': pattern
                        }
                        break
                
                # 检测Wi-Fi函数
                for pattern in wifi_patterns:
                    if re.match(pattern, func_name.lower()):
                        self.protocol_functions.append({)
                            'name': func_name,
                            'protocol': 'wifi',
                            'layer': self._infer_wifi_layer(func_name),
                            'pattern': pattern
                        }
                        break
        
        except Exception as e:
            logger.warning(f"识别协议栈函数失败: {e}")
    
    def _infer_bluetooth_layer(self, func_name: str) -> str:
        """推断蓝牙协议层"""
        name_lower = func_name.lower()
        
        if 'hci' in name_lower:
            return 'HCI'
        elif 'l2cap' in name_lower:
            return 'L2CAP'
        elif 'sdp' in name_lower:
            return 'SDP'
        elif 'rfcomm' in name_lower:
            return 'RFCOMM'
        elif 'smp' in name_lower:
            return 'SMP'
        elif 'a2dp' in name_lower:
            return 'A2DP'
        elif 'bnep' in name_lower:
            return 'BNEP'
        else:
            return 'unknown'
    
    def _infer_wifi_layer(self, func_name: str) -> str:
        """推断Wi-Fi协议层"""
        name_lower = func_name.lower()
        
        if 'ieee80211' in name_lower or 'mac80211' in name_lower:
            return 'MAC'
        elif 'wlan' in name_lower or 'cfg80211' in name_lower:
            return 'management'
        elif 'wpa' in name_lower or 'eapol' in name_lower:
            return 'security'
        elif 'hostap' in name_lower:
            return 'AP'
        else:
            return 'unknown'
    
    def _analyze_frame_parsing(self):
        """分析帧解析逻辑"""
        if not self.firmware_path:
            return
        
        try:
            from modules.decomp_ai import DecompilerAI
            
            decompiler = DecompilerAI(self.firmware_path, client=None)
            
            for proto_func in self.protocol_functions:
                try:
                    analysis = decompiler.analyze_function(proto_func['name'], {})
                    pseudocode = analysis.get('pseudocode', '')
                    
                    # 分析帧解析逻辑
                    if pseudocode:
                        proto_func['parsing_analysis'] = self._parse_frame_logic(pseudocode)
                        proto_func['pseudocode_snippet'] = pseudocode[:500] if len(pseudocode) > 500 else pseudocode
                
                except Exception as e:
                    logger.debug(f"分析函数 {proto_func['name']} 失败: {e}")
        
        except Exception as e:
            logger.warning(f"分析帧解析逻辑失败: {e}")
    
    def _parse_frame_logic(self, pseudocode: str) -> Dict[str, Any]:
        """解析帧处理逻辑"""
        analysis = {
            'has_length_check': False,
            'has_type_check': False,
            'has_boundary_check': False,
            'unsafe_operations': [],
            'potential_overflows': []
        }
        
        # 检查长度检查
        length_check_patterns = [
            r'(length|len|size)\s*[<>!=]=?',
            r'memcpy.*length',
            r'strncpy',
            r'__memcpy_chk'
        ]
        
        for pattern in length_check_patterns:
            if re.search(pattern, pseudocode):
                analysis['has_length_check'] = True
                break
        
        # 检查类型检查
        if re.search(r'(type|opcode|cmd)\s*==', pseudocode):
            analysis['has_type_check'] = True
        
        # 检查边界检查
        if re.search(r'(offset|index).*<.*(length|size)', pseudocode):
            analysis['has_boundary_check'] = True
        
        # 检查不安全操作
        unsafe_patterns = [
            ('memcpy', '无长度限制的memcpy'),
            ('strcpy', '无长度限制的strcpy'),
            ('sprintf', '无长度限制的sprintf'),
            ('gets', '危险函数gets')
        ]
        
        for pattern, desc in unsafe_patterns:
            if pattern in pseudocode:
                analysis['unsafe_operations'].append(desc)
        
        # 检查潜在溢出
        overflow_patterns = [
            r'(buffer|buf)\s*\+\s*\d+',
            r'(buffer|buf)\[.*\]'
        ]
        
        for pattern in overflow_patterns:
            if re.search(pattern, pseudocode):
                analysis['potential_overflows'].append(pattern)
        
        return analysis
    
    def _detect_vulnerabilities(self):
        """检测漏洞"""
        for proto_func in self.protocol_functions:
            parsing_analysis = proto_func.get('parsing_analysis', {})
            
            # 基于解析分析检测漏洞
            if not parsing_analysis.get('has_length_check'):
                self.vulnerabilities.append({)
                    'function': proto_func['name'],
                    'protocol': proto_func['protocol'],
                    'layer': proto_func['layer'],
                    'type': 'buffer_overflow',
                    'severity': 'high',
                    'description': '缺少长度检查，可能导致缓冲区溢出',
                    'cwe': 'CWE-119'
                }
            
            if not parsing_analysis.get('has_type_check'):
                self.vulnerabilities.append({)
                    'function': proto_func['name'],
                    'protocol': proto_func['protocol'],
                    'layer': proto_func['layer'],
                    'type': 'type_confusion',
                    'severity': 'medium',
                    'description': '缺少类型/操作码检查，可能导致类型混淆',
                    'cwe': 'CWE-843'
                }
            
            for unsafe_op in parsing_analysis.get('unsafe_operations', []):
                self.vulnerabilities.append({)
                    'function': proto_func['name'],
                    'protocol': proto_func['protocol'],
                    'layer': proto_func['layer'],
                    'type': 'unsafe_function',
                    'severity': 'high',
                    'description': f'使用危险函数: {unsafe_op}',
                    'cwe': 'CWE-119'
                }
        
        # 去重
        seen = set()
        unique_vulns = []
        for vuln in self.vulnerabilities:
            key = f"{vuln['function']}_{vuln['type']}",
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        self.vulnerabilities = unique_vulns
    
    def _generate_fuzz_cases(self):
        """生成模糊测试用例"""
        # 蓝牙HCI模糊测试用例
        bt_cases = self._generate_bluetooth_fuzz_cases()
        self.fuzz_cases.extend(bt_cases)
        
        # Wi-Fi模糊测试用例
        wifi_cases = self._generate_wifi_fuzz_cases()
        self.fuzz_cases.extend(wifi_cases)
    
    def _generate_bluetooth_fuzz_cases(self) -> List[Dict[str, Any]]:
        """生成蓝牙模糊测试用例"""
        cases = []
        
        # HCI命令模糊测试
        cases.append({)
            'protocol': 'bluetooth',
            'layer': 'HCI',
            'type': 'fuzz_case',
            'name': 'HCI超长参数',
            'description': '发送长度超过预期的HCI命令参数',
            'payload_template': '\\x01\\x00\\xff\\xff' + '\\x41' * 1024,
            'target_function': 'hci_recv'
        }
        
        cases.append({)
            'protocol': 'bluetooth',
            'layer': 'HCI',
            'type': 'fuzz_case',
            'name': 'HCI无效操作码',
            'description': '发送无效的HCI操作码',
            'payload_template': '\\x01\\xff\\xff\\x00' + '\\x00' * 16,
            'target_function': 'hci_recv'
        }
        
        # L2CAP模糊测试
        cases.append({)
            'protocol': 'bluetooth',
            'layer': 'L2CAP',
            'type': 'fuzz_case',
            'name': 'L2CAP超大SDU',
            'description': '发送超过MTU的L2CAP SDU',
            'payload_template': '\\x00\\x00\\xff\\xff' + '\\x41' * 2048,
            'target_function': 'l2cap_recv'
        }
        
        # SMP模糊测试（配对认证）
        cases.append({)
            'protocol': 'bluetooth',
            'layer': 'SMP',
            'type': 'fuzz_case',
            'name': 'SMP无效配对请求',
            'description': '发送畸形的SMP配对请求',
            'payload_template': '\\xff' + '\\x00' * 63,
            'target_function': 'smp_process'
        }
        
        return cases
    
    def _generate_wifi_fuzz_cases(self) -> List[Dict[str, Any]]:
        """生成Wi-Fi模糊测试用例"""
        cases = []
        
        # 管理帧模糊测试
        cases.append({)
            'protocol': 'wifi',
            'layer': 'MAC',
            'type': 'fuzz_case',
            'name': '超长SSID',
            'description': '发送SSID长度超过32字节的管理帧',
            'payload_template': '\\x00\\x00' + '\\xff' + '\\x41' * 100,
            'target_function': 'ieee80211_rx'
        }
        
        cases.append({)
            'protocol': 'wifi',
            'layer': 'MAC',
            'type': 'fuzz_case',
            'name': '畸形信标帧',
            'description': '发送字段长度不一致的信标帧',
            'payload_template': '\\x80\\x00' + '\\x00' * 100 + '\\xff' * 50,
            'target_function': 'ieee80211_rx'
        }
        
        # EAPOL模糊测试
        cases.append({)
            'protocol': 'wifi',
            'layer': 'security',
            'type': 'fuzz_case',
            'name': 'EAPOL超长帧',
            'description': '发送超过预期长度的EAPOL帧',
            'payload_template': '\\x00\\x00' + '\\xff\\xff' + '\\x41' * 1024,
            'target_function': 'eapol_process'
        }
        
        return cases
    
    def _calculate_risk_level(self) -> str:
        """计算总体风险等级"""
        high_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'high')
        medium_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'medium')
        
        if high_count >= 2:
            return 'high'
        elif high_count == 1 or medium_count >= 3:
            return 'medium'
        elif medium_count > 0 or len(self.vulnerabilities) > 0:
            return 'low'
        else:
            return 'none'


def main():
    """命令行入口"""
    import argparse
    
    parser = argparse.ArgumentParser(description='无线协议栈分析器')
    parser.add_argument('--firmware', required=True, help='固件文件路径')
    parser.add_argument('--output', default='/tmp/wireless_analysis_report.txt', help='报告输出路径')
    
    args = parser.parse_args()
    
    analyzer = WirelessProtocolAnalyzer(args.firmware)
    result = analyzer.analyze()
    
    with open(args.output, 'w') as f:
        f.write("无线协议栈分析报告\n")
        f.write("=" * 50 + "\n\n")
        
        f.write("风险等级: {}\n\n".format(result['risk_level']

        
        f.write("检测到的协议函数:\n")
        f.write("-" * 30 + "\n")
        for func in result['protocol_functions']:
            f.write(f"函数: {func['name']}\n")
            f.write(f"  协议: {func['protocol']}\n")
            f.write(f"  层级: {func['layer']}\n\n")
        
        f.write("发现的漏洞:\n")
        f.write("-" * 30 + "\n")
        for vuln in result['vulnerabilities']:
            f.write(f"函数: {vuln['function']}\n")
            f.write(f"  协议: {vuln['protocol']}\n")
            f.write(f"  类型: {vuln['type']}\n")
            f.write(f"  严重度: {vuln['severity']}\n")
            f.write(f"  描述: {vuln['description']}\n")
            f.write(f"  CWE: {vuln['cwe']}\n\n")
        
        f.write("生成的模糊测试用例:\n")
        f.write("-" * 30 + "\n")
        for case in result['fuzz_cases']:
            f.write(f"名称: {case['name']}\n")
            f.write(f"  协议: {case['protocol']}\n")
            f.write(f"  描述: {case['description']}\n")
            f.write(f"  目标函数: {case['target_function']}\n\n")
    
    print(f"分析报告已保存到: {args.output}")


if __name__ == '__main__':
    main()))