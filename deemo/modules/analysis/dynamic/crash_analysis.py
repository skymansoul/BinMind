import logging
import json
import re
from typing import Dict, Any, Optional, Tuple, List

from config import Config, get_current_ai_model, call_ai_with_retry
from prompts import CRASH_ANALYSIS_TEMPLATE
from .src.crash_scorer import (
    REGISTER_PATTERNS,
    REGISTER_NAMES,
    parse_registers_from_text,
    heuristic_analysis as _heuristic_analysis,
    _heuristic_detect_types,
    _heuristic_extract_analysis,
    _heuristic_detect_exploitability,
    _heuristic_detect_difficulty,
    _heuristic_extract_recommendations,
)

logger = logging.getLogger(__name__)


CRASH_FORMAT_JSON = 'json'
CRASH_FORMAT_GDB = 'gdb'
CRASH_FORMAT_ASAN = 'asan'
CRASH_FORMAT_AUTO = 'auto'


def detect_crash_format(content: str) -> str:
    """
    自动检测崩溃数据格式
    
    Args:
    content: 崩溃数据内容（可能是 JSON 字符串或文本）
    
    返回:
    格式类型: 'json', 'gdb', 'asan'
    """
    if not content:
        return CRASH_FORMAT_JSON
    
    if isinstance(content, dict):
        return CRASH_FORMAT_JSON
    
    content_str = str(content).strip()
    
    if content_str.startswith('{') or content_str.startswith('['):
        try:
            json.loads(content_str)
            return CRASH_FORMAT_JSON
        except json.JSONDecodeError:
            pass
    
    if 'ERROR: AddressSanitizer:' in content_str:
        return CRASH_FORMAT_ASAN
    
    if re.search(r'#\d+\s+0x[0-9a-fA-F]+\s+in\s+\w+\s*\(', content_str):
        return CRASH_FORMAT_GDB
    
    if re.search(r'(Program received signal|SIGSEGV|SIGABRT)', content_str):
        return CRASH_FORMAT_GDB
    
    return CRASH_FORMAT_JSON


def parse_gdb_backtrace(text: str) -> Dict[str, Any]:
    """
    解析 GDB 回溯格式
    
    Args:
    text: GDB 回溯文本
    
    返回:
    解析后的崩溃数据字典
    """
    result = {
        'registers': {},
        'stack_trace': [],
        'fault_instruction': '',
        'output': '',
        'signal': '',
        'format': 'gdb'
    }
    
    if not text:
        return result
    
    lines = text.split('\n')
    current_func = None
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        backtrace_match = re.match(r'#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(\w+)\s*\(', line)
        if backtrace_match:
            frame_num = int(backtrace_match.group(1))
            address = backtrace_match.group(2)
            func_name = backtrace_match.group(3)
            result['stack_trace'].append({
                'frame': frame_num,
                'address': address,
                'function': func_name,
                'raw': line
            })
            
            if frame_num == 0:
                current_func = func_name
        
        signal_match = re.search(r'Program received signal\s+(\w+)', line)
        if signal_match:
            result['signal'] = signal_match.group(1)
        
        if current_func and line.startswith('=>') or 'faulting instruction' in line.lower():
            result['fault_instruction'] = line
    
    registers = parse_registers_from_text(text)
    if registers:
        result['registers'] = registers
    
    if result['stack_trace']:
        result['stack_trace_str'] = '\n'.join([
            f"#{f['frame']}  {f['address']} in {f['function']} ()"
            for f in result['stack_trace']
        ])
    
    logger.info(f"已解析 GDB 回溯: {len(result['stack_trace'])} 个栈帧")
    
    return result


def parse_asan_report(text: str) -> Dict[str, Any]:
    """
    解析 ASAN 报告格式
    
    Args:
    text: ASAN 报告文本
    
    返回:
    解析后的崩溃数据字典
    """
    result = {
        'registers': {},
        'stack_trace': [],
        'fault_instruction': '',
        'output': '',
        'error_type': '',
        'fault_address': '',
        'format': 'asan'
    }
    
    if not text:
        return result
    
    asan_match = re.search(r'ERROR: AddressSanitizer: (\w+-on-address-error on unknown address (0x[0-9a-fA-F]+)', text)
    if asan_match:
        result['error_type'] = asan_match.group(1)
        result['fault_address'] = asan_match.group(2)
    
    if 'ERROR: AddressSanitizer:' in text:
        lines = text.split('ERROR: AddressSanitizer:')[1].split('\n') if 'ERROR: AddressSanitizer:' in text else text.split('\n')
        first_line = lines[0].strip() if lines else ''
        if first_line:
            error_parts = first_line.split()
            if error_parts:
                result['error_type'] = error_parts[0]
    
    stack_frames = re.findall(r'#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(\w+)', text)
    for match in stack_frames:
        result['stack_trace'].append({
            'frame': int(match[0]),
            'address': match[1],
            'function': match[2]
        })
    
    registers = parse_registers_from_text(text)
    if registers:
        result['registers'] = registers
    
    if result['stack_trace']:
        result['stack_trace_str'] = '\n'.join([
            f"#{f['frame']}  {f['address']} in {f['function']} ()"
            for f in result['stack_trace']
        ])
    
    logger.info(f"已解析 ASAN 报告: 错误类型={result['error_type']}")
    
    return result


def load_and_parse_crash_data(file_path: str, format_type: str = CRASH_FORMAT_AUTO) -> Optional[Dict[str, Any]]:
    """
    加载并解析崩溃数据文件，自动检测格式
    
    Args:
    file_path: 崩溃数据文件路径
    format_type: 格式类型: 'auto', 'json', 'gdb', 'asan'
    
    返回:
    解析后的崩溃数据字典
    """
    logger = logging.getLogger(__name__)
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except FileNotFoundError:
        logger.error(f"崩溃数据文件不存在: {file_path}")
        return None
    except Exception as e:
        logger.error(f"读取崩溃数据文件失败: {e}")
        return None
    
    if format_type == CRASH_FORMAT_AUTO:
        detected = detect_crash_format(content)
        logger.info(f"自动检测到崩溃数据格式: {detected}")
        format_type = detected
    
    if format_type == CRASH_FORMAT_JSON:
        try:
            data = json.loads(content)
            logger.info("已解析 JSON 格式崩溃数据")
            return data
        except json.JSONDecodeError as e:
            logger.warning(f"JSON 解析失败，尝试其他格式: {e}")
            format_type = detect_crash_format(content)
    
    if format_type == CRASH_FORMAT_GDB:
        return parse_gdb_backtrace(content)
    
    if format_type == CRASH_FORMAT_ASAN:
        return parse_asan_report(content)
    
    logger.warning(f"未知格式，尝试启发式解析")
    return {
        'raw_text': content[:1000],
        'registers': parse_registers_from_text(content),
        'format': 'unknown'
    }


class CrashAnalyzer:
    """
    崩溃信息分析器



    
    """
    
    def __init__(self, openai_client=None):
        """
        初始化崩溃分析器
      openai_client: OpenAI 客户端实例（可选）
        """
        self.client = openai_client
    
    def parse_crash_info(self, crash_data: Dict[str, Any]) -> Dict[str, str]:
        """
        解析崩溃信息，提取关键数据
        
        crash_data: 原始崩溃数据
            


        
        """
        parsed = {
            'registers': '',
            'stack_trace': '',
            'fault_instruction': '',
            'program_output': ''
        }
        
        try:
            if 'registers' in crash_data:
                regs = crash_data['registers']
                if isinstance(regs, dict):
                    parsed['registers'] = '\n'.join([f"{k}: {v}" for k, v in regs.items()])
                elif isinstance(regs, str):
                    parsed_regs = parse_registers_from_text(regs)
                    if parsed_regs:
                        parsed['registers'] = '\n'.join([f"{k}: {v}" for k, v in parsed_regs.items()])
                    else:
                        parsed['registers'] = regs
                else:
                    parsed['registers'] = str(regs)
            
            raw_text = str(crash_data)
            if not parsed['registers']:
                parsed_regs = parse_registers_from_text(raw_text)
                if parsed_regs:
                    parsed['registers'] = '\n'.join([f"{k}: {v}" for k, v in parsed_regs.items()])
            
            if 'stack_trace' in crash_data:
                stack_trace = crash_data['stack_trace']
                if isinstance(stack_trace, list):
                    parsed['stack_trace'] = '\n'.join(str(frame) for frame in stack_trace)
                else:
                    parsed['stack_trace'] = str(stack_trace)
            elif 'backtrace' in crash_data:
                backtrace = crash_data['backtrace']
                if isinstance(backtrace, list):
                    parsed['stack_trace'] = '\n'.join(str(frame) for frame in backtrace)
                else:
                    parsed['stack_trace'] = str(backtrace)
            
            if 'fault_instruction' in crash_data:
                parsed['fault_instruction'] = str(crash_data['fault_instruction'])
            elif 'rip' in crash_data or 'eip' in crash_data:
                ip = crash_data.get('rip') or crash_data.get('eip')
                parsed['fault_instruction'] = f"Instruction Pointer: {ip}"
            
            if 'output' in crash_data:
                parsed['program_output'] = str(crash_data['output'])
            elif 'stdout' in crash_data:
                parsed['program_output'] = str(crash_data['stdout'])
            
            if 'signal' in crash_data:
                parsed['program_output'] += f"\nSignal: {crash_data['signal']}"
            
            logger.info("崩溃信息解析完成")
            
        except Exception as e:
            logger.error(f"解析崩溃信息时出错: {e}")
        
        return parsed
    
    def heuristic_analysis(self, crash_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        基于规则的启发式崩溃分析
        


        crash_data: 崩溃数据
            

        分析结果
        """
        result = {
            'crash_type': 'Unknown',
            'vulnerability_type': 'Unknown',
            'analysis': '',
            'exploitability': 'Unknown',
            'difficulty': 'Unknown',
            'recommendations': []
        }
        
        try:
            registers = {}
            if 'registers' in crash_data:
                if isinstance(crash_data['registers'], dict):
                    registers = {k.lower(): v for k, v in crash_data['registers'].items()}
                elif isinstance(crash_data['registers'], str):
                    registers = parse_registers_from_text(crash_data['registers'])
            
            fault_instruction = crash_data.get('fault_instruction', '')
            stack_trace = crash_data.get('stack_trace', '')
            if isinstance(stack_trace, list):
                stack_trace = ' '.join(str(frame) for frame in stack_trace)
            
            rip = registers.get('rip') or registers.get('eip') or ''
            rsp = registers.get('rsp') or registers.get('esp') or ''
            
            try:
                rip_val = int(str(rip), 16) if isinstance(rip, str) and '0x' in rip else 0
            except (ValueError, TypeError):
                rip_val = 0
            
            if rip_val:
                if '41414141' in str(rip) or '42424242' in str(rip) or 'deadbeef' in str(rip).lower():
                    result['crash_type'] = 'Controlled RIP - Memory Corruption'
                    result['vulnerability_type'] = 'Stack Buffer Overflow or Use-After-Free'
                    result['exploitability'] = 'High'
                    result['difficulty'] = 'Easy'
                    result['analysis'] = 'RIP 被可控数据覆盖，表明存在内存破坏漏洞'
                    result['recommendations'] = [
                        '确认偏移量',
                        '检查是否有 Canary 保护',
                        '寻找 ROP gadgets'
                    ]
            
            crash_text = str(crash_data).lower()
            
            if 'sigsegv' in crash_text or 'segmentation fault' in crash_text:
                result['crash_type'] = 'Segmentation Fault'
                if '41414141' in crash_text or 'aaaa' in crash_text.lower():
                    result['vulnerability_type'] = 'Memory Corruption'
                    result['exploitability'] = 'Medium'
            
            if 'sigabrt' in crash_text or 'abort' in crash_text:
                result['crash_type'] = 'Abort Signal'
                if 'stack smashing' in crash_text or '__stack_chk_fail' in stack_trace.lower():
                    result['vulnerability_type'] = 'Stack Overflow (Detected by Canary)'
                    result['analysis'] = '栈溢出被 Canary 保护检测到'
                    result['exploitability'] = 'Low (if canary cannot be leaked)'
                    result['difficulty'] = 'Hard'
                    result['recommendations'] = [
                        '尝试泄露 Canary 值',
                        '寻找格式化字符串漏洞',
                        '检查是否存在信息泄露'
                    ]
            
            if '%n' in crash_text or '%x%x%x%x' in crash_text:
                result['vulnerability_type'] = 'Format String Vulnerability'
                result['analysis'] = '发现格式化字符串模式'
                result['exploitability'] = 'High'
                result['recommendations'] = [
                    '确认格式化字符串可控',
                    '尝试读取内存',
                    '尝试写入内存'
                ]
            
            if 'double free' in crash_text:
                result['vulnerability_type'] = 'Double Free'
                result['crash_type'] = 'Heap Corruption'
                result['exploitability'] = 'Medium'
            
            if 'use-after-free' in crash_text:
                result['vulnerability_type'] = 'Use-After-Free'
                result['crash_type'] = 'Use-After-Free'
                result['exploitability'] = 'High'
            
            if 'heap' in crash_text and ('corrupt' in crash_text or 'overflow' in crash_text):
                result['vulnerability_type'] = 'Heap Corruption'
                result['crash_type'] = 'Heap Overflow/Corruption'
                result['exploitability'] = 'Medium'
            
            logger.info(f"启发式分析完成，判断漏洞类型: {result['vulnerability_type']}")
            
        except Exception as e:
            logger.error(f"启发式分析出错: {e}")
        
        return result
    
    def call_openai_analysis(
        self,
        crash_info: Dict[str, str],
        protection_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        调用 OpenAI API 分析崩溃
        
        crash_info: 解析后的崩溃信息
        protection_info: 保护机制信息
        
        
        分析结果
        """
        if not self.client:
            logger.warning("未配置 OpenAI 客户端，使用启发式分析")
            return {}
        
        try:
            prompt = CRASH_ANALYSIS_TEMPLATE.format(
                registers=crash_info.get('registers', 'N/A'),
                stack_trace=crash_info.get('stack_trace', 'N/A'),
                fault_instruction=crash_info.get('fault_instruction', 'N/A'),
                program_output=crash_info.get('program_output', 'N/A'),
                protection_info=str(protection_info)
            )
            
            logger.info("调用 AI API 进行崩溃分析...")
            
            result_text = call_ai_with_retry(
                self.client,
                model=get_current_ai_model(),
                messages=[
                    {"role": "system", "content": "你是一个资深的二进制安全研究员，专业分析程序崩溃和漏洞。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2000
            )
            logger.info("AI 崩溃分析完成")
            
            return self._parse_ai_response(result_text)
            
        except Exception as e:
            logger.error(f"调用 OpenAI API 失败: {e}")
            return {}
    
    def _parse_ai_response(self, response_text: str) -> Dict[str, Any]:
        """
        解析 响应，增强容错能力
        支持从 ```json 代码块中提取 JSON
        """
        default_result = {
            'raw_response': response_text,
            'crash_type': 'Unknown',
            'vulnerability_type': 'Unknown',
            'analysis': response_text[:500] if response_text else '',
            'exploitability': 'Unknown',
            'difficulty': 'Unknown',
            'recommendations': [],
            'parse_error': True
        }
        
        if not response_text:
            logger.warning("AI 返回空响应")
            return default_result
        
        json_str = None
        
        json_block_match = re.search(r'```json\n([\s\S]*?)\n```', response_text)
        if json_block_match:
            json_str = json_block_match.group(1).strip()
            logger.debug("从代码块中提取到 JSON")
        else:
            code_block_match = re.search(r'```\n([\s\S]*?)\n```', response_text)
            if code_block_match:
                block_content = code_block_match.group(1).strip()
                if block_content.startswith('{') or block_content.startswith('['):
                    json_str = block_content
                    logger.debug("从通用代码块中提取到 JSON")
        
        if not json_str:
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                json_str = json_match.group()
                logger.debug("从正则匹配中提取到 JSON")
        
        if json_str:
            json_str = self._try_repair_json(json_str)
            
            try:
                parsed = json.loads(json_str)
                
                result = {
                    'raw_response': response_text,
                    'crash_type': parsed.get('crash_type', 'Unknown'),
                    'vulnerability_type': parsed.get('vulnerability_type', 'Unknown'),
                    'analysis': parsed.get('analysis', ''),
                    'exploitability': parsed.get('exploitability', 'Unknown'),
                    'difficulty': parsed.get('difficulty', 'Unknown'),
                    'recommendations': parsed.get('recommendations', []),
                    'parse_error': False
                }
                
                if not isinstance(result['recommendations'], list):
                    result['recommendations'] = []
                
                return result
            except json.JSONDecodeError as e:
                logger.error(f"解析 AI 响应 JSON 失败: {e}")
                logger.debug(f"原始响应片段: {response_text[:500]}")
        
        logger.warning("AI 响应中未找到有效的 JSON 格式，使用启发式解析")
        
        crash_type, vuln_type = self._heuristic_detect_types(response_text)
        analysis = self._heuristic_extract_analysis(response_text)
        exploitability = self._heuristic_detect_exploitability(response_text)
        difficulty = self._heuristic_detect_difficulty(response_text)
        recommendations = self._heuristic_extract_recommendations(response_text)
        
        return {
            'raw_response': response_text,
            'crash_type': crash_type,
            'vulnerability_type': vuln_type,
            'analysis': analysis,
            'exploitability': exploitability,
            'difficulty': difficulty,
            'recommendations': recommendations,
            'parse_error': True,
            'parse_mode': 'heuristic'
        }
    
    def _try_repair_json(self, json_str: str) -> str:
        """
        尝试修复常见的 JSON 格式错误
        """
        repaired = json_str.strip()
        
        trailing_comma_pattern = re.compile(r',\s*([}\]])')
        repaired = trailing_comma_pattern.sub(r'\1', repaired)
        
        if repaired.count('{') > repaired.count('}'):
            repaired += '}' * (repaired.count('{') - repaired.count('}'))
        elif repaired.count('[') > repaired.count(']'):
            repaired += ']' * (repaired.count('[') - repaired.count(']'))
        
        lines = repaired.split('\n')
        cleaned_lines = []
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('//'):
                continue
            if '#' in stripped:
                stripped = stripped.split('#')[0]
            cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)
    
    def _heuristic_detect_types(self, text: str) -> Tuple[str, str]:
        """
        启发式检测崩溃类型和漏洞类型
        """
        text_lower = text.lower()
        
        crash_types = [
            ('Segmentation Fault', ['segmentation fault', 'sigsegv', 'segfault']),
            ('Abort', ['sigabrt', 'abort', 'stack smashing']),
            ('Bus Error', ['sigbus', 'bus error']),
            ('Floating Point Exception', ['sigfpe', 'floating point']),
        ]
        
        vuln_types = [
            ('Stack Buffer Overflow', ['stack overflow', '栈溢出', 'buffer overflow']),
            ('Format String', ['format string', '格式化字符串']),
            ('Heap Overflow', ['heap overflow', '堆溢出']),
            ('Use-After-Free', ['use-after-free', '使用后释放']),
            ('Double Free', ['double free']),
            ('Memory Corruption', ['memory corruption', '内存损坏']),
        ]
        
        crash_type = 'Unknown'
        for name, patterns in crash_types:
            if any(p in text_lower for p in patterns):
                crash_type = name
                break
        
        vuln_type = 'Unknown'
        for name, patterns in vuln_types:
            if any(p in text_lower for p in patterns):
                vuln_type = name
                break
        
        return crash_type, vuln_type
    
    def _heuristic_extract_analysis(self, text: str) -> str:
        """
        启发式提取分析内容
        """
        lines = text.strip().split('\n')
        analysis_lines = []
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('```') and not line.startswith('#'):
                analysis_lines.append(line)
            if len(analysis_lines) >= 10:
                break
        
        analysis = ' '.join(analysis_lines)
        return analysis[:1000] if len(analysis) > 1000 else analysis
    
    def _heuristic_detect_exploitability(self, text: str) -> str:
        """
        启发式检测可利用性
        """
        text_lower = text.lower()
        
        if 'high' in text_lower or '高' in text_lower:
            return 'High'
        elif 'medium' in text_lower or '中' in text_lower:
            return 'Medium'
        elif 'low' in text_lower or '低' in text_lower:
            return 'Low'
        return 'Unknown'
    
    def _heuristic_detect_difficulty(self, text: str) -> str:
        """
        启发式检测利用难度
        """
        text_lower = text.lower()
        
        if 'easy' in text_lower or '简单' in text_lower:
            return 'Easy'
        elif 'hard' in text_lower or '困难' in text_lower:
            return 'Hard'
        elif 'medium' in text_lower or '中等' in text_lower:
            return 'Medium'
        return 'Unknown'
    
    def _heuristic_extract_recommendations(self, text: str) -> List[str]:
        """
        启发式提取
        """
        recommendations = []
        
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('-') or line.startswith('*') or line.startswith('•'):
                rec = line[1:].strip()
                if rec:
                    recommendations.append(rec)
            elif line.startswith('建议') or line.startswith('recommend'):
                rec = line.split(':', 1)[-1].strip()
                if rec:
                    recommendations.append(rec)
        
        return recommendations[:5]
    
    def analyze(
        self,
        crash_data: Dict[str, Any],
        protection_info: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        完整的崩溃分析流程
        
  
            crash_data: 原始崩溃数据
            protection_info: 保护机制信息（可选）
 
            综合分析结果
        """
        logger.info("开始崩溃分析...")
        
        parsed_info = self.parse_crash_info(crash_data)
        heuristic_result = self.heuristic_analysis(crash_data)
        
        ai_result = {}
        if self.client:
            ai_result = self.call_openai_analysis(parsed_info, protection_info or {})
        
        final_result = {
            'parsed_info': parsed_info,
            'heuristic_analysis': heuristic_result,
            'ai_analysis': ai_result,
            'combined': self._merge_analysis(heuristic_result, ai_result)
        }
        
        return final_result
    
    def _merge_analysis(
        self,
        heuristic: Dict[str, Any],
        ai: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        合并启发式分析和 分析结果
        """
        merged = heuristic.copy()
        
        try:
            if ai and not ai.get('parse_error', False):
                ai_vuln_type = ai.get('vulnerability_type', 'Unknown')
                if ai_vuln_type and ai_vuln_type != 'Unknown':
                    merged['vulnerability_type'] = ai_vuln_type
                
                if ai.get('analysis'):
                    merged['analysis'] = ai['analysis']
                
                if ai.get('exploitability'):
                    merged['exploitability'] = ai['exploitability']
                
                if ai.get('difficulty'):
                    merged['difficulty'] = ai['difficulty']
                
                if ai.get('recommendations'):
                    merged['recommendations'] = ai['recommendations']
        except Exception as e:
            logger.error(f"合并分析结果时出错: {e}")
        
        return merged


CRASH_FORMAT_COREDUMP = 'coredump'
CRASH_FORMAT_WINDBG = 'windbg'
CRASH_FORMAT_LINUX_CORE = 'linux_core'


def detect_crash_format_enhanced(content: str) -> str:
    """
    增强版崩溃数据格式检测
    
    Args:
    content: 崩溃数据内容
    
    返回:
    格式类型
    """
    if not content:
        return CRASH_FORMAT_JSON
    
    content_str = str(content).strip()
    
    if content_str.startswith('{') or content_str.startswith('['):
        try:
            json.loads(content_str)
            return CRASH_FORMAT_JSON
        except json.JSONDecodeError:
            pass
    
    if 'ERROR: AddressSanitizer:' in content_str:
        return CRASH_FORMAT_ASAN
    
    if 'HEAP SUMMARY:' in content_str or 'freed by thread' in content_str:
        return CRASH_FORMAT_ASAN
    
    if 'Microsoft (R) Windows Debugger' in content_str or '!analyze -v' in content_str:
        return CRASH_FORMAT_WINDBG
    
    if 'FAULTING_IP:' in content_str or 'EXCEPTION_RECORD:' in content_str:
        return CRASH_FORMAT_WINDBG
    
    if 'Core was generated by' in content_str:
        return CRASH_FORMAT_LINUX_CORE
    
    if '#0  0x' in content_str and 'in ?? ()' in content_str:
        return CRASH_FORMAT_LINUX_CORE
    
    if 'Program received signal' in content_str:
        return CRASH_FORMAT_GDB
    
    if re.search(r'#\d+\s+0x[0-9a-fA-F]+\s+in\s+\w+', content_str):
        return CRASH_FORMAT_GDB
    
    if 'Signal si_code:' in content_str or 'si_pid:' in content_str:
        return CRASH_FORMAT_COREDUMP
    
    if 'Backtrace stopped:' in content_str:
        return CRASH_FORMAT_GDB
    
    return CRASH_FORMAT_JSON


def parse_coredump_summary(text: str) -> Dict[str, Any]:
    """
    解析 coredump 摘要格式
    
    Args:
    text: coredump 摘要文本
    
    返回:
    解析后的崩溃数据字典
    """
    result = {
        'registers': {},
        'stack_trace': [],
        'fault_instruction': '',
        'output': '',
        'signal': '',
        'process_name': '',
        'format': 'coredump'
    }
    
    if not text:
        return result
    
    lines = text.split('\n')
    
    core_match = re.search(r'Core was generated by `([^\']+)', text)
    if core_match:
        result['process_name'] = core_match.group(1)
    
    signal_match = re.search(r'Program terminated with signal (\w+)', text)
    if signal_match:
        result['signal'] = signal_match.group(1)
    
    ip_match = re.search(r'(?:rip|eip|pc)\s*=\s*(0x[0-9a-fA-F]+)', text, re.IGNORECASE)
    if ip_match:
        result['fault_instruction'] = f"IP = {ip_match.group(1)}"
    
    stack_pattern = re.compile(r'#(\d+)\s+(0x[0-9a-fA-F]+)\s+(?:in\s+)?([\w.?]+)')
    for match in stack_pattern.finditer(text):
        result['stack_trace'].append({
            'frame': int(match.group(1)),
            'address': match.group(2),
            'function': match.group(3),
            'raw': match.group(0)
        })
    
    registers = parse_registers_from_text(text)
    if registers:
        result['registers'] = registers
    
    if result['stack_trace']:
        result['stack_trace_str'] = '\n'.join([
            f"#{f['frame']}  {f['address']} in {f['function']}"
            for f in result['stack_trace']
        ])
    
    logger.info(f"已解析 coredump 摘要: {len(result['stack_trace'])} 个栈帧, 信号={result['signal']}")
    
    return result


def parse_windbg_output(text: str) -> Dict[str, Any]:
    """
    解析 WinDbg 输出格式
    
    Args:
    text: WinDbg 输出文本
    
    返回:
    解析后的崩溃数据字典
    """
    result = {
        'registers': {},
        'stack_trace': [],
        'fault_instruction': '',
        'output': '',
        'exception_code': '',
        'format': 'windbg'
    }
    
    if not text:
        return result
    
    exc_match = re.search(r'EXCEPTION_CODE:\s*(0x[0-9a-fA-F]+)', text)
    if exc_match:
        result['exception_code'] = exc_match.group(1)
    
    fault_match = re.search(r'FAULTING_IP:\s*([a-zA-Z]+)\+([0-9a-fA-Fx]+)', text)
    if fault_match:
        result['fault_instruction'] = f"{fault_match.group(1)}+{fault_match.group(2)}"
    
    stack_pattern = re.compile(r'([0-9a-fA-F`]+)\s+([0-9a-fA-F`]+)\s+([0-9a-fA-F`]+)\s+:\s+(\w+)')
    for match in stack_pattern.finditer(text):
        result['stack_trace'].append({
            'child_sp': match.group(1),
            'ret_address': match.group(2),
            'args': match.group(3),
            'function': match.group(4),
            'raw': match.group(0)
        })
    
    registers = parse_registers_from_text(text)
    if registers:
        result['registers'] = registers
    
    logger.info(f"已解析 WinDbg 输出: {len(result['stack_trace'])} 个栈帧")
    
    return result


def normalize_to_internal_format(crash_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    将各种格式的崩溃数据统一转换为内部表示格式
    
    Args:
    crash_data: 原始崩溃数据
    
    返回:
    标准化的内部表示
    """
    normalized = {
        'registers': {},
        'stack_trace': [],
        'fault_instruction': '',
        'signal': '',
        'error_type': '',
        'fault_address': '',
        'format': 'normalized',
        'raw': crash_data
    }
    
    if not isinstance(crash_data, dict):
        return normalized
    
    reg_keys = ['registers', 'regs', 'reg', 'register_values']
    for key in reg_keys:
        if key in crash_data:
            regs = crash_data[key]
            if isinstance(regs, dict):
                normalized['registers'] = {k.lower(): v for k, v in regs.items()}
            elif isinstance(regs, str):
                normalized['registers'] = parse_registers_from_text(regs)
            break
    
    stack_keys = ['stack_trace', 'stacktrace', 'backtrace', 'bt', 'call_stack']
    for key in stack_keys:
        if key in crash_data:
            stack = crash_data[key]
            if isinstance(stack, list):
                normalized['stack_trace'] = stack
            elif isinstance(stack, str):
                frames = []
                for i, line in enumerate(stack.strip().split('\n')):
                    line = line.strip()
                    if line:
                        frames.append({'frame': i, 'raw': line})
                normalized['stack_trace'] = frames
            break
    
    if 'fault_instruction' in crash_data:
        normalized['fault_instruction'] = str(crash_data['fault_instruction'])
    elif 'instruction_pointer' in crash_data:
        normalized['fault_instruction'] = str(crash_data['instruction_pointer'])
    elif 'rip' in normalized['registers']:
        normalized['fault_instruction'] = f"rip = {normalized['registers']['rip']}"
    elif 'eip' in normalized['registers']:
        normalized['fault_instruction'] = f"eip = {normalized['registers']['eip']}"
    
    signal_keys = ['signal', 'sig', 'signal_name', 'signal_type']
    for key in signal_keys:
        if key in crash_data:
            normalized['signal'] = str(crash_data[key])
            break
    
    error_keys = ['error_type', 'crash_type', 'exception', 'exception_type']
    for key in error_keys:
        if key in crash_data:
            normalized['error_type'] = str(crash_data[key])
            break
    
    fault_addr_keys = ['fault_address', 'crash_address', 'access_address', 'bad_address']
    for key in fault_addr_keys:
        if key in crash_data:
            normalized['fault_address'] = str(crash_data[key])
            break
    
    if 'format' in crash_data:
        normalized['original_format'] = crash_data['format']
    
    if normalized['stack_trace']:
        normalized['stack_trace_str'] = '\n'.join([
            f"#{i} {f.get('function', '??')} @ {f.get('address', '?')}"
            for i, f in enumerate(normalized['stack_trace'][:10])
        ])
    
    return normalized


def load_and_parse_crash_data_enhanced(
    file_path: str, 
    format_type: str = CRASH_FORMAT_AUTO
) -> Optional[Dict[str, Any]]:
    """
    增强版崩溃数据加载和解析
    
    Args:
    file_path: 崩溃数据文件路径
    format_type: 格式类型
    
    返回:
    解析并标准化后的崩溃数据
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except FileNotFoundError:
        logger.error(f"崩溃数据文件不存在: {file_path}")
        return None
    except Exception as e:
        logger.error(f"读取崩溃数据文件失败: {e}")
        return None
    
    if format_type == CRASH_FORMAT_AUTO:
        detected = detect_crash_format_enhanced(content)
        logger.info(f"自动检测到崩溃数据格式: {detected}")
        format_type = detected
    
    raw_data = None
    
    if format_type == CRASH_FORMAT_JSON:
        try:
            raw_data = json.loads(content)
            logger.info("已解析 JSON 格式崩溃数据")
        except json.JSONDecodeError as e:
            logger.warning(f"JSON 解析失败，尝试其他格式: {e}")
            format_type = detect_crash_format_enhanced(content)
    
    if raw_data is None:
        if format_type == CRASH_FORMAT_GDB:
            raw_data = parse_gdb_backtrace(content)
        elif format_type == CRASH_FORMAT_ASAN:
            raw_data = parse_asan_report(content)
        elif format_type == CRASH_FORMAT_COREDUMP or format_type == CRASH_FORMAT_LINUX_CORE:
            raw_data = parse_coredump_summary(content)
        elif format_type == CRASH_FORMAT_WINDBG:
            raw_data = parse_windbg_output(content)
        else:
            logger.warning(f"未知格式，使用启发式解析")
            raw_data = {
                'raw_text': content[:2000],
                'registers': parse_registers_from_text(content),
                'format': 'unknown'
            }
    
    if raw_data:
        normalized = normalize_to_internal_format(raw_data)
        normalized['original_raw'] = raw_data
        return normalized
    
    return None


def list_supported_formats() -> List[Dict[str, Any]]:
    """
    列出所有支持的崩溃数据格式
    
    返回:
    格式列表
    """
    return [
        {
            'name': CRASH_FORMAT_JSON,
            'description': 'JSON 格式（项目内部格式）',
            'auto_detect': True,
            'examples': ['{"registers": {...}, "stack_trace": [...]}']
        },
        {
            'name': CRASH_FORMAT_GDB,
            'description': 'GDB 回溯输出格式',
            'auto_detect': True,
            'examples': ['Program received signal SIGSEGV', '#0 0x... in main()']
        },
        {
            'name': CRASH_FORMAT_ASAN,
            'description': 'AddressSanitizer 报告格式',
            'auto_detect': True,
            'examples': ['ERROR: AddressSanitizer: SEGV', 'HEAP SUMMARY:']
        },
        {
            'name': CRASH_FORMAT_COREDUMP,
            'description': 'Linux coredump 摘要格式',
            'auto_detect': True,
            'examples': ['Core was generated by', 'Program terminated with signal']
        },
        {
            'name': CRASH_FORMAT_WINDBG,
            'description': 'WinDbg 调试输出格式',
            'auto_detect': True,
            'examples': ['FAULTING_IP:', 'EXCEPTION_CODE:']
        }
    ]
