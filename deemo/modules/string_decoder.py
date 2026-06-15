import logging
import base64
import binascii
import urllib.parse
import re
from typing import Dict, Any, List, Optional, Tuple, Union
from enum import Enum

logger = logging.getLogger(__name__)


class DecodeMethod(Enum):
    """解码方法枚举"""
    BASE64 = "base64"
    HEX = "hex"
    XOR = "xor"
    ROT13 = "rot13"
    URL = "url"
    UNICODE_ESCAPE = "unicode_escape"
    QUOTED_PRINTABLE = "quoted_printable"


class StringAnalysis:
    """字符串分析结果类"""
    
    def __init__(self, original: str):
        self.original = original
        self.decoded_text: Optional[str] = None
        self.decoding_method: Optional[str] = None
        self.is_human_readable: bool = False
        self.entropy: float = 0.0
        self.confidence: float = 0.0
        self.possible_decodings: List[Dict[str, Any]] = []
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'original': self.original,
            'decoded_text': self.decoded_text,
            'decoding_method': self.decoding_method,
            'is_human_readable': self.is_human_readable,
            'entropy': self.entropy,
            'confidence': self.confidence,
            'possible_decodings': self.possible_decodings
        }


class StringDecoder:
    """
    二进制字符串自动解码与解混淆器
    
    该类负责扫描二进制中的所有字符串，自动识别并解码经过简单编码的字符串，
    恢复明文，辅助发现隐藏的配置、域名、命令等。
    """
    
    def __init__(
        self,
        min_length: int = 4,
        max_length: int = 1000,
        enable_lang_detect: bool = False
    ):
        """
        初始化字符串解码器
        
        Args:
            min_length: 最小字符串长度
            max_length: 最大字符串长度
            enable_lang_detect: 是否启用语言检测
        """
        self.min_length = min_length
        self.max_length = max_length
        self.enable_lang_detect = enable_lang_detect
        self._lang_detector = None
        if self.enable_lang_detect:
            try:
                from langdetect import detect
                self._lang_detector = detect
            except ImportError:
                logger.warning("langdetect 未安装，语言检测功能将被禁用")
                self.enable_lang_detect = False
    
    def _calculate_entropy(self, s: str) -> float:
        """
        计算字符串的熵值
        
        Args:
            s: 输入字符串
            
        Returns:
            熵值 (0-8)
        """
        if not s:
            return 0.0
        
        import math
        
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        
        entropy = 0.0
        length = len(s)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _is_human_readable(self, s: str) -> bool:
        """
        判断字符串是否为人类可读
        
        Args:
            s: 输入字符串
            
        Returns:
            是否可读
        """
        if not s:
            return False
        
        printable_ratio = sum(1 for c in s if c.isprintable() or c in '\n\r\t') / len(s)
        if printable_ratio < 0.7:
            return False
        
        if len(s) < 4:
            return True
        
        ascii_ratio = sum(1 for c in s if ord(c) < 128) / len(s)
        if ascii_ratio < 0.5:
            return False
        
        return True
    
    def _try_base64(self, s: str) -> List[Dict[str, Any]]:
        """
        尝试 Base64 解码
        
        Args:
            s: 输入字符串
            
        Returns:
            解码结果列表
        """
        results = []
        try:
            decoded = base64.b64decode(s, validate=True).decode('utf-8', errors='ignore')
            if decoded and len(decoded) > 0:
                score = self._evaluate_decode_result(decoded)
                results.append({
                    'method': DecodeMethod.BASE64.value,
                    'result': decoded,
                    'score': score
                })
        except Exception:
            pass
        
        try:
            decoded = base64.urlsafe_b64decode(s + '=' * ((4 - len(s) % 4) % 4)).decode('utf-8', errors='ignore')
            if decoded and len(decoded) > 0:
                score = self._evaluate_decode_result(decoded)
                results.append({
                    'method': f"{DecodeMethod.BASE64.value}_urlsafe",
                    'result': decoded,
                    'score': score
                })
        except Exception:
            pass
        
        return results
    
    def _try_hex(self, s: str) -> List[Dict[str, Any]]:
        """
        尝试 Hex 解码
        
        Args:
            s: 输入字符串
            
        Returns:
            解码结果列表
        """
        results = []
        try:
            cleaned = s.replace(' ', '').replace('-', '').replace('0x', '')
            if len(cleaned) % 2 == 0 and len(cleaned) >= 4:
                decoded = binascii.unhexlify(cleaned).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 0:
                    score = self._evaluate_decode_result(decoded)
                    results.append({
                        'method': DecodeMethod.HEX.value,
                        'result': decoded,
                        'score': score
                    })
        except Exception:
            pass
        
        return results
    
    def _try_xor(self, s: str) -> List[Dict[str, Any]]:
        """
        尝试 XOR 解码（暴力破解常用密钥）
        
        Args:
            s: 输入字符串
            
        Returns:
            解码结果列表
        """
        results = []
        
        common_keys = [0x00, 0x01, 0x13, 0x2a, 0x33, 0x41, 0x55, 0x66, 0x7f, 0x80, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        
        for key in common_keys:
            try:
                decoded = ''.join(chr(ord(c) ^ key) for c in s)
                if decoded and self._is_human_readable(decoded):
                    score = self._evaluate_decode_result(decoded)
                    if score > 0.5:
                        results.append({
                            'method': f"{DecodeMethod.XOR.value}_0x{key:02x}",
                            'result': decoded,
                            'score': score
                        })
            except Exception:
                pass
        
        return results
    
    def _try_rot13(self, s: str) -> List[Dict[str, Any]]:
        """
        尝试 ROT13 解码
        
        Args:
            s: 输入字符串
            
        Returns:
            解码结果列表
        """
        results = []
        try:
            decoded = s.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))
            if decoded != s:
                score = self._evaluate_decode_result(decoded)
                results.append({
                    'method': DecodeMethod.ROT13.value,
                    'result': decoded,
                    'score': score
                })
        except Exception:
            pass
        
        return results
    
    def _try_url_decode(self, s: str) -> List[Dict[str, Any]]:
        """
        尝试 URL 解码
        
        Args:
            s: 输入字符串
            
        Returns:
            解码结果列表
        """
        results = []
        try:
            decoded = urllib.parse.unquote(s)
            if decoded != s:
                score = self._evaluate_decode_result(decoded)
                results.append({
                    'method': DecodeMethod.URL.value,
                    'result': decoded,
                    'score': score
                })
        except Exception:
            pass
        
        try:
            decoded = urllib.parse.unquote_plus(s)
            if decoded != s:
                score = self._evaluate_decode_result(decoded)
                results.append({
                    'method': f"{DecodeMethod.URL.value}_plus",
                    'result': decoded,
                    'score': score
                })
        except Exception:
            pass
        
        return results
    
    def _try_unicode_escape(self, s: str) -> List[Dict[str, Any]]:
        """
        尝试 Unicode 转义解码
        
        Args:
            s: 输入字符串
            
        Returns:
            解码结果列表
        """
        results = []
        try:
            decoded = s.encode('utf-8').decode('unicode-escape')
            if decoded != s:
                score = self._evaluate_decode_result(decoded)
                results.append({
                    'method': DecodeMethod.UNICODE_ESCAPE.value,
                    'result': decoded,
                    'score': score
                })
        except Exception:
            pass
        
        return results
    
    def _try_quoted_printable(self, s: str) -> List[Dict[str, Any]]:
        """
        尝试 Quoted-Printable 解码
        
        Args:
            s: 输入字符串
            
        Returns:
            解码结果列表
        """
        results = []
        try:
            from email.quoprimime import unquote
            decoded = unquote(s)
            if decoded != s:
                score = self._evaluate_decode_result(decoded)
                results.append({
                    'method': DecodeMethod.QUOTED_PRINTABLE.value,
                    'result': decoded,
                    'score': score
                })
        except Exception:
            pass
        
        return results
    
    def _evaluate_decode_result(self, decoded: str) -> float:
        """
        评估解码结果的质量
        
        Args:
            decoded: 解码后的字符串
            
        Returns:
            分数 (0-1)
        """
        score = 0.0
        
        if not decoded:
            return 0.0
        
        if len(decoded) < 2:
            return 0.0
        
        printable_ratio = sum(1 for c in decoded if c.isprintable()) / len(decoded)
        if printable_ratio < 0.9:
            return 0.3
        
        if self._is_human_readable(decoded):
            score += 0.4
        
        word_pattern = re.compile(r'[a-zA-Z]{3,}')
        word_count = len(word_pattern.findall(decoded))
        if word_count >= 1:
            score += min(word_count * 0.15, 0.3)
        
        common_words = {'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'it', 
                       'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at', 'this',
                       'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she', 
                       'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their',
                       'what', 'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 
                       'go', 'me', 'when', 'make', 'can', 'like', 'time', 'no', 'just',
                       'him', 'know', 'take', 'people', 'into', 'year', 'your', 'good',
                       'some', 'could', 'them', 'see', 'other', 'than', 'then', 'now',
                       'look', 'only', 'come', 'its', 'over', 'think', 'also', 'back',
                       'after', 'use', 'two', 'how', 'our', 'work', 'first', 'well',
                       'way', 'even', 'new', 'want', 'because', 'any', 'these', 'give',
                       'day', 'most', 'us', 'hello', 'world', 'test', 'code', 'data',
                       'secret', 'password', 'user', 'admin', 'system', 'server', 'client',
                       'config', 'api', 'key', 'token', 'url', 'host', 'port', 'database',
                       'username', 'email', 'address', 'path', 'file', 'version', 'build'}
        
        decoded_lower = decoded.lower()
        decoded_words = word_pattern.findall(decoded_lower)
        common_word_count = sum(1 for w in decoded_words if w in common_words)
        if common_word_count >= 1:
            score += min(common_word_count * 0.15, 0.2)
        
        url_pattern = re.compile(r'https?://[\w.-]+')
        email_pattern = re.compile(r'[\w.-]+@[\w.-]+\.\w+')
        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if url_pattern.search(decoded) or email_pattern.search(decoded) or ip_pattern.search(decoded):
            score += 0.3
        
        whitespace_ratio = decoded.count(' ') / len(decoded) if len(decoded) > 0 else 0
        if 0.1 < whitespace_ratio < 0.4:
            score += 0.1
        
        if self.enable_lang_detect and self._lang_detector:
            try:
                lang = self._lang_detector(decoded)
                if lang in ['zh', 'en', 'ja', 'ko']:
                    score += 0.2
            except Exception:
                pass
        
        return min(score, 1.0)
    
    def _looks_like_encoded(self, s: str) -> bool:
        """
        判断字符串是否看起来像编码格式
        
        Args:
            s: 输入字符串
            
        Returns:
            是否看起来像编码格式
        """
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        hex_chars = set('0123456789ABCDEFabcdef')
        
        if len(s) % 4 == 0 and all(c in base64_chars for c in s):
            return True
        
        if len(s) % 2 == 0 and len(s) >= 4 and all(c in hex_chars for c in s):
            return True
        
        if '%' in s:
            return True
        
        if '\\u' in s:
            return True
        
        if len(s) >= 4 and self._looks_like_rot13(s):
            return True
        
        return False
    
    def _looks_like_rot13(self, s: str) -> bool:
        """
        判断字符串是否看起来像ROT13编码
        
        Args:
            s: 输入字符串
            
        Returns:
            是否看起来像ROT13编码
        """
        rot13_map = str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
        )
        decoded = s.translate(rot13_map)
        
        if decoded == s:
            return False
        
        if not decoded.isprintable():
            return False
        
        word_pattern = re.compile(r'[a-zA-Z]{4,}')
        decoded_words = word_pattern.findall(decoded)
        original_words = word_pattern.findall(s)
        
        if len(decoded_words) >= 2 and len(original_words) >= 2:
            common_words = {'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'it', 
                           'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at', 'this',
                           'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she', 
                           'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their',
                           'what', 'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 
                           'go', 'me', 'when', 'make', 'can', 'like', 'time', 'no', 'just',
                           'him', 'know', 'take', 'people', 'into', 'year', 'your', 'good',
                           'some', 'could', 'them', 'see', 'other', 'than', 'then', 'now',
                           'look', 'only', 'come', 'its', 'over', 'think', 'also', 'back',
                           'after', 'use', 'two', 'how', 'our', 'work', 'first', 'well',
                           'way', 'even', 'new', 'want', 'because', 'any', 'these', 'give',
                           'day', 'most', 'us', 'hello', 'world', 'test', 'code', 'data',
                           'secret', 'password', 'user', 'admin', 'system', 'server', 'client'}
            
            decoded_word_set = set(w.lower() for w in decoded_words)
            original_word_set = set(w.lower() for w in original_words)
            
            decoded_common_count = sum(1 for w in decoded_word_set if w in common_words)
            original_common_count = sum(1 for w in original_word_set if w in common_words)
            
            if decoded_common_count >= 2 and original_common_count == 0:
                return True
        
        return False
    
    def analyze_string(self, s: str) -> StringAnalysis:
        """
        分析单个字符串，尝试各种解码方法
        
        Args:
            s: 原始字符串
            
        Returns:
            分析结果
        """
        if len(s) < self.min_length or len(s) > self.max_length:
            return StringAnalysis(original=s)
        
        analysis = StringAnalysis(original=s)
        analysis.entropy = self._calculate_entropy(s)
        analysis.is_human_readable = self._is_human_readable(s)
        
        if analysis.is_human_readable and not self._looks_like_encoded(s):
            analysis.decoded_text = s
            analysis.confidence = 1.0
            return analysis
        
        attempts = []
        
        if '\\u' in s:
            attempts.extend(self._try_unicode_escape(s))
        else:
            attempts.extend(self._try_base64(s))
            attempts.extend(self._try_hex(s))
            attempts.extend(self._try_url_decode(s))
            attempts.extend(self._try_quoted_printable(s))
            attempts.extend(self._try_rot13(s))
            attempts.extend(self._try_xor(s))
        
        analysis.possible_decodings = sorted(attempts, key=lambda x: x['score'], reverse=True)
        
        if analysis.possible_decodings:
            best = analysis.possible_decodings[0]
            if best['score'] > 0.5:
                analysis.decoded_text = best['result']
                analysis.decoding_method = best['method']
                analysis.confidence = best['score']
                return analysis
        
        if analysis.is_human_readable:
            analysis.decoded_text = s
            analysis.confidence = 1.0
        
        return analysis
    
    def analyze_strings(self, strings: List[str]) -> List[StringAnalysis]:
        """
        分析字符串列表
        
        Args:
            strings: 字符串列表
            
        Returns:
            分析结果列表
        """
        results = []
        for s in strings:
            if isinstance(s, str):
                result = self.analyze_string(s)
                results.append(result)
        return results
    
    def find_suspicious_patterns(self, strings: List[str]) -> List[Dict[str, Any]]:
        """
        从字符串列表中查找可疑模式
        
        Args:
            strings: 字符串列表
            
        Returns:
            可疑模式列表
        """
        suspicious = []
        
        patterns = [
            (r'https?://[\w.-]+(?:/[\w./-]*)?', 'url'),
            (r'[\w.-]+@[\w.-]+\.\w+', 'email'),
            (r'(?:mysql|postgresql|mongodb|sqlite)://[\w.:@/]+', 'database'),
            (r'(?:api[_-]?key|secret|token)[=:]\s*[\w]+', 'api_key'),
            (r'(?:password|passwd|pwd)[=:]\s*[\w]+', 'password'),
            (r'(?:username|user)[=:]\s*[\w]+', 'username'),
            (r'[A-Za-z0-9+/]{20,}', 'base64_like'),
            (r'[0-9A-Fa-f]{32,}', 'hex_like'),
        ]
        
        for s in strings:
            if not isinstance(s, str):
                continue
            
            for pattern, pattern_type in patterns:
                if re.search(pattern, s):
                    suspicious.append({
                        'original': s,
                        'pattern_type': pattern_type,
                        'matched_pattern': pattern
                    })
        
        return suspicious
    
    def decode_all(self, strings: List[str]) -> Dict[str, Any]:
        """
        对字符串列表进行全面解码分析
        
        Args:
            strings: 字符串列表
            
        Returns:
            解码映射表
        """
        logger.info(f"开始分析 {len(strings)} 个字符串...")
        
        results = {
            'original_strings': strings,
            'decoded_mapping': [],
            'suspicious_patterns': [],
            'stats': {
                'total_strings': len(strings),
                'decoded_count': 0,
                'human_readable_count': 0
            }
        }
        
        decoded_count = 0
        human_readable_count = 0
        
        for s in strings:
            if not isinstance(s, str):
                continue
            
            analysis = self.analyze_string(s)
            result = analysis.to_dict()
            results['decoded_mapping'].append(result)
            
            if analysis.decoded_text:
                decoded_count += 1
            if analysis.is_human_readable:
                human_readable_count += 1
        
        results['suspicious_patterns'] = self.find_suspicious_patterns(strings)
        
        results['stats']['decoded_count'] = decoded_count
        results['stats']['human_readable_count'] = human_readable_count
        
        logger.info(f"字符串分析完成: {decoded_count}/{len(strings)} 已解码")
        return results
    
    def decode_and_enrich(self, binary_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        解码字符串并丰富二进制信息
        
        Args:
            binary_info: 二进制信息字典
            
        Returns:
            更新后的二进制信息
        """
        strings = binary_info.get('key_strings', [])
        if not strings:
            strings = binary_info.get('strings', [])
        
        if not strings:
            logger.warning("没有找到字符串列表")
            return binary_info
        
        decoded_result = self.decode_all(strings)
        binary_info['decoded_strings'] = decoded_result
        
        return binary_info
