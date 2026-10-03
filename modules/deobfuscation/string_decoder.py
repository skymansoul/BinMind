import logging
import base64
import binascii
import urllib.parse
import re
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class DecodeMethod(Enum):
    BASE64 = "base64"
    HEX = "hex"
    XOR = "xor"
    ROT13 = "rot13"
    URL = "url"
    UNICODE_ESCAPE = "unicode_escape"
    QUOTED_PRINTABLE = "quoted_printable"


@dataclass
class StringAnalysis:
    """String analysis result container."""
    original: str
    decoded_text: Optional[str] = None
    decoding_method: Optional[str] = None
    is_human_readable: bool = False
    entropy: float = 0.0
    confidence: float = 0.0
    possible_decodings: list = field(default_factory=list)

    def to_dict(self):
        result = {}
        result['original'] = self.original
        result['decoded_text'] = self.decoded_text
        result['decoding_method'] = self.decoding_method.value if isinstance(self.decoding_method, DecodeMethod) else self.decoding_method
        result['is_human_readable'] = self.is_human_readable
        result['entropy'] = self.entropy
        result['confidence'] = self.confidence
        result['possible_decodings'] = self.possible_decodings if self.possible_decodings is not None else []
        return result


class StringDecoder:
    """
    Binary string auto-decoder and deobfuscator.

    Scans all strings in a binary, auto-detects and decodes simply-encoded
    strings, recovers plaintext, and helps uncover hidden configs, domain
    names, commands, etc.
    """

    def __init__(self,
        min_length=4,
        max_length=1000,
        enable_lang_detect=False
    ):
        self.min_length = min(max(min_length, 1), 100000)
        self.max_length = min(max(max_length, 1), 100000)
        self.enable_lang_detect = enable_lang_detect
        self._lang_detector = None

        if self.enable_lang_detect:
            try:
                from langdetect import detect
                self._lang_detector = detect
            except ImportError:
                logger.warning("langdetect not installed, language detection disabled")
                self.enable_lang_detect = False

    def _calculate_entropy(self, s):
        """Calculate Shannon entropy of a string."""
        if s is None or s == "":
            return 0.0

        freq = {}
        for c in s:
            if c in freq:
                freq[c] = freq[c] + 1
            else:
                freq[c] = 1

        entropy = 0.0
        length = len(s)
        if length == 0:
            return 0.0

        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    def _is_human_readable(self, s):
        """Check if string is human-readable."""
        if s is None or s == "":
            return False

        length = len(s)
        if length == 0:
            return False

        printable = 0
        for c in s:
            if c.isprintable() or c in '\n\r\t':
                printable += 1
        printable_ratio = printable / length
        if printable_ratio < 0.7:
            return False

        if length < 4:
            return True

        ascii_count = 0
        for c in s:
            if ord(c) < 128:
                ascii_count += 1
        ascii_ratio = ascii_count / length
        if ascii_ratio < 0.5:
            return False

        return True

    def _try_base64(self, s):
        """Try Base64 decoding."""
        results = []
        if s is None or s == "":
            return results

        try:
            decoded = base64.b64decode(s, validate=True)
            decoded_str = decoded.decode('utf-8', errors='ignore')
            if decoded_str is not None and len(decoded_str) > 0:
                score = self._evaluate_decode_result(decoded_str)
                results.append({
                    'method': DecodeMethod.BASE64.value,
                    'result': decoded_str,
                    'score': score
                })
        except Exception:
            logger.debug("suppressed", exc_info=True)

        try:
            padding = (4 - len(s) % 4) % 4
            padded = s + '=' * padding
            decoded = base64.urlsafe_b64decode(padded)
            decoded_str = decoded.decode('utf-8', errors='ignore')
            if decoded_str is not None and len(decoded_str) > 0:
                score = self._evaluate_decode_result(decoded_str)
                results.append({
                    'method': DecodeMethod.BASE64.value + "_urlsafe",
                    'result': decoded_str,
                    'score': score
                })
        except Exception:
            logger.debug("suppressed", exc_info=True)

        return results

    def _try_hex(self, s):
        """Try Hex decoding."""
        results = []
        if s is None or s == "":
            return results

        try:
            cleaned = s.replace(' ', '').replace('-', '').replace('0x', '')
            length = len(cleaned)
            if length % 2 == 0 and length >= 4:
                decoded = binascii.unhexlify(cleaned)
                decoded_str = decoded.decode('utf-8', errors='ignore')
                if decoded_str is not None and len(decoded_str) > 0:
                    score = self._evaluate_decode_result(decoded_str)
                    results.append({
                        'method': DecodeMethod.HEX.value,
                        'result': decoded_str,
                        'score': score
                    })
        except Exception:
            logger.debug("suppressed", exc_info=True)

        return results

    def _try_xor(self, s):
        """Try XOR decoding with common keys."""
        results = []
        if s is None or s == "":
            return results

        common_keys = [
            0x00, 0x01, 0x13, 0x2a, 0x33, 0x41, 0x55, 0x66, 0x7f,
            0x80, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]

        for key in common_keys:
            try:
                decoded_str = ''.join(chr(ord(c) ^ key) for c in s)
                if decoded_str is not None and decoded_str != "" and self._is_human_readable(decoded_str):
                    score = self._evaluate_decode_result(decoded_str)
                    if score > 0.5:
                        results.append({
                            'method': DecodeMethod.XOR.value + "_0x{:02x}".format(key),
                            'result': decoded_str,
                            'score': score
                        })
            except Exception:
                logger.debug("suppressed", exc_info=True)

        return results

    def _try_rot13(self, s):
        """Try ROT13 decoding."""
        results = []
        if s is None or s == "":
            return results

        try:
            upper_in  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            upper_out = 'NOPQRSTUVWXYZABCDEFGHIJKLM'
            lower_in  = 'abcdefghijklmnopqrstuvwxyz'
            lower_out = 'nopqrstuvwxyzabcdefghijklm'
            map_in    = upper_in + lower_in
            map_out   = upper_out + lower_out

            decoded_str = s.translate(str.maketrans(map_in, map_out))

            if decoded_str is not None and decoded_str != s:
                score = self._evaluate_decode_result(decoded_str)
                results.append({
                    'method': DecodeMethod.ROT13.value,
                    'result': decoded_str,
                    'score': score
                })
        except Exception:
            logger.debug("suppressed", exc_info=True)

        return results

    def _try_url_decode(self, s):
        """Try URL decoding."""
        results = []
        if s is None or s == "":
            return results

        try:
            decoded_str = urllib.parse.unquote(s)
            if decoded_str is not None and decoded_str != s:
                score = self._evaluate_decode_result(decoded_str)
                results.append({
                    'method': DecodeMethod.URL.value,
                    'result': decoded_str,
                    'score': score
                })
        except Exception:
            logger.debug("suppressed", exc_info=True)

        try:
            decoded_str = urllib.parse.unquote_plus(s)
            if decoded_str is not None and decoded_str != s:
                score = self._evaluate_decode_result(decoded_str)
                results.append({
                    'method': DecodeMethod.URL.value + "_plus",
                    'result': decoded_str,
                    'score': score
                })
        except Exception:
            logger.debug("suppressed", exc_info=True)

        return results

    def _try_unicode_escape(self, s):
        """Try unicode escape decoding."""
        results = []
        if s is None or s == "":
            return results

        try:
            decoded_str = s.encode('utf-8').decode('unicode-escape')
            if decoded_str is not None and decoded_str != s:
                score = self._evaluate_decode_result(decoded_str)
                results.append({
                    'method': DecodeMethod.UNICODE_ESCAPE.value,
                    'result': decoded_str,
                    'score': score
                })
        except Exception:
            logger.debug("suppressed", exc_info=True)

        return results

    def _try_quoted_printable(self, s):
        """Try quoted-printable decoding."""
        results = []
        if s is None or s == "":
            return results

        try:
            from email.quoprimime import unquote
            decoded_str = unquote(s)
            if decoded_str is not None and decoded_str != s:
                score = self._evaluate_decode_result(decoded_str)
                results.append({
                    'method': DecodeMethod.QUOTED_PRINTABLE.value,
                    'result': decoded_str,
                    'score': score
                })
        except Exception:
            logger.debug("suppressed", exc_info=True)

        return results

    def _evaluate_decode_result(self, decoded_str):
        """Evaluate the quality of a decoded result."""
        score = 0.0

        if decoded_str is None or decoded_str == "":
            return 0.0

        if len(decoded_str) < 2:
            return 0.0

        length = len(decoded_str)
        printable = 0
        for c in decoded_str:
            if c.isprintable():
                printable += 1
        printable_ratio = printable / length
        if printable_ratio < 0.9:
            return 0.3

        if self._is_human_readable(decoded_str):
            score += 0.4

        word_pattern = re.compile(r'[a-zA-Z]{3,}')
        words = word_pattern.findall(decoded_str)
        word_count = len(words)

        if word_count >= 1:
            word_bonus = min(max(word_count * 0.15, 0.0), 0.3)
            score += word_bonus

        common_words = {
            'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'it',
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
            'username', 'email', 'address', 'path', 'file', 'version', 'build',
        }

        decoded_lower = decoded_str.lower()
        decoded_words = word_pattern.findall(decoded_lower)

        common_count = 0
        for w in decoded_words:
            if w in common_words:
                common_count += 1

        if common_count >= 1:
            common_bonus = min(max(common_count * 0.15, 0.0), 0.2)
            score += common_bonus

        url_pattern   = re.compile(r'https?://[\w.-]+')
        email_pattern = re.compile(r'[\w.-]+@[\w.-]+\.\w+')
        ip_pattern    = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if url_pattern.search(decoded_str) is not None or \
           email_pattern.search(decoded_str) is not None or \
           ip_pattern.search(decoded_str) is not None:
            score += 0.3

        if len(decoded_str) > 0:
            whitespace_ratio = decoded_str.count(' ') / len(decoded_str)
        else:
            whitespace_ratio = 0
        if 0.1 < whitespace_ratio < 0.4:
            score += 0.1

        if self.enable_lang_detect and self._lang_detector is not None:
            try:
                lang = self._lang_detector(decoded_str)
                if lang is not None and lang in ['zh', 'en', 'ja', 'ko']:
                    score += 0.2
            except Exception:
                logger.debug("suppressed", exc_info=True)

        return min(max(score, 0.0), 1.0)

    def _looks_like_encoded(self, s):
        """Check if string looks encoded."""
        if s is None or s == "":
            return False

        base64_set = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        hex_set    = set('0123456789ABCDEFabcdef')

        if len(s) % 4 == 0:
            all_b64 = True
            for c in s:
                if c not in base64_set:
                    all_b64 = False
                    break
            if all_b64:
                return True

        if len(s) % 2 == 0 and len(s) >= 4:
            all_hex = True
            for c in s:
                if c not in hex_set:
                    all_hex = False
                    break
            if all_hex:
                return True

        if '%' in s:
            return True

        if '\\u' in s:
            return True

        if len(s) >= 4 and self._looks_like_rot13(s):
            return True

        return False

    def _looks_like_rot13(self, s):
        """Check if string looks like ROT13."""
        if s is None or s == "":
            return False

        upper_in  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        upper_out = 'NOPQRSTUVWXYZABCDEFGHIJKLM'
        lower_in  = 'abcdefghijklmnopqrstuvwxyz'
        lower_out = 'nopqrstuvwxyzabcdefghijklm'

        map_in  = upper_in + lower_in
        map_out = upper_out + lower_out

        decoded = s.translate(str.maketrans(map_in, map_out))

        if decoded is None or decoded == s:
            return False

        if not decoded.isprintable():
            return False

        word_pattern = re.compile(r'[a-zA-Z]{4,}')
        decoded_words  = word_pattern.findall(decoded)
        original_words = word_pattern.findall(s)

        if len(decoded_words) < 2 or len(original_words) < 2:
            return False

        common_words = {
            'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'it',
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
        }

        decoded_set  = set(w.lower() for w in decoded_words)
        original_set = set(w.lower() for w in original_words)

        decoded_common  = sum(1 for w in decoded_set if w in common_words)
        original_common = sum(1 for w in original_set if w in common_words)

        if decoded_common >= 2 and original_common == 0:
            return True

        return False

    def analyze_string(self, s):
        """Analyze a single string with all decoders."""
        if s is None:
            return StringAnalysis(original=s)

        length = len(s)
        if length < self.min_length or length > self.max_length:
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

        sorted_attempts = sorted(attempts, key=lambda x: x.get('score', 0), reverse=True)
        analysis.possible_decodings = sorted_attempts

        if analysis.possible_decodings is not None and len(analysis.possible_decodings) > 0:
            best = analysis.possible_decodings[0]
            if best is not None and best.get('score', 0) > 0.5:
                analysis.decoded_text = best.get('result', None)
                analysis.decoding_method = best.get('method', None)
                analysis.confidence = best.get('score', 0.0)
                return analysis

        if analysis.is_human_readable:
            analysis.decoded_text = s
            analysis.confidence = 1.0

        return analysis

    def analyze_strings(self, strings):
        """Analyze a list of strings."""
        results = []
        if strings is None:
            return results

        for s in strings:
            if isinstance(s, str) and s is not None:
                result = self.analyze_string(s)
                if result is not None:
                    results.append(result)
        return results

    def find_suspicious_patterns(self, strings):
        """Find suspicious patterns in string list."""
        suspicious = []
        if strings is None:
            return suspicious

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
            if s is None or not isinstance(s, str):
                continue

            for pattern, pat_type in patterns:
                if re.search(pattern, s) is not None:
                    suspicious.append({
                        'original': s,
                        'pattern_type': pat_type,
                        'matched_pattern': pattern
                    })

        return suspicious

    def decode_all(self, strings):
        """Full decode analysis on string list."""
        if strings is None:
            logger.warning("strings is None")
            return {
                'original_strings': [],
                'decoded_mapping': [],
                'suspicious_patterns': [],
                'stats': {
                    'total_strings': 0,
                    'decoded_count': 0,
                    'human_readable_count': 0,
                }
            }

        total = len(strings)
        logger.info(f"Analyzing {total} strings...")

        results = {
            'original_strings': strings,
            'decoded_mapping': [],
            'suspicious_patterns': [],
            'stats': {
                'total_strings': total,
                'decoded_count': 0,
                'human_readable_count': 0,
            }
        }

        decoded_count = 0
        human_count = 0

        for s in strings:
            if s is None or not isinstance(s, str):
                continue

            analysis = self.analyze_string(s)
            if analysis is not None:
                results['decoded_mapping'].append(analysis.to_dict())

                if analysis.decoded_text is not None:
                    decoded_count += 1
                if analysis.is_human_readable:
                    human_count += 1

        results['suspicious_patterns'] = self.find_suspicious_patterns(strings)
        results['stats']['decoded_count'] = decoded_count
        results['stats']['human_readable_count'] = human_count

        logger.info(f"String analysis complete: {decoded_count}/{total} decoded")
        return results

    def decode_and_enrich(self, binary_info):
        """Decode strings and enrich binary info dict."""
        if binary_info is None:
            logger.warning("binary_info is None")
            return {}

        strings = binary_info.get('key_strings', [])
        if strings is None or len(strings) == 0:
            strings = binary_info.get('strings', [])

        if strings is None or len(strings) == 0:
            logger.warning("No string list found")
            return binary_info

        decoded = self.decode_all(strings)
        binary_info['decoded_strings'] = decoded

        return binary_info
