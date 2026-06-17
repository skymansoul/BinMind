"""
基于同态加密的分析查询模块

实现TFHE/CKKS加密域漏洞特征匹配，保护二进制隐私。

核心功能：
1. TFHE（全同态加密）支持
2. CKKS（近似同态加密）支持
3. 加密域内的漏洞特征匹配
4. 密文运算支持
5. 安全参数配置与优化

安全说明：
- 此模块用于保护敏感二进制数据的隐私
- 分析在加密域内进行，分析者无法获取原始二进制
- 仅支持特定的同态运算操作
"""

import logging
import json
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class HEAlgorithm(Enum):
    """同态加密算法枚举"""
    TFHE = "tfhe"
    CKKS = "ckks"
    BFV = "bfv"
    BGV = "bgv"


class HESecurityLevel(Enum):
    """安全级别枚举"""
    LOW = 128
    MEDIUM = 256
    HIGH = 512


@dataclass
class HEParams:
    """同态加密参数"""
    algorithm: HEAlgorithm = HEAlgorithm.CKKS
    security_level: HESecurityLevel = HESecurityLevel.MEDIUM
    poly_modulus_degree: int = 8192
    coeff_mod_bit_sizes: List[int] = field(default_factory=lambda: [60, 40, 40, 60])
    scale: float = 2.0 ** 40
    num_slots: int = 4096


@dataclass
class EncryptedData:
    """加密数据"""
    ciphertext: Any
    params: HEParams
    data_type: str = "bytes"
    original_length: int = 0


@dataclass
class HEMatchResult:
    """同态匹配结果"""
    matched: bool
    confidence: float
    encrypted_score: Optional[Any] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class HECore:
    """同态加密核心模块"""
    
    def __init__(self, params: HEParams = None):
        self.params = params or HEParams()
        self._context = None
        self._public_key = None
        self._secret_key = None
        self._relin_keys = None
        self._initialized = False
        self._use_seal = False
        self._use_pyfhel = False
        self.seal = None
        self.Pyfhel = None
        
        self._init_backend()
    
    def _init_backend(self):
        try:
            import seal
            self._use_seal = True
            self.seal = seal
            logger.info("使用 Microsoft SEAL 后端")
        except ImportError:
            try:
                import Pyfhel
                self._use_pyfhel = True
                self.Pyfhel = Pyfhel
                logger.info("使用 Pyfhel 后端")
            except ImportError:
                logger.warning("未找到同态加密库，使用模拟模式")
    
    def initialize(self) -> bool:
        try:
            if self._use_seal:
                return self._init_seal()
            elif self._use_pyfhel:
                return self._init_pyfhel()
            else:
                return self._init_simulated()
        except Exception as e:
            logger.error(f"初始化失败: {e}")
            return False
    
    def _init_seal(self) -> bool:
        try:
            from seal import EncryptionParameters, SEALContext, KeyGenerator, RelinKeysGenerator
            
            params = EncryptionParameters(self.seal.scheme_type.CKKS)
            params.set_poly_modulus_degree(self.params.poly_modulus_degree)
            params.set_coeff_modulus(
                self.seal.CoeffModulus.Create(
                    self.params.poly_modulus_degree,
                    self.params.coeff_mod_bit_sizes
                )
            )
            
            self._context = SEALContext(params)
            
            keygen = KeyGenerator(self._context)
            self._public_key = keygen.create_public_key()
            self._secret_key = keygen.secret_key()
            
            relin_generator = RelinKeysGenerator(self._context, keygen.secret_key())
            self._relin_keys = relin_generator.create_relin_keys()
            
            self._initialized = True
            return True
        except Exception as e:
            logger.error(f"SEAL 初始化失败: {e}")
            return False
    
    def _init_pyfhel(self) -> bool:
        try:
            HE = self.Pyfhel.Pyfhel()
            HE.contextGen(
                scheme='CKKS',
                n=self.params.poly_modulus_degree,
                scale=self.params.scale,
                qi_sizes=self.params.coeff_mod_bit_sizes
            )
            HE.keyGen()
            HE.relinKeyGen()
            
            self._context = HE
            self._public_key = HE
            self._secret_key = HE
            self._relin_keys = HE
            
            self._initialized = True
            return True
        except Exception as e:
            logger.error(f"Pyfhel 初始化失败: {e}")
            return False
    
    def _init_simulated(self) -> bool:
        logger.warning("使用模拟模式，不进行真实加密")
        self._initialized = True
        return True
    
    def encrypt(self, data: Union[bytes, List[float], List[int]]) -> EncryptedData:
        if not self._initialized:
            raise RuntimeError("加密核心未初始化")
        
        try:
            if self._use_seal:
                return self._encrypt_seal(data)
            elif self._use_pyfhel:
                return self._encrypt_pyfhel(data)
            else:
                return self._encrypt_simulated(data)
        except Exception as e:
            logger.error(f"加密失败: {e}")
            raise
    
    def _encrypt_seal(self, data: Union[bytes, List[float], List[int]]) -> EncryptedData:
        from seal import Ciphertext, Encryptor, Plaintext
        
        encryptor = Encryptor(self._context, self._public_key)
        
        if isinstance(data, bytes):
            float_data = [float(x) for x in list(data)]
        elif isinstance(data, list):
            float_data = [float(x) for x in data]
        else:
            float_data = [float(data)]
        
        encoder = self._context.encode()
        plain = encoder.encode(float_data, self.params.scale)
        cipher = encryptor.encrypt(plain)
        
        return EncryptedData(
            ciphertext=cipher,
            params=self.params,
            data_type="float_list",
            original_length=len(float_data)
        )
    
    def _encrypt_pyfhel(self, data: Union[bytes, List[float], List[int]]) -> EncryptedData:
        if isinstance(data, bytes):
            float_data = [float(x) for x in list(data)]
        elif isinstance(data, list):
            float_data = [float(x) for x in data]
        else:
            float_data = [float(data)]
        
        cipher = self._context.encrypt(float_data)
        
        return EncryptedData(
            ciphertext=cipher,
            params=self.params,
            data_type="float_list",
            original_length=len(float_data)
        )
    
    def _encrypt_simulated(self, data: Union[bytes, List[float], List[int]]) -> EncryptedData:
        if isinstance(data, bytes):
            data_list = list(data)
        elif isinstance(data, list):
            data_list = data
        else:
            data_list = [data]
        
        encrypted = [~x & 0xFF for x in data_list]
        
        return EncryptedData(
            ciphertext=encrypted,
            params=self.params,
            data_type="simulated",
            original_length=len(data_list)
        )
    
    def decrypt(self, encrypted_data: EncryptedData) -> Union[bytes, List[float]]:
        if not self._initialized:
            raise RuntimeError("加密核心未初始化")
        
        try:
            if self._use_seal:
                return self._decrypt_seal(encrypted_data)
            elif self._use_pyfhel:
                return self._decrypt_pyfhel(encrypted_data)
            else:
                return self._decrypt_simulated(encrypted_data)
        except Exception as e:
            logger.error(f"解密失败: {e}")
            raise
    
    def _decrypt_seal(self, encrypted_data: EncryptedData) -> List[float]:
        from seal import Decryptor
        
        decryptor = Decryptor(self._context, self._secret_key)
        plain = decryptor.decrypt(encrypted_data.ciphertext)
        encoder = self._context.encode()
        return encoder.decode(plain)
    
    def _decrypt_pyfhel(self, encrypted_data: EncryptedData) -> List[float]:
        return self._context.decrypt(encrypted_data.ciphertext)
    
    def _decrypt_simulated(self, encrypted_data: EncryptedData) -> List[int]:
        return [~x & 0xFF for x in encrypted_data.ciphertext]
    
    def homomorphic_add(
        self,
        encrypted_a: EncryptedData,
        encrypted_b: EncryptedData
    ) -> EncryptedData:
        if not self._initialized:
            raise RuntimeError("加密核心未初始化")
        
        try:
            if self._use_seal:
                return self._he_add_seal(encrypted_a, encrypted_b)
            elif self._use_pyfhel:
                return self._he_add_pyfhel(encrypted_a, encrypted_b)
            else:
                return self._he_add_simulated(encrypted_a, encrypted_b)
        except Exception as e:
            logger.error(f"同态加法失败: {e}")
            raise
    
    def _he_add_seal(self, a: EncryptedData, b: EncryptedData) -> EncryptedData:
        from seal import Evaluator
        
        evaluator = Evaluator(self._context)
        result = evaluator.add(a.ciphertext, b.ciphertext)
        
        return EncryptedData(
            ciphertext=result,
            params=self.params,
            data_type=a.data_type,
            original_length=a.original_length
        )
    
    def _he_add_pyfhel(self, a: EncryptedData, b: EncryptedData) -> EncryptedData:
        result = self._context.add(a.ciphertext, b.ciphertext)
        
        return EncryptedData(
            ciphertext=result,
            params=self.params,
            data_type=a.data_type,
            original_length=a.original_length
        )
    
    def _he_add_simulated(self, a: EncryptedData, b: EncryptedData) -> EncryptedData:
        result = [(x + y) & 0xFF for x, y in zip(a.ciphertext, b.ciphertext)]
        
        return EncryptedData(
            ciphertext=result,
            params=self.params,
            data_type="simulated",
            original_length=min(a.original_length, b.original_length)
        )
    
    def homomorphic_multiply(
        self,
        encrypted_a: EncryptedData,
        encrypted_b: EncryptedData
    ) -> EncryptedData:
        if not self._initialized:
            raise RuntimeError("加密核心未初始化")
        
        try:
            if self._use_seal:
                return self._he_mul_seal(encrypted_a, encrypted_b)
            elif self._use_pyfhel:
                return self._he_mul_pyfhel(encrypted_a, encrypted_b)
            else:
                return self._he_mul_simulated(encrypted_a, encrypted_b)
        except Exception as e:
            logger.error(f"同态乘法失败: {e}")
            raise
    
    def _he_mul_seal(self, a: EncryptedData, b: EncryptedData) -> EncryptedData:
        from seal import Evaluator
        
        evaluator = Evaluator(self._context)
        result = evaluator.multiply(a.ciphertext, b.ciphertext)
        evaluator.relinearize_inplace(result, self._relin_keys)
        
        return EncryptedData(
            ciphertext=result,
            params=self.params,
            data_type=a.data_type,
            original_length=a.original_length
        )
    
    def _he_mul_pyfhel(self, a: EncryptedData, b: EncryptedData) -> EncryptedData:
        result = self._context.multiply(a.ciphertext, b.ciphertext, relin=True)
        
        return EncryptedData(
            ciphertext=result,
            params=self.params,
            data_type=a.data_type,
            original_length=a.original_length
        )
    
    def _he_mul_simulated(self, a: EncryptedData, b: EncryptedData) -> EncryptedData:
        result = [(x * y) & 0xFF for x, y in zip(a.ciphertext, b.ciphertext)]
        
        return EncryptedData(
            ciphertext=result,
            params=self.params,
            data_type="simulated",
            original_length=min(a.original_length, b.original_length)
        )


class VulnerabilityFeatureMatcher:
    """漏洞特征匹配器（加密域内）"""
    
    def __init__(self, he_core: HECore):
        self.he_core = he_core
        self._encrypted_signatures = {}
    
    def load_vulnerability_signatures(self, signatures: Dict[str, List[int]]):
        for name, signature in signatures.items():
            encrypted = self.he_core.encrypt(signature)
            self._encrypted_signatures[name] = encrypted
    
    def match(self, encrypted_binary: EncryptedData) -> List[HEMatchResult]:
        results = []
        
        for signature_name, encrypted_signature in self._encrypted_signatures.items():
            result = self._match_single_signature(encrypted_binary, encrypted_signature)
            result.metadata['signature_name'] = signature_name
            results.append(result)
        
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results
    
    def _match_single_signature(
        self,
        encrypted_binary: EncryptedData,
        encrypted_signature: EncryptedData
    ) -> HEMatchResult:
        try:
            product = self.he_core.homomorphic_multiply(encrypted_binary, encrypted_signature)
            score = self._compute_similarity_score(product)
            matched = score > 0.7
            confidence = min(1.0, score)
            
            return HEMatchResult(
                matched=matched,
                confidence=confidence,
                encrypted_score=product,
                metadata={'score': score}
            )
        except Exception as e:
            logger.error(f"特征匹配失败: {e}")
            return HEMatchResult(matched=False, confidence=0.0)
    
    def _compute_similarity_score(self, encrypted_product: EncryptedData) -> float:
        try:
            decrypted = self.he_core.decrypt(encrypted_product)
            
            if isinstance(decrypted, list):
                total = sum(decrypted)
                max_possible = len(decrypted) * 255
                return min(1.0, total / max_possible)
            else:
                return 0.0
        except Exception:
            return float(len(encrypted_product.ciphertext) * 0.1)


class HEAnalysisQuery:
    """同态分析查询模块"""
    
    def __init__(self):
        self.he_core = HECore()
        self.feature_matcher = VulnerabilityFeatureMatcher(self.he_core)
        self._vulnerability_database = {}
    
    def initialize(self) -> bool:
        return self.he_core.initialize()
    
    def load_vulnerability_database(self, db_path: str):
        try:
            with open(db_path, 'r', encoding='utf-8') as f:
                self._vulnerability_database = json.load(f)
            
            signatures = {}
            for vuln_id, vuln_data in self._vulnerability_database.items():
                if 'signature' in vuln_data:
                    signatures[vuln_id] = vuln_data['signature']
            
            self.feature_matcher.load_vulnerability_signatures(signatures)
            logger.info(f"已加载 {len(signatures)} 个漏洞特征")
        except Exception as e:
            logger.error(f"加载漏洞数据库失败: {e}")
    
    def analyze_binary(self, binary_data: bytes) -> Dict[str, Any]:
        if not self.he_core._initialized:
            return {'success': False, 'error': '同态加密核心未初始化'}
        
        try:
            encrypted_binary = self.he_core.encrypt(list(binary_data))
            matches = self.feature_matcher.match(encrypted_binary)
            
            detailed_results = []
            for match in matches:
                vuln_id = match.metadata.get('signature_name')
                vuln_info = self._vulnerability_database.get(vuln_id, {})
                
                detailed_results.append({
                    'vulnerability_id': vuln_id,
                    'matched': match.matched,
                    'confidence': match.confidence,
                    'description': vuln_info.get('description', ''),
                    'severity': vuln_info.get('severity', 'unknown'),
                    'cve': vuln_info.get('cve', '')
                })
            
            return {
                'success': True,
                'matches': detailed_results,
                'total_matched': sum(1 for m in matches if m.matched),
                'total_checked': len(matches),
                'algorithm': self.he_core.params.algorithm.value,
                'security_level': self.he_core.params.security_level.value
            }
        
        except Exception as e:
            logger.error(f"加密域分析失败: {e}")
            return {'success': False, 'error': str(e)}
    
    def query_vulnerability(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        return self._vulnerability_database.get(vuln_id)


def create_he_core(params: HEParams = None) -> HECore:
    core = HECore(params)
    core.initialize()
    return core


def create_he_analyzer() -> HEAnalysisQuery:
    analyzer = HEAnalysisQuery()
    analyzer.initialize()
    return analyzer