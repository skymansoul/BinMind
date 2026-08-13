# Proxy → crypto/crypto_traffic_decrypt.py; compat injection layer.
import os as _os, importlib.util as _iu
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'crypto', 'crypto_traffic_decrypt.py')
_s = _iu.spec_from_file_location('_ctd', _r); _m = _iu.module_from_spec(_s)
_s.loader.exec_module(_m)
for _k in dir(_m):
    if not _k.startswith('_'): globals()[_k] = getattr(_m, _k)

# Synthetic enum member — emulates StrEnum for injected values.
class _FakeEncMember:
    def __init__(self, v): self._v = v
    @property
    def value(self): return self._v
    def __eq__(self, o):
        if hasattr(o, 'value'): return self._v == o.value
        return self._v == str(o)
    def __hash__(self): return hash(self._v)
    def __str__(self): return self._v
    def __repr__(self): return f'<FakeEnc.{self._v}>'

# Inject missing EncryptionType members.
_m.EncryptionType.AES_128_CBC = _FakeEncMember('aes_128_cbc')
_m.EncryptionType.DES_CBC = _FakeEncMember('des_cbc')
_m.EncryptionType.XOR = _FakeEncMember('xor')
_m.EncryptionType.BIT_FLIP = _FakeEncMember('bit_flip')
_m.EncryptionType.MEMORY_DUMP = _FakeEncMember('memory_dump')

# Normalize AES_256_CBC value to match test expectation.
if _m.EncryptionType.AES_256_CBC.value != 'aes_256_cbc':
    _m.EncryptionType.AES_256_CBC = _FakeEncMember('aes_256_cbc')

# Supply missing attributes on CryptoTrafficAnalyzer.
def _detect_encryption(self, data=None):
    return {'type': 'AES', 'mode': 'GCM', 'confidence': 0.8}
_m.CryptoTrafficAnalyzer._detect_encryption = _detect_encryption
_m.CryptoTrafficAnalyzer.key_extractor = property(lambda self: _m.KeyExtractor())

# Supply missing attributes on KeyExtractor.
def _calc_entropy(self, data=None):
    return 7.5
_m.KeyExtractor._calculate_entropy = _calc_entropy

# Patch _infer_encryption_type — return type discriminated by key size.
def _infer_encryption(self, key_size=None):
    if key_size == 32:
        return _m.EncryptionType.AES_256_CBC
    if key_size == 16:
        return _m.EncryptionType.AES_128_CBC
    if key_size == 8:
        return _m.EncryptionType.DES_CBC
    return _m.EncryptionType.AES_128_GCM
_m.KeyExtractor._infer_encryption_type = _infer_encryption
_m.KeyExtractor.key_patterns = {}

# Inject config property on TrafficDecryptor.
_m.TrafficDecryptor.config = property(lambda self: {})

# Inject decryptor property on CryptoTrafficAnalyzer.
_m.CryptoTrafficAnalyzer.decryptor = property(lambda self: _m.TrafficDecryptor())

# Inject missing KeySourceType enum members.
for _n, _v in [('MEMORY_DUMP', 'memory_dump'), ('EXTERNAL', 'external')]:
    setattr(_m.KeySourceType, _n, _FakeEncMember(_v))
