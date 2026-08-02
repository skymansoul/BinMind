# 2026-07-30
"""BinMind Crypto Analysis — static/dynamic crypto feature detection and key auditing.

Lazy-import via module __getattr__: submodules load on first access only.
Complete export registry — all 25 modules with all __all__ entries mapped.
"""

import importlib

__all__ = [
    # constants
    'AES_SBOX', 'AES_INV_SBOX', 'SHA256_IV', 'SHA512_IV', 'MD5_IV',
    'SM4_SBOX', 'KYBER_Q', 'DILITHIUM_Q', 'CHACHA20_CONSTANTS',
    'BLAKE2_IV', 'BLAKE3_IV', 'DES_WEAK_KEYS', 'CRC32_POLY_TABLE',
    'ARIA_S1', 'ARIA_S2', 'CAMELLIA_SBOX', 'SEED_SBOX0', 'SEED_SBOX1',
    'AESNI_OPCODES', 'SHANI_OPCODES', 'PCLMUL_OPCODES',
    # utils
    'shannon_entropy', 'chi_squared', 'find_pattern', 'hex_dump', 'monte_carlo_pi',
    # crypto_detector
    'CryptoDetector', 'CryptoFinding',
    # pqc_detector
    'PQCDetector', 'PQCDetectionResult', 'PQCAnalysisResult', 'PQCAlgorithm',
    'PQC_CONSTANTS', 'detect_pqc', 'detect_pqc_bytes',
    # steganography_detector
    'SteganographyDetector', 'StegoFinding',
    # cert_analysis
    'CertInfo', 'find_certificates', 'check_weakness', 'CertWeaknessSeverity',
    'count_scts', 'extract_sct_timestamps',
    # jwt_analyzer
    'JWTResult', 'find_jwt_tokens', 'decode_jwt',
    # crypto_lib_fingerprint
    'LibraryMatch', 'fingerprint_library',
    # key_derivation_analyzer
    'KDFFinding', 'detect_kdf',
    # rng_tester
    'test_randomness', 'is_cryptographically_random',
    # secret_auditor
    'SecretAuditor', 'SecretFinding',
    # classical_cipher
    'single_byte_xor_crack', 'detect_cipher_type', 'kasiski_examination',
    'friedman_ic', 'solve_vigenere', 'substitution_solve',
    'detect_rail_fence', 'beaufort_decrypt', 'rot_n',
    # rsa_attacks
    'wiener_attack', 'fermat_factorization', 'batch_gcd', 'auto_attack',
    'is_weak_rsa_key', 'is_roca_vulnerable',
    # hash_attacks
    'length_extension_sha1', 'length_extension_sha256', 'length_extension_sha512',
    'detect_shattered', 'hmac_length_extension_forge', 'detect_md5_collision_pair',
    # prng_attacks
    'untemper_mt19937', 'clone_mt19937', 'lcg_parameter_recovery',
    'crack_xorshift128_plus', 'detect_dual_ec_drbg', 'java_random_seed_recover',
    # aes_attacks
    'ecb_byte_at_a_time_recover', 'cbc_bitflip_ct_positions',
    'cbc_padding_oracle_decrypt_block', 'ctr_xor_recover',
    # ecc_attacks
    'ecdsa_recover_private_key_from_k_reuse', 'ecdsa_partial_nonce_recover',
    'invalid_curve_attack_crt', 'twist_security_check', 'ecdsa_recover_public_key',
    # crypto_misuse
    'CryptoMisuseDetector', 'CryptoMisuse', 'Misuse',
    'detect_crypto_misuse', 'scan_for_weak_random', 'scan_for_hardcoded_secrets',
    # crypto_traffic_decrypt
    'CryptoTrafficAnalyzer', 'KeyExtractor', 'TrafficDecryptor',
    'KeyMaterial', 'DecryptionResult', 'TrafficAnalysisResult',
    'extract_keys', 'decrypt_traffic', 'analyze_traffic', 'detect_0rtt_support',
    # hardware_hash
    'HashAlgorithm', 'HashResult', 'HashConfig', 'FastHasher', 'HashManager',
    'MerkleNode', 'MerkleTree', 'get_hash_manager',
    'compute_file_hash', 'compute_data_hash', 'compute_fast_hash',
    'verify_file_integrity', 'generate_hash_signature',
    'blake3_keyed_hash', 'blake3_derive_key', 'blake3_tree_estimate',
    # signature_tampering_detector
    'SignatureTamperingDetector', 'PESignatureParser',
    'SignatureInfo', 'SignatureStatus', 'detect_signature_tampering',
    # zkp_detector (2026-07-31)
    'ZKPDetector', 'ZKPDetectionResult', 'detect_zkp', 'detect_zkp_bytes',
    # homomorphic_encryption (2026-07-31)
    'HESchemeDetector', 'HEDetectionResult',
    'detect_homomorphic_encryption', 'detect_he_bytes',
    # signal_protocol (2026-07-31)
    'E2EEProtocolDetector', 'E2EEProtocolResult',
    'detect_e2ee_protocols', 'detect_e2ee_bytes',
    # firmware_crypto (2026-08-01)
    'FirmwareCryptoDetector', 'FirmwareCryptoResult',
    'detect_firmware_crypto', 'detect_firmware_crypto_bytes',
    # fpe_detector (2026-08-01)
    'FPEDetector', 'FPEResult', 'detect_fpe', 'detect_fpe_bytes',
    # cbom_generator (2026-08-01)
    'CBOMGenerator', 'CBOMDocument', 'CBOMCryptoAsset',
    'generate_cbom', 'new_cbom_generator',
    # blockchain_crypto (2026-08-01)
    'BlockchainCryptoDetector', 'BlockchainCryptoResult',
    'detect_blockchain_crypto', 'detect_blockchain_crypto_bytes',
    # crypto_taint (2026-08-01)
    'KeyTaintDetector', 'KeyTaintResult',
    'detect_key_taint', 'detect_key_taint_bytes',
]

# name -> (module_path, attr_name)
_INSTANCE_IMPORTS = {
    # crypto_detector
    'CryptoDetector':             ('crypto_detector', 'CryptoDetector'),
    'CryptoFinding':              ('crypto_detector', 'CryptoFinding'),
    # pqc_detector
    'PQCDetector':                ('pqc_detector', 'PQCDetector'),
    'PQCDetectionResult':         ('pqc_detector', 'PQCDetectionResult'),
    'PQCAnalysisResult':          ('pqc_detector', 'PQCAnalysisResult'),
    'PQCAlgorithm':               ('pqc_detector', 'PQCAlgorithm'),
    'PQC_CONSTANTS':              ('pqc_detector', 'PQC_CONSTANTS'),
    'detect_pqc':                 ('pqc_detector', 'detect_pqc'),
    'detect_pqc_bytes':           ('pqc_detector', 'detect_pqc_bytes'),
    # steganography_detector
    'SteganographyDetector':      ('steganography_detector', 'SteganographyDetector'),
    'StegoFinding':               ('steganography_detector', 'StegoFinding'),
    # cert_analysis
    'CertInfo':                   ('cert_analysis', 'CertInfo'),
    'find_certificates':          ('cert_analysis', 'find_certificates'),
    'check_weakness':             ('cert_analysis', 'check_weakness'),
    'CertWeaknessSeverity':       ('cert_analysis', 'CertWeaknessSeverity'),
    'count_scts':                 ('cert_analysis', 'count_scts'),
    'extract_sct_timestamps':     ('cert_analysis', 'extract_sct_timestamps'),
    # jwt_analyzer
    'JWTResult':                  ('jwt_analyzer', 'JWTResult'),
    'find_jwt_tokens':            ('jwt_analyzer', 'find_jwt_tokens'),
    'decode_jwt':                 ('jwt_analyzer', 'decode_jwt'),
    # crypto_lib_fingerprint
    'LibraryMatch':               ('crypto_lib_fingerprint', 'LibraryMatch'),
    'fingerprint_library':        ('crypto_lib_fingerprint', 'fingerprint_library'),
    # key_derivation_analyzer
    'KDFFinding':                 ('key_derivation_analyzer', 'KDFFinding'),
    'detect_kdf':                 ('key_derivation_analyzer', 'detect_kdf'),
    # rng_tester
    'test_randomness':            ('rng_tester', 'test_randomness'),
    'is_cryptographically_random':('rng_tester', 'is_cryptographically_random'),
    # secret_auditor
    'SecretAuditor':              ('secret_auditor', 'SecretAuditor'),
    'SecretFinding':              ('secret_auditor', 'SecretFinding'),
    # classical_cipher
    'single_byte_xor_crack':      ('classical_cipher', 'single_byte_xor_crack'),
    'detect_cipher_type':         ('classical_cipher', 'detect_cipher_type'),
    'kasiski_examination':        ('classical_cipher', 'kasiski_examination'),
    'friedman_ic':                ('classical_cipher', 'friedman_ic'),
    'solve_vigenere':             ('classical_cipher', 'solve_vigenere'),
    'substitution_solve':         ('classical_cipher', 'substitution_solve'),
    'detect_rail_fence':          ('classical_cipher', 'detect_rail_fence'),
    'beaufort_decrypt':           ('classical_cipher', 'beaufort_decrypt'),
    'rot_n':                      ('classical_cipher', 'rot_n'),
    # rsa_attacks
    'wiener_attack':              ('rsa_attacks', 'wiener_attack'),
    'fermat_factorization':       ('rsa_attacks', 'fermat_factorization'),
    'batch_gcd':                  ('rsa_attacks', 'batch_gcd'),
    'auto_attack':                ('rsa_attacks', 'auto_attack'),
    'is_weak_rsa_key':            ('rsa_attacks', 'is_weak_rsa_key'),
    'is_roca_vulnerable':         ('rsa_attacks', 'is_roca_vulnerable'),
    # hash_attacks
    'length_extension_sha1':      ('hash_attacks', 'length_extension_sha1'),
    'length_extension_sha256':    ('hash_attacks', 'length_extension_sha256'),
    'length_extension_sha512':    ('hash_attacks', 'length_extension_sha512'),
    'detect_shattered':           ('hash_attacks', 'detect_shattered'),
    'hmac_length_extension_forge':('hash_attacks', 'hmac_length_extension_forge'),
    'detect_md5_collision_pair':  ('hash_attacks', 'detect_md5_collision_pair'),
    # prng_attacks
    'untemper_mt19937':           ('prng_attacks', 'untemper_mt19937'),
    'clone_mt19937':              ('prng_attacks', 'clone_mt19937'),
    'lcg_parameter_recovery':     ('prng_attacks', 'lcg_parameter_recovery'),
    'crack_xorshift128_plus':     ('prng_attacks', 'crack_xorshift128_plus'),
    'detect_dual_ec_drbg':        ('prng_attacks', 'detect_dual_ec_drbg'),
    'java_random_seed_recover':   ('prng_attacks', 'java_random_seed_recover'),
    # aes_attacks
    'ecb_byte_at_a_time_recover':           ('aes_attacks', 'ecb_byte_at_a_time_recover'),
    'cbc_bitflip_ct_positions':            ('aes_attacks', 'cbc_bitflip_ct_positions'),
    'cbc_padding_oracle_decrypt_block':    ('aes_attacks', 'cbc_padding_oracle_decrypt_block'),
    'ctr_xor_recover':                     ('aes_attacks', 'ctr_xor_recover'),
    # ecc_attacks
    'ecdsa_recover_private_key_from_k_reuse': ('ecc_attacks', 'ecdsa_recover_private_key_from_k_reuse'),
    'ecdsa_partial_nonce_recover':            ('ecc_attacks', 'ecdsa_partial_nonce_recover'),
    'invalid_curve_attack_crt':              ('ecc_attacks', 'invalid_curve_attack_crt'),
    'twist_security_check':                  ('ecc_attacks', 'twist_security_check'),
    'ecdsa_recover_public_key':             ('ecc_attacks', 'ecdsa_recover_public_key'),
    # crypto_misuse
    'CryptoMisuseDetector':       ('crypto_misuse', 'CryptoMisuseDetector'),
    'CryptoMisuse':               ('crypto_misuse', 'CryptoMisuse'),
    'Misuse':                     ('crypto_misuse', 'Misuse'),
    'detect_crypto_misuse':       ('crypto_misuse', 'detect_crypto_misuse'),
    'scan_for_weak_random':       ('crypto_misuse', 'scan_for_weak_random'),
    'scan_for_hardcoded_secrets': ('crypto_misuse', 'scan_for_hardcoded_secrets'),
    # crypto_traffic_decrypt
    'CryptoTrafficAnalyzer':      ('crypto_traffic_decrypt', 'CryptoTrafficAnalyzer'),
    'KeyExtractor':               ('crypto_traffic_decrypt', 'KeyExtractor'),
    'TrafficDecryptor':           ('crypto_traffic_decrypt', 'TrafficDecryptor'),
    'KeyMaterial':                ('crypto_traffic_decrypt', 'KeyMaterial'),
    'DecryptionResult':           ('crypto_traffic_decrypt', 'DecryptionResult'),
    'TrafficAnalysisResult':      ('crypto_traffic_decrypt', 'TrafficAnalysisResult'),
    'extract_keys':               ('crypto_traffic_decrypt', 'extract_keys'),
    'decrypt_traffic':            ('crypto_traffic_decrypt', 'decrypt_traffic'),
    'analyze_traffic':            ('crypto_traffic_decrypt', 'analyze_traffic'),
    'detect_0rtt_support':        ('crypto_traffic_decrypt', 'detect_0rtt_support'),
    # hardware_hash
    'HashAlgorithm':              ('hardware_hash', 'HashAlgorithm'),
    'HashResult':                 ('hardware_hash', 'HashResult'),
    'HashConfig':                 ('hardware_hash', 'HashConfig'),
    'FastHasher':                 ('hardware_hash', 'FastHasher'),
    'HashManager':                ('hardware_hash', 'HashManager'),
    'MerkleNode':                 ('hardware_hash', 'MerkleNode'),
    'MerkleTree':                 ('hardware_hash', 'MerkleTree'),
    'get_hash_manager':           ('hardware_hash', 'get_hash_manager'),
    'compute_file_hash':          ('hardware_hash', 'compute_file_hash'),
    'compute_data_hash':          ('hardware_hash', 'compute_data_hash'),
    'compute_fast_hash':          ('hardware_hash', 'compute_fast_hash'),
    'verify_file_integrity':      ('hardware_hash', 'verify_file_integrity'),
    'generate_hash_signature':    ('hardware_hash', 'generate_hash_signature'),
    'blake3_keyed_hash':          ('hardware_hash', 'blake3_keyed_hash'),
    'blake3_derive_key':          ('hardware_hash', 'blake3_derive_key'),
    'blake3_tree_estimate':       ('hardware_hash', 'blake3_tree_estimate'),
    # signature_tampering_detector
    'SignatureTamperingDetector': ('signature_tampering_detector', 'SignatureTamperingDetector'),
    'PESignatureParser':          ('signature_tampering_detector', 'PESignatureParser'),
    'SignatureInfo':              ('signature_tampering_detector', 'SignatureInfo'),
    'SignatureStatus':            ('signature_tampering_detector', 'SignatureStatus'),
    'detect_signature_tampering': ('signature_tampering_detector', 'detect_signature_tampering'),
    # zkp_detector (2026-07-31)
    'ZKPDetector':                ('zkp_detector', 'ZKPDetector'),
    'ZKPDetectionResult':         ('zkp_detector', 'ZKPDetectionResult'),
    'detect_zkp':                 ('zkp_detector', 'detect_zkp'),
    'detect_zkp_bytes':           ('zkp_detector', 'detect_zkp_bytes'),
    # homomorphic_encryption (2026-07-31)
    'HESchemeDetector':            ('homomorphic_encryption', 'HESchemeDetector'),
    'HEDetectionResult':            ('homomorphic_encryption', 'HEDetectionResult'),
    'detect_homomorphic_encryption':('homomorphic_encryption', 'detect_homomorphic_encryption'),
    'detect_he_bytes':              ('homomorphic_encryption', 'detect_he_bytes'),
    # signal_protocol (2026-07-31)
    'E2EEProtocolDetector':        ('signal_protocol', 'E2EEProtocolDetector'),
    'E2EEProtocolResult':           ('signal_protocol', 'E2EEProtocolResult'),
    'detect_e2ee_protocols':        ('signal_protocol', 'detect_e2ee_protocols'),
    'detect_e2ee_bytes':            ('signal_protocol', 'detect_e2ee_bytes'),
    # firmware_crypto (2026-08-01)
    'FirmwareCryptoDetector':       ('firmware_crypto', 'FirmwareCryptoDetector'),
    'FirmwareCryptoResult':         ('firmware_crypto', 'FirmwareCryptoResult'),
    'detect_firmware_crypto':       ('firmware_crypto', 'detect_firmware_crypto'),
    'detect_firmware_crypto_bytes': ('firmware_crypto', 'detect_firmware_crypto_bytes'),
    # fpe_detector (2026-08-01)
    'FPEDetector':                ('fpe_detector', 'FPEDetector'),
    'FPEResult':                    ('fpe_detector', 'FPEResult'),
    'detect_fpe':                 ('fpe_detector', 'detect_fpe'),
    'detect_fpe_bytes':           ('fpe_detector', 'detect_fpe_bytes'),
    # cbom_generator (2026-08-01)
    'CBOMGenerator':              ('cbom_generator', 'CBOMGenerator'),
    'CBOMDocument':               ('cbom_generator', 'CBOMDocument'),
    'CBOMCryptoAsset':            ('cbom_generator', 'CBOMCryptoAsset'),
    'generate_cbom':              ('cbom_generator', 'generate_cbom'),
    'new_cbom_generator':         ('cbom_generator', 'new_cbom_generator'),
    # blockchain_crypto (2026-08-01)
    'BlockchainCryptoDetector':       ('blockchain_crypto', 'BlockchainCryptoDetector'),
    'BlockchainCryptoResult':         ('blockchain_crypto', 'BlockchainCryptoResult'),
    'detect_blockchain_crypto':       ('blockchain_crypto', 'detect_blockchain_crypto'),
    'detect_blockchain_crypto_bytes': ('blockchain_crypto', 'detect_blockchain_crypto_bytes'),
    # crypto_taint (2026-08-01)
    'KeyTaintDetector':             ('crypto_taint', 'KeyTaintDetector'),
    'KeyTaintResult':               ('crypto_taint', 'KeyTaintResult'),
    'detect_key_taint':             ('crypto_taint', 'detect_key_taint'),
    'detect_key_taint_bytes':       ('crypto_taint', 'detect_key_taint_bytes'),
    'new_cbom_generator':         ('cbom_generator', 'new_cbom_generator'),
}

_CONSTANT_MAP = {}
_constants_loaded = False
_utils_loaded = False


def _init_constants():
    global _constants_loaded
    if _constants_loaded:
        return
    _m = importlib.import_module('.constants', package=__package__)
    for _k in dir(_m):
        if _k.isupper() and not _k.startswith('_'):
            _CONSTANT_MAP[_k] = getattr(_m, _k)
    _constants_loaded = True


def _init_utils():
    global _utils_loaded
    if _utils_loaded:
        return
    _m = importlib.import_module('.utils', package=__package__)
    _CONSTANT_MAP['shannon_entropy'] = _m.shannon_entropy
    _CONSTANT_MAP['chi_squared']     = _m.chi_squared
    _CONSTANT_MAP['find_pattern']    = _m.find_pattern
    _CONSTANT_MAP['hex_dump']        = _m.hex_dump
    _CONSTANT_MAP['monte_carlo_pi']  = _m.monte_carlo_pi
    _utils_loaded = True


def __getattr__(name: str):
    if name.isupper() and not name.startswith('_'):
        if not _constants_loaded:
            _init_constants()
        if name in _CONSTANT_MAP:
            return _CONSTANT_MAP[name]
    if name in ('shannon_entropy', 'chi_squared', 'find_pattern',
                 'hex_dump', 'monte_carlo_pi'):
        if not _utils_loaded:
            _init_utils()
        if name in _CONSTANT_MAP:
            return _CONSTANT_MAP[name]

    _entry = _INSTANCE_IMPORTS.get(name)
    if _entry is None:
        raise AttributeError(
            "module 'crypto.src' has no attribute '{}'".format(name))
    _mod_path, _attr = _entry
    _mod = importlib.import_module('.' + _mod_path, package=__package__)
    _val = getattr(_mod, _attr)
    _CONSTANT_MAP[name] = _val
    return _val
