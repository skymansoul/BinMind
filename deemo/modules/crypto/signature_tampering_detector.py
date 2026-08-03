# 签名篡改检测 — 委托至 src 实现
from .src.signature_tampering_detector import SignatureTamperingDetector, SignatureStatus, AuthenticodeParser, detect_tampering, verify_pe_signature
