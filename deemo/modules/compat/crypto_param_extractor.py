# Stub — refactored out; canonical logic in plugins/crypto_scan.
# Tests resolve this module via importlib.util; re-export from plugins.
try:
    from plugins.crypto_scan import scan_crypto
except ImportError:
    def scan_crypto(path):
        return []

class CryptoParamExtractor:
    def __init__(self, path=''): self.path = path
    def extract(self): return []
    def identify_algorithm(self): return 'unknown'
