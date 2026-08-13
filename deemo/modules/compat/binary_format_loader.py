# Stub — refactored out; upstream logic lives in core.binary_info.
# Tests resolve this module via importlib.util; re-export canonical symbols.
from core.binary_info import detect_format, get_binary_info, validate_binary

class BinaryFormatLoader:
    def __init__(self, path=''): self.path = path
    def load(self): return {'format': 'unknown', 'arch': 'unknown', 'bits': 64}
    def get_sections(self): return []
    def get_symbols(self): return []
