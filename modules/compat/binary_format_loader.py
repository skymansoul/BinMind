from core.binary_info import detect_format, get_binary_info, validate_binary

class BinaryFormatLoader:
    def __init__(self, path=''): self.path = path
    def load(self): return {'format': 'unknown', 'arch': 'unknown', 'bits': 64}
    def get_sections(self): return []
    def get_symbols(self): return []
