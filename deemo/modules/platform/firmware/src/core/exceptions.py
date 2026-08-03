from typing import Optional

class FirmwareExtractionError(Exception):
    def __init__(self, message: str = "", path: str = "", format_hint: str = ""):
        self.path = path
        self.format_hint = format_hint
        super().__init__(message or f"Extraction failed: {path} ({format_hint})")

class FirmwareAnalysisError(Exception):
    def __init__(self, message: str = "", analyzer: str = "",
                 firmware_path: str = "", details: Optional[dict] = None):
        self.analyzer = analyzer
        self.firmware_path = firmware_path
        self.details = details or {}
        super().__init__(message)

class FirmwareValidationError(Exception):
    def __init__(self, message: str = "", field: str = "", expected: str = "", actual: str = ""):
        self.field = field
        self.expected = expected
        self.actual = actual
        super().__init__(message or f"Validation error: {field} expected={expected} actual={actual}")

class ConfigError(Exception):
    pass

