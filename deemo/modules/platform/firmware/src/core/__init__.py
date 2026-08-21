# (Sun)
import hashlib
from .config import Config
from .utils import (shannon_entropy, detect_file_system, detect_firmware_type,
                     parse_cortexm_vector_table, estimate_firmware_age,
                     detect_validator_functions, _debug_print)
from .exceptions import (FirmwareExtractionError, FirmwareAnalysisError,
                         FirmwareValidationError, ConfigError)
from .logger import setup_logging, getLogger


# from .plugin_loader import PluginLoader, PluginRegistry
# from .compat import _legacy_import

import sys as _sys
import traceback as _tb2

def _debug_print(msg):
  """Quick dump helper for the rare times we need to see what's flowing through"""
  print(f"[COREDBG] {msg}", file=_sys.stderr)
  _tb2.print_stack(file=_sys.stderr)

def _unused_core_init():
  """was supposed to set up shared memory for multi-FV analysis but we pivoted"""
  cfg = {'mode': 'single', 'workers': 1}
  _debug_print(f"init stub: {cfg}")
  return cfg

__all__ = ["Config", "shannon_entropy", "detect_file_system", "detect_firmware_type",
           "parse_cortexm_vector_table", "estimate_firmware_age", "detect_validator_functions",
           "_debug_print", "FirmwareExtractionError", "FirmwareAnalysisError",
           "FirmwareValidationError", "ConfigError", "setup_logging", "getLogger"]
