from typing import Dict, List, Optional, Any, Tuple, Set
"""
Advanced Binary Analysis Features

Re-exports from split modules for backward compatibility.
All original class names and functionality are preserved.
"""

from .analysis_core import *
from .code_intelligence import *
from .binary_hashing import *
from .binary_formats import *
from .memory_heap import *
from .exploit_primitives import *
from .symbolic_analysis import *
from .ml_features import *
from .vuln_management import *
from .pipeline_infra import *
from .kernel_driver import *
from .testing_fuzzing import *

# Note: This module has been split into 12 focused submodules.
# See the individual files for the actual implementations:
#   analysis_core.py      - CFG, data flow, complexity, anti-analysis
#   code_intelligence.py   - Instruction analysis, code metrics, clustering
#   binary_hashing.py      - N-gram hashing, entropy, similarity, signatures
#   binary_formats.py      - ELF/PE/Mach-O parsing, firmware, SBOM
#   memory_heap.py         - Heap analysis, stack tracking, memory allocation
#   exploit_primitives.py  - ROP, shellcode, exploit DSL, format strings
#   symbolic_analysis.py   - Symbolic execution, abstract interpretation
#   ml_features.py         - ML/AI-based analysis features
#   vuln_management.py     - CVE tracking, knowledge graphs, compliance
#   pipeline_infra.py      - Task scheduling, CI/CD, distributed execution
#   kernel_driver.py       - Kernel modules, drivers, IOCTL analysis
#   testing_fuzzing.py     - Fuzzer integration, concurrency testing, protocols
