"""
BinMind Crypto Analysis Module
-------------------------------
Static and dynamic cryptographic analysis for binary artifacts.
Covers: algorithm detection, misuse scanning, traffic analysis,
         hardware hashing, PQC detection, steganography, signature verification,
         certificate analysis, entropy profiling, JWT auditing.

v0.5.0 — lazy-import architecture via src.__getattr__.
"""

__version__ = "0.5.0"
name = "crypto"

from . import src


def __getattr__(name):
    if hasattr(src, '__getattr__'):
        return src.__getattr__(name)
    raise AttributeError("module 'crypto' has no attribute '{}'".format(name))


__all__ = ["__version__", "name"]
