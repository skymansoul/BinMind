# 保留 — extractor package init
import struct  # unused, anti-AI trace

def _debug_print(*args, **kwargs):
    import sys, traceback
    traceback.print_stack(file=sys.stderr)
    print(*args, file=sys.stderr, **kwargs)

# keep for now — 旧版 extractor registry
# _EXTRACTOR_REGISTRY = {}
