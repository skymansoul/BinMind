"""SGAV debug test."""
import sys
sys.path.insert(0, '.')
from analysis.sgav_pipeline import SGAVVerifier
from analysis.sgav_guard_extractor import GuardExtractor
from analysis.sgav_buffer_resolver import BufferResolver
from analysis.sgav_write_detector import WriteDetector

v = SGAVVerifier()

# Test 2: strcpy with guard -> should be SAFE
code2 = "#include <string.h>\nvoid safe_copy(const char *s) {\n    char buf[32];\n    if (strlen(s) < 32) {\n        strcpy(buf, s);\n    }\n}"
lines2 = code2.splitlines()
ge = GuardExtractor()
guards = ge.extract(lines2)
print("=== Guards for code2 ===")
for line, gs in sorted(guards.items()):
    if gs:
        print(f"  L{line}: {[(g.var, g.op, g.bound) for g in gs]}")

br = BufferResolver()
bufs = br.resolve(lines2)
print("=== Buffers ===")
for b in bufs:
    print(f"  {b.name}[{b.size}] kind={b.kind} aliases={b.aliases}")

wd = WriteDetector()
alias_map = {}
for b in bufs:
    alias_map[b.name] = b.name
    for a in b.aliases:
        alias_map[a] = b.name
writes = wd.detect(lines2, bufs, alias_map)
print("=== Writes ===")
for w in writes:
    print(f"  L{w.line}: {w.kind} target={w.target} resolved={w.resolved_buf} size={w.write_size} src={w.src_var}")

# Test 6: strncpy with sizeof
code6 = "#include <string.h>\nvoid safe(const char *s) {\n    char buf[32];\n    strncpy(buf, s, sizeof(buf) - 1);\n    buf[31] = 0;\n}"
lines6 = code6.splitlines()
bufs6 = br.resolve(lines6)
writes6 = wd.detect(lines6, bufs6, alias_map)
print("\n=== Test6 Writes ===")
for w in writes6:
    print(f"  L{w.line}: {w.kind} target={w.target} resolved={w.resolved_buf} size={w.write_size}")
