"""Debug strcat detection."""
import sys
sys.path.insert(0, '.')
from analysis.sgav_buffer_resolver import BufferResolver
from analysis.sgav_write_detector import WriteDetector

code7 = "\n".join([
    "#include <string.h>",
    "int main() {",
    "    char buf[32] = {0};",
    '    strcat(buf, "AAAA");',
    '    strcat(buf, "BBBB");',
    '    strcat(buf, "CCCC");',
    '    strcat(buf, "DDDD");',
    '    strcat(buf, "EEEE");',
    "}",
])
lines = code7.splitlines()
br = BufferResolver()
bufs = br.resolve(lines)
print("Buffers:", [(b.name, b.size) for b in bufs])
wd = WriteDetector()
alias_map = {b.name: b.name for b in bufs}
for b in bufs:
    alias_map.update({a: b.name for a in b.aliases})
writes = wd.detect(lines, bufs, alias_map)
print("Writes:")
for w in writes:
    print(f"  L{w.line}: {w.kind} target={w.target} resolved={w.resolved_buf}")
