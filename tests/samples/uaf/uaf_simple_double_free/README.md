# uaf_simple_double_free
**CWE-416** — Use-After-Free

## Usage
```bash
make && ./vuln
```

## Detection Goal
BinMind TARPS pipeline should detect use-after-free in this sample while filtering safe pointer-nullify patterns.
