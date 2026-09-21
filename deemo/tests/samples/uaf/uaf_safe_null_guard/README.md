---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '7cc5862e-2496-40b1-862a-aab89d7bbcf8'
  PropagateID: '7cc5862e-2496-40b1-862a-aab89d7bbcf8'
  ReservedCode1: '0e098919-35ff-4bd5-82ba-5ed16b1e5cc2'
  ReservedCode2: '0e098919-35ff-4bd5-82ba-5ed16b1e5cc2'
---

# uaf_safe_null_guard
**CWE-416** — Use-After-Free (safe 对照)

## Usage
```bash
make && ./vuln
```

## Detection Goal
free 后立即置 NULL，判空路径提前返回，全程无悬垂解引用。pipeline 应报告 0 findings（TN）。

构建环境注记：Makefile 为 gcc 模板；随库分发的 vuln.exe 由 MSVC 19.51 (`cl /Zi /Od /W3`) 构建。

> AI生成