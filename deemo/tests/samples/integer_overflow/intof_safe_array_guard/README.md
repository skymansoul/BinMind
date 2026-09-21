---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '331efe3f-2bf6-4bce-a0b6-7c1b33962137'
  PropagateID: '331efe3f-2bf6-4bce-a0b6-7c1b33962137'
  ReservedCode1: '0a0aa941-79c6-4c17-ac27-b1eb67b45e59'
  ReservedCode2: '0a0aa941-79c6-4c17-ac27-b1eb67b45e59'
---

# intof_safe_array_guard
**CWE-190** — Integer Overflow (safe 对照)

## Usage
```bash
make && ./vuln
```

## Detection Goal
数组索引写入前完整边界检查（0 <= idx < 64），索引必在界内。pipeline 应报告 0 findings（TN）。

构建环境注记：Makefile 为 gcc 模板；随库分发的 vuln.exe 由 MSVC 19.51 (`cl /Zi /Od /W3`) 构建。

> AI生成