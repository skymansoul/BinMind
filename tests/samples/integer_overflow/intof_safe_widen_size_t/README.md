---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'f7c9abde-7e93-4331-9b96-925f3e7cd963'
  PropagateID: 'f7c9abde-7e93-4331-9b96-925f3e7cd963'
  ReservedCode1: '2b75b261-3005-43a2-8bd2-a6c82d2cfb17'
  ReservedCode2: '2b75b261-3005-43a2-8bd2-a6c82d2cfb17'
---

# intof_safe_widen_size_t
**CWE-190** — Integer Overflow (safe 对照)

## Usage
```bash
make && ./vuln
```

## Detection Goal
运算前拒绝负值并宽化到 size_t，无符号加法不会回绕成小值，且上限保护。pipeline 应报告 0 findings（TN）。

构建环境注记：Makefile 为 gcc 模板；随库分发的 vuln.exe 由 MSVC 19.51 (`cl /Zi /Od /W3`) 构建。

> AI生成