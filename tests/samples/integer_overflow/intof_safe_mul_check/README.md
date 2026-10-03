---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '580caca9-1308-49c8-994e-024033c057a5'
  PropagateID: '580caca9-1308-49c8-994e-024033c057a5'
  ReservedCode1: 'ecd691c1-66d4-4672-bb21-0d9f99ffce5f'
  ReservedCode2: 'ecd691c1-66d4-4672-bb21-0d9f99ffce5f'
---

# intof_safe_mul_check
**CWE-190** — Integer Overflow (safe 对照)

## Usage
```bash
make && ./vuln
```

## Detection Goal
乘法前用除法预检查上界（`n > INT_MAX / m` 拒绝），乘积不会溢出。pipeline 应报告 0 findings（TN）。

构建环境注记：Makefile 为 gcc 模板；随库分发的 vuln.exe 由 MSVC 19.51 (`cl /Zi /Od /W3`) 构建。

> AI生成