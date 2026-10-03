---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '9eb729c6-177e-49a1-882c-193fbbe891f8'
  PropagateID: '9eb729c6-177e-49a1-882c-193fbbe891f8'
  ReservedCode1: '9f6a1a3f-78a1-4f3b-b32b-6185e8053a4f'
  ReservedCode2: '9f6a1a3f-78a1-4f3b-b32b-6185e8053a4f'
---

# intof_safe_alloc_check
**CWE-190** — Integer Overflow (safe 对照)

## Usage
```bash
make && ./vuln
```

## Detection Goal
分配尺寸经下界（>0）与上限（<=1024）双重校验后才进入 malloc。pipeline 应报告 0 findings（TN）。

构建环境注记：Makefile 为 gcc 模板；随库分发的 vuln.exe 由 MSVC 19.51 (`cl /Zi /Od /W3`) 构建。

> AI生成