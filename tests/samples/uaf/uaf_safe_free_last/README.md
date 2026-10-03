---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'e57cf28b-8114-4c7d-a55b-630855d75e48'
  PropagateID: 'e57cf28b-8114-4c7d-a55b-630855d75e48'
  ReservedCode1: 'f9bf86a6-3390-495c-bfa4-5fac1e8a14a6'
  ReservedCode2: 'f9bf86a6-3390-495c-bfa4-5fac1e8a14a6'
---

# uaf_safe_free_last
**CWE-416** — Use-After-Free (safe 对照)

## Usage
```bash
make && ./vuln
```

## Detection Goal
所有堆使用均在 free 之前完成，释放后不再触碰指针。BinMind pipeline 对本样本应报告 0 findings（TN）。

构建环境注记：Makefile 为 gcc 模板；随库分发的 vuln.exe 由 MSVC 19.51 (`cl /Zi /Od /W3`) 构建，与 intof 系样本一致。

> AI生成