---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '4590b810-9033-4c4e-995b-25bc34d33087'
  PropagateID: '4590b810-9033-4c4e-995b-25bc34d33087'
  ReservedCode1: 'a087bff9-3e22-4093-9b02-c587492d7a3f'
  ReservedCode2: 'a087bff9-3e22-4093-9b02-c587492d7a3f'
---

# uaf_safe_two_bufs
**CWE-416** — Use-After-Free (safe 对照)

## Usage
```bash
make && ./vuln
```

## Detection Goal
双缓冲各自使用完毕后释放，无别名交叉与释放后使用。pipeline 应报告 0 findings（TN）。

构建环境注记：Makefile 为 gcc 模板；随库分发的 vuln.exe 由 MSVC 19.51 (`cl /Zi /Od /W3`) 构建。

> AI生成