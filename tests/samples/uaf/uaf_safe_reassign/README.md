---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '945de6d8-5799-405b-9dbd-68262e02e631'
  PropagateID: '945de6d8-5799-405b-9dbd-68262e02e631'
  ReservedCode1: '3bf4ab16-f607-44fa-ab1d-c7da73c290e4'
  ReservedCode2: '3bf4ab16-f607-44fa-ab1d-c7da73c290e4'
---

# uaf_safe_reassign
**CWE-416** — Use-After-Free (safe 对照)

## Usage
```bash
make && ./vuln
```

## Detection Goal
free 后指针变量被重新分配覆盖，悬垂状态消除，后续使用均指向新块。pipeline 应报告 0 findings（TN）。

构建环境注记：Makefile 为 gcc 模板；随库分发的 vuln.exe 由 MSVC 19.51 (`cl /Zi /Od /W3`) 构建。

> AI生成