---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'a1405b43-cb62-4549-9424-c5005de6e323'
  PropagateID: 'a1405b43-cb62-4549-9424-c5005de6e323'
  ReservedCode1: '9f28f871-f7e2-4aba-b06f-3eed654bc8ab'
  ReservedCode2: '9f28f871-f7e2-4aba-b06f-3eed654bc8ab'
---

# uaf_safe_struct_owner
**CWE-416** — Use-After-Free (safe 对照)

## Usage
```bash
make && ./vuln
```

## Detection Goal
结构体指针字段释放后仅更新标量字段，不再解引用指针字段。pipeline 应报告 0 findings（TN）。

构建环境注记：Makefile 为 gcc 模板；随库分发的 vuln.exe 由 MSVC 19.51 (`cl /Zi /Od /W3`) 构建。

> AI生成