---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '3bada4c6-6858-47e0-9abd-273f4a15c2d6'
  PropagateID: '3bada4c6-6858-47e0-9abd-273f4a15c2d6'
  ReservedCode1: 'c2b335f6-65e7-47a8-823f-a13f2f0c96ff'
  ReservedCode2: 'c2b335f6-65e7-47a8-823f-a13f2f0c96ff'
---

# intof_safe_bounded_add
**CWE-190** — Integer Overflow (safe 对照)

## Usage
```bash
make && ./vuln
```

## Detection Goal
加法前显式上界检查（`extra > INT_MAX - size` 拒绝），total 不会回绕。pipeline 应报告 0 findings（TN）。

构建环境注记：Makefile 为 gcc 模板；随库分发的 vuln.exe 由 MSVC 19.51 (`cl /Zi /Od /W3`) 构建，与 intof 系样本一致。

> AI生成