---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'f93e7c4b-c290-467d-8977-3af1ba2c172d'
  PropagateID: 'f93e7c4b-c290-467d-8977-3af1ba2c172d'
  ReservedCode1: 'bedadcf0-a94a-4676-b550-f8f437470ea5'
  ReservedCode2: 'bedadcf0-a94a-4676-b550-f8f437470ea5'
---

# uaf_safe_loop_fresh
**CWE-416** — Use-After-Free (safe 对照)

## Usage
```bash
make && ./vuln
```

## Detection Goal
循环每轮迭代内完成分配-使用-释放，无跨迭代使用。pipeline 应报告 0 findings（TN）。

构建环境注记：Makefile 为 gcc 模板；随库分发的 vuln.exe 由 MSVC 19.51 (`cl /Zi /Od /W3`) 构建。

> AI生成