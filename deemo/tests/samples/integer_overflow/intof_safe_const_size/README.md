---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'ab976ad0-a347-4edb-8931-1bcf36058911'
  PropagateID: 'ab976ad0-a347-4edb-8931-1bcf36058911'
  ReservedCode1: 'd98085e5-5a93-4d4a-9014-01b4b50cbbe0'
  ReservedCode2: 'd98085e5-5a93-4d4a-9014-01b4b50cbbe0'
---

# intof_safe_const_size
**CWE-190** — Integer Overflow (safe 对照)

## Usage
```bash
make && ./vuln
```

## Detection Goal
缓冲尺寸为编译期常量（enum CAP=256），无外部输入参与长度运算。pipeline 应报告 0 findings（TN）。

构建环境注记：Makefile 为 gcc 模板；随库分发的 vuln.exe 由 MSVC 19.51 (`cl /Zi /Od /W3`) 构建。

> AI生成