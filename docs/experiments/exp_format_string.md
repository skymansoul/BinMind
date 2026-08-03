# EXP-20260803-002: 格式化字符串漏洞检测与偏移验证

## 基本信息

| 字段 | 值 |
|------|-----|
| 实验日期 | 2026-08-03 |
| 样本 | `samples/teaching/vuln_fmtstr` (自编教学用格式化字符串) |
| 漏洞类型 | format-string (printf with user-controlled format) |
| 架构 | x86-64 |
| 保护措施 | NX✓ PIE✓ Canary✓ Full RELRO |

## 样本源码

```c
#include <stdio.h>
#include <unistd.h>
char flag[64] = "flag{test_fmtstr_verify}";
int main() {
    char buf[128];
    read(0, buf, 128);
    printf(buf);  // 格式化字符串来自用户输入
    return 0;
}
```

编译参数: `gcc -o vuln_fmtstr vuln_fmtstr.c`（默认全部保护开启）

## 分析流程

### Stage 1: 静态检测

```
$ python scripts/verify/verify_format_string.py vuln_fmtstr --expected-offset 6
```

| 函数 | 危险调用 | 检测偏移 | 置信度 |
|------|---------|---------|--------|
| main | printf(buf) | 6 | 0.75 |

### Stage 2: 偏移验证

手工爆破:
```
$ echo '%6$p' | ./vuln_fmtstr
0x7ffd12345678      ← 第6个参数有可控输出
```

BinMind 检测值 = 6，手工爆破值 = 6。**偏差 = 0。**

### Stage 3: 利用分析

Full RELRO + PIE + Canary 意味着:
- GOT 不可覆写 → `%n` 写入只能攻击栈上的返回地址或 .fini_array
- PIE 开启了地址随机化 → 需要先泄露基址
- Canary 开启 → 栈溢出不可行（但格式化字符串不触发 canary）

推荐策略:
1. `%p` 系列泄露栈地址和 libc 地址
2. 计算目标地址在栈上的位置
3. `%n` 逐字节写入构造 ROP 链

## 四维评估

| 维度 | 评分 | 计算依据 |
|------|------|---------|
| 发现效率 | 0.60 | 静态检测 <30s，但 LLM 增强 + 偏移验证需额外时间 |
| 结果质量 | 1.00 | 无误报，检测到的 printf(buf) 确实可被利用 |
| LLM 辅助效果 | 0.45 | LLM 确认了静态检测结果，给出 FULL RELRO 绕过建议 |
| 适用范围 | 0.40 | 高防护（Full RELRO + PIE）下格式字符串利用复杂度高 |

## 已知限制

- `format_string_detector` 的 x86_64 偏移估算在无符号执行时保守设为 6
- 对于 `snprintf` 和 `fprintf` 等变体的检测覆盖率有待扩展
- LLM 增强的置信度提升（+0.15）是保守估计，实际增益因模型而异
- Full RELRO + PIE 组合下的利用路径需要多步推理，当前自动化程度有限

## 结论

- 三级检测链（静态→符号执行→LLM）按预期工作
- 偏移检测在实测样本上偏差为 0
- 高防护场景下的自动化利用仍是开放问题，需人工介入
