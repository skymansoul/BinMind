# BinMind 实验样本库

按来源类型分为三个子目录：

| 目录 | 用途 | 样本示例 |
|------|------|---------|
| `ctf/` | CTF 竞赛题目 | pwnable.tw, HackTheBox, DefCon Quals |
| `teaching/` | 教学演示样本 | 自编含漏洞小程序（含源码和编译脚本） |
| `cve/` | 公开 CVE 漏洞样本 | CVE-2024-xxxx 复现环境 |

## 样本命名规范

```
{来源}_{漏洞类型}_{架构}
例如: ctf_pwnable_stack_x86-64, teaching_fmtstr_i386
```

## 使用方式

```bash
# 注册样本
python -c "from core.sample_manager import SampleManager; mgr = SampleManager(); mgr.register('samples/ctf/vuln_binary')"

# 批量扫描
python -c "from core.sample_manager import SampleManager; mgr = SampleManager(); mgr.batch_scan('samples/ctf/')"

# 批量分析
python scripts/batch_analyze.py samples/ctf/ -o results/ctf/
```
