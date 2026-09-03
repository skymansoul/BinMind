# Binary Vulnerability Analysis Report

**Binary:** `06_stack_overflow_canary.exe`  
**Architecture:** x86-64 (64-bit)  
**Format:** PE  
**Generated:** 2026-09-04 03:57:45  

---

## 程序初步画像

### 保护机制

| 机制 | 状态 |
|------|------|
| NX | ✓ 启用 |
| PIE | ✓ 启用 |
| RELRO | none |
| Canary | ✗ 关闭 |
| ASLR | ✓ 启用 |

### PLT 函数 (共 70 个, 展示前 20)

- `gets`
- `fprintf`
- `memcpy`
- `puts`
- `free`
- `malloc`
- `WinMainCRTStartup`
- `_FindPESection`
- `_FindPESectionByName`
- `_FindPESectionExec`
- `_GetPEImageBase`
- `_IsNonwritableInCurrentImage`
- `_ValidateImageBase`
- `_amsg_exit`
- `_cexit`
- `_configthreadlocale`
- `_crt_atexit`
- `_errno`
- `_fpreset`
- `_get_invalid_parameter_handler`

### ROP Gadgets 摘要

- **总数:** 4833
- **类型分布:**
  - `ret`: 2485
  - `pop_rbp`: 1814
  - `pop_rbx`: 309
  - `pop_rax`: 78
  - `pop_rcx`: 45
  - `leave`: 44
  - `pop_rsi`: 18
  - `pop_rdx`: 17
  - `push_rsp`: 13
  - `pop_rdi`: 10

### 关键字符串 (展示前 20)

- len size section         type    string
- 44  45                   ascii   !This program cannot be run in DOS mode.\r\r\n$
- 5   6                    ascii   .text
- 6   7                    ascii   `.data
- 6   7                    ascii   .rdata
- 6   7                    ascii   .pdata
- 7   8                    ascii   @.xdata
- 5   6                    ascii   @.bss
- 6   7                    ascii   .idata
- 5   6                    ascii   @.tls
- 6   7                    ascii   .reloc
- 4   5                    ascii   B/14
- 4   5                    ascii   B/29
- 4   5                    ascii   B/41
- 4   5                    ascii   B/55
- 4   5                    ascii   B/67
- 4   5                    ascii   B/80
- 4   5                    ascii   B/91
- 4   5    .text           ascii   L$ E
- 6   7    .text           ascii   f=MZt\n

### libc 版本信息

- **版本:** 

- **利用难度评估:** **MEDIUM**
- **推荐利用策略:**
  - ret2plt (puts@PLT → leak libc → system)
  - direct-stack-overflow (no canary)
  - GOT overwrite (partial RELRO)

---

## Summary

- **Total vulnerabilities:** 14
- **Critical:** 5
- **Medium:** 5
- **Low:** 4

---

## Findings

### 1. buffer_overflow [Critical]
- **Function:** `sym.vuln`
- **CWE:** CWE-242
- **Description:** gets 为不安全函数
- **Location:** sym.vuln
- **Review:** pending
- **Tier:** lead

### 2. buffer_overflow [Critical]
- **Function:** `sym.vuln`
- **CWE:** CWE-242
- **Description:** gets 为不安全函数
- **Location:** sym.vuln
- **Review:** pending
- **Tier:** lead

### 3. buffer_overflow [Critical]
- **Function:** `sym.vuln`
- **CWE:** CWE-242
- **Description:** gets 为不安全函数
- **Location:** sym.vuln
- **Review:** pending
- **Tier:** lead

### 4. buffer_overflow [Critical]
- **Function:** `sym.vuln`
- **CWE:** CWE-242
- **Description:** gets 为不安全函数
- **Location:** sym.vuln
- **Review:** pending
- **Tier:** lead

### 5. buffer_overflow [Critical]
- **Function:** `sym.gets`
- **CWE:** CWE-242
- **Description:** gets 为不安全函数
- **Location:** sym.gets
- **Review:** pending
- **Tier:** lead

### 6. buffer_overflow [Medium]
- **Function:** `sym.duplicate_ppstrings`
- **CWE:** CWE-120
- **Description:** memcpy 需检查长度参数
- **Location:** sym.duplicate_ppstrings
- **Review:** pending
- **Tier:** lead

### 7. buffer_overflow [Medium]
- **Function:** `sym.duplicate_ppstrings`
- **CWE:** CWE-120
- **Description:** memcpy 需检查长度参数
- **Location:** sym.duplicate_ppstrings
- **Review:** pending
- **Tier:** lead

### 8. heap-overflow [Medium]
- **Function:** `sym.vuln`
- **CWE:** CWE-122
- **Description:** gets("", size=[?,?](0)) into "" (size=[?,?](0)) [POSSIBLE@L1/1]
- **Review:** pending
- **Tier:** candidate

### 9. heap-overflow [Medium]
- **Function:** `sym.vuln`
- **CWE:** CWE-122
- **Description:** gets("", size=[?,?](0)) into "" (size=[?,?](0)) [POSSIBLE@L1/1]
- **Review:** pending
- **Tier:** candidate

### 10. heap-overflow [Medium]
- **Function:** `sym.gets`
- **CWE:** CWE-122
- **Description:** gets(int, size=[?,?](0)) into int (size=[?,?](0)) [POSSIBLE@L1/1]
- **Review:** pending
- **Tier:** candidate

### 11. integer_overflow [Low]
- **Function:** `sym.duplicate_ppstrings`
- **CWE:** CWE-190
- **Description:** malloc 参数需检查整数溢出
- **Location:** sym.duplicate_ppstrings
- **Review:** pending
- **Tier:** lead

### 12. integer_overflow [Low]
- **Function:** `sym.duplicate_ppstrings`
- **CWE:** CWE-190
- **Description:** malloc 参数需检查整数溢出
- **Location:** sym.duplicate_ppstrings
- **Review:** pending
- **Tier:** lead

### 13. integer_overflow [Low]
- **Function:** `sym.duplicate_ppstrings`
- **CWE:** CWE-190
- **Description:** malloc 参数需检查整数溢出
- **Location:** sym.duplicate_ppstrings
- **Review:** pending
- **Tier:** lead

### 14. integer_overflow [Low]
- **Function:** `sym.duplicate_ppstrings`
- **CWE:** CWE-190
- **Description:** malloc 参数需检查整数溢出
- **Location:** sym.duplicate_ppstrings
- **Review:** pending
- **Tier:** lead
