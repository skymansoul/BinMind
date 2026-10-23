

#### 快速安装（演示在wsl_kali中）

```bash
chmod +x install.sh
./install.sh --user

#安装好后可进行检测:
binmind --help
binmind version
```

#### 可选语言设置

```bash
export BINMIND_LANGUAGE=zh/en

#若想持久化中文输出：
echo 'export BINMIND_LANGUAGE=zh' >> ~/.bashrc
source ~/.bashrc
```

#### LLM配置

```bash
export AI_MODEL="gpt-4o-mini"
export AI_PROVIDER="openai"
export API_KEY="你的 API Key"
export BASE_URL="https://api.openai.com/v1"
```

#### 测试环节

**安装测试依赖：**

```bash
pip install -r requirements-dev.txt
```

**内置轻量测试：**

```bash
binmind --test
```

**全量测试：**

```bash
python -m pytest
```

**运行指定检测文件：**

```bash
python -m pytest tests/test_report.py -v
```

**快速语法测试：**

```bash
python -m py_compile main.py binmind.py cli/commands.py core/report.py core/i18n.py modules/analysis_tools/reverse_report.py
```

#### 基本使用

**分析单个二进制**

```bash
binmind analyze ./pwn -o ./results
```

**输出markdown报告**

```bash
binmind analyze ./pwn -o ./results -f markdown
```

**输出 JSON 报告**

```bash
binmind analyze ./pwn -o ./results -f json
```

**限制最大分析函数数量**

```bash
binmind analyze ./pwn --max-funcs 50 -o ./results
```

**只分析指定函数**

```bash
binmind analyze ./pwn --functions main  -o ./result
```

**包含库函数**

```bash
binmind analyze ./pwn --include-lib -o ./results
```

**启用并行分析**

```bash
binmind analyze ./pwn --parallel -o ./results
```

**禁用 AI 辅助**

```bash
binmind analyze ./pwn --no-ai -o ./results
```

**显式启用 AI 辅助**

```bash
binmind analyze ./samples/example.bin --ai-analysis -o ./results
```

**搭配崩溃日志分析**

```bash
binmind analyze ./pwn --crash ./crash.log -o ./results
```

**启用符号执行**

```bash
binmind analyze ./pwn --symbolic -o ./results
```

**批量分析目录**

```bash
binmind batch ./samples/fmt -o ./results
```



#### 逆向工程报告

**先分析**

```bash
binmind analyze ./pwn -o ./results
```

**再生成逆向报告（默认保存到./reports/）**

```bash
binmind --reverse-report --binary ./pwn
```

**中文/英文报告**

```bash
BINMIND_LANGUAGE=zh/en binmind --reverse-report --binary ./pwn
```



#### 调试工具入口

**查看二进制保护机制：**

```bash
binmind debug checksec ./pwn
```

**查看 PLT 信息：**

```bash
binmind debug plt ./pwn
```

**提取关键字符串：**

```bash
binmind debug strings ./pwn
```

**查看 ROP gadgets：**

```bash
binmind debug gadgets ./pwn
```

**libc 泄露辅助：**

```bash
binmind debug libc ./pwn
```

**符号执行调试：**

```bash
binmind debug symexec ./pwn
```



#### 人工复核队列

**列出待复核发现：**

```bash
binmind review -o ./results --list
```

**标记某条记录为确认漏洞：**

```bash
binmind review -o ./results --index 0 --verdict confirmed
```

**标记误报：**

```bash
binmind review -o ./results --index 0 --verdict false_positive
```

**恢复待定：**

```bash
binmind review -o ./results --index 0 --verdict pending
```



#### 导出与重放

**导出某个二进制的分析报告：**

```bash
binmind export ./samples/example.bin -o ./exported_reports
```

**查看数据库中的分析状态：**

```bash
binmind status
```

**重放历史分析：**

```bash
binmind replay 1
```
