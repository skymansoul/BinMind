#!/usr/bin/env python3
# scripts/run_llm_experiment.py - LLM 开/关对照实验一次性入口
#
# 密钥来源: ANTHROPIC_API_KEY 环境变量 > getpass 交互输入;
# 无密钥时以回退模式运行 (LLM 开组产生 skipped 记录, 不中断)。
# 结束后删除 .temp_claude_key 并从环境清除密钥, 无持久化残留。
# --self-destruct: 额外删除本脚本 (一次性实验辅助脚本)。
import getpass
import os
import subprocess
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_KEY_FILE = os.path.join(_ROOT, '.temp_claude_key')
_JSONL = os.path.join(_ROOT, 'logs', 'llm_calls.jsonl')
_CSV = os.path.join(_ROOT, 'logs', 'benchmark_results.csv')


def _count_lines(path):
    try:
        with open(path, encoding='utf-8') as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def main():
    argv = [a for a in sys.argv[1:] if a != '--self-destruct']
    self_destruct = '--self-destruct' in sys.argv[1:]
    if not argv:
        print('[INFO] 用法: python scripts/run_llm_experiment.py <样本...> [--self-destruct]')
        return 1

    key = os.environ.get('ANTHROPIC_API_KEY', '').strip()
    if not key:
        try:
            key = getpass.getpass('Claude API Key (回车跳过, 回退模式): ').strip()
        except (EOFError, KeyboardInterrupt):
            key = ''
    injected = bool(key)

    n_before = _count_lines(_JSONL)
    off_rc = on_rc = 1
    try:
        if key:
            with open(_KEY_FILE, 'w', encoding='utf-8') as fh:
                fh.write(key)
            os.chmod(_KEY_FILE, 0o600)
            os.environ['ANTHROPIC_API_KEY'] = key
        # benchmark 与 ai_backends 经环境变量识别 claude 通道
        os.environ['LLM_PROVIDER'] = 'claude'

        off = subprocess.run(
            [sys.executable, os.path.join(_ROOT, 'scripts', 'benchmark.py')] + argv,
            cwd=_ROOT)
        on = subprocess.run(
            [sys.executable, os.path.join(_ROOT, 'scripts', 'benchmark.py')] + argv + ['--llm'],
            cwd=_ROOT)
        off_rc, on_rc = off.returncode, on.returncode
    finally:
        if os.path.exists(_KEY_FILE):
            os.remove(_KEY_FILE)
        os.environ.pop('ANTHROPIC_API_KEY', None)
        os.environ.pop('LLM_PROVIDER', None)

    n_after = _count_lines(_JSONL)
    print('[SUMMARY]')
    print('  LLM 关/开组返回码: %d / %d' % (off_rc, on_rc))
    print('  llm_calls.jsonl 新增记录: %d' % max(0, n_after - n_before))
    print('  benchmark 结果: %s' % _CSV)

    if self_destruct:
        try:
            os.remove(os.path.abspath(__file__))
        except OSError:
            pass
    return 0 if (off_rc == 0 and on_rc == 0) else 2


if __name__ == '__main__':
    sys.exit(main())
