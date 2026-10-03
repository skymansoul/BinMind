#!/usr/bin/env python3
"""
LLM 后端配置辅助脚本。

检测可用的 LLM 后端（本地 Ollama/llama.cpp/DeepSeek 代理 或云端 API），
更新 config.py 中的对应配置项，并执行连接测试。

用法:
  python scripts/setup_llm.py                          # 自动检测
  python scripts/setup_llm.py --provider openai --key sk-xxx    # 手动配置
  python scripts/setup_llm.py --provider deepseek --key xxx --url http://localhost:8800/v1
  python scripts/setup_llm.py --provider ollama --model llama3
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    Config, get_openai_client, test_api_connection,
    AI_PROVIDER_OPENAI, AI_PROVIDER_OLLAMA, AI_PROVIDER_LLAMACPP, AI_PROVIDER_CUSTOM,
)


def check_local_endpoints():
    """检测本地可用的 LLM 端点。"""
    import urllib.request
    import urllib.error

    results = {}

    # Ollama
    try:
        req = urllib.request.Request('http://localhost:11434/api/tags')
        urllib.request.urlopen(req, timeout=3)
        results['ollama'] = 'http://localhost:11434'
    except Exception:
        pass

    # llama.cpp
    try:
        req = urllib.request.Request('http://localhost:8080/v1/models')
        urllib.request.urlopen(req, timeout=3)
        results['llamacpp'] = 'http://localhost:8080'
    except Exception:
        pass

    # DeepSeek 本地代理
    for port in [8800, 8801, 8888]:
        try:
            url = f'http://localhost:{port}/v1/models'
            req = urllib.request.Request(url)
            urllib.request.urlopen(req, timeout=3)
            results['custom'] = f'http://localhost:{port}/v1'
            break
        except Exception:
            continue

    return results


def configure_openai(api_key, base_url=None, model=None):
    Config.AI_PROVIDER = AI_PROVIDER_OPENAI
    Config.OPENAI_API_KEY = api_key
    if base_url:
        Config.OPENAI_BASE_URL = base_url
    if model:
        Config.OPENAI_MODEL = model
    print(f'Configured OpenAI: model={Config.OPENAI_MODEL}')
    if base_url:
        print(f'  Base URL: {base_url}')


def configure_custom(api_key, base_url, model='deepseek-chat'):
    Config.AI_PROVIDER = AI_PROVIDER_CUSTOM
    Config.CUSTOM_API_KEY = api_key
    Config.CUSTOM_BASE_URL = base_url
    Config.CUSTOM_MODEL = model
    print(f'Configured Custom: {model} @ {base_url}')


def configure_ollama(model='llama3'):
    Config.AI_PROVIDER = AI_PROVIDER_OLLAMA
    Config.OLLAMA_MODEL = model
    print(f'Configured Ollama: model={model}')


def test_connection():
    client = get_openai_client()
    if client is None:
        print('Failed to create client')
        return False

    ok = test_api_connection(client)
    if ok:
        print('Connection test: PASSED')
    else:
        print('Connection test: FAILED')
    return ok


def main():
    parser = argparse.ArgumentParser(description='Setup LLM backend for BinMind')
    parser.add_argument('--provider', choices=['openai', 'deepseek', 'ollama', 'llamacpp'],
                        help='LLM provider')
    parser.add_argument('--key', help='API key')
    parser.add_argument('--url', help='API base URL (for deepseek/custom)')
    parser.add_argument('--model', help='Model name')
    parser.add_argument('--test-only', action='store_true',
                        help='Only test existing configuration')

    args = parser.parse_args()

    if args.test_only:
        test_connection()
        return

    if args.provider:
        if args.provider == 'openai':
            configure_openai(args.key or '', base_url=args.url, model=args.model)
        elif args.provider == 'deepseek':
            configure_custom(args.key or '', args.url or 'http://localhost:8800/v1',
                             args.model or 'deepseek-chat')
        elif args.provider == 'ollama':
            configure_ollama(model=args.model or 'llama3')
        elif args.provider == 'llamacpp':
            Config.AI_PROVIDER = AI_PROVIDER_LLAMACPP
            print('Configured llama.cpp')

        if args.provider != 'ollama':
            test_connection()
        return

    # 自动检测模式
    print('Auto-detecting local LLM endpoints...')
    endpoints = check_local_endpoints()

    if endpoints:
        print(f'Found {len(endpoints)} local endpoint(s):')
        for name, url in endpoints.items():
            print(f'  {name}: {url}')

        if 'custom' in endpoints:
            print('\nConfiguring DeepSeek proxy...')
            configure_custom('deepseek-local', endpoints['custom'])
            test_connection()
        elif 'ollama' in endpoints:
            print('\nConfiguring Ollama...')
            configure_ollama()
        elif 'llamacpp' in endpoints:
            print('\nConfiguring llama.cpp...')
            Config.AI_PROVIDER = AI_PROVIDER_LLAMACPP
    else:
        print('No local endpoints found.')
        print()
        print('To configure manually:')
        print('  python scripts/setup_llm.py --provider openai --key sk-your-key')
        print('  python scripts/setup_llm.py --provider deepseek --key xxx --url http://localhost:8800/v1')
        print('  python scripts/setup_llm.py --provider ollama --model llama3')
        print()
        print('Or set environment variables:')
        print('  OPENAI_API_KEY=sk-xxx')
        print('  OPENAI_BASE_URL=http://localhost:8800/v1')


if __name__ == '__main__':
    main()
