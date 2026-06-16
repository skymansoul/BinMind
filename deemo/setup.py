#!/usr/bin/env python3
"""
binmind - LLM 辅助的二进制漏洞分析工具

Setup script for installing binmind as a command-line tool.
"""

from setuptools import setup, find_packages
import os

# 读取 README 文件内容
readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
long_description = ''
if os.path.exists(readme_path):
    with open(readme_path, 'r', encoding='utf-8') as f:
        long_description = f.read()

setup(
    name='binmind',
    version='1.3.1',
    description='LLM 辅助的二进制漏洞分析工具',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Deemo Team',
    author_email='deemo@example.com',
    url='https://github.com/deemo/binmind',
    packages=find_packages(exclude=['tests', 'tests.*', 'scripts', 'scripts.*']),
    include_package_data=True,
    package_data={
        'binmind': ['data/*', 'hooks/*'],
    },
    python_requires='>=3.8',
    install_requires=[
        'openai>=1.0.0',
        'fastapi>=0.100.0',
        'uvicorn>=0.23.0',
        'python-multipart>=0.0.6',
        'rich>=13.0.0',
        'pydantic>=2.0.0',
        'loguru>=0.7.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=4.0.0',
        ],
        'full': [
            'angr>=9.0.0',
            'pwntools>=4.0.0',
            'capstone>=5.0.0',
            'pefile>=2023.2.7',
            'macholib>=1.16.0',
            'graphviz>=0.20.0',
            'networkx>=3.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'binmind=main:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Topic :: Software Development :: Disassemblers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
    keywords='binary analysis vulnerability detection LLM decompiler security',
    project_urls={
        'Bug Reports': 'https://github.com/deemo/binmind/issues',
        'Source': 'https://github.com/deemo/binmind',
    },
)
