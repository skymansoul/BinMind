#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.license_compliance import LicenseScanner, ComplianceAnalyzer, generate_compliance_report

# 测试许可证扫描
print("=== Testing License Scanner ===")
scanner = LicenseScanner()
pkg_info = scanner.scan_package('typer')
if pkg_info:
    print(f"Package: {pkg_info.name}")
    print(f"Version: {pkg_info.version}")
    print(f"License: {pkg_info.license_type.value}")
else:
    print("Package not found")

# 测试合规性分析
print("\n=== Testing Compliance Analyzer ===")
analyzer = ComplianceAnalyzer()
report = analyzer.analyze('requirements.txt')
print(f"Total packages: {report.summary.get('total_packages', 0)}")
print(f"Total conflicts: {report.summary.get('total_conflicts', 0)}")

# 测试生成合规性报告
print("\n=== Testing Report Generation ===")
report = generate_compliance_report('requirements.txt', 'compliance_report.json')
print("Report generated successfully")

print("\n=== All tests passed! ===")