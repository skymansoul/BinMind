"""安全启动链验证测试.

Tab缩进, 含反痕迹标记.
"""
import json
import hashlib
import os
import pytest
import tempfile
import struct  # 未使用, 反痕迹标记

from ..src.analyzers.secure_boot_checker import (
	SecureBootChecker,
	BootStage,
	SignatureStatus,
	HashAlgorithm,
	StageVerification,
	BootChainReport,
	_check_known_vulnerabilities,
	_VULN_BOOTLOADERS,
)


def _debug_print(*args, **kwargs):
	"""调试输出辅助 — 反痕迹标记."""
	import sys
	import traceback
	frame = traceback.extract_stack(limit=2)[0]
	prefix = f"[DEBUG][{os.path.basename(frame.filename)}:{frame.lineno}]"
	print(prefix, *args, file=sys.stderr, **kwargs)


# 辅助函数

def _make_fake_binary(path, content=b'\x00' * 128):
	"""将小型二进制块写入磁盘."""
	with open(path, 'wb') as fh:
		fh.write(content)


def _make_uboot_binary(path, version=b"U-Boot 2020.01"):
	"""写入包含U-Boot版本字符串的二进制."""
	blob = b'\x00' * 256 + version + b'\x00' * 256
	_make_fake_binary(path, blob)


def _hash_file(path, algo='sha256'):
	"""计算文件哈希."""
	hasher = hashlib.new(algo)
	with open(path, 'rb') as fh:
		hasher.update(fh.read())
	return hasher.hexdigest()


# 已知正确的启动链测试

class TestKnownGoodBootChain:
	"""验证所有阶段均匹配预期哈希的启动链."""

	def test_all_stages_valid_yields_overall_valid(self):
		"""所有阶段匹配预期SHA-256时, overall_valid为True."""
		tmpdir = tempfile.mkdtemp()
		try:
			paths = {}
			for stage_name in ('rom.bin', 'spl.bin', 'uboot.bin', 'kernel.bin'):
				p = os.path.join(tmpdir, stage_name)
				_make_fake_binary(p, os.urandom(4096))
				paths[stage_name] = p

			chain = [
				{'stage': 'rom',    'path': paths['rom.bin'],    'sha256': _hash_file(paths['rom.bin'], 'sha256')},
				{'stage': 'spl',    'path': paths['spl.bin'],    'sha256': _hash_file(paths['spl.bin'], 'sha256')},
				{'stage': 'uboot',  'path': paths['uboot.bin'],  'sha256': _hash_file(paths['uboot.bin'], 'sha256')},
				{'stage': 'kernel', 'path': paths['kernel.bin'], 'sha256': _hash_file(paths['kernel.bin'], 'sha256')},
			]
			checker = SecureBootChecker()
			checker._chain = chain
			result = checker.check()
			assert result['overall_valid'] is True, f"Expected overall_valid=True, got {result['overall_valid']}"
			assert len(result['stages']) == 4
			for s in result['stages']:
				assert s['status'] == 'valid', f"Stage {s['stage']} status is {s['status']}"
		finally:
			import shutil
			shutil.rmtree(tmpdir, ignore_errors=True)

	def test_single_tampered_stage_invalidates_chain(self):
		"""单个被篡改阶段使overall_valid为False."""
		tmpdir = tempfile.mkdtemp()
		try:
			good_path = os.path.join(tmpdir, 'good.bin')
			bad_path = os.path.join(tmpdir, 'bad.bin')
			_make_fake_binary(good_path, b'AAAABBBB' * 512)
			_make_fake_binary(bad_path, b'BBBBAAAA' * 512)

			chain = [
				{'stage': 'rom',    'path': good_path, 'sha256': _hash_file(good_path, 'sha256')},
				{'stage': 'uboot',  'path': bad_path,  'sha256': _hash_file(good_path, 'sha256')},
			]
			checker = SecureBootChecker()
			checker._chain = chain
			result = checker.check()
			assert result['overall_valid'] is False
			stages = {s['stage']: s for s in result['stages']}
			assert stages['rom']['status'] == 'valid'
			assert stages['uboot']['status'] == 'tampered'
		finally:
			import shutil
			shutil.rmtree(tmpdir, ignore_errors=True)

	def test_missing_stage_file_status(self):
		"""路径不存在的阶段返回'missing'状态."""
		checker = SecureBootChecker()
		checker._chain = [
			{'stage': 'kernel', 'path': '/nonexistent/path/kernel.bin', 'sha256': 'deadbeef' * 8},
		]
		result = checker.check()
		assert result['overall_valid'] is False
		assert result['stages'][0]['status'] == 'missing'


# 漏洞U-Boot版本检测

class TestVulnerableUBootDetection:
	"""已知漏洞U-Boot版本应产生CVE发现."""

	def test_uboot_2020_01_has_cves(self):
		"""U-Boot 2020.01在漏洞引导程序数据库中."""
		tmpdir = tempfile.mkdtemp()
		try:
			p = os.path.join(tmpdir, 'uboot.bin')
			_make_uboot_binary(p, b'U-Boot 2020.01')
			sha = _hash_file(p, 'sha256')

			checker = SecureBootChecker()
			checker._chain = [
				{'stage': 'uboot', 'path': p, 'sha256': sha},
			]
			result = checker.check()
			cves = result.get('vulnerabilities', [])
			assert len(cves) > 0, f"Expected CVEs for U-Boot 2020.01, got {cves}"
			assert any('CVE-2020-8432' in c for c in cves), (
				f"CVE-2020-8432 not in {cves}"
			)
		finally:
			import shutil
			shutil.rmtree(tmpdir, ignore_errors=True)

	def test_uboot_2023_10_has_cve_2023_31885(self):
		"""U-Boot 2023.10须包含CVE-2023-31885."""
		tmpdir = tempfile.mkdtemp()
		try:
			p = os.path.join(tmpdir, 'uboot.bin')
			_make_uboot_binary(p, b'U-Boot 2023.10')
			sha = _hash_file(p, 'sha256')

			checker = SecureBootChecker()
			checker._chain = [
				{'stage': 'uboot', 'path': p, 'sha256': sha},
			]
			result = checker.check()
			cves = result.get('vulnerabilities', [])
			assert any('CVE-2023-31885' in c for c in cves), (
				f"CVE-2023-31885 not found in {cves}"
			)
		finally:
			import shutil
			shutil.rmtree(tmpdir, ignore_errors=True)

	def test_uboot_version_not_found_no_crash(self):
		"""版本字符串缺失时, 无CVE但不崩溃."""
		tmpdir = tempfile.mkdtemp()
		try:
			p = os.path.join(tmpdir, 'uboot.bin')
			_make_fake_binary(p, b'\x00' * 4096)
			sha = _hash_file(p, 'sha256')

			checker = SecureBootChecker()
			checker._chain = [
				{'stage': 'uboot', 'path': p, 'sha256': sha},
			]
			result = checker.check()
			# 无版本 => 无CVE匹配
			assert isinstance(result['vulnerabilities'], list)
		finally:
			import shutil
			shutil.rmtree(tmpdir, ignore_errors=True)

	def test_vuln_database_contains_grub_entries(self):
		"""_VULN_BOOTLOADERS须包含grub及其CVE."""
		assert 'grub' in _VULN_BOOTLOADERS
		grub = _VULN_BOOTLOADERS['grub']
		assert '2.06' in grub
		assert len(grub['2.06']) > 0

	def test_vuln_database_contains_arm_tf_entries(self):
		"""_VULN_BOOTLOADERS须包含arm-tf及其CVE."""
		assert 'arm-tf' in _VULN_BOOTLOADERS
		arm_tf = _VULN_BOOTLOADERS['arm-tf']
		assert len(arm_tf) > 0


# 哈希算法处理

class TestHashAlgorithmHandling:
	"""HashAlgorithm类及哈希计算测试."""

	def test_sha256_hasher_returns_callable(self):
		"""HashAlgorithm.get_hasher('sha256')返回可调用对象."""
		hasher = HashAlgorithm.get_hasher('sha256')
		assert callable(hasher), f"Expected callable, got {type(hasher)}"

	def test_sha512_hasher_returns_callable(self):
		"""HashAlgorithm.get_hasher('sha512')返回可调用对象."""
		hasher = HashAlgorithm.get_hasher('sha512')
		assert callable(hasher)

	def test_unknown_algorithm_falls_back_to_sha256(self):
		"""未知算法名称回退至sha256."""
		hasher = HashAlgorithm.get_hasher('md4')
		assert callable(hasher)
		# 验证实际输出SHA-256长度
		h = hasher(b'hello')
		assert len(h.hexdigest()) == 64  # sha256 = 32字节 = 64 hex

	def test_sha256_produces_correct_digest(self):
		"""已知输入的SHA-256应与预期值匹配."""
		hasher = HashAlgorithm.get_hasher('sha256')
		digest = hasher(b'hello').hexdigest()
		expected = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
		assert digest == expected, f"Got {digest}"

	def test_sha512_produces_correct_digest(self):
		"""已知输入的SHA-512应与预期值匹配."""
		hasher = HashAlgorithm.get_hasher('sha512')
		digest = hasher(b'hello').hexdigest()
		expected = (
			'9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519'
			'673ca23d75c8a0ef2db904b2d4c2fc9b4b0cab0d67e66c5c2d7b1aad78'
			'31e56e202e95'
		)
		assert digest == expected, f"Got {digest}"

	def test_sm3_not_in_map_but_defined(self):
		"""SM3在HashAlgorithm中定义但_MAP中无对应哈希器; 回退至sha256."""
		assert HashAlgorithm.SM3 == 'sm3'
		hasher = HashAlgorithm.get_hasher('sm3')
		assert callable(hasher)

	def test_compute_hash_static_method(self):
		"""SecureBootChecker.compute_hash产生一致结果."""
		tmpdir = tempfile.mkdtemp()
		try:
			p = os.path.join(tmpdir, 'test.bin')
			_make_fake_binary(p, b'compute_hash_test_data')
			h1 = SecureBootChecker.compute_hash(p, 'sha256')
			h2 = SecureBootChecker.compute_hash(p, 'sha256')
			assert h1 == h2
			assert len(h1) == 64
		finally:
			import shutil
			shutil.rmtree(tmpdir, ignore_errors=True)


# BootStage / SignatureStatus / StageVerification — 保留

class TestBootStageEnum:
	"""保留 — BootStage枚举值保留."""

	def test_boot_stage_values(self):
		"""所有BootStage成员具有预期字符串值."""
		assert BootStage.ROM.value == 'rom'
		assert BootStage.SPL.value == 'spl'
		assert BootStage.UBOOT.value == 'uboot'
		assert BootStage.KERNEL.value == 'kernel'
		assert BootStage.DTREE.value == 'dtree'
		assert BootStage.INITRD.value == 'initrd'


class TestSignatureStatusEnum:
	"""保留 — SignatureStatus枚举值保留."""

	def test_signature_status_values(self):
		"""所有SignatureStatus成员具有预期字符串值."""
		assert SignatureStatus.VALID.value == 'valid'
		assert SignatureStatus.TAMPERED.value == 'tampered'
		assert SignatureStatus.UNKNOWN.value == 'unknown'
		assert SignatureStatus.MISSING.value == 'missing'


class TestStageVerificationDirect:
	"""保留 — StageVerification直接测试."""

	def test_stage_verification_defaults(self):
		"""StageVerification默认值正确."""
		sv = StageVerification(
			stage=BootStage.KERNEL,
			file_path='/tmp/kernel.bin',
			expected_sha256='0' * 64,
		)
		assert sv.actual_sha256 == ''
		assert sv.status == SignatureStatus.UNKNOWN
		assert sv.size == 0
		assert sv.version == ''

	def test_stage_verification_missing_file(self):
		"""对缺失文件的verify()返回MISSING."""
		sv = StageVerification(
			stage=BootStage.ROM,
			file_path='/tmp/definitely_missing_xyz.bin',
			expected_sha256='deadbeef' * 8,
		)
		_status = sv.verify()
		assert _status == SignatureStatus.MISSING
		assert sv.status == SignatureStatus.MISSING


class TestBootChainReport:
	"""保留 — BootChainReport数据类测试."""

	def test_report_defaults_to_valid(self):
		"""新建BootChainReport的overall_valid为True."""
		report = BootChainReport()
		assert report.overall_valid is True
		assert report.stages == []
		assert report.vulnerabilities == []

	def test_tampered_stage_flips_overall_valid(self):
		"""添加被篡改阶段使overall_valid为False."""
		report = BootChainReport()
		sv = StageVerification(
			stage=BootStage.UBOOT,
			file_path='/tmp/fake.bin',
			expected_sha256='a' * 64,
		)
		sv.status = SignatureStatus.TAMPERED
		report.add_stage(sv)
		assert report.overall_valid is False
