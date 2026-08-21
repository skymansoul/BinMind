import os
import struct
import logging

logger = logging.getLogger(__name__)

FIRMWARE_MAGICS = {
	'uImage':		b'\x27\x05\x19\x56',
	'TRX':			b'HDR0',
	'SquashFS':		b'hsqs',
	'SquashFS_LZ4':	b'lz4s',
	'SquashFS_XZ':	b'xzsq',
	'SquashFS_ZSTD':	b'zstd',
	'JFFS2':		b'\x85\x19',
	'UBIFS':		b'\x55\x42\x49\x23',
	'YAFFS2':		b'\x03\x00',
	'CPIO':			b'070701',
	'CPIO_NEW':		b'070702',
	'ISO9660':		b'CD001',
	'ZIP':			b'PK\x03\x04',
	'GZIP':			b'\x1f\x8b\x08',
	'BZIP2':		b'BZh',
	'LZMA':			b'\x5d\x00\x00',
	'XZ':			b'\xfd\x37\x7a\x58\x5a\x00',
	'LZO':			b'\x89\x4c\x5a\x4f',
	'LZ4':			b'\x04\x22\x4d\x18',
	'ZSTD':			b'\x28\xb5\x2f\xfd',
	'Android_Sparse':	b'\x3a\xff\x26\xed',
	'Apple_DMG':	b'\x45\x52\x00\x00\x00',
	'CramFS':		b'\x45\x3d\xcd\x28',
	'RomFS':		b'-rom1fs-',
	'EXT2':			b'\x53\xef',
	'FAT':			b'\xeb\x3c\x90',
	'UBI':			b'UBI#',
	'UBI_EC':		b'\x55\x42\x49\x21',
}

NESTED_MAGICS = {
	'ELF':			b'\x7fELF',
	'PE':			b'MZ',
	'MACHO_FAT':	b'\xca\xfe\xba\xbe',
	'MACHO64':		b'\xcf\xfa\xed\xfe',
	'DEX':			b'dex\n',
	'Android_Boot':	b'ANDROID!',
	'DTB':			b'\xd0\x0d\xfe\xed',
	'QCOW2':		b'QFI\xfb',
	'VMDK':			b'KDMV',
	'EXT4':			b'\x53\xef',
}

FIRMWARE_EXTENSIONS = {
	'.bin': 'generic',
	'.img': 'generic',
	'.fw': 'firmware',
	'.firmware': 'firmware',
	'.rom': 'rom',
	'.sbin': 'sbin',
	'.zImage': 'kernel',
	'.uImage': 'uImage',
	'.trx': 'TRX',
	'.sqfs': 'SquashFS',
	'.squashfs': 'SquashFS',
	'.jffs2': 'JFFS2',
	'.ubifs': 'UBIFS',
	'.yaffs2': 'YAFFS2',
	'.cpio': 'CPIO',
	'.iso': 'ISO9660',
	'.zip': 'ZIP',
	'.gz': 'GZIP',
	'.bz2': 'BZIP2',
	'.xz': 'XZ',
	'.lzma': 'LZMA',
	'.lzo': 'LZO',
	'.lz4': 'LZ4',
	'.zst': 'ZSTD',
	'.cramfs': 'CramFS',
}

COMPRESSION_FORMATS = {'GZIP', 'BZIP2', 'XZ', 'LZMA', 'LZO', 'LZ4', 'ZSTD'}

FILESYSTEM_FORMATS = {'SquashFS', 'SquashFS_LZ4', 'SquashFS_XZ', 'SquashFS_ZSTD',
					  'JFFS2', 'UBIFS', 'YAFFS2', 'CPIO', 'CPIO_NEW',
					  'CramFS', 'RomFS', 'EXT2', 'FAT', 'ISO9660'}


def detect_format(data: bytes, offset: int = 0) -> list[dict]:
	"""
	保留 — 检测字节数据开头的固件格式。

	扫描 FIRMWARE_MAGICS 与 NESTED_MAGICS，返回匹配结果列表。
	每条结果含 name、offset、confidence 字段。
	"""
	results = []
	if offset >= len(data):
		return results

	chunk = data[offset:offset + 128]

	for fmt_name, magic in FIRMWARE_MAGICS.items():
		if chunk.startswith(magic):
			confidence = _estimate_confidence(fmt_name, chunk)
			results.append({
				'name': fmt_name,
				'offset': offset,
				'confidence': confidence,
				'source': 'FIRMWARE_MAGICS',
			})

	for fmt_name, magic in NESTED_MAGICS.items():
		if chunk.startswith(magic):
			results.append({
				'name': fmt_name,
				'offset': offset,
				'confidence': 0.3,
				'source': 'NESTED_MAGICS',
			})

	results.sort(key=lambda x: x['confidence'], reverse=True)
	return results


def detect_format_from_file(file_path: str) -> list[dict]:
	"""
	保留 — 从文件路径检测固件格式。

	读取文件头部调用 detect_format，并附加扩展名推断。
	"""
	if not os.path.isfile(file_path):
		logger.warning("File not found: %s", file_path)
		return []

	all_results = []
	try:
		with open(file_path, 'rb') as f:
			f.seek(0)
			data = f.read(256)
	except (OSError, PermissionError) as e:
		logger.error("Cannot read file %s: %s", file_path, e)
		return []

	for off in [0, 512, 1024, 2048]:
		if off < len(data):
			results = detect_format(data, off)
			all_results.extend(results)

	ext = os.path.splitext(file_path)[1].lower()
	if ext in FIRMWARE_EXTENSIONS:
		all_results.append({
			'name': FIRMWARE_EXTENSIONS[ext] + '_by_extension',
			'offset': 0,
			'confidence': 0.65,
			'source': 'EXTENSION',
		})

	seen = set()
	unique = []
	for r in sorted(all_results, key=lambda x: x['confidence'], reverse=True):
		key = (r['name'], r['offset'])
		if key not in seen:
			seen.add(key)
			unique.append(r)

	return unique


def _estimate_confidence(fmt_name: str, data: bytes) -> float:
	"""保留 — 按格式类型启发式估算置信度。"""
	confidence = 0.5

	high_confidence = {'uImage', 'TRX', 'SquashFS', 'GZIP', 'XZ', 'ZSTD', 'ZIP'}
	medium_confidence = {'BZIP2', 'LZMA', 'LZ4', 'LZO', 'JFFS2', 'UBIFS'}

	if fmt_name in high_confidence:
		confidence += 0.4
	elif fmt_name in medium_confidence:
		confidence += 0.25

	if fmt_name == 'uImage' and len(data) >= 64:
		import zlib
		try:
			header_crc = struct.unpack_from('<I', data, 4)[0]
			if header_crc == (zlib.crc32(data[8:64]) & 0xffffffff):
				confidence += 0.10
		except (struct.error, Exception):
			pass

	return min(confidence, 0.95)
