# utils/ 运维工具集，非核心分析流水线
# ~ 2026-07-31
# 广度优先拓展: 二进制I/O、哈希(SimHash/MinHash)、熵分析、模式扫描、
# LRU/TTL/LFU 缓存、序列差分、字符串处理、并发工具、计时统计、
# 安全文件系统操作、序列化+压缩、结构化日志、魔数检测、线段树区间查询

# 二进制读写与 hex dump
from modules.utils.binary_io import (
    read_u8, read_u16, read_u32, read_u64,
    read_i32, read_i64,
    read_uleb128, read_sleb128, encode_uleb128, encode_sleb128,
    align_up, align_down, is_aligned,
    hexdump, hexdump_bytes,
    read_file_bytes, read_file_chunks, write_file_bytes,
    find_bytes, find_all_bytes, extract_range,
)

# 哈希: 密码学 + SimHash + MinHash + 滚动分块
from modules.utils.hash_utils import (
    md5, sha1, sha256, sha512, blake2b, blake2s,
    file_sha256, file_md5,
    simhash_64, simhash_hamming, simhash_similarity,
    tokenize_ngram_hashes,
    minhash_signature, minhash_jaccard_estimate,
    rolling_hash_chunks,
    hash_to_bytes, bytes_to_hash, int_hash,
)

# 熵值分析
from modules.utils.entropy_utils import (
    shannon_entropy, shannon_entropy_fast,
    renyi_entropy,
    byte_histogram, byte_frequencies, most_frequent_bytes,
    chi_square_uniformity,
    compression_ratio_estimate,
    is_likely_code, is_likely_compressed_or_crypto,
    entropy_profile,
)

# 字节模式扫描
from modules.utils.pattern_scan import (
    bmh_search, bmh_search_all,
    AhoCorasick,
    wildcard_match, parse_wildcard_pattern, ida_pattern_search,
    regex_search, regex_search_one,
    make_signature, bytes_diff_locations,
)

# 缓存
from modules.utils.lru import (
    LRUCache, TTLCache, LFUCache,
    memoize, ttl_memoize,
)

# 差分与比对
from modules.utils.diff_utils import (
    myers_diff, unified_diff_lines,
    lcs_length, lcs_sequence,
    sequence_similarity, jaccard_similarity, dice_coefficient,
    byte_diff, hex_diff,
    apply_patch,
    set_difference_report,
)

# 字符串处理
from modules.utils.string_utils import (
    is_utf8, is_ascii, detect_encoding,
    extract_ascii_strings, extract_wide_strings, extract_strings_auto,
    escape_bytes, unescape_to_bytes,
    normalize_line_endings, collapse_whitespace,
    strip_null_bytes, truncate_with_ellipsis,
    ngram_set, ngram_similarity,
    format_size, hex_dump_compact,
)

# 并发工具
from modules.utils.concurrent_utils import (
    ThreadPool, batched, parallel_batch,
    RateLimiter,
    AtomicCounter, ConcurrentDict,
    run_in_thread, wait_all,
)

# 计时与统计
from modules.utils.timer_utils import (
    Timer, CumulativeTimer,
    timed, timeit,
    TimingStats,
    start_timer, stop_timer, get_timer_elapsed, reset_all_timers,
)

# 安全文件操作
from modules.utils.safe_fs import (
    atomic_write, atomic_write_text,
    sanitize_filename,
    is_safe_path, safe_join,
    temp_file, temp_dir,
    walk_files,
    file_checksum_sha256, ensure_dir,
)

# 序列化/压缩
from modules.utils.serialize_utils import (
    json_dumps, json_dump, json_loads, json_load,
    msgpack_dumps, msgpack_loads,
    compress_zlib, decompress_zlib,
    compress_gzip, decompress_gzip,
    compress_lzma, decompress_lzma,
    compress_auto, decompress_auto,
    json_dumps_compressed, json_loads_compressed,
    pickle_dumps, pickle_loads, pickle_dump, pickle_load,
)

# 结构化日志
from modules.utils.log_utils import (
    ColoredFormatter, JSONLineFormatter,
    setup_logging, get_logger, ContextLogger,
    add_rotating_file_handler,
)

# 魔数文件格式检测
from modules.utils.magic_bytes import (
    detect_by_magic, detect_file_type,
    is_executable, is_archive,
    find_magic_offset, add_custom_magic,
)

# 线段树与区间运算
from modules.utils.segment_tree import (
    SegmentTree,
    merge_intervals, intersect_intervals, subtract_intervals,
    interval_length, contains_point, gap_intervals,
)

# 跨尺度熵指纹 (CSEF) —— 多尺度熵 + 跨尺度耦合 + 自适应 Tsallis q
from modules.utils.cross_scale_entropy import (
    CrossScaleProfile,
    compute_csef,
    compute_csef_streaming,
)
from modules.utils.csef_scan import (
    StreamingCSEF,
    csef_region_scan,
    csef_region_labels,
)

# 渐进式 SimHash 二叉检索树 (PSH-Trie)
from modules.utils.simhash_trie import (
    SimHashTrie,
    SimHashIndex,
    SimHashNode,
)

# 自适应多模式匹配引擎 (AMPSE) —— 频率感知 AC 自动机
from modules.utils.adaptive_matcher import (
    AdaptiveAhoCorasick,
    ThreadSafeAdaptiveAC,
)

# 熵引导的内容定义分块 (EG-CDC)
from modules.utils.entropy_cdc import (
    EntropyGuidedCDC,
    ChunkInfo,
    eg_cdc_chunks,
    eg_cdc_boundary_entropy_map,
    eg_cdc_compare,
)
