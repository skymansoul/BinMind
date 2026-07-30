"""
Heap exploitation analysis. Supports ptmalloc (glibc) allocator
patterns: tcache poisoning, fastbin dup, unsorted bin attack,
and house-of-* family primitives.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def detect_allocator(binary_path: str) -> str:
    """Guess the allocator from binary characteristics."""
    # For now, heuristic based on import analysis
    try:
        with open(binary_path, 'rb') as f:
            data = f.read(65536)
        if b'ptmalloc' in data or b'__malloc_hook' in data:
            return 'ptmalloc'
        if b'jemalloc' in data:
            return 'jemalloc'
        if b'tcmalloc' in data:
            return 'tcmalloc'
    except Exception:
        pass
    return 'ptmalloc'  # default on Linux


def analyze_allocation_sites(binary_path: str) -> List[Dict]:
    """Find malloc/calloc/realloc/free call sites and flag risky patterns."""
    import subprocess
    from config import R2_PATH

    try:
        proc = subprocess.run(
            [R2_PATH, '-q', '-e', 'io.color=false',
             '-c', 'axt malloc; axt calloc; axt free; axt realloc',
             binary_path],
            capture_output=True, text=True, timeout=60)
        raw = proc.stdout
    except Exception:
        return []

    findings = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        # look for patterns: free() without nulling, double-free potential
        if 'free' in line:
            findings.append({
                'site': line.strip(),
                'risk': 'potential use-after-free',
                'note': 'verify if pointer is nulled after free',
            })

    return findings


class HeapLayout:
    """Simple heap layout description for exploit planning."""

    def __init__(self, allocator: str = 'ptmalloc',
                 chunk_size: int = 0x80, tcache_count: int = 7):
        self.allocator = allocator
        self.chunk_size = chunk_size
        self.tcache_count = tcache_count
        self.bins: Dict[str, list] = {
            'tcache': [], 'fastbin': [], 'smallbin': [],
            'largebin': [], 'unsorted': [],
        }

    def add_chunk(self, size: int, bin_type: str = 'tcache'):
        if bin_type in self.bins:
            self.bins[bin_type].append({'size': size, 'status': 'free'})

    def plan_poison(self, target_addr: int) -> Dict:
        """
        Plan a tcache poisoning attack. Returns steps to achieve
        arbitrary write at target_addr.
        """
        steps = []
        n = self.tcache_count
        chunk = self.chunk_size

        steps.append(f'1. Allocate {n} chunks of size {hex(chunk)}')
        steps.append(f'2. Free all {n} chunks to fill tcache')
        steps.append(f'3. Free one more to send to unsorted bin (leak libc)')
        steps.append('4. Use UAF/double-free to overwrite tcache fd pointer')
        steps.append(f'5. Target address: {hex(target_addr)}')

        return {
            'technique': 'tcache poisoning',
            'steps': steps,
            'requires_leak': True,
            'chunk_size': chunk,
            'tcache_fill': n,
            'target': hex(target_addr),
        }


def suggest_technique(vuln_type: str, allocator: str = 'ptmalloc') -> Dict:
    """Suggest a heap exploitation technique based on vuln type."""

    techs = {
        'use-after-free': {
            'technique': 'tcache-poisoning',
            'difficulty': 'easy',
            'glibc_max': '2.35',
            'steps': [
                'fill tcache (7 frees)',
                'trigger UAF to leak heap/libc',
                'overwrite freed chunk fd pointer',
                'alloc twice to get arbitrary write',
            ],
        },
        'double-free': {
            'technique': 'fastbin-dup',
            'difficulty': 'medium',
            'glibc_max': '2.31',
            'steps': [
                'free(A), free(B), free(A)  // bypass double-free check',
                'alloc to get overlapping chunk',
                'overwrite fd to target',
            ],
        },
        'heap-buffer-overflow': {
            'technique': 'house-of-force / overlapping-chunks',
            'difficulty': 'medium',
            'glibc_max': '2.32',
            'steps': [
                'overflow adjacent chunk metadata',
                'forge chunk size to overlap target region',
                'free and re-allocate overlapping chunk',
                'write through overlapping chunk',
            ],
        },
    }

    return techs.get(vuln_type, {
        'technique': 'unknown',
        'difficulty': 'unknown',
        'steps': ['manual analysis required'],
    })
