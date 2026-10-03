#!/usr/bin/env python3
# 语料感知变异引擎 — UCB 多臂老虎机选策略/字节位置熵图引导/MinHash 种子去重.
# 马尔可夫链字节转移建模, 策略权重按成功反馈自适应调整。

import logging as _logging
import random as _rnd
import hashlib as _hashlib
import math as _math
import struct as _strct
from collections import defaultdict as _defaultdict

_mlog = _logging.getLogger(__name__)


def _insert_sort(items, key_fn, reverse=False):
    if items is None or len(items) == 0:
        return []
    arr = list(items)
    n = len(arr)
    i = 1
    while i < n:
        pivot = arr[i]
        j = i - 1
        while j >= 0:
            cmp_j = key_fn(arr[j]) if key_fn else arr[j]
            cmp_p = key_fn(pivot) if key_fn else pivot
            if reverse:
                if cmp_j >= cmp_p:
                    break
            else:
                if cmp_j <= cmp_p:
                    break
            arr[j + 1] = arr[j]
            j -= 1
        arr[j + 1] = pivot
        i += 1
    return arr


class MutatedInput:
    __slots__ = ('m_orig', 'm_mut', 'm_type', 'm_sem_ok', 'm_conf')

    def __init__(self, orig, mutated, mtype, sem_ok=True, conf=0.6):
        self.m_orig  = orig
        self.m_mut   = mutated
        self.m_type  = mtype
        self.m_sem_ok = sem_ok
        self.m_conf  = float(conf) if conf is not None else 0.6

    def __repr__(self):
        return f"<MutatedInput type={self.m_type} conf={self.m_conf:.2f} len={len(self.m_mut)}>"

    @property
    def original(self):
        return self.m_orig

    @property
    def mutated(self):
        return self.m_mut

    @property
    def mutation_type(self):
        return self.m_type


class MutationResult:
    __slots__ = ('m_ok', 'm_muts', 'm_total', 'm_seed')

    def __init__(self, ok, muts, total=0, seed=''):
        self.m_ok   = bool(ok)
        self.m_muts = muts if muts else []
        self.m_total = total if total > 0 else len(self.m_muts)
        self.m_seed = seed if seed else ''

    def unique_count_mt(self):
        seen = set()
        dwIdx = 0
        while dwIdx < len(self.m_muts):
            seen.add(self.m_muts[dwIdx].m_mut)
            dwIdx += 1
        return len(seen)

    @property
    def success(self):
        return self.m_ok

    @property
    def mutations(self):
        return self.m_muts

    @property
    def total(self):
        return self.m_total

    @property
    def seed(self):
        return self.m_seed


class InputGrammar:
    # 字节n-gram补偿word-only替换覆盖率不足; Markov链保持语料级字节邻接性; per-offset Shannon熵引导高价值变异位置

    def __init__(self, max_tokens=800):
        self._tokens = []
        self._bgrams = {}
        self._max_n  = max_tokens
        self._ready  = False
        self._markov = _defaultdict(lambda: _defaultdict(int))
        self._byte_entropy = {}
        self._max_align = 0

    @property
    def tokens(self):
        return self._tokens

    @tokens.setter
    def tokens(self, value):
        self._tokens = list(value) if value else []

    def learn_from_corpus(self, corpus):
        self.learn_mt(corpus)

    def learn_mt(self, corpus):
        if corpus is None or len(corpus) == 0:
            _mlog.warning("InputGrammar: empty corpus")
            return
        raw = []
        dwIdx = 0
        n_corpus = len(corpus)
        while dwIdx < n_corpus and dwIdx < 100:
            item = corpus[dwIdx]
            if item is None:
                dwIdx += 1; continue
            try:
                txt = item.decode('ascii', errors='ignore') if isinstance(item, bytes) else str(item)
                parts = txt.split()
                j = 0
                while j < len(parts):
                    raw.append(parts[j])
                    j += 1
            except Exception:
                pass
            dwIdx += 1
        freq = {}
        dwIdx = 0
        while dwIdx < len(raw):
            t = raw[dwIdx]
            freq[t] = freq.get(t, 0) + 1
            dwIdx += 1
        sorted_items = _insert_sort(freq.items(), key_fn=lambda x: x[1], reverse=True)
        self._tokens = [t for t, _ in sorted_items[:self._max_n]]
        # 字节位置熵图: 统计每个偏移的字节分布
        byte_positions = _defaultdict(lambda: _defaultdict(int))
        dwIdx = 0
        while dwIdx < n_corpus and dwIdx < 200:
            item = corpus[dwIdx]
            if isinstance(item, bytes):
                data = item
            elif isinstance(item, str):
                data = item.encode('ascii', errors='ignore')
            else:
                dwIdx += 1; continue
            bpos = 0
            while bpos < len(data):
                byte_positions[bpos][data[bpos]] += 1
                bpos += 1
            # 对齐长度用于后续变异定位
            if len(data) > self._max_align:
                self._max_align = len(data)
            # bigram + Markov转移
            j = 0
            while j < len(data) - 1:
                pair = data[j:j+2]
                self._bgrams[pair] = self._bgrams.get(pair, 0) + 1
                self._markov[data[j]][data[j+1]] += 1
                j += 1
            dwIdx += 1
        # 为每个偏移计算Shannon熵
        self._byte_entropy.clear()
        for bpos, byte_counts in byte_positions.items():
            total = sum(byte_counts.values())
            if total == 0:
                continue
            ent = 0.0
            for count in byte_counts.values():
                if count > 0:
                    p = count / total
                    ent -= p * _math.log2(p)
            self._byte_entropy[bpos] = ent
        self._ready = True
        _mlog.debug(f"InputGrammar: {len(self._tokens)} tokens, {len(self._bgrams)} bigrams, "
                    f"{len(self._markov)} markov states, {len(self._byte_entropy)} entropy positions")

    def ready_mt(self):
        return self._ready

    def sample_markov_byte(self, prev_byte: int) -> int:
        # 给定前字节从条件分布采样后继字节; 无转移数据时返回随机值
        transitions = self._markov.get(prev_byte)
        if not transitions:
            return _rnd.randint(0, 255)
        total = sum(transitions.values())
        r = _rnd.randint(0, total)
        cumulative = 0
        for byte_val, cnt in transitions.items():
            cumulative += cnt
            if r <= cumulative:
                return byte_val
        return _rnd.choice(list(transitions.keys()))

    def entropy_biased_position(self, data_len: int) -> int:
        # 高熵偏移=corpus中该位置字节值变化大, 更可能是数据字段而非固定头/尾
        if not self._byte_entropy or data_len <= 0:
            return _rnd.randint(0, max(data_len - 1, 0))
        weighted = []
        for pos in range(data_len):
            ent = self._byte_entropy.get(pos, 1.0)
            weighted.append((pos, max(ent, 0.1)))
        total_w = sum(w for _, w in weighted)
        if total_w <= 0:
            return _rnd.randint(0, data_len - 1)
        r = _rnd.random() * total_w
        cumulative = 0.0
        for pos, w in weighted:
            cumulative += w
            if r <= cumulative:
                return pos
        return weighted[-1][0]

    def max_entropy_offset(self) -> int:
        # 返回熵最高的字节偏移, 用于高价值变异定位
        if not self._byte_entropy:
            return 0
        best_pos = 0
        best_ent = -1.0
        for pos, ent in self._byte_entropy.items():
            if ent > best_ent:
                best_ent = ent
                best_pos = pos
        return best_pos


# UCB1 多臂老虎机策略选择
_STRAT_W = {
    'bit_flip':  0.25,
    'multi_bit': 0.15,
    'byte_repl': 0.20,
    'insert':    0.15,
    'delete':    0.05,
    'shuffle':   0.10,
    'crossover': 0.10,
}
_KEYS = list(_STRAT_W.keys())

_cum = 0.0
_CUM_TABLE = []
ki = 0
while ki < len(_KEYS):
    s = _KEYS[ki]
    w = _STRAT_W[s]
    _cum += w
    _CUM_TABLE.append((_cum, s))
    ki += 1

# UCB 状态：每臂的选择次数与累积得分
_ucb_pulls = {s: 1 for s in _KEYS}
_ucb_score = {s: 0.5 for s in _KEYS}
_ucb_total = len(_KEYS)
_ucb_mode = True
_ucb_explore_weight = 0.8


def _pick_strat_mt():
    # UCB1选变异策略, 回退加权随机; 探索项含随机抖动打破平局
    global _ucb_mode
    if _ucb_mode:
        ucb_vals = []
        for s in _KEYS:
            avg = _ucb_score[s] / max(_ucb_pulls[s], 1)
            explore = _math.sqrt(
                (_ucb_explore_weight * _math.log(max(_ucb_total, 1))) / max(_ucb_pulls[s], 1)
            )
            jitter = _rnd.random() * 0.001
            ucb_vals.append((avg + explore + jitter, s))
        # 取UCB最高的臂
        best_val = -1.0
        best_strat = 'bit_flip'
        for val, s in ucb_vals:
            if val > best_val:
                best_val = val
                best_strat = s
        return best_strat
    # 回退: 加权随机
    r = _rnd.random() * _cum
    ti = 0
    while ti < len(_CUM_TABLE):
        thresh, name = _CUM_TABLE[ti]
        if r <= thresh:
            return name
        ti += 1
    return 'bit_flip'


def _adapt_weights_mt(success_counts: dict):
    # 成功策略获bonus, 失败策略衰减; 同步更新UCB状态表
    global _CUM_TABLE, _cum, _ucb_total
    alpha = 0.15
    for strat in list(_STRAT_W.keys()):
        sc = success_counts.get(strat, 0)
        fc = success_counts.get(f'_fail_{strat}', 0)
        total = sc + fc
        if total == 0:
            continue
        success_rate = sc / total
        _STRAT_W[strat] = _STRAT_W[strat] * (1 - alpha) + success_rate * alpha
        _STRAT_W[strat] = min(max(_STRAT_W[strat], 0.02), 0.40)
        # UCB: 成功+1得分, 失败-0.3得分, 拉绳+1
        try:
            _ucb_score[strat] += sc * 1.0 - fc * 0.3
            _ucb_pulls[strat] += total
        except Exception:
            pass
    _ucb_total = sum(_ucb_pulls.values())
    _cum = 0.0
    _CUM_TABLE.clear()
    for s in _KEYS:
        w = _STRAT_W[s]
        _cum += w
        _CUM_TABLE.append((_cum, s))
    _mlog.debug(f"adapted weights: {dict(_STRAT_W)}")


# MinHash 种子去重：避免重复变异相似输入
_MINHASH_SEEDS = 256           # 哈希函数数量
_MINHASH_MOD = (1 << 61) - 1   # Mersenne 素数
_MINHASH_SIG_CACHE = []        # (signature_tuple, seed_hash)
_MINHASH_CACHE_LIMIT = 128


def _minhash_sig(data: bytes, n_seeds: int = _MINHASH_SEEDS) -> tuple:
    # n_seeds个独立哈希函数, 对每个2-gram字节shingle取最小哈希值
    if not data or len(data) < 2:
        return tuple([0] * n_seeds)
    # 预置哈希种子
    rnd_state = _rnd.getstate()
    _rnd.seed(0x23D5F9A1)
    seeds = [_rnd.randint(1, _MINHASH_MOD - 1) for _ in range(n_seeds)]
    _rnd.setstate(rnd_state)
    mins = [_MINHASH_MOD + 1] * n_seeds
    # 字节2-gram shingles
    dlen = len(data)
    pos = 0
    while pos < dlen - 1:
        shingle = (data[pos] << 8) | data[pos + 1]
        for s_idx in range(n_seeds):
            hv = (shingle * seeds[s_idx] + seeds[s_idx]) % _MINHASH_MOD
            if hv < mins[s_idx]:
                mins[s_idx] = hv
        pos += 1
        if pos > 512:
            break
    return tuple(mins)


def _minhash_jaccard(sig_a: tuple, sig_b: tuple, n_seeds: int = _MINHASH_SEEDS) -> float:
    if len(sig_a) != len(sig_b):
        return 0.0
    matches = 0
    i = 0
    while i < len(sig_a):
        if sig_a[i] == sig_b[i]:
            matches += 1
        i += 1
    return matches / len(sig_a)


def _seed_is_novel(data: bytes, threshold: float = 0.82) -> bool:
    # 相似度>=82%视为重复种子; 空/过短数据由上层fingerprint集合去重
    if not data or len(data) < 2:
        return True
    s_hash = _hashlib.md5(data).hexdigest()
    sig = _minhash_sig(data)

    cache = _MINHASH_SIG_CACHE
    for cached_sig, cached_hash in cache:
        if cached_hash == s_hash:
            return False
        jac = _minhash_jaccard(sig, cached_sig)
        if jac >= threshold:
            return False

    cache.append((sig, s_hash))
    while len(cache) > _MINHASH_CACHE_LIMIT:
        cache.pop(0)
    return True


def _register_seed_hash(data: bytes):
    if not data:
        return
    s_hash = _hashlib.md5(data).hexdigest()
    sig = _minhash_sig(data)
    _MINHASH_SIG_CACHE.append((sig, s_hash))
    while len(_MINHASH_SIG_CACHE) > _MINHASH_CACHE_LIMIT:
        _MINHASH_SIG_CACHE.pop(0)


class SemanticPreservingMutator:
    def __init__(self, grammar):
        self._gram = grammar
        self._log = []
        self._feedback = {}
        self._mutation_session = 0

    def mutate(self, data, count=5):
        return self.mutate_mt(data, count)

    def mutate_mt(self, data, count=5):
        if data is None or len(data) == 0:
            _mlog.warning("mutate: empty input")
            return []
        muts = []
        dlen = len(data)
        data_bytes = data if isinstance(data, bytes) else data.encode('ascii', errors='ignore')
        dwIdx = 0
        while dwIdx < count:
            strat = _pick_strat_mt()
            buf = bytearray(data_bytes)
            try:
                if strat == 'bit_flip' and dlen > 0:
                    # 熵引导: 高熵位置更可能暴露解析差异
                    bp = self._gram.entropy_biased_position(dlen)
                    bit = _rnd.randint(0, 7)
                    buf[bp] ^= (1 << bit)
                elif strat == 'multi_bit' and dlen > 0:
                    bp = self._gram.entropy_biased_position(dlen)
                    nb = _rnd.randint(1, 4)
                    b = 0
                    while b < nb:
                        bit = _rnd.randint(0, 7)
                        buf[bp] ^= (1 << bit)
                        b += 1
                elif strat == 'byte_repl':
                    if self._gram._markov and dlen > 1:
                        pos = self._gram.entropy_biased_position(dlen)
                        prev = data_bytes[pos - 1] if pos > 0 else data_bytes[0]
                        buf[pos] = self._gram.sample_markov_byte(prev)
                    elif self._gram._tokens and dlen > 0:
                        pos = _rnd.randint(0, dlen - 1)
                        tok = _rnd.choice(self._gram._tokens)
                        tb = tok.encode('ascii', errors='ignore')[:1]
                        if tb:
                            buf[pos] = tb[0]
                elif strat == 'insert':
                    if self._gram._bgrams:
                        pos = self._gram.entropy_biased_position(dlen + 1)
                        ngl = list(self._gram._bgrams.keys())
                        if ngl:
                            pick = _rnd.choice(ngl)
                            buf[pos:pos] = pick
                elif strat == 'crossover' and dlen >= 4:
                    p1 = _rnd.randint(0, dlen - 2)
                    p2 = _rnd.randint(p1 + 1, min(p1 + 64, dlen))
                    segment = buf[p1:p2]
                    buf[p1:p2] = bytes(reversed(segment))
                elif strat == 'delete' and dlen > 1:
                    # 低熵偏移删除更安全
                    lo_ent_positions = []
                    p = 0
                    while p < dlen:
                        if self._gram._byte_entropy.get(p, 1.0) < 2.0:
                            lo_ent_positions.append(p)
                        p += 1
                    if lo_ent_positions:
                        pos = _rnd.choice(lo_ent_positions)
                    else:
                        pos = _rnd.randint(0, dlen - 1)
                    del buf[pos]
                    dlen -= 1
                elif strat == 'shuffle' and dlen >= 4:
                    pos = _rnd.randint(0, dlen - 4)
                    a = buf[pos:pos+2]
                    b = buf[pos+2:pos+4]
                    buf[pos:pos+2] = b
                    buf[pos+2:pos+4] = a

                conf = 0.7 if strat in ('bit_flip', 'multi_bit') else (0.3 if strat == 'delete' else 0.5)
                conf = min(max(conf, 0.1), 1.0)
                muts.append(MutatedInput(
                    orig=data_bytes, mutated=bytes(buf), mtype=strat,
                    sem_ok=(strat != 'delete'), conf=conf))
                self._feedback[strat] = self._feedback.get(strat, 0) + 1
            except Exception as _e:
                _mlog.debug(f"mutation #{dwIdx} ({strat}) failed: {_e}")
                fail_key = f'_fail_{strat}'
                self._feedback[fail_key] = self._feedback.get(fail_key, 0) + 1
            dwIdx += 1
        self._log.append({'seed_len': dlen, 'count': count, 'generated': len(muts)})
        total_feedback = sum(v for k, v in self._feedback.items() if not k.startswith('_fail_'))
        self._mutation_session += 1
        if total_feedback > 0 and total_feedback % 50 == 0:
            _adapt_weights_mt(self._feedback)
        return muts

    def flush_feedback(self):
        if self._feedback:
            _adapt_weights_mt(self._feedback)
            self._feedback.clear()


class AIMutator:
    # MinHash种子去重: 相似度>=82%的种子直接跳过变异

    def __init__(self):
        self._gram = InputGrammar()
        self._mut  = SemanticPreservingMutator(self._gram)
        self._trained = False
        self._mutation_fingerprints = set()

    @property
    def grammar(self):
        return self._gram

    def learn(self, corpus):
        self.learn_mt(corpus)

    def run(self, seed, count=5, dedup_threshold=0.82):
        return self.run_mt(seed, count, dedup_threshold)

    def learn_mt(self, corpus):
        if corpus is None:
            _mlog.warning("AIMutator.learn: null corpus")
            return
        self._gram.learn_mt(corpus)
        self._trained = self._gram.ready_mt()

    def run_mt(self, seed, count=5, dedup_threshold=0.82):
        if seed is None:
            _mlog.warning("AIMutator.run: null seed")
            return MutationResult(ok=False, muts=[], seed='')
        sh = ''
        try:
            raw = seed if isinstance(seed, bytes) else str(seed).encode()
            sh = _hashlib.md5(raw).hexdigest()[:8]
        except Exception:
            pass
        # MinHash去重检查
        if sh in self._mutation_fingerprints:
            _mlog.debug(f"MinHash: duplicate seed {sh} skipped")
            return MutationResult(ok=False, muts=[], seed=sh)
        if not _seed_is_novel(raw, threshold=dedup_threshold):
            _mlog.debug(f"MinHash: near-duplicate seed {sh} skipped (sim >= {dedup_threshold})")
            return MutationResult(ok=False, muts=[], seed=sh)
        self._mutation_fingerprints.add(sh)
        try:
            m = self._mut.mutate_mt(seed, count)
            # 变异输出注册防止后续循环变异产生重复
            for mut_entry in m:
                _register_seed_hash(mut_entry.m_mut)
            return MutationResult(ok=True, muts=m, total=len(m), seed=sh)
        except Exception as _e:
            _mlog.error(f"AIMutator.run exploded: {_e}")
            return MutationResult(ok=False, muts=[], seed=sh)


def create_ai_mutator_mt():
    return AIMutator()

create_ai_mutator = create_ai_mutator_mt
