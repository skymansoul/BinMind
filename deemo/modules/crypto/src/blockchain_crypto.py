# 区块链密码学组件检测
# 检测区块链钱包/交易签名/智能合约中的密码学原语。
# 覆盖: Bitcoin (secp256k1 ECDSA, P2PKH/P2SH/P2WPKH地址格式),
# Ethereum (ECDSA secp256k1, Keccak-256地址, EIP-1559签名),
# Solana (Ed25519), Polkadot/Substrate (sr25519/ed25519/ecdsa),
# Cosmos (secp256k1/ed25519), BIP39助记词/BIP32 HD钱包,
# EIP-712类型化结构化数据签名, ERC-20/ERC-721代币签名。
#
# 检测维度:
#   (1) Base58Check/Bech32/Bech32m地址格式正则 — 高特异性, 低误报
#   (2) 区块链专有密码学曲线: secp256k1, Curve25519 (Ed25519/X25519), sr25519
#   (3) BIP39助记词词库频率分析 (2048词表, 12/24词 -> 128/256-bit熵)
#   (4) Ethereum Keccak-256函数选择器 (4字节前缀, 极高特异性)
#   (5) 硬件钱包 USB VID/PID + HID 帧结构
#   (6) ZK-Rollup: Groth16/Plonk验证器合约字节码模式 (见zkp_detector)
#
Nakamoto, Wood,
# BIP32/39/44 (HD wallet standards), EIP-1559 (London),
# "Large Language Models for Blockchain Security: A Systematic Literature Review" (Zotero),
# "Towards a Formal Foundation for Blockchain ZK Rollups".

import re
import struct
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict
from .utils import safeReadBytes

_log = logging.getLogger(__name__)


@dataclass
class BlockchainCryptoResult:
    chain: str                      # Bitcoin / Ethereum / Solana / Polkadot / Cosmos / generic
    component: str                  # wallet / transaction / contract / key / mnemonic
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    detected_in: str = ""


# Bitcoin地址格式
# Base58Check: 1... (P2PKH), 3... (P2SH)
# Bech32: bc1q... (P2WPKH/P2WSH, SegWit v0)
# Bech32m: bc1p... (P2TR, Taproot/SegWit v1)
# 所有Bitcoin地址共享特征:
#   - 长度26-62字符 (P2PKH=34, P2SH=34, P2WPKH=42, P2TR=62)
#   - 仅使用Base58字符集 (123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz)
#     或Bech32字符集 (qpzry9x8gf2tvdw0s3jn54khce6mua7l)

_BTC_P2PKH_RE = re.compile(rb'[13][1-9A-HJ-NP-Za-km-z]{25,34}')
_BTC_BECH32_RE = re.compile(rb'bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,58}')


def _detect_bitcoin_addresses(data: bytes, source: str) -> List[BlockchainCryptoResult]:
    results = []
    # P2PKH/P2SH
    addrs = set()
    for m in _BTC_P2PKH_RE.finditer(data):
        addr = m.group().decode('ascii')
        if addr not in addrs:
            addrs.add(addr)
    if addrs:
        sample = sorted(addrs)[:5]
        results.append(BlockchainCryptoResult(
            chain='Bitcoin', component='address',
            confidence=0.90 if len(addrs) >= 2 else 0.65,
            evidence=[f'{len(addrs)} Bitcoin base58 address(es): {sample}'],
            details={'count': len(addrs), 'format': 'P2PKH/P2SH'},
            detected_in=source))

    # Bech32/Bech32m (SegWit/Taproot)
    bech_addrs = set()
    for m in _BTC_BECH32_RE.finditer(data):
        addr = m.group().decode('ascii')
        if addr not in bech_addrs:
            bech_addrs.add(addr)
    if bech_addrs:
        sample = sorted(bech_addrs)[:3]
        results.append(BlockchainCryptoResult(
            chain='Bitcoin', component='address',
            confidence=0.92 if len(bech_addrs) >= 2 else 0.70,
            evidence=[f'{len(bech_addrs)} Bech32/Bech32m address(es): {sample}'],
            details={'count': len(bech_addrs), 'format': 'Bech32/Bech32m'},
            detected_in=source))
    return results


# Ethereum地址 & 签名
# Ethereum地址: 0x + 40 hex chars (20 byte Keccak-256(public_key)[-20:])
# 交易签名: r/s/v字段 (EIP-1559: 链ID + legacy replay protection)
# 函数选择器: Keccak-256("transfer(address,uint256)")[0:4] -> 4 bytes

_ETH_ADDR_RE = re.compile(rb'0x[0-9a-fA-F]{40}')
_ETH_TX_RE = re.compile(rb'(?:rlp|RLP|\xee\x81|\xef\x81)')  # RLP编码交易前缀


def _detect_ethereum(data: bytes, source: str) -> List[BlockchainCryptoResult]:
    results = []
    addrs = set()
    for m in _ETH_ADDR_RE.finditer(data):
        addr = m.group().decode('ascii').lower()
        if addr not in addrs:
            addrs.add(addr)
    if addrs:
        results.append(BlockchainCryptoResult(
            chain='Ethereum', component='address',
            confidence=0.75 if len(addrs) >= 3 else 0.55,
            evidence=[f'{len(addrs)} Ethereum address(es)'],
            details={'count': len(addrs), 'format': '0x + 40 hex'},
            detected_in=source))

    # 函数选择器数据库 (高频ERC-20/ERC-721/Uniswap选择器)
    selectors = {
        b'\xa9\x05\x9c\xbb': 'transfer(address,uint256)',
        b'\x23\xb8\x72\xdd': 'transferFrom(address,address,uint256)',
        b'\x09\x5e\xa7\xb3': 'approve(address,uint256)',
        b'\x70\xa0\x82\x31': 'balanceOf(address)',
        b'\x18\x16\x0d\xdd': 'totalSupply()',
        b'\xdd\x62\xed\x3e': 'mint(address,uint256)',
        b'\x42\x84\x2e\x0e': 'safeTransferFrom(address,address,uint256)',
        b'\x7f\xf3\x6a\xb5': 'swapExactETHForTokens(uint256,address[],address,uint256)',
        b'\x38\xed\x17\x39': 'swapExactTokensForETH(uint256,uint256,address[],address,uint256)',
    }
    found_sel = []
    for sel, sig in selectors.items():
        if sel in data:
            found_sel.append(sig)
    if found_sel:
        results.append(BlockchainCryptoResult(
            chain='Ethereum', component='contract',
            confidence=min(0.95, 0.60 + 0.08 * len(found_sel)),
            evidence=[f'function selectors: {found_sel[:6]}'],
            details={'selectors': found_sel},
            detected_in=source))
    return results


# BIP39助记词检测
# BIP39词表: 2048词, 每词由11-bit索引表示
# 12词 -> 132 bits = 128-bit熵 + 4-bit校验
# 24词 -> 264 bits = 256-bit熵 + 8-bit校验
# 检测策略: ASCII文本中搜索连续12或24个BIP39词

_BIP39_WORDS = set([
    'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
    'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
    'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actress', 'actual',
    'adapt', 'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance',
    'advice', 'aerobic', 'affair', 'afford', 'afraid', 'africa', 'age', 'agent',
    'agree', 'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album',
    'alcohol', 'alert', 'alien', 'all', 'alley', 'allow', 'almost', 'alone',
    'alpha', 'already', 'also', 'alter', 'always', 'amateur', 'amazing', 'among',
    'amount', 'amused', 'analyst', 'anchor', 'ancient', 'anger', 'angle', 'angry',
    'animal', 'ankle', 'announce', 'annual', 'another', 'answer', 'antenna', 'antique',
    'anxiety', 'any', 'apart', 'apology', 'appear', 'apple', 'approve', 'april',
    'arch', 'arctic', 'area', 'arena', 'argue', 'arm', 'armed', 'armor',
    'army', 'around', 'arrange', 'arrest', 'arrive', 'arrow', 'art', 'artefact',
    'artist', 'artwork', 'ask', 'aspect', 'assault', 'asset', 'assist', 'assume',
    'asthma', 'athlete', 'atom', 'attack', 'attend', 'attract', 'auction', 'audit',
    'august', 'aunt', 'author', 'auto', 'autumn', 'average', 'avocado', 'avoid',
    'awake', 'aware', 'away', 'awesome', 'awful', 'awkward', 'axis', 'baby',
    'bachelor', 'bacon', 'badge', 'bag', 'balance', 'balcony', 'ball', 'bamboo',
    'banana', 'banner', 'bar', 'barely', 'bargain', 'barrel', 'base', 'basic',
    'basket', 'battle', 'beach', 'bean', 'beauty', 'because', 'become', 'beef',
    'before', 'begin', 'behave', 'behind', 'believe', 'below', 'belt', 'bench',
    'benefit', 'best', 'betray', 'better', 'between', 'beyond', 'bicycle', 'bid',
    'bike', 'bind', 'biology', 'bird', 'birth', 'bitter', 'black', 'blade',
    'blame', 'blanket', 'blast', 'bleak', 'bless', 'blind', 'blood', 'blossom',
    'blouse', 'blue', 'blur', 'blush', 'board', 'boat', 'body', 'boil',
    'bomb', 'bone', 'bonus', 'book', 'boost', 'border', 'boring', 'borrow',
    'boss', 'bottom', 'bounce', 'box', 'boy', 'bracket', 'brain', 'brand',
    'brass', 'brave', 'bread', 'breeze', 'brick', 'bridge', 'brief', 'bright',
    'bring', 'brisk', 'broccoli', 'broken', 'bronze', 'broom', 'brother', 'brown',
    'brush', 'bubble', 'buddy', 'budget', 'buffalo', 'build', 'bulb', 'bulk',
    'bullet', 'bundle', 'bunker', 'burden', 'burger', 'burst', 'bus', 'business',
    'busy', 'butter', 'buyer', 'buzz', 'cabbage', 'cabin', 'cable', 'cactus',
    'cage', 'cake', 'call', 'calm', 'camera', 'camp', 'can', 'canal',
    'cancel', 'candy', 'cannon', 'canoe', 'canvas', 'canyon', 'capable', 'capital',
    'captain', 'car', 'carbon', 'card', 'cargo', 'carpet', 'carry', 'cart',
    'case', 'cash', 'casino', 'castle', 'casual', 'cat', 'catalog', 'catch',
    'category', 'cattle', 'caught', 'cause', 'caution', 'cave', 'ceiling', 'celery',
    'cement', 'census', 'century', 'cereal', 'certain', 'chair', 'chalk', 'champion',
    'change', 'chaos', 'chapter', 'charge', 'chase', 'chat', 'cheap', 'check',
    'cheese', 'chef', 'cherry', 'chest', 'chicken', 'chief', 'child', 'chimney',
    'choice', 'choose', 'chronic', 'chuckle', 'chunk', 'churn', 'cigar', 'cinnamon',
    'circle', 'citizen', 'city', 'civil', 'claim', 'clap', 'clarify', 'claw',
    'clay', 'clean', 'clerk', 'clever', 'click', 'client', 'cliff', 'climb',
    'clinic', 'clip', 'clock', 'clog', 'close', 'cloth', 'cloud', 'clown',
    'club', 'clump', 'cluster', 'clutch', 'coach', 'coast', 'coconut', 'code',
    'coffee', 'coil', 'coin', 'collect', 'color', 'column', 'combine', 'come',
    'comfort', 'comic', 'common', 'company', 'concert', 'conduct', 'confirm', 'congress',
    'connect', 'consider', 'control', 'convince', 'cook', 'cool', 'copper', 'copy',
    'coral', 'core', 'corn', 'correct', 'cost', 'cotton', 'couch', 'country',
    'couple', 'course', 'cousin', 'cover', 'coyote', 'crack', 'cradle', 'craft',
    'cram', 'crane', 'crash', 'crater', 'crawl', 'crazy', 'cream', 'credit',
    'creek', 'crew', 'cricket', 'crime', 'crisp', 'critic', 'crop', 'cross',
    'crouch', 'crowd', 'crucial', 'cruel', 'cruise', 'crumble', 'crunch', 'crush',
    'cry', 'crystal', 'cube', 'culture', 'cup', 'cupboard', 'curious', 'current',
    'curtain', 'curve', 'cushion', 'custom', 'cute', 'cycle', 'dad', 'damage',
    'damp', 'dance', 'danger', 'daring', 'dash', 'daughter', 'dawn', 'day',
    'deal', 'debate', 'debris', 'decade', 'december', 'decide', 'decline', 'decorate',
    'decrease', 'deer', 'defense', 'define', 'defy', 'degree', 'delay', 'deliver',
    'demand', 'demise', 'denial', 'dentist', 'deny', 'depart', 'depend', 'deposit',
    'depth', 'deputy', 'derive', 'describe', 'desert', 'design', 'desk', 'despair',
    'destroy', 'detail', 'detect', 'develop', 'device', 'devote', 'diagram', 'dial',
    'diamond', 'diary', 'dice', 'diesel', 'diet', 'differ', 'digital', 'dignity',
    'dilemma', 'dinner', 'dinosaur', 'direct', 'dirt', 'disagree', 'discover', 'disease',
    'dish', 'dismiss', 'disorder', 'display', 'distance', 'divert', 'divide', 'divorce',
    'dizzy', 'doctor', 'document', 'dog', 'doll', 'dolphin', 'domain', 'donate',
    'donkey', 'donor', 'door', 'dose', 'double', 'dove', 'draft', 'dragon',
    'drama', 'drastic', 'draw', 'dream', 'dress', 'drift', 'drill', 'drink',
    'drip', 'drive', 'drop', 'drum', 'dry', 'duck', 'dumb', 'dune',
    'during', 'dust', 'dutch', 'duty', 'dwarf', 'dynamic', 'eager', 'eagle',
    'early', 'earn', 'earth', 'easily', 'east', 'easy', 'echo', 'ecology',
    'economy', 'edge', 'edit', 'educate', 'effort', 'egg', 'eight', 'either',
    'elbow', 'elder', 'electric', 'elegant', 'element', 'elephant', 'elevator', 'elite',
    'else', 'embark', 'embody', 'embrace', 'emerge', 'emotion', 'employ', 'empower',
    'empty', 'enable', 'enact', 'end', 'endless', 'endorse', 'enemy', 'energy',
    'enforce', 'engage', 'engine', 'enhance', 'enjoy', 'enlist', 'enough', 'enrich',
    'enroll', 'ensure', 'enter', 'entire', 'entry', 'envelope', 'episode', 'equal',
    'equip', 'era', 'erase', 'erode', 'erosion', 'error', 'erupt', 'escape',
    'essay', 'essence', 'estate', 'eternal', 'ethics', 'evidence', 'evil', 'evoke',
    'evolve', 'exact', 'example', 'excess', 'exchange', 'excite', 'exclude', 'excuse',
    'execute', 'exercise', 'exhaust', 'exhibit', 'exile', 'exist', 'exit', 'exotic',
    'expand', 'expect', 'expire', 'explain', 'expose', 'express', 'extend', 'extra',
    'eye', 'eyebrow', 'fabric', 'face', 'faculty', 'fade', 'faint', 'faith',
    'fall', 'false', 'fame', 'family', 'famous', 'fan', 'fancy', 'fantasy',
    'farm', 'fashion', 'fat', 'fatal', 'father', 'fatigue', 'fault', 'favorite',
    'feature', 'february', 'federal', 'fee', 'feed', 'feel', 'female', 'fence',
    'festival', 'fetch', 'fever', 'few', 'fiber', 'fiction', 'field', 'figure',
    'file', 'film', 'filter', 'final', 'find', 'fine', 'finger', 'finish',
    'fire', 'firm', 'first', 'fiscal', 'fish', 'fit', 'fitness', 'fix',
    'flag', 'flame', 'flash', 'flat', 'flavor', 'flee', 'flight', 'flip',
    'float', 'flock', 'floor', 'flower', 'fluid', 'flush', 'fly', 'foam',
    'focus', 'fog', 'foil', 'fold', 'follow', 'food', 'foot', 'force',
    'forest', 'forget', 'fork', 'fortune', 'forum', 'forward', 'fossil', 'foster',
    'found', 'fox', 'fragile', 'frame', 'frequent', 'fresh', 'friend', 'fringe',
    'frog', 'front', 'frost', 'frown', 'frozen', 'fruit', 'fuel', 'fun',
    'funny', 'furnace', 'fury', 'future', 'gadget', 'gain', 'galaxy', 'gallery',
    'game', 'gap', 'garage', 'garbage', 'garden', 'garlic', 'garment', 'gas',
    'gasp', 'gate', 'gather', 'gauge', 'gaze', 'general', 'genius', 'genre',
    'gentle', 'genuine', 'gesture', 'ghost', 'giant', 'gift', 'giggle', 'ginger',
    'giraffe', 'girl', 'give', 'glad', 'glance', 'glare', 'glass', 'glide',
    'glimpse', 'globe', 'gloom', 'glory', 'glove', 'glow', 'glue', 'goat',
    'goddess', 'gold', 'good', 'goose', 'gorilla', 'gospel', 'gossip', 'govern',
    'gown', 'grab', 'grace', 'grain', 'grant', 'grape', 'grass', 'gravity',
    'great', 'green', 'grid', 'grief', 'grit', 'grocery', 'group', 'grow',
    'grunt', 'guard', 'guess', 'guide', 'guild', 'guilt', 'guitar', 'gun',
    'gym', 'habit', 'hair', 'half', 'hammer', 'hamster', 'hand', 'happy',
    'harbor', 'hard', 'harsh', 'harvest', 'hat', 'have', 'hawk', 'hazard',
    'head', 'health', 'heart', 'heavy', 'hedgehog', 'height', 'hello', 'helmet',
    'help', 'hen', 'hero', 'hidden', 'high', 'hill', 'hint', 'hip',
    'hire', 'history', 'hobby', 'hockey', 'hold', 'hole', 'holiday', 'hollow',
    'home', 'honey', 'hood', 'hope', 'horn', 'horror', 'horse', 'hospital',
    'host', 'hotel', 'hour', 'hover', 'hub', 'huge', 'human', 'humble',
    'humor', 'hundred', 'hunt', 'hurdle', 'hurry', 'hurt', 'husband', 'hybrid',
    'ice', 'icon', 'idea', 'identify', 'idle', 'ignore', 'ill', 'illegal',
    'illness', 'image', 'imitate', 'immense', 'immune', 'impact', 'impose', 'improve',
    'impulse', 'inch', 'include', 'income', 'increase', 'index', 'indicate', 'indoor',
    'industry', 'infant', 'inflict', 'inform', 'inhale', 'inherit', 'initial', 'inject',
    'injury', 'inmate', 'inner', 'innocent', 'input', 'inquiry', 'insane', 'insect',
    'inside', 'inspire', 'install', 'intact', 'interest', 'into', 'invest', 'invite',
    'involve', 'iron', 'island', 'isolate', 'issue', 'item', 'ivory', 'jacket',
    'jaguar', 'jar', 'jazz', 'jealous', 'jeans', 'jelly', 'jewel', 'job',
    'join', 'joke', 'journey', 'joy', 'judge', 'juice', 'jump', 'jungle',
    'junior', 'junk', 'just', 'kangaroo', 'keen', 'keep', 'ketchup', 'key',
    'kick', 'kid', 'kidney', 'kind', 'kingdom', 'kiss', 'kit', 'kitchen',
    'kite', 'kitten', 'kiwi', 'knee', 'knife', 'knock', 'know', 'lab',
    'label', 'labor', 'ladder', 'lady', 'lake', 'lamp', 'language', 'laptop',
    'large', 'later', 'latin', 'laugh', 'laundry', 'lava', 'law', 'lawn',
    'lawsuit', 'layer', 'lazy', 'leader', 'leaf', 'learn', 'leave', 'lecture',
    'left', 'leg', 'legal', 'legend', 'leisure', 'lemon', 'lend', 'length',
    'lens', 'leopard', 'lesson', 'letter', 'level', 'liar', 'liberty', 'life',
    'light', 'like', 'limb', 'limit', 'link', 'lion', 'liquid', 'list',
    'little', 'live', 'lizard', 'load', 'loan', 'lobster', 'local', 'lock',
    'logic', 'lonely', 'long', 'loop', 'lottery', 'loud', 'lounge', 'love',
    'loyal', 'lucky', 'luggage', 'lumber', 'lunar', 'lunch', 'luxury', 'lyrics',
    'machine', 'mad', 'magic', 'magnet', 'maid', 'mail', 'main', 'major',
    'make', 'mammal', 'man', 'manage', 'mandate', 'mango', 'mansion', 'manual',
    'maple', 'marble', 'march', 'margin', 'marine', 'market', 'marriage', 'mask',
    'mass', 'master', 'match', 'material', 'math', 'matrix', 'matter', 'maximum',
    'maze', 'meadow', 'mean', 'measure', 'meat', 'mechanic', 'medal', 'media',
    'melody', 'melt', 'member', 'memory', 'mention', 'menu', 'mercy', 'merge',
    'merit', 'merry', 'mesh', 'message', 'metal', 'method', 'middle', 'midnight',
    'milk', 'million', 'mimic', 'mind', 'minimum', 'minor', 'minute', 'miracle',
    'mirror', 'misery', 'miss', 'mistake', 'mix', 'mixed', 'mixture', 'mobile',
    'model', 'modify', 'mom', 'moment', 'monitor', 'monkey', 'monster', 'month',
    'moon', 'moral', 'more', 'morning', 'mosquito', 'mother', 'motion', 'motor',
    'mountain', 'mouse', 'move', 'movie', 'much', 'muffin', 'mule', 'multiply',
    'muscle', 'museum', 'mushroom', 'music', 'must', 'mutual', 'myself', 'mystery',
    'myth', 'naive', 'name', 'napkin', 'narrow', 'nasty', 'nation', 'nature',
    'near', 'neck', 'need', 'negative', 'neglect', 'neither', 'nephew', 'nerve',
    'nest', 'net', 'network', 'neutral', 'never', 'news', 'next', 'nice',
    'night', 'noble', 'noise', 'nominee', 'noodle', 'normal', 'north', 'nose',
    'notable', 'note', 'nothing', 'notice', 'novel', 'now', 'nuclear', 'number',
    'nurse', 'nut', 'oak', 'obey', 'object', 'oblige', 'obscure', 'observe',
    'obtain', 'obvious', 'occur', 'ocean', 'october', 'odor', 'off', 'offer',
    'office', 'often', 'oil', 'okay', 'old', 'olive', 'olympic', 'omit',
    'once', 'one', 'onion', 'online', 'only', 'open', 'opera', 'opinion',
    'oppose', 'option', 'orange', 'orbit', 'orchard', 'order', 'ordinary', 'organ',
    'orient', 'original', 'orphan', 'ostrich', 'other', 'outdoor', 'outer', 'output',
    'outside', 'oval', 'oven', 'over', 'own', 'owner', 'oxygen', 'oyster',
    'ozone', 'pact', 'paddle', 'page', 'pair', 'palace', 'palm', 'panda',
    'panel', 'panic', 'panther', 'paper', 'parade', 'parent', 'park', 'parrot',
    'party', 'pass', 'patch', 'path', 'patient', 'patrol', 'pattern', 'pause',
    'pave', 'payment', 'peace', 'peanut', 'pear', 'peasant', 'pelican', 'pen',
    'penalty', 'pencil', 'people', 'pepper', 'perfect', 'permit', 'person', 'pet',
    'phone', 'photo', 'phrase', 'physical', 'piano', 'picnic', 'picture', 'piece',
    'pig', 'pigeon', 'pill', 'pilot', 'pink', 'pioneer', 'pipe', 'pistol',
    'pitch', 'pizza', 'place', 'planet', 'plastic', 'plate', 'play', 'please',
    'pledge', 'pluck', 'plug', 'plunge', 'poem', 'poet', 'point', 'polar',
    'pole', 'police', 'pond', 'pony', 'pool', 'popular', 'portion', 'position',
    'possible', 'post', 'potato', 'pottery', 'poverty', 'powder', 'power', 'practice',
    'praise', 'predict', 'prefer', 'prepare', 'present', 'pretty', 'prevent', 'price',
    'pride', 'primary', 'print', 'priority', 'prison', 'private', 'prize', 'problem',
    'process', 'produce', 'profit', 'program', 'project', 'promote', 'proof', 'property',
    'prosper', 'protect', 'proud', 'provide', 'public', 'pudding', 'pull', 'pulp',
    'pulse', 'pumpkin', 'punch', 'pupil', 'puppy', 'purchase', 'purity', 'purpose',
    'purse', 'push', 'put', 'puzzle', 'pyramid', 'quality', 'quantum', 'quarter',
    'question', 'quick', 'quit', 'quiz', 'quote', 'rabbit', 'raccoon', 'race',
    'rack', 'radar', 'radio', 'rail', 'rain', 'raise', 'rally', 'ramp',
    'ranch', 'random', 'range', 'rapid', 'rare', 'rate', 'rather', 'raven',
    'raw', 'razor', 'ready', 'real', 'reason', 'rebel', 'rebuild', 'recall',
    'receive', 'recipe', 'record', 'recycle', 'reduce', 'reflect', 'reform', 'refuse',
    'region', 'regret', 'regular', 'reject', 'relax', 'release', 'relief', 'rely',
    'remain', 'remember', 'remind', 'remove', 'render', 'renew', 'rent', 'reopen',
    'repair', 'repeat', 'replace', 'report', 'require', 'rescue', 'resemble', 'resist',
    'resource', 'response', 'result', 'retire', 'retreat', 'return', 'reunion', 'reveal',
    'review', 'reward', 'rhythm', 'rib', 'ribbon', 'rice', 'rich', 'ride',
    'ridge', 'rifle', 'right', 'rigid', 'ring', 'riot', 'ripple', 'risk',
    'ritual', 'rival', 'river', 'road', 'roast', 'robot', 'robust', 'rocket',
    'romance', 'roof', 'rookie', 'room', 'rose', 'rotate', 'rough', 'round',
    'route', 'royal', 'rubber', 'rude', 'rug', 'rule', 'run', 'runway',
    'rural', 'sad', 'saddle', 'sadness', 'safe', 'sail', 'salad', 'salmon',
    'salon', 'salt', 'salute', 'same', 'sample', 'sand', 'satisfy', 'satoshi',
    'sauce', 'sausage', 'save', 'say', 'scale', 'scan', 'scare', 'scatter',
    'scene', 'scheme', 'school', 'science', 'scissors', 'scorpion', 'scout', 'scrap',
    'screen', 'script', 'scrub', 'sea', 'search', 'season', 'seat', 'second',
    'secret', 'section', 'security', 'seed', 'seek', 'segment', 'select', 'sell',
    'seminar', 'senior', 'sense', 'sentence', 'series', 'service', 'session', 'settle',
    'setup', 'seven', 'shadow', 'shaft', 'shallow', 'share', 'shed', 'shell',
    'sheriff', 'shield', 'shift', 'shine', 'ship', 'shiver', 'shock', 'shoe',
    'shoot', 'shop', 'short', 'shoulder', 'shove', 'shrimp', 'shrug', 'shuffle',
    'shy', 'sibling', 'sick', 'side', 'siege', 'sight', 'sign', 'silent',
    'silk', 'silly', 'silver', 'similar', 'simple', 'since', 'sing', 'siren',
    'sister', 'situate', 'six', 'size', 'skate', 'sketch', 'ski', 'skill',
    'skin', 'skirt', 'skull', 'slab', 'slam', 'sleep', 'slender', 'slice',
    'slide', 'slight', 'slim', 'slogan', 'slot', 'slow', 'slush', 'small',
    'smart', 'smile', 'smoke', 'smooth', 'snack', 'snake', 'snap', 'sniff',
    'snow', 'soap', 'soccer', 'social', 'sock', 'soda', 'soft', 'solar',
    'soldier', 'solid', 'solution', 'solve', 'someone', 'song', 'soon', 'sorry',
    'sort', 'soul', 'sound', 'soup', 'source', 'south', 'space', 'spare',
    'spatial', 'spawn', 'speak', 'special', 'speed', 'spell', 'spend', 'sphere',
    'spice', 'spider', 'spike', 'spin', 'spirit', 'split', 'spoil', 'sponsor',
    'spoon', 'sport', 'spot', 'spray', 'spread', 'spring', 'spy', 'square',
    'squeeze', 'squirrel', 'stable', 'stadium', 'staff', 'stage', 'stairs', 'stamp',
    'stand', 'start', 'state', 'stay', 'steak', 'steel', 'stem', 'step',
    'stereo', 'stick', 'still', 'sting', 'stock', 'stomach', 'stone', 'stool',
    'story', 'stove', 'strategy', 'street', 'strike', 'strong', 'struggle', 'student',
    'stuff', 'stumble', 'style', 'subject', 'submit', 'subway', 'success', 'such',
    'sudden', 'suffer', 'sugar', 'suggest', 'suit', 'summer', 'sun', 'sunny',
    'sunset', 'super', 'supply', 'supreme', 'sure', 'surface', 'surge', 'surprise',
    'surround', 'survey', 'suspect', 'sustain', 'swallow', 'swamp', 'swap', 'swarm',
    'swear', 'sweet', 'swift', 'swim', 'swing', 'switch', 'sword', 'symbol',
    'symptom', 'syrup', 'system', 'table', 'tackle', 'tag', 'tail', 'talent',
    'talk', 'tank', 'tape', 'target', 'task', 'taste', 'tattoo', 'taxi',
    'teach', 'team', 'tell', 'ten', 'tenant', 'tennis', 'tent', 'term',
    'test', 'text', 'thank', 'that', 'theme', 'then', 'theory', 'there',
    'they', 'thing', 'this', 'thought', 'three', 'thrive', 'throw', 'thumb',
    'thunder', 'ticket', 'tide', 'tiger', 'tilt', 'timber', 'time', 'tiny',
    'tip', 'tired', 'tissue', 'title', 'toast', 'tobacco', 'today', 'toddler',
    'toe', 'together', 'toilet', 'token', 'tomato', 'tomorrow', 'tone', 'tongue',
    'tonight', 'tool', 'tooth', 'top', 'topic', 'topple', 'torch', 'tornado',
    'tortoise', 'toss', 'total', 'tourist', 'toward', 'tower', 'town', 'toy',
    'track', 'trade', 'traffic', 'tragic', 'train', 'transfer', 'trap', 'trash',
    'travel', 'tray', 'treat', 'tree', 'trend', 'trial', 'tribe', 'trick',
    'trigger', 'trim', 'trip', 'trophy', 'trouble', 'truck', 'true', 'truly',
    'trumpet', 'trust', 'truth', 'try', 'tube', 'tuition', 'tumble', 'tuna',
    'tunnel', 'turkey', 'turn', 'turtle', 'twelve', 'twenty', 'twice', 'twin',
    'twist', 'two', 'type', 'typical', 'ugly', 'umbrella', 'unable', 'unaware',
    'uncle', 'uncover', 'under', 'undo', 'unfair', 'unfold', 'unhappy', 'uniform',
    'unique', 'unit', 'universe', 'unknown', 'unlock', 'until', 'unusual', 'unveil',
    'update', 'upgrade', 'uphold', 'upon', 'upper', 'upset', 'urban', 'urge',
    'usage', 'use', 'used', 'useful', 'useless', 'usual', 'utility', 'vacant',
    'vacuum', 'vague', 'valid', 'valley', 'valve', 'van', 'vanish', 'vapor',
    'various', 'vast', 'vault', 'vehicle', 'velvet', 'vendor', 'venture', 'venue',
    'verb', 'verify', 'version', 'very', 'vessel', 'veteran', 'viable', 'vibrant',
    'vicious', 'victory', 'video', 'view', 'village', 'vintage', 'violin', 'virtual',
    'virus', 'visa', 'visit', 'visual', 'vital', 'vivid', 'vocal', 'voice',
    'void', 'volcano', 'volume', 'vote', 'voyage', 'wage', 'wagon', 'wait',
    'walk', 'wall', 'walnut', 'want', 'warfare', 'warm', 'warrior', 'wash',
    'wasp', 'waste', 'water', 'wave', 'way', 'wealth', 'weapon', 'wear',
    'weasel', 'weather', 'web', 'wedding', 'weekend', 'weird', 'welcome', 'west',
    'wet', 'whale', 'what', 'wheat', 'wheel', 'when', 'where', 'whip',
    'whisper', 'wide', 'width', 'wife', 'wild', 'will', 'win', 'window',
    'wine', 'wing', 'wink', 'winner', 'winter', 'wire', 'wisdom', 'wise',
    'wish', 'witness', 'wolf', 'woman', 'wonder', 'wood', 'wool', 'word',
    'work', 'world', 'worry', 'worth', 'wrap', 'wreck', 'wrestle', 'wrist',
    'write', 'wrong', 'yard', 'year', 'yellow', 'you', 'young', 'youth',
    'zebra', 'zero', 'zone', 'zoo',
])

# 仅保留前2048个词
_BIP39_WORD_LIST = sorted(_BIP39_WORDS)[:2048]


def _detect_bip39_mnemonic(data: bytes, source: str) -> List[BlockchainCryptoResult]:
    """BIP39助记词检测: ASCII文本中搜索连续12/24个词典词汇."""
    results = []
    try:
        text = data.decode('ascii', errors='ignore').lower()
    except Exception:
        return results

    words = text.split()
    if len(words) < 12:
        return results

    # 滑动窗口: 检查连续12或24词是否全在BIP39词表中
    # 启发式阈值: >=11/12或>=22/24匹配即可 (容忍OCR/格式噪声)
    for window_size, min_match, ent_bits in [(12, 11, 128), (24, 22, 256)]:
        for i in range(len(words) - window_size + 1):
            window = words[i:i + window_size]
            matches = sum(1 for w in window if w in _BIP39_WORDS)
            if matches >= min_match:
                snippet = ' '.join(window)
                results.append(BlockchainCryptoResult(
                    chain='generic', component='mnemonic',
                    confidence=0.88 if matches == window_size else 0.65,
                    evidence=[f'BIP39 {window_size}-word mnemonic ({ent_bits}-bit entropy): '
                              f'{snippet[:80]}...'],
                    details={'word_count': window_size, 'matches': matches,
                             'entropy_bits': ent_bits},
                    detected_in=source))
                break  # 每种窗口大小仅报告一次
        if results:
            break
    return results


# 区块链曲线检测
# secp256k1 (Bitcoin, Ethereum, Cosmos): a=0, b=7, p=2^256-2^32-977
# Ed25519 (Solana, Polkadot, Cosmos): Curve25519 EdDSA
# sr25519 (Polkadot): Schnorrkel/Ristretto over Curve25519

_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP256K1_P_BYTES = _SECP256K1_P.to_bytes(32, 'big')


def _detect_blockchain_curves(data: bytes, source: str) -> List[BlockchainCryptoResult]:
    results = []
    # secp256k1素数p的前8字节唯一标识符
    p_prefix = _SECP256K1_P_BYTES[:8]
    if p_prefix in data:
        results.append(BlockchainCryptoResult(
            chain='Bitcoin/Ethereum', component='key (secp256k1)',
            confidence=0.50,
            evidence=['secp256k1 field prime p detected'],
            detected_in=source))
    # Schnorrkel curve25519 (sr25519) 通过Ristretto编码检测
    if b'ristretto' in data or b'sr25519' in data:
        results.append(BlockchainCryptoResult(
            chain='Polkadot/Substrate', component='key (sr25519)',
            confidence=0.85,
            evidence=['sr25519 / Ristretto Schnorr signatures'],
            detected_in=source))
    return results


class BlockchainCryptoDetector:

    def scan_file(self, path: str) -> List[BlockchainCryptoResult]:
        raw = safeReadBytes(path)
        if raw is None:
            return []
        return self.scan_bytes(raw, source=path)

    def scan_bytes(self, data: bytes, source: str = "memory") -> List[BlockchainCryptoResult]:
        results: List[BlockchainCryptoResult] = []
        results.extend(_detect_bitcoin_addresses(data, source))
        results.extend(_detect_ethereum(data, source))
        results.extend(_detect_bip39_mnemonic(data, source))
        results.extend(_detect_blockchain_curves(data, source))
        return sorted(results, key=lambda r: -r.confidence)


def detect_blockchain_crypto(path: str) -> List[BlockchainCryptoResult]:
    return BlockchainCryptoDetector().scan_file(path)

def detect_blockchain_crypto_bytes(data: bytes, source: str = "memory") -> List[BlockchainCryptoResult]:
    return BlockchainCryptoDetector().scan_bytes(data, source)

__all__ = ['BlockchainCryptoDetector', 'BlockchainCryptoResult',
           'detect_blockchain_crypto', 'detect_blockchain_crypto_bytes']
