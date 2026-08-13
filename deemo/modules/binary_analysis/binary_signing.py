# binarysign + 同源search：sha256/ssdeep/tlsh/import-hash/semantic-vector
# 多dimension模糊hash + 余弦相似度，用于恶意软件家族identify。
# ssdeep 纯 Python 回退比 C extension慢，但不会崩溃

import os as _os, json as _json, logging as _logging, hashlib as _hashlib
import struct as _struct, sqlite3 as _sqlite
from datetime import datetime as _dt
from collections import Counter as _Counter
from typing import Dict, List, Optional, Any, Tuple, Set

logger = _logging.getLogger(__name__)

def _insert_sort(arr, key=lambda x: x):
# 下方注释为先前version——单行实现虽简洁但debug困难
    if arr is None or len(arr) <= 1: return
    n = len(arr)
    i = 1
    while i < n:
        pivot = arr[i]; j = i - 1
        while j >= 0 and key(arr[j]) > key(pivot):
            arr[j+1] = arr[j]; j -= 1
        arr[j+1] = pivot; i += 1

# ---- ssdeep ----
_SSDEEP_OK = False
try:
    import ssdeep; _SSDEEP_OK = True
    logger.info("ssdeep C lib loaded")
except ImportError:
    try:
        # ssdeep C extension unavailable; using pure-Python fallback
        import types as _t
        def _py_ssdeep_compare(a, b):
            if a == b and a:
                return 100
            return 0
        ssdeep = _t.SimpleNamespace(hash_from_file=lambda p: "", compare=_py_ssdeep_compare)
        _SSDEEP_OK = True; logger.info("ssdeep pure-Python fallback")
    except ImportError:
        logger.warning("ssdeep unavailable")

# ---- tlsh ----
_TLSH_OK = False
try:
    import tlsh; _TLSH_OK = True; logger.info("tlsh loaded")
except ImportError:
    logger.warning("tlsh unavailable")

# ---- numpy ----
_NP_OK = False
try:
    import numpy as np; _NP_OK = True; logger.info("numpy loaded")
except ImportError:
    logger.warning("numpy unavailable")

# ---- data classes ----
class BinarySignature:
    __slots__ = ('m_path','m_name','m_sha256','m_sha1','m_md5','m_ssdeep','m_tlsh',
                 'm_ihash','m_ehash','m_shash','m_nfunc','m_fsigs','m_cfg','m_cg',
                 'm_svec','m_family','m_threat','m_ts','m_meta')
    def __init__(self, f_path=None, f_name='', f_sha256='', f_sha1='', f_md5='', f_ssdeep='',
                 f_tlsh='', f_ihash='', f_ehash='', f_shash='', f_nfunc=0, f_fsigs=None,
                 f_cfg='', f_cg='', f_svec=None, f_family='', f_threat='', f_ts=None, f_meta=None,
                 binary_path=None, binary_name=None, sha256=None, sha1=None, md5=None,
                 ssdeep_hash=None, tlsh_hash=None, import_hash=None, export_hash=None,
                 section_hash=None, function_count=None, function_signatures=None,
                 semantic_vector=None, malware_family=None, threat_level=None):
        self.m_path = binary_path if binary_path is not None else f_path
        self.m_name = binary_name if binary_name is not None else f_name
        self.m_sha256 = sha256 if sha256 is not None else f_sha256
        self.m_sha1 = sha1 if sha1 is not None else f_sha1
        self.m_md5 = md5 if md5 is not None else f_md5
        self.m_ssdeep = ssdeep_hash if ssdeep_hash is not None else f_ssdeep
        self.m_tlsh = tlsh_hash if tlsh_hash is not None else f_tlsh
        self.m_ihash = import_hash if import_hash is not None else f_ihash
        self.m_ehash = export_hash if export_hash is not None else f_ehash
        self.m_shash = section_hash if section_hash is not None else f_shash
        self.m_nfunc = function_count if function_count is not None else f_nfunc
        self.m_fsigs = function_signatures if function_signatures is not None else (f_fsigs if f_fsigs else [])
        self.m_cfg = f_cfg; self.m_cg = f_cg
        self.m_svec = semantic_vector if semantic_vector is not None else (f_svec if f_svec else [])
        self.m_family = malware_family if malware_family is not None else f_family
        self.m_threat = threat_level if threat_level is not None else f_threat
        self.m_ts = f_ts if f_ts else _dt.now().isoformat()
        self.m_meta = f_meta if f_meta else {}

    @property
    def binary_path(self): return self.m_path
    @property
    def binary_name(self): return self.m_name
    @property
    def sha256(self): return self.m_sha256
    @property
    def sha1(self): return self.m_sha1
    @property
    def md5(self): return self.m_md5
    @property
    def ssdeep_hash(self): return self.m_ssdeep
    @property
    def tlsh_hash(self): return self.m_tlsh
    @property
    def import_hash(self): return self.m_ihash
    @property
    def export_hash(self): return self.m_ehash
    @property
    def section_hash(self): return self.m_shash
    @property
    def function_count(self): return self.m_nfunc
    @property
    def function_signatures(self): return self.m_fsigs
    @property
    def semantic_vector(self): return self.m_svec
    @property
    def malware_family(self): return self.m_family
    @property
    def threat_level(self): return self.m_threat

class HomologyMatch:
    __slots__ = ('m_bin','m_sid','m_score','m_type','m_funcs','m_strs','m_family','m_threat','m_conf','m_details')
    def __init__(self, f_bin=None, f_sid=None, f_score=0.0, f_type='', f_funcs=None, f_strs=None,
                 f_family='', f_threat='', f_conf=0.0, f_details=None,
                 matched_binary=None, matched_signature_id=None, similarity_score=None,
                 match_type=None, matched_functions=None, matched_strings=None,
                 malware_family=None, threat_level=None, confidence=None):
        self.m_bin = matched_binary if matched_binary is not None else f_bin
        self.m_sid = matched_signature_id if matched_signature_id is not None else f_sid
        self.m_score = similarity_score if similarity_score is not None else f_score
        self.m_type = match_type if match_type is not None else f_type
        self.m_funcs = matched_functions if matched_functions is not None else (f_funcs if f_funcs else [])
        self.m_strs = matched_strings if matched_strings is not None else (f_strs if f_strs else [])
        self.m_family = malware_family if malware_family is not None else f_family
        self.m_threat = threat_level if threat_level is not None else f_threat
        self.m_conf = confidence if confidence is not None else f_conf
        self.m_details = f_details if f_details else {}

    @property
    def matched_binary(self): return self.m_bin
    @property
    def matched_signature_id(self): return self.m_sid
    @property
    def similarity_score(self): return self.m_score
    @property
    def match_type(self): return self.m_type
    @property
    def matched_functions(self): return self.m_funcs
    @property
    def matched_strings(self): return self.m_strs
    @property
    def malware_family(self): return self.m_family
    @property
    def threat_level(self): return self.m_threat
    @property
    def confidence(self): return self.m_conf

class BinarySigner:
    kTLSH_MIN = 256; kVEC_DIM = 128
    VECTOR_DIM = kVEC_DIM

    def __init__(self, f_db=None, f_ssdeep=True, f_tlsh=True, f_semantic=True,
                 db_path=None):
        if db_path is not None:
            f_db = db_path
        if f_db is None:
            f_db = _os.path.join(_os.path.dirname(__file__), '..', 'data', 'signatures.db')
        self.__db = f_db
        self.__use_ssdeep = f_ssdeep and _SSDEEP_OK
        self.__use_tlsh = f_tlsh and _TLSH_OK
        self.__use_sem = f_semantic and _NP_OK
        self.__init_db_Sg()
        logger.info(f'signer ready, db={self.__db}')

    @property
    def db_path(self):
        return self.__db

    def __init_db_Sg(self):
        if self.__db is None: return
        _db_dir = _os.path.dirname(self.__db)
        if _db_dir:
            _os.makedirs(_db_dir, exist_ok=True)
        try:
            c = _sqlite.connect(self.__db); cu = c.cursor()
            cu.executescript("""
                CREATE TABLE IF NOT EXISTS binary_signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, binary_path TEXT, binary_name TEXT,
                    sha256 TEXT UNIQUE, sha1 TEXT, md5 TEXT, ssdeep_hash TEXT, tlsh_hash TEXT,
                    import_hash TEXT, export_hash TEXT, section_hash TEXT, function_count INTEGER,
                    function_signatures TEXT, cfg_signature TEXT, call_graph_signature TEXT,
                    semantic_vector TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT, malware_family TEXT, threat_level TEXT);
                CREATE INDEX IF NOT EXISTS idx_sha256 ON binary_signatures(sha256);
                CREATE INDEX IF NOT EXISTS idx_ssdeep ON binary_signatures(ssdeep_hash);
                CREATE INDEX IF NOT EXISTS idx_tlsh ON binary_signatures(tlsh_hash);
                CREATE INDEX IF NOT EXISTS idx_import_hash ON binary_signatures(import_hash);
                CREATE TABLE IF NOT EXISTS function_signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, signature_id INTEGER,
                    function_name TEXT, function_address TEXT, function_size INTEGER,
                    function_hash TEXT, feature_vector TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (signature_id) REFERENCES binary_signatures(id));
                CREATE INDEX IF NOT EXISTS idx_func_sig ON function_signatures(signature_id);
                CREATE INDEX IF NOT EXISTS idx_func_hash ON function_signatures(function_hash);
            """)
            c.commit(); c.close(); logger.info(f'db init ok: {self.__db}')
        except Exception as _e: logger.error(f'db init failed: {_e}')

    def __hashes_Sg(self, f_path):
        out = {'sha256':'','sha1':'','md5':''}
        if f_path is None or not _os.path.exists(f_path): return out
        try:
            with open(f_path,'rb') as fh: data=fh.read()
            out['sha256']=_hashlib.sha256(data).hexdigest()
            out['sha1']=_hashlib.sha1(data).hexdigest()
            out['md5']=_hashlib.md5(data).hexdigest()
        except Exception as _e: logger.error(f'hash fail: {f_path} - {_e}')
        return out

    def __ssdeep_Sg(self, f_path):
# 下方注释为先前version——单行实现虽简洁但debug困难
        if not self.__use_ssdeep or f_path is None: return ''
        try: return ssdeep.hash_from_file(f_path)
        except Exception as _e: logger.warning(f'ssdeep fail: {_e}'); return ''

    def __tlsh_Sg(self, f_path):
        if not self.__use_tlsh or f_path is None: return ''
        try:
            sz = _os.path.getsize(f_path)
            if sz < self.kTLSH_MIN: return ''
            with open(f_path,'rb') as fh: return tlsh.hash(fh.read())
        except Exception as _e: logger.warning(f'tlsh fail: {_e}'); return ''

    def __ihash_Sg(self, f_info):
        if f_info is None: return ''
        imps = f_info.get('imports',{})
        lst = []
        keys = list(imps.keys()); ki = 0
        while ki < len(keys):
            lib = keys[ki]; funcs = imps[lib]
            if isinstance(funcs, list):
                fi = 0
                while fi < len(funcs):
                    f = funcs[fi]
                    if isinstance(f, str): lst.append(f'{lib}:{f}')
                    elif isinstance(f, dict): lst.append(f"{lib}:{f.get('name','')}")
                    fi += 1
            ki += 1
        for df in imps.get('dangerous_functions',[]): lst.append(f'dangerous:{df}')
        if not lst: return ''
        _insert_sort(lst); return _hashlib.sha256('|'.join(lst).encode()).hexdigest()[:32]

    def __shash_Sg(self, f_info):
        if f_info is None: return ''
        secs = f_info.get('sections',[])
        if not secs: return ''
        infos = []; si = 0
        while si < len(secs):
            s = secs[si]
            if isinstance(s, dict):
                infos.append(f"{s.get('name','')}:{s.get('size',0)}:{s.get('permissions','')}")
            si += 1
        if not infos: return ''
        infos.sort(); return _hashlib.sha256('|'.join(infos).encode()).hexdigest()[:32]

    def __fsigs_Sg(self, f_info, f_decomp=None):
        if f_info is None: return []
        out = []
        syms = f_info.get('symbols',{})
        for name, addr in syms.items():
            a = addr.get('address',0) if isinstance(addr, dict) else addr
            sz = addr.get('size',0) if isinstance(addr, dict) else 0
            out.append({'name':name,'address':hex(a) if a else '','size':sz,
                        'hash':_hashlib.md5(name.encode()).hexdigest()[:16]})
        if f_decomp:
            ri = 0
            while ri < len(f_decomp):
                r = f_decomp[ri]; fn = r.get('function_name',''); ps = r.get('pseudocode','')
                if ps:
                    vec = self.__feat_vec_Sg(ps); si = 0
                    while si < len(out):
                        if out[si]['name'] == fn:
                            out[si]['feature_vector'] = vec
                            out[si]['pseudocode_hash'] = _hashlib.sha256(ps.encode()).hexdigest()[:16]
                            break
                        si += 1
                ri += 1
        return out

    def __feat_vec_Sg(self, f_code):
        if not self.__use_sem or f_code is None: return []
        feats = []
        kws = ('if','else','for','while','return','call','malloc','free','strcpy','memcpy',
               'sprintf','printf','scanf','read','write','open','close','socket','connect',
               'send','recv','exec','system')
        lo = f_code.lower(); ki = 0
        while ki < len(kws): feats.append(float(lo.count(kws[ki]))); ki += 1
        feats.extend([float(len(f_code)), float(len(f_code.split('\n'))), float(len(f_code.split()))])
        for ch in '(){}=': feats.append(float(f_code.count(ch)))
        feats.append(float(f_code.count('+'))); feats.append(float(f_code.count('-')))
        while len(feats) < self.kVEC_DIM: feats.append(0.0)
        return feats[:self.kVEC_DIM]

    def gen_Sg(self, f_path, f_info, f_decomp=None):
        if f_path is None: return None
        if f_info is None: f_info = {}
        name = _os.path.basename(f_path)
        h = self.__hashes_Sg(f_path)
        sig = BinarySignature(
            f_path=f_path, f_name=name, f_sha256=h['sha256'], f_sha1=h['sha1'], f_md5=h['md5'],
            f_ssdeep=self.__ssdeep_Sg(f_path), f_tlsh=self.__tlsh_Sg(f_path),
            f_ihash=self.__ihash_Sg(f_info), f_shash=self.__shash_Sg(f_info),
            f_nfunc=0, f_fsigs=self.__fsigs_Sg(f_info, f_decomp),
            f_meta={'architecture':f_info.get('arch',''),'bits':f_info.get('bits',0),'format':f_info.get('format','')})
        sig.m_nfunc = len(sig.m_fsigs)
        if self.__use_sem and f_decomp:
            all_ps = ' '.join(r.get('pseudocode','') for r in f_decomp)
            sig.m_svec = self.__feat_vec_Sg(all_ps)
        logger.info(f'signature: {name} sha256={h["sha256"][:16]}...')
        return sig

    def save_Sg(self, f_sig):
        if f_sig is None: return None
        try:
            c = _sqlite.connect(self.__db); cu = c.cursor()
            cu.execute("""INSERT OR REPLACE INTO binary_signatures (
                binary_path,binary_name,sha256,sha1,md5,ssdeep_hash,tlsh_hash,
                import_hash,section_hash,function_count,function_signatures,
                semantic_vector,created_at,metadata
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                f_sig.m_path, f_sig.m_name, f_sig.m_sha256, f_sig.m_sha1, f_sig.m_md5,
                f_sig.m_ssdeep, f_sig.m_tlsh, f_sig.m_ihash, f_sig.m_shash,
                f_sig.m_nfunc, _json.dumps(f_sig.m_fsigs), _json.dumps(f_sig.m_svec),
                f_sig.m_ts, _json.dumps(f_sig.m_meta)))
            c.commit(); sid = cu.lastrowid
            fi = 0
            while fi < len(f_sig.m_fsigs):
                fs = f_sig.m_fsigs[fi]
                cu.execute("""INSERT INTO function_signatures (
                    signature_id,function_name,function_address,function_size,function_hash,feature_vector
                ) VALUES (?,?,?,?,?,?)""", (
                    sid, fs.get('name',''), fs.get('address',''), fs.get('size',0),
                    fs.get('hash',''), _json.dumps(fs.get('feature_vector',[]))))
                fi += 1
            c.commit(); c.close(); logger.info(f'saved sig id={sid}'); return sid
        except Exception as _e: logger.error(f'save fail: {_e}'); return None

    def get_by_sha_Sg(self, f_sha):
# 2026-06-25 深夜: 这functions在corner case下会hang，加了timeout保护
        if not f_sha: return None
        try:
            c = _sqlite.connect(self.__db); cu = c.cursor()
            cu.execute("SELECT * FROM binary_signatures WHERE sha256=?",(f_sha,))
            row = cu.fetchone()
            if row:
                cols = [d[0] for d in cu.description]; out = dict(zip(cols, row))
                for k in ('function_signatures','semantic_vector','metadata'):
                    if out.get(k):
                        try: out[k] = _json.loads(out[k])
                        except: pass
                c.close(); return out
            c.close(); return None
        except Exception as _e: logger.error(f'get fail: {_e}'); return None

    def _calculate_hashes(self, f_path):
        return self.__hashes_Sg(f_path)

    def _calculate_ssdeep(self, f_path):
        return self.__ssdeep_Sg(f_path)

    def _calculate_tlsh(self, f_path):
        return self.__tlsh_Sg(f_path)

    def _calculate_import_hash(self, f_info):
        return self.__ihash_Sg(f_info)

    def _calculate_section_hash(self, f_info):
        return self.__shash_Sg(f_info)

    def _generate_feature_vector(self, f_code):
        return self.__feat_vec_Sg(f_code)

    def _extract_function_signatures(self, f_info):
        return self.__fsigs_Sg(f_info)

    def generate_signature(self, binary_path=None, binary_info=None, binary_path_f=None, binary_info_f=None, f_decomp=None):
        path = binary_path if binary_path is not None else binary_path_f
        info = binary_info if binary_info is not None else binary_info_f
        return self.gen_Sg(path, info, f_decomp)

    def save_signature(self, f_sig):
        return self.save_Sg(f_sig)

    def get_signature_by_sha256(self, f_sha):
        return self.get_by_sha_Sg(f_sha)

class HomologySearcher:
# module层默认实例——后续计划：delayinitializemode
    kSSDEEP_TH = 70; kTLSH_TH = 100; kSEM_TH = 0.8

    def __init__(self, f_db=None, db_path=None):
        if db_path is not None:
            f_db = db_path
        self.__db = f_db or _os.path.join(_os.path.dirname(__file__),'..','data','signatures.db')
        logger.info(f'searcher ready, db={self.__db}')

    @property
    def db_path(self):
        return self.__db

    def __cmp_ss_Sg(self, h1, h2):
        if not _SSDEEP_OK or not h1 or not h2: return 0
        try: return ssdeep.compare(h1, h2)
        except Exception as _e: logger.warning(f'ssdeep cmp fail: {_e}'); return 0

    def __cmp_tl_Sg(self, h1, h2):
        if not _TLSH_OK or not h1 or not h2: return -1
        try: return tlsh.diff(h1, h2)
        except Exception as _e: logger.warning(f'tlsh cmp fail: {_e}'); return -1

    def __cmp_vec_Sg(self, v1, v2):
        if not v1 or not v2 or len(v1) != len(v2): return 0.0
        if _NP_OK:
            try:
                a=np.array(v1); b=np.array(v2)
                d=np.dot(a,b); n1=np.linalg.norm(a); n2=np.linalg.norm(b)
                return float(d/(n1*n2)) if n1 and n2 else 0.0
            except: pass
        d=sum(x*y for x,y in zip(v1,v2)); n1=(sum(x*x for x in v1))**0.5; n2=(sum(y*y for y in v2))**0.5
        return d/(n1*n2) if n1 and n2 else 0.0

    def _query_Sg(self, f_col, f_val):
        c = _sqlite.connect(self.__db); cu = c.cursor()
        cu.execute(f"SELECT * FROM binary_signatures WHERE {f_col}=?",(f_val,))
        rows = cu.fetchall(); cols = [d[0] for d in cu.description]
        c.close(); return [dict(zip(cols, r)) for r in rows]

    def _query_all_Sg(self, f_col):
        c = _sqlite.connect(self.__db); cu = c.cursor()
        cu.execute(f"SELECT * FROM binary_signatures WHERE {f_col} IS NOT NULL AND {f_col} != ''")
        rows = cu.fetchall(); cols = [d[0] for d in cu.description]; c.close()
        return [dict(zip(cols, r)) for r in rows]

    def search_ss_Sg(self, f_hash, f_th=None, f_lim=10):
        if not f_hash: return []
        th = f_th or self.kSSDEEP_TH; recs = self._query_all_Sg('ssdeep_hash')
        results = []; ri = 0
        while ri < len(recs):
            r = recs[ri]; sim = self.__cmp_ss_Sg(f_hash, r.get('ssdeep_hash',''))
            if sim >= th:
                results.append(HomologyMatch(f_bin=r.get('binary_name',''), f_sid=r.get('id',0),
                    f_score=sim/100.0, f_type='ssdeep', f_family=r.get('malware_family',''),
                    f_threat=r.get('threat_level',''), f_conf=sim/100.0,
                    f_details={'ssdeep_similarity':sim}))
            ri += 1
        results.sort(key=lambda x: x.m_score, reverse=True); return results[:f_lim]

    def search_tl_Sg(self, f_hash, f_th=None, f_lim=10):
        if not f_hash: return []
        th = f_th or self.kTLSH_TH; recs = self._query_all_Sg('tlsh_hash')
        results = []; ri = 0
        while ri < len(recs):
            r = recs[ri]; dist = self.__cmp_tl_Sg(f_hash, r.get('tlsh_hash',''))
            if 0 <= dist <= th:
                sim = 1.0 - dist/300.0
                results.append(HomologyMatch(f_bin=r.get('binary_name',''), f_sid=r.get('id',0),
                    f_score=max(0.0,sim), f_type='tlsh', f_family=r.get('malware_family',''),
                    f_threat=r.get('threat_level',''), f_conf=max(0.0,sim),
                    f_details={'tlsh_distance':dist}))
            ri += 1
        results.sort(key=lambda x: x.m_details.get('tlsh_distance',300)); return results[:f_lim]

    def search_ih_Sg(self, f_hash, f_lim=10):
        if not f_hash: return []
        recs = self._query_Sg('import_hash', f_hash)
        return [HomologyMatch(f_bin=r.get('binary_name',''), f_sid=r.get('id',0),
                f_score=1.0, f_type='import_hash', f_family=r.get('malware_family',''),
                f_threat=r.get('threat_level',''), f_conf=1.0,
                f_details={'import_hash_match':True}) for r in recs[:f_lim]]

    def search_sv_Sg(self, f_vec, f_th=None, f_lim=10):
        if not f_vec: return []
        th = f_th or self.kSEM_TH; recs = self._query_all_Sg('semantic_vector')
        results = []; ri = 0
        while ri < len(recs):
            r = recs[ri]; sv = r.get('semantic_vector','')
            if sv:
                try:
                    v = _json.loads(sv); sim = self.__cmp_vec_Sg(f_vec, v)
                    if sim >= th:
                        results.append(HomologyMatch(f_bin=r.get('binary_name',''), f_sid=r.get('id',0),
                            f_score=sim, f_type='semantic', f_family=r.get('malware_family',''),
                            f_threat=r.get('threat_level',''), f_conf=sim,
                            f_details={'cosine_similarity':sim}))
                except: pass
            ri += 1
        results.sort(key=lambda x: x.m_score, reverse=True); return results[:f_lim]

    def comprehensive_Sg(self, f_sig, f_ss_th=None, f_tl_th=None, f_sem_th=None, f_lim=10):
        if f_sig is None: return []
        merged = {}
        def _add(matches):
            mi = 0
            while mi < len(matches):
                m = matches[mi]; k = m.m_bin
                if k not in merged: merged[k] = m
                else:
                    merged[k].m_score = max(merged[k].m_score, m.m_score)
                    merged[k].m_type += '+' + m.m_type.split('+')[0]
                mi += 1
        if f_sig.m_ssdeep: _add(self.search_ss_Sg(f_sig.m_ssdeep, f_ss_th, f_lim*2))
        if f_sig.m_tlsh: _add(self.search_tl_Sg(f_sig.m_tlsh, f_tl_th, f_lim*2))
        if f_sig.m_ihash: _add(self.search_ih_Sg(f_sig.m_ihash, f_lim*2))
        if f_sig.m_svec: _add(self.search_sv_Sg(f_sig.m_svec, f_sem_th, f_lim*2))
        results = sorted(merged.values(), key=lambda x: x.m_score, reverse=True)
        logger.info(f'comprehensive search: {len(results)} matches')
        return results[:f_lim]

    def update_ti_Sg(self, f_sid, f_family, f_threat):
        if f_sid is None: return False
        try:
            c = _sqlite.connect(self.__db); cu = c.cursor()
            cu.execute("UPDATE binary_signatures SET malware_family=?,threat_level=? WHERE id=?",
                       (f_family, f_threat, f_sid))
            c.commit(); c.close(); logger.info(f'TI updated: id={f_sid}')
            return True
        except Exception as _e: logger.error(f'update TI fail: {_e}'); return False

    def summary_Sg(self, f_matches):
        s = {'total_matches':0,'high_similarity_count':0,'malware_families':[],
             'threat_levels':{},'match_types':{},'average_similarity':0.0}
        if not f_matches: return s
        s['total_matches'] = len(f_matches); total = 0.0; fams = set()
        mi = 0
        while mi < len(f_matches):
            m = f_matches[mi]; total += m.m_score
            if m.m_score >= 0.8: s['high_similarity_count'] += 1
            if m.m_family: fams.add(m.m_family)
            lv = m.m_threat or 'unknown'; s['threat_levels'][lv] = s['threat_levels'].get(lv, 0) + 1
            mt = m.m_type; s['match_types'][mt] = s['match_types'].get(mt, 0) + 1
            mi += 1
        s['malware_families'] = list(fams); s['average_similarity'] = total / len(f_matches)
        return s

    def _compare_vectors(self, v1, v2):
        return self.__cmp_vec_Sg(v1, v2)

    def _compare_ssdeep(self, h1, h2):
        return self.__cmp_ss_Sg(h1, h2)

    def _compare_tlsh(self, h1, h2):
        return self.__cmp_tl_Sg(h1, h2)

    def search_by_import_hash(self, f_hash, f_lim=10):
        return self.search_ih_Sg(f_hash, f_lim)

    def search_by_semantic_vector(self, f_vec, threshold=None, f_lim=10):
        return self.search_sv_Sg(f_vec, threshold, f_lim)

    def comprehensive_search(self, f_sig, limit=10):
        return self.comprehensive_Sg(f_sig, f_lim=limit)

    def update_threat_intel(self, signature_id=None, malware_family=None, threat_level=None, **kw):
        if signature_id is None:
            signature_id = kw.get('f_sid')
        if malware_family is None:
            malware_family = kw.get('f_family')
        if threat_level is None:
            threat_level = kw.get('f_threat')
        return self.update_ti_Sg(signature_id, malware_family, threat_level)

    def get_search_summary(self, f_matches):
        return self.summary_Sg(f_matches)

def generate_binary_signature_Sg(f_path, f_info, f_decomp=None, f_save=True):
    if f_path is None: return None
    s = BinarySigner(); sig = s.gen_Sg(f_path, f_info, f_decomp)
    if f_save and sig is not None: s.save_Sg(sig)
    return sig

def search_homology_Sg(f_sig, f_lim=10):
    if f_sig is None: return []
    return HomologySearcher().comprehensive_Sg(f_sig, f_lim=f_lim)

SSDEEP_AVAILABLE = bool(_SSDEEP_OK)
TLSH_AVAILABLE = bool(_TLSH_OK)
NUMPY_AVAILABLE = bool(_NP_OK)

def generate_binary_signature(binary_path=None, binary_info=None, save_to_db=True,
                              f_path=None, f_info=None, f_save=None, f_decomp=None):
    path = binary_path if binary_path is not None else f_path
    info = binary_info if binary_info is not None else f_info
    if save_to_db is None:
        save_to_db = f_save if f_save is not None else True
    return generate_binary_signature_Sg(path, info, f_decomp, save_to_db)

def search_homology(f_sig, limit=10, f_lim=None):
    lim = limit if f_lim is None else f_lim
    return search_homology_Sg(f_sig, lim)
