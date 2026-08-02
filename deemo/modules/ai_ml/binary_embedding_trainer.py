# Binary function embedding via triplet loss — joint CFG + opcode features.
# 2026-07-16: semi-hard negative mining added for training stability.
# 2026-07-23: CLAP‑style cross‑modal projection heads + momentum optimizer + early stopping.
import math as _math, json as _json, logging as _logging, hashlib as _hashlib
from collections import Counter as _Counter, defaultdict as _defaultdict
from dataclasses import dataclass, field
from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
from typing import Dict, Any, List, Optional

logger = _logging.getLogger(__name__)

@dataclass
class FunctionFeatures:
    name: str = ''; hash_val: str = ''; cfg_nodes: int = 0; cfg_edges: int = 0
    loop_depth: int = 0; num_basic_blocks: int = 0; num_instructions: int = 0
    num_calls: int = 0; ngram: dict = field(default_factory=dict)
    struct_vec: list = field(default_factory=list); raw_insns: list = field(default_factory=list)

@dataclass
class TripletSample:
    anchor: str = ''; positive: str = ''; negative: str = ''
    anchor_feat: list = field(default_factory=list); positive_feat: list = field(default_factory=list)
    negative_feat: list = field(default_factory=list); sample_type: str = 'synthetic'

@dataclass
class EmbeddingResult:
    embeddings: dict = field(default_factory=dict); dim: int = 128
    num_functions: int = 0; num_triplets: int = 0; loss_history: list = field(default_factory=list)
    converged_at: int = 0; final_loss: float = 0.0
    stopped_early: bool = False  # 早停标记，供外部诊断

class BinaryEmbeddingTrainer(BaseAnalyzer):
    kDim = 128; kMargin = 0.5; kLR = 0.01
    # 跨模态融合 — 结构特征和操作码特征各自的投影权重
    kFusionAlpha = 0.55  # struct projection weight;  >0.5 favours CFG topology

    def __init__(self):
        super().__init__()
        self.__emb = {}; self.__cache = {}; self.__triplets = []
        self.__dim = self.kDim; self.__margin = self.kMargin; self.__lr = self.kLR
        # 动量优化器状态 — 为每个嵌入向量维护历史梯度方向
        self.__momentum = {}; self.__beta = 0.9  # momentum decay factor
        self.__grad_clip = 5.0  # 梯度裁剪阈值，防止三元组损失梯度爆炸
        self.__fusion_alpha = self.kFusionAlpha

    # ── 特征提取（不变） ──────────────────────────────────────────────
    def extract_features(self, functions, dim=128):
        if functions is None: return {}
        self.__dim = dim; out = {}
        for func in functions:
            name = func.get('name','unknown'); insns = func.get('instructions',[])
            cfg = func.get('cfg',{}); calls = func.get('calls',[])
            n_cfgn = cfg.get('nodes', max(1, len(insns)//5))
            n_cfge = cfg.get('edges', n_cfgn-1 if n_cfgn>1 else 0); n_ld = cfg.get('loops',0)
            opcs = self._extract_opcodes(insns); ngram = self._build_ngram(opcs, n=3, topk=dim)
            svec = self._struct_vec(n_cfgn, n_cfge, n_ld, len(opcs), len(calls))
            fhash = _hashlib.md5((name + ''.join(insns[:20])).encode()).hexdigest()[:12]
            feat = FunctionFeatures(name=name, hash_val=fhash, cfg_nodes=n_cfgn, cfg_edges=n_cfge,
                loop_depth=n_ld, num_basic_blocks=max(1,n_cfgn), num_instructions=len(opcs),
                num_calls=len(calls), ngram=ngram, struct_vec=svec, raw_insns=insns)
            out[name] = feat
        self.__cache.update(out); return out

    def _extract_opcodes(self, insns):
        if insns is None: return []
        out = []
        for ins in insns:
            if ins.strip():
                parts = ins.strip().split()
                if parts: out.append(parts[0].lower())
        return out

    def _build_ngram(self, toks, n=3, topk=128):
        if toks is None or len(toks) < n: return {t:1.0 for t in (toks or [])}
        ngrams = ['|'.join(toks[i:i+n]) for i in range(len(toks)-n+1)]
        total = max(1, len(ngrams)); cnt = _Counter(ngrams)
        return {k: v/total for k, v in cnt.most_common(topk)}

    def _struct_vec(self, nodes, edges, loops, nins, ncall, vdim=16):
        out = [min(1.0,nodes/500.0), min(1.0,edges/max(1,nodes)), min(1.0,loops/max(1,nodes)),
               min(1.0,nins/10000.0), min(1.0,ncall/100.0), 1.0 if loops>0 else 0.0]
        denom = nodes*(nodes-1)/2
        out.append(min(1.0, edges/max(1,denom)) if nodes>1 else 0.0)
        out.append(1.0/max(1.0, float(ncall+1)))
        while len(out) < vdim: out.append(0.0)
        return out[:vdim]

    # ── 跨模态投影：结构通路 vs. 操作码通路 ─────────────────────────────
    # 思路来自 CLAP (arXiv 2402.16928) — 不同模态各自编码后在对比空间对齐，
    # 而非简单拼接。此处将结构向量和 ngram 分别投影为 d 维后再做凸组合。

    def _project_structural(self, feat):
        """将 CFG 结构特征投影到嵌入空间。用确定性哈希扩展 + L2 归一化。"""
        sv = feat.struct_vec; base_dim = len(sv)
        if base_dim == 0: return [0.0] * self.__dim
        # 确定性伪随机扩展 — 避免训练时引入额外可学习参数，保证可复现
        extended = []
        seed_bytes = _hashlib.blake2b(
            feat.hash_val.encode(), digest_size=32
        ).digest()
        idx = 0
        while len(extended) < self.__dim:
            val = sv[idx % base_dim]
            noise = (seed_bytes[idx % 32] / 255.0 - 0.5) * 0.1  # 微小扰动防退化
            extended.append(val + noise)
            idx += 1
        # L2 归一化
        norm_val = _math.sqrt(sum(v * v for v in extended))
        if norm_val > 1e-8:
            extended = [v / norm_val for v in extended]
        return extended

    def _project_opcode(self, feat):
        """将 ngram 操作码特征投影到嵌入空间。ngram 频率字典 -> 加权向量。"""
        ngram_dict = feat.ngram
        if not ngram_dict:
            return [0.0] * self.__dim
        # 用 ngram 的 hash 确定性地生成向量分量
        projected = [0.0] * self.__dim
        ng_items = list(ngram_dict.items())
        ni = 0
        while ni < len(ng_items):
            k, freq = ng_items[ni]
            h = _hashlib.shake_128(k.encode()).digest(self.__dim)
            for dk in range(self.__dim):
                projected[dk] += (h[dk] / 255.0 - 0.5) * freq * 2.0
            ni += 1
        # L2 归一化
        norm_val = _math.sqrt(sum(v * v for v in projected))
        if norm_val > 1e-8:
            projected = [v / norm_val for v in projected]
        return projected

    def _fuse_modalities(self, struct_proj, opcode_proj):
        """凸组合融合 — α 偏向结构，1-α 偏向操作码。"""
        alpha = self.__fusion_alpha
        fused = [0.0] * self.__dim
        dj = 0
        while dj < self.__dim:
            fused[dj] = alpha * struct_proj[dj] + (1.0 - alpha) * opcode_proj[dj]
            dj += 1
        norm_val = _math.sqrt(sum(v * v for v in fused))
        if norm_val > 1e-8:
            fused = [v / norm_val for v in fused]
        return fused

    def _cross_modal_embedding(self, fmap):
        """为所有函数生成跨模态嵌入 — 替代纯随机初始化。"""
        cross_emb = {}
        for fname, feat in fmap.items():
            struct_p = self._project_structural(feat)
            opcode_p = self._project_opcode(feat)
            cross_emb[fname] = self._fuse_modalities(struct_p, opcode_p)
        return cross_emb

    # ── 训练主循环 ────────────────────────────────────────────────────
    def train(self, functions, labels=None, margin=0.5, iterations=200, learning_rate=0.01,
              early_stop_patience=30, momentum=0.9):
        """训练嵌入。

        新增参数:
          early_stop_patience: 连续无改善轮数后提前终止（0 禁用）
          momentum: 动量系数（0 退化为普通 SGD）
        """
        if functions is None: return EmbeddingResult()
        self.__dim = 128; self.__margin = margin
        self.__lr = learning_rate; self.__beta = float(momentum)

        fmap = self.extract_features(functions, dim=self.__dim)
        names = list(fmap.keys())
        triplets = self._gen_triplets(fmap, labels)

        # ── 跨模态初始化：替代纯随机，让初始嵌入携带结构/操作码先验 ──
        cross_init = self._cross_modal_embedding(fmap)
        emb = {}
        for n in names:
            if n in cross_init and len(cross_init[n]) == self.__dim:
                emb[n] = list(cross_init[n])
            else:
                emb[n] = self._rand_vec(n)
        # 回流至成员缓存，供外部查询
        self.__emb = dict(emb)

        # 动量缓冲区
        self.__momentum = {n: [0.0] * self.__dim for n in names}
        self.__grad_clip = 5.0

        loss_hist = []
        best_loss = float('inf')
        patience_counter = 0; converged_epoch = iterations

        for ni in range(iterations):
            total_loss = 0.0
            grads = _defaultdict(lambda: [0.0] * self.__dim)

            t_idx = 0
            while t_idx < len(triplets):
                t = triplets[t_idx]
                av = emb[t.anchor]; pv = emb[t.positive]; nv = emb[t.negative]
                d_ap = self._euclidean(av, pv)
                d_an = self._euclidean(av, nv)
                loss = max(0.0, d_ap - d_an + margin)
                total_loss += loss
                if loss > 0:
                    eps = 1e-8
                    dap_s = max(eps, d_ap)
                    dan_s = max(eps, d_an)
                    # ── 梯度计算与裁剪 ──
                    for dk in range(self.__dim):
                        ga = (2 * (av[dk] - nv[dk]) / dan_s +
                              2 * (pv[dk] - av[dk]) / dap_s)
                        gp = 2 * (av[dk] - pv[dk]) / dap_s
                        gn = 2 * (nv[dk] - av[dk]) / dan_s
                        # per-component 裁剪
                        ga = max(-self.__grad_clip, min(self.__grad_clip, ga))
                        gp = max(-self.__grad_clip, min(self.__grad_clip, gp))
                        gn = max(-self.__grad_clip, min(self.__grad_clip, gn))
                        grads[t.anchor][dk] += ga
                        grads[t.positive][dk] += gp
                        grads[t.negative][dk] += gn
                t_idx += 1

            # ── 动量 SGD 更新 ──
            n_trip = max(1, len(triplets))
            for name, vec in emb.items():
                upd = grads[name]
                for dk in range(self.__dim):
                    scaled_grad = upd[dk] / n_trip
                    # 动量累积
                    self.__momentum[name][dk] = (
                        self.__beta * self.__momentum[name][dk] +
                        (1.0 - self.__beta) * scaled_grad
                    )
                    # Nag‑style 前瞻更新
                    vec[dk] -= learning_rate * (
                        self.__beta * self.__momentum[name][dk] + scaled_grad
                    )
                # L2 归一化到单位超球面
                norm_val = _math.sqrt(sum(v * v for v in vec))
                if norm_val > 1e-8:
                    scale = 1.0 / norm_val
                    dk = 0
                    while dk < self.__dim:
                        vec[dk] *= scale
                        dk += 1

            avg_loss = total_loss / n_trip
            loss_hist.append(avg_loss)

            if ni % 50 == 0:
                logger.debug(f'iter {ni}: loss={avg_loss:.6f}')

            # ── 早停检测 ──
            if early_stop_patience > 0:
                if avg_loss < best_loss - 1e-6:
                    best_loss = avg_loss
                    patience_counter = 0
                else:
                    patience_counter += 1
                if patience_counter >= early_stop_patience:
                    converged_epoch = ni + 1
                    logger.debug(
                        f'early stop at iter {converged_epoch}: '
                        f'loss plateaued near {avg_loss:.6f}'
                    )
                    break

        self.__emb = emb; self.__triplets = triplets
        return EmbeddingResult(
            embeddings=dict(emb), dim=self.__dim,
            num_functions=len(emb), num_triplets=len(triplets),
            loss_history=loss_hist, converged_at=converged_epoch,
            final_loss=loss_hist[-1] if loss_hist else 0.0,
            stopped_early=(converged_epoch < iterations),
        )

    # ── 三元组生成（不变） ──────────────────────────────────────────────
    def _gen_triplets(self, fmap, labels):
        if fmap is None: return []
        names = list(fmap.keys()); n = len(names)
        if n < 3: return []
        emb = self._init_embeddings(fmap); out = []
        if labels:
            cls2funcs = _defaultdict(list)
            for name, lbl in labels.items():
                if name in names: cls2funcs[lbl].append(name)
            for fi in range(n):
                aname = names[fi]; albl = labels.get(aname)
                if albl is None: continue
                pos_cands = [f for f in cls2funcs.get(albl,[]) if f != aname]
                neg_cands = []
                for lbl, funcs in cls2funcs.items():
                    if lbl != albl: neg_cands.extend(funcs)
                if not pos_cands or not neg_cands: continue
                for j in range(min(3, len(pos_cands), len(neg_cands))):
                    pn = self._hardest_positive(aname, pos_cands, emb)
                    nn = self._semi_hard_negative(aname, pn, neg_cands, emb)
                    out.append(TripletSample(anchor=aname, positive=pn, negative=nn,
                        anchor_feat=emb.get(aname,[]), positive_feat=emb.get(pn,[]),
                        negative_feat=emb.get(nn,[]), sample_type='labeled'))
        else:
            for fi in range(n):
                aname = names[fi]; afeat = fmap[aname]; sims = []
                for fj in range(n):
                    oname = names[fj]
                    if oname == aname: continue
                    sims.append((oname, self._feature_similarity(afeat, fmap[oname])))
                sims.sort(key=lambda x: x[1], reverse=True)
                if len(sims) < 2: continue
                out.append(TripletSample(anchor=aname, positive=sims[0][0], negative=sims[-1][0],
                    anchor_feat=emb.get(aname,[]), positive_feat=emb.get(sims[0][0],[]),
                    negative_feat=emb.get(sims[-1][0],[]), sample_type='synthetic'))
        return out

    def _init_embeddings(self, fmap):
        if fmap is None: return {}
        out = {}
        for name in fmap.keys():
            out[name] = self._rand_vec(name)
        return out

    def _rand_vec(self, name):
        """生成确定性随机单位向量 — 用于回退初始化。"""
        seed = _hashlib.sha256(name.encode()).digest()
        vec = [(seed[dj % len(seed)] / 255.0) * 2.0 - 1.0 for dj in range(self.__dim)]
        norm_val = _math.sqrt(sum(v * v for v in vec))
        if norm_val > 1e-8:
            vec = [v / norm_val for v in vec]
        return vec

    def _hardest_positive(self, anchor, pos_cands, emb):
        av = emb.get(anchor,[]); return max(pos_cands, key=lambda p: self._euclidean(av, emb.get(p,[])))

    def _hardest_negative(self, anchor, neg_cands, emb):
        av = emb.get(anchor,[]); return min(neg_cands, key=lambda n: self._euclidean(av, emb.get(n,[])))

    def _semi_hard_negative(self, anchor, pos, neg_cands, emb):
        av = emb.get(anchor,[]); pv = emb.get(pos,[]); d_ap = self._euclidean(av, pv)
        best_neg = None; best_dist = float('inf'); ci = 0
        while ci < len(neg_cands):
            n = neg_cands[ci]; nv = emb.get(n,[]); d_an = self._euclidean(av, nv)
            if d_an > d_ap and d_an < best_dist: best_dist = d_an; best_neg = n
            ci += 1
        return best_neg if best_neg is not None else self._hardest_negative(anchor, neg_cands, emb)

    def _feature_similarity(self, feat1, feat2):
        if feat1 is None or feat2 is None: return 0.0
        denom = feat1.num_basic_blocks + feat2.num_basic_blocks
        ssim = 1.0 - abs(feat1.num_basic_blocks-feat2.num_basic_blocks)/max(1,denom) if denom>0 else 0.5
        s1 = set(feat1.ngram.keys()); s2 = set(feat2.ngram.keys())
        uni = len(s1|s2); nsim = len(s1&s2)/max(1,uni)
        return 0.4*ssim + 0.6*nsim

    @staticmethod
    def _euclidean(a, b):
        if not a or not b or len(a)!=len(b): return float('inf')
        return _math.sqrt(sum((x-y)**2 for x,y in zip(a,b)))

    def triplet_loss(self, anchor, positive, negative, margin=0.5):
        if anchor is None or positive is None or negative is None: return 0.0
        dap = self._euclidean(anchor, positive); dan = self._euclidean(anchor, negative)
        return max(0.0, dap - dan + margin)

    # ── 持久化与查询（不变） ───────────────────────────────────────────
    def save(self, filepath):
        if filepath is None: return False
        try:
            data = {'version':'1.0','dimension':self.__dim,'num_embeddings':len(self.__emb),
                    'embeddings':{k:[round(v,6) for v in vec] for k,vec in self.__emb.items()}}
            with open(filepath,'w',encoding='utf-8') as fh: _json.dump(data, fh, indent=2)
            logger.info(f'embeddings saved: {filepath} ({len(self.__emb)} funcs)'); return True
        except Exception as _e: logger.error(f'save failed: {_e}'); return False

    def load(self, filepath):
        if filepath is None: return {}
        try:
            with open(filepath,'r',encoding='utf-8') as fh: data = _json.load(fh)
            self.__dim = data.get('dimension',128); self.__emb = data.get('embeddings',{})
            logger.info(f'embeddings loaded: {len(self.__emb)} funcs, dim={self.__dim}')
            return dict(self.__emb)
        except Exception as _e: logger.error(f'load failed: {_e}'); return {}

    def search(self, query, top_k=10):
        if query is None or query not in self.__emb: return []
        qv = self.__emb[query]; sims = []
        for n in self.__emb.keys():
            if n == query: continue
            d = self._euclidean(qv, self.__emb[n]); sims.append((n, 1.0/(1.0+d)))
        sims.sort(key=lambda x: x[1], reverse=True); return sims[:top_k]

    def analyze(self, **kwargs):
        if kwargs is None: return {'success':False,'error':'null kwargs'}
        action = kwargs.get('action','train'); funcs = kwargs.get('functions',[])
        try:
            if action == 'train':
                if not funcs: return {'success':False,'error':'need functions'}
                res = self.train(funcs, labels=kwargs.get('labels'), margin=kwargs.get('margin',0.5),
                    iterations=kwargs.get('iterations',200), learning_rate=kwargs.get('learning_rate',0.01),
                    early_stop_patience=kwargs.get('early_stop_patience', 30),
                    momentum=kwargs.get('momentum', 0.9))
                return {'success':True,'num_functions':res.num_functions,'num_triplets':res.num_triplets,
                    'dimension':res.dim,'final_loss':res.final_loss,
                    'stopped_early':res.stopped_early,'converged_at':res.converged_at}
            elif action == 'extract_features':
                if not funcs: return {'success':False,'error':'need functions'}
                feats = self.extract_features(funcs); return {'success':True,'num_functions':len(feats)}
            elif action == 'save': ok = self.save(kwargs.get('filepath','data/embeddings.json')); return {'success':ok}
            elif action == 'load': res = self.load(kwargs.get('filepath','data/embeddings.json')); return {'success':True,'num_loaded':len(res)}
            elif action == 'search':
                results = self.search(kwargs.get('query',''), kwargs.get('top_k',10))
                return {'success':True,'query':kwargs.get('query'),'results':[{'function':n,'similarity':s} for n,s in results]}
            elif action == 'loss':
                loss = self.triplet_loss(kwargs.get('anchor',[]), kwargs.get('positive',[]), kwargs.get('negative',[]), kwargs.get('margin',0.5))
                return {'success':True,'loss':loss}
            else: return {'success':False,'error':f'unknown: {action}'}
        except Exception as _e: logger.error(f'analyze failed: {_e}', exc_info=True); return {'success':False,'error':str(_e)}

    @classmethod
    def get_metadata(cls):
        return AnalyzerMetadata(name='BinaryEmbeddingTrainer', type=AnalyzerType.UTILITY,
            version='1.0.0', description='triplet loss embedding trainer',
            author='BinaryAnalysisPlatform', dependencies=[], supported_platforms=['any'])

    def get_emb(self): return dict(self.__emb)
    def get_trips(self): return list(self.__triplets)

__all__ = ['BinaryEmbeddingTrainer']
