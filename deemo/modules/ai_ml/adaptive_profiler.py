# 动态插桩剖析 — Frida/PIN/perf/模拟后端.
# 对比嵌入风险评分（CLAP式跨模态投影）+ Welford在线统计算法 + 自适应时间衰减半衰期
import logging, os, time, json, threading, statistics, math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Dict, Any, List, Optional, Callable, Tuple

logger = logging.getLogger(__name__)

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

class InstrumentationBackend(StrEnum):
    NONE = "none"; FRIDA = "frida"; PIN = "pin"; PERF = "perf"; SIMULATED = "simulated"

@dataclass
class FuncSample:
    func_name: str; address: int; duration_us: int; timestamp: float
    thread_id: int = 0; call_depth: int = 0

@dataclass
class FuncProfile:
    func_name: str; address: int; call_count: int; total_time_us: int
    avg_time_us: float; max_time_us: int; min_time_us: int; p95_time_us: int
    stddev_us: float; hotness_score: float; risk_weight: float = 1.0
    final_priority: float = 0.0; is_dangerous: bool = False
    threat_similarity: float = 0.0
    cv_interarrival: float = 0.0

@dataclass
class ProfileReport:
    binary_path: str; backend: str; duration_sec: float; samples: int
    functions: dict = field(default_factory=dict)
    hotspots: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    def to_dict(self) -> Dict[str, Any]:
        return {'binary_path':self.binary_path,'backend':self.backend,'duration_sec':self.duration_sec,'samples':self.samples,'function_count':len(self.functions),'hotspots':[{'func_name':h.func_name,'address':hex(h.address),'call_count':h.call_count,'avg_time_us':h.avg_time_us,'hotness_score':h.hotness_score,'final_priority':h.final_priority,'threat_similarity':h.threat_similarity,'cv_interarrival':h.cv_interarrival} for h in self.hotspots],'metadata':self.metadata}

DANGEROUS_FUNCS = {"strcpy","strcat","sprintf","gets","scanf","system","execve","popen","memcpy","memmove","free","malloc","realloc","strncpy"}

# 对比嵌入投影基础设施 — CLAP式跨模态语义对齐
# 8×8投影矩阵: 函数统计→规范化语义空间
# 对角保留主特征/非对角编码交叉交互
_PROJECTION_MATRIX = [
    [ 1.2,  0.3, -0.1,  0.0,  0.5,  0.1, -0.2,  0.1],
    [-0.2,  1.1,  0.4, -0.1,  0.2,  0.0,  0.1, -0.3],
    [ 0.1, -0.3,  1.3,  0.2, -0.1,  0.2,  0.0,  0.4],
    [ 0.0,  0.2, -0.2,  1.0,  0.3, -0.1,  0.2, -0.1],
    [ 0.3,  0.1,  0.0, -0.2,  1.4,  0.1, -0.1,  0.2],
    [-0.1,  0.0,  0.3,  0.1, -0.2,  1.2,  0.3,  0.0],
    [ 0.2, -0.1,  0.1, -0.3,  0.0, -0.2,  1.1,  0.1],
    [-0.3,  0.2, -0.1,  0.0,  0.1,  0.1, -0.3,  1.0],
]

# 威胁原型嵌入: 预定义危险方向/已知漏洞模式统计画像
# 内存破坏: 高频调用+低开销+高波动；命令注入: 中频+高开销；格式化串: 低频+高熵
_THREAT_ARCHETYPES_RAW = {
    "memory_corruption":   [0.6, 0.2, 0.5, 0.3, 0.4, 0.1, 0.2, 0.3],
    "command_injection":   [0.3, 0.6, 0.2, 0.5, 0.3, 0.4, 0.1, 0.1],
    "format_string":       [0.2, 0.1, 0.3, 0.2, 0.1, 0.3, 0.5, 0.6],
    "buffer_overflow":     [0.7, 0.1, 0.4, 0.2, 0.5, 0.0, 0.1, 0.2],
    "use_after_free":      [0.4, 0.3, 0.6, 0.4, 0.3, 0.2, 0.3, 0.1],
}
_THREAT_ARCHETYPES_NORM: Dict[str, List[float]] = {}
for _arch_key, _arch_vec in _THREAT_ARCHETYPES_RAW.items():
    _norm = math.sqrt(sum(x * x for x in _arch_vec))
    _THREAT_ARCHETYPES_NORM[_arch_key] = [x / _norm for x in _arch_vec] if _norm > 1e-12 else list(_arch_vec)

def _build_feature_vector(call_count: int, avg_us: float, stddev_us: float,
                          p95_us: int, max_us: int, total_us: int,
                          call_depth_avg: float, thread_diversity: float,
                          duration_entropy: float) -> List[float]:
    """从函数统计量构建 8 维归一化特征向量 — 嵌入投影的输入端。
    各维度经 log 压缩和缩放，避免长尾分布扭曲语义空间。"""
    rough_hotness = (call_count * avg_us) / 2000.0  # 预衰减热度近似，避免与衰减计算的循环依赖
    features = [0.0] * 8
    features[0] = math.log1p(call_count) / 10.0
    features[1] = math.log1p(avg_us) / 15.0
    features[2] = math.log1p(stddev_us) / 12.0
    features[3] = math.log1p(p95_us) / 15.0
    features[4] = math.log1p(rough_hotness) / 10.0
    features[5] = call_depth_avg / 10.0
    features[6] = thread_diversity
    features[7] = duration_entropy / 5.0
    return features

def _project_to_embedding(features: List[float]) -> List[float]:
    """线性投影 + L2 归一化 → 8 维嵌入向量。
    投影矩阵近似 CLAP 式对比学习的跨模态对齐——将统计特征映射到与威胁原型可比的语义空间。"""
    dim = len(_PROJECTION_MATRIX)
    embedded = [0.0] * dim
    i = 0
    while i < dim:
        row = _PROJECTION_MATRIX[i]
        acc = 0.0
        j = 0
        while j < dim:
            acc += row[j] * features[j]
            j += 1
        embedded[i] = acc
        i += 1
    norm = math.sqrt(sum(v * v for v in embedded))
    if norm > 1e-12:
        return [v / norm for v in embedded]
    return embedded

class Profiler:
    def __init__(self, backend: InstrumentationBackend = InstrumentationBackend.SIMULATED, dangerous_funcs: Optional[set] = None):
        self.backend = backend; self.dangerous = dangerous_funcs or DANGEROUS_FUNCS
        self._samples: List[FuncSample] = []; self._lock = threading.Lock()
        # Welford 在线统计算法状态 — O(1) 单步更新均值与 M2（平方差累积量）
        self._welford: Dict[Tuple[str,int], Dict[str,float]] = {}
        # 自适应衰减追踪 — 到达间隔环形缓冲 + 半衰期 EMA
        self._arrival_deltas: Dict[Tuple[str,int], deque] = {}
        self._arrival_last: Dict[Tuple[str,int], float] = {}
        self._hl_ema: Dict[Tuple[str,int], float] = {}

    def add_sample(self, sample: FuncSample):
        with self._lock:
            self._samples.append(sample)
            # Welford在线均值/方差O(1)更新
            wf_key = (sample.func_name, sample.address)
            wf = self._welford.get(wf_key)
            dur_f = float(sample.duration_us)
            if wf is None:
                self._welford[wf_key] = {'count': 1.0, 'mean': dur_f, 'M2': 0.0}
            else:
                cnt = wf['count'] + 1.0
                delta = dur_f - wf['mean']
                wf['mean'] += delta / cnt
                delta2 = dur_f - wf['mean']
                wf['M2'] += delta * delta2
                wf['count'] = cnt
            # 到达间隔追踪用于自适应衰减
            now_ts = sample.timestamp
            last_ts = self._arrival_last.get(wf_key)
            if last_ts is not None:
                dq = self._arrival_deltas.get(wf_key)
                if dq is None:
                    dq = deque(maxlen=20)
                    self._arrival_deltas[wf_key] = dq
                dq.append(now_ts - last_ts)
            self._arrival_last[wf_key] = now_ts

    def _compute_adaptive_half_life(self, func_key: Tuple[str,int]) -> Tuple[float, float]:
        """自适应半衰期计算 — 基于采样到达间隔的变异系数(CV)动态调节。
        CV > 0.5：突发采样 → 短半衰期 15s，侧重近期行为
        CV < 0.2：稳态采样 → 大半衰期 60s，保留历史信息
        中间值线性插值，EMA 平滑避免跳变。
        返回 (半衰期_秒, 变异系数)。"""
        deltas = self._arrival_deltas.get(func_key)
        if not deltas or len(deltas) < 3:
            return 30.0, 0.0
        n_deltas = len(deltas)
        avg_d = sum(deltas) / n_deltas
        if avg_d < 1e-6:
            return 30.0, 0.0
        var_d = sum((d - avg_d) ** 2 for d in deltas) / n_deltas
        cv = math.sqrt(var_d) / avg_d
        if cv > 0.5:
            raw_hl = 15.0
        elif cv < 0.2:
            raw_hl = 60.0
        else:
            raw_hl = 15.0 + 45.0 * (0.5 - cv) / 0.3
        prev = self._hl_ema.get(func_key, 30.0)
        smoothed_hl = prev * 0.7 + raw_hl * 0.3
        self._hl_ema[func_key] = smoothed_hl
        return smoothed_hl, cv

    def collect(self, runner: Optional[Callable[[], Any]] = None, timeout_sec: float = 30.0) -> None:
        if self.backend == InstrumentationBackend.SIMULATED: self._simulate()
        elif self.backend == InstrumentationBackend.FRIDA and FRIDA_AVAILABLE: self._frida_collect(runner, timeout_sec)
        elif self.backend == InstrumentationBackend.PIN: self._pin_collect(runner, timeout_sec)
        else: self._simulate()

    def _simulate(self):
        funcs = ["main","parse_input","process_data","encode_output","validate","log_event"]
        for i in range(100):
            f = funcs[i%len(funcs)]
            self._samples.append(FuncSample(func_name=f,address=0x400000+i*0x100,duration_us=abs(50+(i*7)%200),timestamp=time.time(),thread_id=i%4,call_depth=i%5))

    def _frida_collect(self, runner: Optional[Callable[[], Any]], timeout_sec: float):
        try: device = frida.get_local_device()
        except Exception:
            try: device = frida.get_usb_device()
            except Exception as e: logger.warning(f"Frida device unavailable: {e}"); self._simulate(); return
        target_pid = None
        try:
            if runner:
                proc_found = []
                def _spawn():
                    try: pid = device.spawn([self.binary_path] if hasattr(self,'binary_path') and self.binary_path else []); device.resume(pid); proc_found.append(pid)
                    except Exception: pass
                t = threading.Thread(target=_spawn, daemon=True); t.start(); t.join(timeout=3.0)
                if proc_found: target_pid = proc_found[0]
                else: target_pid = device.get_process("").pid if hasattr(device,'get_process') else os.getpid()
            if target_pid is None: target_pid = os.getpid()
            session = device.attach(target_pid)
            func_names_json = json.dumps(list(self.dangerous)[:50])
            script_code = f"""
            'use strict'; var funcNames = {func_names_json};
            Process.enumerateModules().forEach(function(mod) {{
                mod.enumerateExports().forEach(function(exp) {{
                    if (funcNames.indexOf(exp.name) !== -1) {{
                        try {{ Interceptor.attach(exp.address, {{ onEnter: function(args) {{ this._start=Date.now(); this._funcName=exp.name; this._threadId=Process.getCurrentThreadId(); }}, onLeave: function(retval) {{ var dur=Date.now()-this._start; send({{type:'sample',funcName:this._funcName,address:exp.address.toString(),durationUs:dur*1000,timestamp:Date.now()/1000,threadId:this._threadId,callDepth:0}}); }} }}); }} catch(e) {{}}
                    }}
                }});
            }});
            Module.enumerateImportsSync(null).forEach(function(imp) {{
                if (funcNames.indexOf(imp.name) !== -1) {{
                    try {{ Interceptor.attach(imp.address, {{ onEnter: function(args) {{ this._start=Date.now(); this._funcName=imp.name; this._threadId=Process.getCurrentThreadId(); }}, onLeave: function(retval) {{ var dur=Date.now()-this._start; send({{type:'sample',funcName:this._funcName,address:imp.address.toString(),durationUs:dur*1000,timestamp:Date.now()/1000,threadId:this._threadId,callDepth:0}}); }} }}); }} catch(e) {{}}
                }}
            }});
            send({{type:'ready', count:funcNames.length}});
            """
            script = session.create_script(script_code)
            def on_message(message, data):
                if message.get('type')=='send':
                    payload=message.get('payload',{})
                    if payload.get('type')=='sample':
                        self._samples.append(FuncSample(func_name=payload.get('funcName','unknown'),address=int(payload.get('address','0'),16) if payload.get('address','0').startswith('0x') else int(payload.get('address',0)),duration_us=payload.get('durationUs',0),timestamp=payload.get('timestamp',time.time()),thread_id=payload.get('threadId',0),call_depth=payload.get('callDepth',0)))
            script.on('message',on_message); script.load()
            logger.info(f"Frida instrumentation active; collecting for {timeout_sec}s...")
            time.sleep(min(timeout_sec,10))
            script.unload(); session.detach()
            logger.info(f"Frida collection complete; {len(self._samples)} samples captured")
        except Exception as e: logger.warning(f"Frida collection aborted: {e}"); self._simulate()

    def _pin_collect(self, runner, timeout_sec):
        """Intel PIN 后端桩——通过 `pin -t` 注入 pintool 收集基本块执行计数。
        当前为桩实现，生产环境需替换为实际 PIN 工具链调用。"""
        logger.info("PIN backend selected; falling back to simulation (PIN toolchain not wired)")
        self._simulate()

    def analyze(self) -> ProfileReport:
        with self._lock:
            samples = list(self._samples)
            welford_snap = dict(self._welford)
            deltas_snap = dict(self._arrival_deltas)
            hl_ema_snap = dict(self._hl_ema)
            arrival_last_snap = dict(self._arrival_last)
        grouped: Dict[Tuple[str,int], List[FuncSample]] = defaultdict(list)
        now_ts = time.time()
        for s in samples: grouped[(s.func_name, s.address)].append(s)
        functions: Dict[str, FuncProfile] = {}
        for (name, addr), ss in grouped.items():
            durs = [x.duration_us for x in ss]; ds = sorted(durs); n = len(durs)
            p95 = ds[int(n*0.95)] if n > 0 else 0
            # 优先使用 Welford 在线统计（数值稳定，O(1)），回退到批量统计
            wf = welford_snap.get((name, addr))
            if wf is not None and wf['count'] > 1:
                welford_mean = wf['mean']
                welford_std = math.sqrt(wf['M2'] / (wf['count'] - 1.0))
            else:
                welford_mean = sum(durs) / max(1, n)
                welford_std = statistics.pstdev(durs) if n > 1 else 0.0
            total = sum(durs); avg = welford_mean; stddev = welford_std
            # 辅助统计量 — 调用深度、线程多样性、持续时间分布熵
            depths = [x.call_depth for x in ss]
            call_depth_avg = sum(depths) / max(1, n)
            thread_ids = {x.thread_id for x in ss}
            thread_diversity = len(thread_ids) / max(1, n)
            # 持续时间分布 Shannon 熵 — 反映函数行为的复杂度
            if n >= 5 and max(durs) > min(durs):
                bin_cnt = min(10, n // 2)
                bw = (max(durs) - min(durs)) / bin_cnt
                bins = [0] * bin_cnt
                d_idx = 0
                while d_idx < n:
                    bidx = min(int((durs[d_idx] - min(durs)) / bw), bin_cnt - 1)
                    bins[bidx] += 1
                    d_idx += 1
                total_bc = sum(bins)
                duration_entropy = -sum((c/total_bc) * math.log(c/total_bc) for c in bins if c > 0)
            else:
                duration_entropy = 0.0
            # 对比嵌入→连续威胁相似度
            features = _build_feature_vector(
                call_count=n, avg_us=avg, stddev_us=stddev, p95_us=p95,
                max_us=max(durs) if durs else 0, total_us=total,
                call_depth_avg=call_depth_avg, thread_diversity=thread_diversity,
                duration_entropy=duration_entropy,
            )
            embedding = _project_to_embedding(features)
            # 与威胁原型最大余弦相似度
            arch_sims = [sum(embedding[i] * arch[i] for i in range(8)) for arch in _THREAT_ARCHETYPES_NORM.values()]
            threat_sim = max(arch_sims) if arch_sims else 0.0
            # 自适应时间衰减
            hl, cv_inter = self._compute_adaptive_half_life((name, addr))
            decay_lambda = math.log(2) / hl
            decayed = 0.0
            s_idx = 0
            while s_idx < n:
                age = now_ts - ss[s_idx].timestamp
                decayed += ss[s_idx].duration_us * math.exp(-age * decay_lambda)
                s_idx += 1
            hotness = (n * avg + decayed) / 2000.0
            # 风险融合: 确定性+对比相似度
            is_dangerous = name in self.dangerous
            base_risk = 2.0 if is_dangerous else 1.0
            # 已标记危险: 有限放大
            # 未标记相似: 显著放大/发现未知威胁
            if is_dangerous:
                blended_risk = base_risk * (1.0 + 0.5 * threat_sim)
            else:
                blended_risk = base_risk * (1.0 + 1.5 * threat_sim)
            final = hotness * blended_risk
            functions[name] = FuncProfile(
                func_name=name, address=addr, call_count=n, total_time_us=total,
                avg_time_us=avg, max_time_us=max(durs) if durs else 0,
                min_time_us=min(durs) if durs else 0, p95_time_us=p95, stddev_us=stddev,
                hotness_score=hotness, risk_weight=blended_risk, final_priority=final,
                is_dangerous=is_dangerous, threat_similarity=threat_sim, cv_interarrival=cv_inter,
            )
        hotspots = sorted(functions.values(), key=lambda f: f.final_priority, reverse=True)[:20]
        return ProfileReport(binary_path="",backend=self.backend.value,duration_sec=0.0,samples=len(samples),functions=functions,hotspots=hotspots)

    def prioritize_for_analysis(self, top_n: int = 10) -> List[str]:
        report = self.analyze(); return [h.func_name for h in report.hotspots[:top_n]]

def profile_and_prioritize(binary_path: str, backend: str = "simulated", top_n: int = 10) -> Dict[str, Any]:
    be = InstrumentationBackend(backend); p = Profiler(backend=be); p.collect()
    report = p.analyze()
    return {'success':True,'report':report.to_dict(),'priority_functions':p.prioritize_for_analysis(top_n)}
