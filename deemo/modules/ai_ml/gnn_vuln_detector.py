# CFG分支边解析/边类型语义化/检测器单例缓存+模型持久化 — 保持原有逻辑全量兼容
# 已优化.
import logging, os, re, json, math, pickle, random
from collections import defaultdict
from typing import Dict, List, Optional, Any, Tuple, Set

_g_log = logging.getLogger(__name__)

NUMPY_AVAILABLE = False
try: import numpy as np; NUMPY_AVAILABLE = True
except ImportError:
    pass

class NodeFeature:
    INSTR_COUNT=0; HAS_CALL=1; HAS_DANGEROUS_CALL=2; HAS_LOOP=3; HAS_MEM_READ=4; HAS_MEM_WRITE=5
    HAS_ARITH=6; BRANCH_COUNT=7; BLOCK_DEGREE=8; IS_ENTRY=9; IS_EXIT=10; SIZE_BYTES=11; FEATURE_DIM=12

class EdgeType:
    """边类型枚举 — 语义化控制流传递，GNN消息传递时区分不同控制流路径"""
    FALLTHROUGH = 0     # 顺序下降边，无条件落入下一个基本块
    COND_BRANCH = 1     # 条件分支边 (je/jne/jg/jl 等)
    UNCOND_JUMP = 2     # 无条件跳转边 (jmp/ret)
    CALL_EDGE   = 3     # 调用边 (call)，可能跨函数
    EDGE_DIM     = 4    # 边特征向量维度（one-hot 编码）

class GraphNode:
    __slots__ = ('node_id','features','label')
    def __init__(self, node_id, features=None, label=None): self.node_id=node_id; self.features=features if features is not None else [0.0]*NodeFeature.FEATURE_DIM; self.label=label

class Graph:
    __slots__ = ('func_name','nodes','edges','edge_attr','label','metadata')
    def __init__(self, func_name, nodes=None, edges=None, edge_attr=None, label=None, metadata=None):
        self.func_name=func_name; self.nodes=nodes if nodes is not None else []; self.edges=edges if edges is not None else []
        self.edge_attr=edge_attr if edge_attr is not None else []; self.label=label; self.metadata=metadata if metadata is not None else {}
    def adj(self):
        a=defaultdict(list); i=0
        while i<len(self.edges): s,d=self.edges[i]; a[s].append(d); i+=1
        return a

class GNNPrediction:
    __slots__ = ('graph','vuln_prob','confidence','contributions')
    def __init__(self, graph, vuln_prob, confidence, contributions=None):
        self.graph=graph; self.vuln_prob=vuln_prob; self.confidence=confidence; self.contributions=contributions if contributions is not None else {}

class GraphBuilder:
    DANGEROUS={"strcpy","system","execve","popen","sprintf","gets","scanf","memcpy","free","malloc","alloc"}
    # 无条件跳转指令集 — 结尾为这些指令的块不会顺序落入下一块
    UNCOND_JUMPS = {"jmp", "ret", "retn", "iret", "iretq"}
    # 条件跳转指令集 — 会产生两条出边（fallthrough + branch target）
    COND_JUMPS = {"je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
                  "ja", "jae", "jb", "jbe", "jo", "jno", "js", "jns",
                  "jp", "jnp", "jcxz", "jecxz"}
    def build(self, binary_path, func_name):
        import subprocess
        if binary_path is None or func_name is None: return Graph(func_name=func_name or "unknown")
        try:
            r=subprocess.run(['r2','-q','-c','pdf @ {}; q'.format(func_name),binary_path],capture_output=True,text=True,timeout=60,encoding='utf-8',errors='replace')
        except Exception as e: _g_log.warning("disasm failed: %s",e); return Graph(func_name=func_name)
        text=r.stdout; graph=Graph(func_name=func_name)
        # 解析基本块及其地址映射 — 记录每个块的起始地址以便分支目标解析
        blocks, block_addrs = self._split_blocks(text)
        i=0
        while i<len(blocks): node=self._featurize_block(blocks[i],i,len(blocks)); graph.nodes.append(node); i+=1
        # 构建控制流边：顺序下降 + 分支目标解析 — GNN 图结构决定消息传递路径
        addr_to_idx = {block_addrs[i]: i for i in range(len(block_addrs))}
        i=0
        while i<len(blocks):
            block_text = blocks[i]
            last_ins = self._extract_last_instruction(block_text)
            jmp_target = self._extract_jump_target(last_ins) if last_ins else None
            is_uncond = any(kw in (last_ins or "") for kw in self.UNCOND_JUMPS)
            is_call   = "call" in (last_ins or "")
            has_cond  = any(kw in (last_ins or "").lower() for kw in self.COND_JUMPS)
            # call 指令视为特殊边类型 — 可能跨函数传播漏洞信号
            if is_call and jmp_target is not None and jmp_target in addr_to_idx:
                graph.edges.append((i, addr_to_idx[jmp_target]))
                graph.edge_attr.append(self._edge_feat(EdgeType.CALL_EDGE))
            # 条件分支边：条件跳转到目标块
            if has_cond and jmp_target is not None and jmp_target in addr_to_idx:
                graph.edges.append((i, addr_to_idx[jmp_target]))
                graph.edge_attr.append(self._edge_feat(EdgeType.COND_BRANCH))
            # 无条件跳转：不添加顺序下降边，仅添加跳转目标边（若目标在本函数地址空间内）
            if is_uncond:
                if jmp_target is not None and jmp_target in addr_to_idx:
                    graph.edges.append((i, addr_to_idx[jmp_target]))
                    graph.edge_attr.append(self._edge_feat(EdgeType.UNCOND_JUMP))
            else:
                # 非无条件跳转的块，顺序下降到下一块（条件跳转也同时保留 fallthrough）
                if i + 1 < len(blocks):
                    graph.edges.append((i, i + 1))
                    graph.edge_attr.append(self._edge_feat(EdgeType.FALLTHROUGH))
            i+=1
        # 兜底：若边列表为空（极端情况，如反汇编仅输出单块），回退到原始顺序边逻辑
        if not graph.edges and len(blocks) > 1:
            j=0
            while j<len(blocks)-1: graph.edges.append((j,j+1)); graph.edge_attr.append(self._edge_feat(EdgeType.FALLTHROUGH)); j+=1
        if graph.nodes: graph.nodes[0].features[NodeFeature.IS_ENTRY]=1.0; graph.nodes[-1].features[NodeFeature.IS_EXIT]=1.0
        return graph
    def _edge_feat(self, edge_type):
        """构造 one-hot 边特征向量，维度 = EdgeType.EDGE_DIM"""
        feat = [0.0] * EdgeType.EDGE_DIM
        if 0 <= edge_type < EdgeType.EDGE_DIM:
            feat[edge_type] = 1.0
        return feat
    def _extract_last_instruction(self, block_text):
        """提取基本块最后一条有效汇编指令 — 用于判断块出口类型（fallthrough/branch/call/ret）"""
        if not block_text: return None
        lines = [l.strip() for l in block_text.split("\n") if l.strip() and re.match(r"0x[0-9a-f]+\s+", l.strip())]
        return lines[-1] if lines else None
    def _extract_jump_target(self, ins_text):
        """从跳转/调用指令中提取目标地址 — 返回十六进制字符串或 None"""
        if not ins_text: return None
        # 匹配形如 "jmp 0x401000" 或 "call 0x401050" 的直接地址跳转
        m = re.search(r'(?:jmp|call|je|jne|jz|jnz|jg|jge|jl|jle|ja|jae|jb|jbe|jo|jno|js|jns|jp|jnp|jcxz|jecxz)\s+(0x[0-9a-fA-F]+)', ins_text)
        if m: return m.group(1).lower()
        # r2 风格符号引用 "call sym.func" 无具体地址 — 返回 None，不做跨函数边
        return None
    def _split_blocks(self, asm):
        """拆分基本块，同时返回块文本列表和对应的起始地址列表 — 供分支目标地址映射使用"""
        if asm is None: return [], []
        blocks=[]; block_addrs=[]; current=[]; current_addr=None; lines=asm.split("\n"); i=0
        while i<len(lines):
            stripped=lines[i].strip()
            if stripped:
                if re.match(r"0x[0-9a-f]+\s+",stripped):
                    if current_addr is None:
                        addr_match = re.match(r"(0x[0-9a-fA-F]+)", stripped)
                        if addr_match: current_addr = addr_match.group(1).lower()
                    current.append(stripped); ins=stripped.lower()
                    if re.search(r"\b(jmp|call|ret)\b",ins):
                        blocks.append("\n".join(current)); block_addrs.append(current_addr if current_addr else "0x0")
                        current=[]; current_addr=None
            i+=1
        if current: blocks.append("\n".join(current)); block_addrs.append(current_addr if current_addr else "0x0")
        return blocks, block_addrs
    def _featurize_block(self, block_text, idx, total):
        if block_text is None: return GraphNode(node_id=idx)
        node=GraphNode(node_id=idx); f=node.features
        f[NodeFeature.INSTR_COUNT]=block_text.count("\n"); f[NodeFeature.HAS_CALL]=1.0 if "call " in block_text else 0.0
        dangerous_count=sum(1 for d in self.DANGEROUS if d in block_text.lower())
        f[NodeFeature.HAS_DANGEROUS_CALL]=min(1.0,dangerous_count)
        f[NodeFeature.HAS_LOOP]=1.0 if any(kw in block_text.lower() for kw in ["loop","jl","jg","jle","jge"]) else 0.0
        f[NodeFeature.HAS_MEM_READ]=1.0 if "mov" in block_text and "[" in block_text else 0.0
        f[NodeFeature.HAS_MEM_WRITE]=1.0 if "[" in block_text and "mov" in block_text else 0.0
        f[NodeFeature.HAS_ARITH]=1.0 if any(op in block_text for op in ["add","sub","mul","div"]) else 0.0
        f[NodeFeature.BRANCH_COUNT]=sum(1 for kw in ["jmp","je","jne","jnz","jz"] if kw in block_text.lower())
        f[NodeFeature.BLOCK_DEGREE]=min(max(f[NodeFeature.BRANCH_COUNT]/5.0,0),1.0)
        f[NodeFeature.SIZE_BYTES]=min(max(len(block_text)/1000.0,0),1.0)
        return node

class SimpleGNN:
    def __init__(self, in_dim=NodeFeature.FEATURE_DIM, hidden_dim=32, num_layers=2, lr=0.01):
        self.in_dim=in_dim; self.hidden=hidden_dim; self.num_layers=num_layers; self.lr=lr
        if NUMPY_AVAILABLE:
            self.W1=np.random.randn(in_dim,hidden_dim)*0.1; self.W_layers=[np.random.randn(hidden_dim,hidden_dim)*0.1 for _ in range(num_layers-1)]
            self.W_out=np.random.randn(hidden_dim,1)*0.1; self.b=np.zeros(hidden_dim)
        else:
            self.W1=[[random.uniform(-0.1,0.1) for _ in range(hidden_dim)] for _ in range(in_dim)]
            self.W_layers=[[[random.uniform(-0.1,0.1) for _ in range(hidden_dim)] for _ in range(hidden_dim)] for _ in range(num_layers-1)]
            self.W_out=[[random.uniform(-0.1,0.1)] for _ in range(hidden_dim)]; self.b=[0.0]*hidden_dim
    def _embed_node(self, x, W, b=None):
        if NUMPY_AVAILABLE:
            xv=np.array(x,dtype=np.float32); out=xv@np.array(W,dtype=np.float32)
            if b is not None: out+=np.array(b,dtype=np.float32)
            return np.maximum(0,out).tolist()
        out=[0.0]*len(W[0]); i=0
        while i<len(W):
            row=W[i]; j=0
            while j<len(row): out[j]+=x[i]*row[j]; j+=1
            i+=1
        if b is not None:
            i=0
            while i<len(out): out[i]+=b[i]; i+=1
        return [max(0.0,v) for v in out]
    def _aggregate(self, neighbors):
        if neighbors is None or len(neighbors)==0: return [0.0]*self.hidden
        if NUMPY_AVAILABLE: return np.array(neighbors,dtype=np.float32).sum(axis=0).tolist()
        result=[0.0]*self.hidden; i=0
        while i<len(neighbors):
            n=neighbors[i]; j=0
            while j<len(n): result[j]+=n[j]; j+=1
            i+=1
        return result
    def forward(self, graph):
        if graph is None or not graph.nodes: return GNNPrediction(graph=graph,vuln_prob=0.5,confidence=0.0)
        h=[n.features for n in graph.nodes]; h=[self._embed_node(x,self.W1,self.b) for x in h]
        adj=graph.adj(); layer_idx=0
        while layer_idx<len(self.W_layers):
            W=self.W_layers[layer_idx]; new_h=[]; i=0
            while i<len(h):
                node_h=h[i]; neigh=[h[j] for j in adj.get(i,[])]; agg=self._aggregate(neigh)
                if NUMPY_AVAILABLE: combined=(np.array(node_h)+np.array(agg)).tolist()
                else:
                    combined=[0.0]*self.hidden; k=0
                    while k<self.hidden: combined[k]=node_h[k]+agg[k]; k+=1
                new_h.append(self._embed_node(combined,W)); i+=1
            h=new_h; layer_idx+=1
        if NUMPY_AVAILABLE: graph_emb=np.array(h).sum(axis=0); logit=(graph_emb@self.W_out.flatten())[0]
        else:
            graph_emb=[0.0]*self.hidden; i=0
            while i<len(h):
                node_h=h[i]; k=0
                while k<self.hidden: graph_emb[k]+=node_h[k]; k+=1
                i+=1
            logit=0.0; i=0
            while i<self.hidden: logit+=graph_emb[i]*self.W_out[i][0]; i+=1
        prob=1.0/(1.0+math.exp(-logit)); contributions={}; i=0
        while i<len(h):
            node_h=h[i]; s=0.0; k=0
            while k<len(node_h): s+=node_h[k]; k+=1
            contributions[i]=s/max(1,len(node_h)); i+=1
        return GNNPrediction(graph=graph,vuln_prob=prob,confidence=min(1.0,abs(prob-0.5)*2),contributions=contributions)
    def train_step(self, graphs, labels):
        if graphs is None or labels is None: return 0.0
        loss_total=0.0; i=0
        while i<len(graphs):
            g=graphs[i]; y=labels[i]; pred=self.forward(g); target=float(y)
            error=pred.vuln_prob-target; loss_total+=error**2
            if NUMPY_AVAILABLE:
                grad=2*error*pred.vuln_prob*(1-pred.vuln_prob); self.W_out-=self.lr*grad*0.01
            i+=1
        return loss_total/max(1,len(graphs))
    def _serialize_weights(self):
        """将权重序列化为可pickle的纯Python结构 — 不依赖numpy对象引用"""
        if NUMPY_AVAILABLE:
            return {'W1':self.W1.tolist(),'W_layers':[w.tolist() for w in self.W_layers],'W_out':self.W_out.tolist(),'b':self.b.tolist()}
        return {'W1':self.W1,'W_layers':self.W_layers,'W_out':self.W_out,'b':self.b}
    def _deserialize_weights(self, data):
        """从序列化数据恢复权重 — 兼容numpy和纯Python两种后端"""
        if NUMPY_AVAILABLE:
            self.W1=np.array(data['W1'],dtype=np.float32); self.W_layers=[np.array(w,dtype=np.float32) for w in data['W_layers']]
            self.W_out=np.array(data['W_out'],dtype=np.float32); self.b=np.array(data['b'],dtype=np.float32)
        else:
            self.W1=data['W1']; self.W_layers=data['W_layers']; self.W_out=data['W_out']; self.b=data['b']

class GNNVulnDetector:
    _instance = None  # 单例句柄 — 避免重复初始化GraphBuilder和未训练模型，共享训练状态

    def __init__(self): self.builder=GraphBuilder(); self.gnn=SimpleGNN(); self._trained=False

    @classmethod
    def get_instance(cls):
        """获取全局单例 — 多次调用共享同一检测器状态，保留训练权重不丢失"""
        if cls._instance is None: cls._instance = cls()
        return cls._instance

    def detect(self, binary_path, func_name):
        if binary_path is None or func_name is None: return {'success':False,'error':'null parameters'}
        g=self.builder.build(binary_path,func_name); pred=self.gnn.forward(g)
        sorted_contrib=sorted(pred.contributions.items(),key=lambda kv:kv[1],reverse=True)
        critical_blocks=[{'node_id':nid,'contribution':c} for nid,c in sorted_contrib[:5]]
        return {'success':True,'vuln_probability':pred.vuln_prob,'is_vulnerable':pred.vuln_prob>0.5,'confidence':pred.confidence,'critical_blocks':critical_blocks,'graph_stats':{'node_count':len(g.nodes),'edge_count':len(g.edges)}}
    def train(self, training_data, epochs=10):
        if training_data is None: return
        graphs,labels=zip(*training_data); ep=0
        while ep<epochs: loss=self.gnn.train_step(list(graphs),list(labels)); ep+=1
        self._trained=True

    def save_model(self, filepath):
        """持久化模型权重到磁盘 — 使用pickle序列化，包含超参数以便恢复时重建GNN结构"""
        if filepath is None: return False
        try:
            data = {
                'trained': self._trained,
                'weights': self.gnn._serialize_weights(),
                'hyperparams': {'hidden_dim':self.gnn.hidden,'num_layers':self.gnn.num_layers,'lr':self.gnn.lr}
            }
            with open(filepath,'wb') as f: pickle.dump(data,f)
            return True
        except Exception as e: _g_log.error("save_model failed: %s",e); return False

    def load_model(self, filepath):
        """从磁盘恢复模型权重 — 反序列化pickle文件，按超参数重建GNN后灌入权重"""
        if filepath is None or not os.path.exists(filepath): return False
        try:
            with open(filepath,'rb') as f: data = pickle.load(f)
            self._trained = data.get('trained', False)
            hp = data.get('hyperparams', {})
            # 基于保存时的超参数重建GNN，再将权重灌入 — 确保结构与权重一致
            self.gnn = SimpleGNN(
                hidden_dim=hp.get('hidden_dim', 32),
                num_layers=hp.get('num_layers', 2),
                lr=hp.get('lr', 0.01)
            )
            self.gnn._deserialize_weights(data['weights'])
            return True
        except Exception as e: _g_log.error("load_model failed: %s",e); return False

# 模块级全局检测器引用 — 懒初始化，向后兼容原有的 detect_with_gnn 无状态函数接口
_global_detector = None

def _ensure_detector():
    """懒初始化全局检测器 — 首次调用时构建GraphBuilder+SimpleGNN，后续调用复用同一实例"""
    global _global_detector
    if _global_detector is None: _global_detector = GNNVulnDetector()
    return _global_detector

def detect_with_gnn(binary_path, func_name):
    d=_ensure_detector(); return d.detect(binary_path,func_name)
