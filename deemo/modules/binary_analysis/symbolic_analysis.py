# Symbolic execution v0.5 — angr+z3, watchdog, solver strat, op timeout, diversity
import os,re,time,pickle,hashlib,threading
from dataclasses import dataclass; from collections import defaultdict

ANGR=False;Z3=False
def _angr():
    global ANGR
    if ANGR: return True
    try: import angr,claripy; ANGR=True; return True
    except: return False
def _z3():
    global Z3
    if Z3: return True
    try: import z3; Z3=True; return True
    except: return False
def _inc(n,d=1):
    try: from . import inc_counter; inc_counter(n,d)
    except: pass

@dataclass class ER: ok:bool;stdin:bytes|None;hit:bool;st:int;el:float;err:str='';mg:int=0;stall:bool=False

class WD:
    def __init__(self,iv=5.0,ms=10): self.iv=iv; self.ms=ms; self.sc=0; self.la=0; self.tm=None; self.cb=None; self.rn=False
    def start(self,sg,os=None): self.rn=True; self.la=len(sg.active)+len(sg.found); self.sc=0; self.cb=os; self._sch(sg)
    def _sch(self,sg):
        if not self.rn: return; self.tm=threading.Timer(self.iv,self._ck,args=[sg]); self.tm.daemon=True; self.tm.start()
    def _ck(self,sg):
        if not self.rn: return; cur=len(sg.active)+len(sg.found)
        if cur<=self.la: self.sc+=1
        else: self.sc=0; self.la=cur
        if self.sc>=self.ms:
            if self.cb: self.cb(); return
        self._sch(sg)
    def stop(self): self.rn=False
    def __enter__(self): return self
    def __exit__(self,*_): self.stop(); return False

def find_input(bp,target,avoid=None,to=300,mg=False,mcv=0,dr=False):
    if dr: return ER(False,None,False,0,0.0,err='DRY-RUN')
    if not _angr(): return ER(False,None,False,0,0.0,err='no angr')
    import angr,claripy; st=time.time()
    try:
        proj=angr.Project(bp,auto_load_libs=False); state=proj.factory.entry_state()
        if mcv>0 and hasattr(state,'solver'):
            sv=[v for v in state.solver.all_variables if v.symbolic]
            if len(sv)>mcv:
                import random
                for var in sv[mcv:]: state.add_constraints(var==state.solver.eval(var))
        sg=proj.factory.simulation_manager(state); sf=threading.Event()
        with WD()as wd: wd.start(sg,on_stall=lambda:sf.set())
        if avoid: sg.explore(find=target,avoid=avoid)
        else: sg.explore(find=target)
        mc=0; stalled=sf.is_set()
        if mg and len(sg.active)>50:
            try: pre=len(sg.active); sg.merge(); mc=pre-len(sg.active)
            except: pass
        el=time.time()-st
        if sg.found: _inc('sym.hit',1); return ER(True,sg.found[0].posix.dumps(0),True,len(sg.active)+len(sg.deadended)+len(sg.found),el,stalled=stalled,mg=mc)
        _inc('sym.miss',1); return ER(False,None,False,len(sg.active)+len(sg.deadended),el,f"No state 0x{target:x}",mg=mc)
    except Exception as e: return ER(False,None,False,0,time.time()-st,err=str(e))

class CE:
    def __init__(self): self._c={}
    def ex(self,s): return list(s.solver.constraints)if _z3()or hasattr(s.solver,'constraints')else[]
    def sm(self,cs,ut=True):
        if not cs or not _z3(): return cs
        import z3; ck=hashlib.sha256(str(cs).encode()).hexdigest()[:16]
        if ck in self._c: return self._c[ck]
        if ut:
            try: t=z3.Then('simplify','solve-eqs','propagate-values','simplify'); g=z3.Goal(); g.add(*cs); s=[c for sg in t(g)for c in sg]; self._c[ck]=s; return s
            except: pass
        self._c[ck]=cs; return cs
    def si(self,s):
        try: return s.posix.dumps(0)
        except: pass
        if _angr():
            try: si=s.posix.get_fd(0); return si.concrete if hasattr(si,'concrete')else None
            except: pass
        return None
    @staticmethod
    def smt2(cs,fn):
        if not _z3(): return
        import z3; s=z3.Solver(); [s.add(c)for c in cs]; [f.write(s.to_smt2())for f in[open(fn,'w')]]

class SE:
    def __init__(self): self._l=10000; self._v=set()
    def ex(self,bp,pat,ap=None):
        if not _angr(): return{'e':'no angr'}
        import angr
        try:
            proj=angr.Project(bp,auto_load_libs=False); state=proj.factory.entry_state(); sg=proj.factory.simulation_manager(state)
            fs=[]; avs=[]; fr=re.compile(pat,re.I)if pat else None; ar=re.compile(ap,re.I)if ap else None; sp=0
            while sp<self._l and sg.active:
                sg.step(); sp+=1
                for s in sg.active:
                    ak=(s.addr,hash(str(s.solver.constraints)))
                    if ak in self._v: continue; self._v.add(ak)
                    try: txt=s.posix.dumps(1).decode(errors='ignore')
                    except: txt=''
                    if fr and fr.search(txt): fs.append(s)
                    if ar and ar.search(txt): avs.append(s)
                if fs: break
            return{'sp':sp,'f':len(fs),'av':len(avs),'ac':len(sg.active),'de':len(sg.deadended)}
        except Exception as e: return{'e':str(e)}

class VF:
    def bo(self,bp,fa,bs=0):
        if not _angr(): return{'v':False,'e':'no angr'}
        import angr
        try:
            proj=angr.Project(bp,auto_load_libs=False); state=proj.factory.blank_state(addr=fa)
            if proj.kb.functions.get(fa)is None: return{'v':False,'r':'not found'}
            sg=proj.factory.simulation_manager(state); sg.run(); return{'v':False,'a':True,'s':len(sg.deadended)}
        except Exception as e: return{'v':False,'e':str(e)}
    def io(self,bp,fa):
        if not _angr(): return{'v':False,'e':'no angr'}
        import angr
        try: proj=angr.Project(bp,auto_load_libs=False); state=proj.factory.blank_state(addr=fa); sg=proj.factory.simulation_manager(state); sg.run(); return{'v':False,'a':True,'n':'manual'}
        except Exception as e: return{'v':False,'e':str(e)}

def pd(sg):
    if not sg.active: return 0.0
    ac=defaultdict(int); [ac.__setitem__(s.addr,ac[s.addr]+1)for s in sg.active]; n=len(sg.active)
    if n<=1: return 1.0; cs=sorted(ac.values()); cms=0; gs=0
    for i,c in enumerate(cs): cms+=c; gs+=(i+1)*c
    return round(1.0-((2*gs)/(n*cms)-(n+1)/n),3)

def batch(bp,ts,top=60,mg=False): return{t:find_input(bp,t,to=top,mg=mg)for t in ts}

class CC:
    def __init__(self,d='.sc'): self.d=d; os.makedirs(d,exist_ok=True)
    def __enter__(self): return self
    def __exit__(self,*_): return False
    def _cp(self,bp): return os.path.join(self.d,f'{hashlib.sha256(bp.encode()).hexdigest()[:16]}.pkl')
    def load(self,bp):
        cp=self._cp(bp)
        if os.path.exists(cp):
            with open(cp,'rb')as f: return pickle.load(f)
        return None
    def save(self,bp,data):
        with open(self._cp(bp),'wb')as f: pickle.dump(data,f)

if __name__=='__main__':
    import sys
    if len(sys.argv)>2: r=find_input(sys.argv[1],int(sys.argv[2],16),mg=True); print(f"OK:{r.ok} Hit:{r.hit} States:{r.st} Time:{r.el:.2f}s")
