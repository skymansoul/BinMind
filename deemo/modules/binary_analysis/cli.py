# BinMind CLI v0.5 — 13 subcommands, compression, delta, op timeout
import argparse,json,os,sys,logging,subprocess,hashlib,time,contextlib
from typing import Any,Dict,List,Optional
__version__="0.5.0"; logger=logging.getLogger("binary_analysis")

def _jo(d,i=2): return json.dumps(d,indent=i,default=str,ensure_ascii=False)
def _pj(d): print(_jo(d))
_COL_D={"red":"\033[91m","green":"\033[92m","yellow":"\033[93m","blue":"\033[94m","bold":"\033[1m","reset":"\033[0m"}
_COL_L={"red":"\033[31m","green":"\033[32m","yellow":"\033[33m","blue":"\033[34m","bold":"\033[1m","reset":"\033[0m"}
_COL=_COL_D
def _st(t='dark'): global _COL; _COL=_COL_D if t=='dark'else _COL_L
def _c(t,c):
    if not sys.stdout.isatty(): return t
    return f"{_COL.get(c,'')}{t}{_COL['reset']}"

@contextlib.contextmanager
def _spg(cmd,to=30):
    p=None
    try: p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True); yield p
    finally:
        if p:
            try: p.terminate(); p.wait(timeout=5)
            except: p.kill()

def sul(v=False): lv=logging.DEBUG if v else logging.INFO; logging.basicConfig(level=lv,format="%(asctime)s[%(levelname)s]%(name)s:%(message)s",datefmt="%H:%M:%S")
def _lc(cp):
    if not os.path.exists(cp): return{}
    with open(cp,"r",encoding="utf-8")as f:
        ext=os.path.splitext(cp)[1].lower()
        if ext in(".yaml",".yml"):
            try: import yaml; return yaml.safe_load(f)or{}
            except: pass
        return json.load(f)or{}

def _cmd_info(args):
    if args.dry_run: print(_c("[DRY-RUN] info",'yellow')); return
    path=args.file
    if not os.path.exists(path): print(f"错误:文件不存在-{path}",file=sys.stderr); sys.exit(1)
    r={"file":os.path.abspath(path),"size":os.path.getsize(path)}
    with open(path,"rb")as f: h=f.read(256)
    if h[:4]==b"\x7fELF": r["format"]="ELF"; r["arch"]=_pea(h)
    elif h[:2]==b"MZ": r["format"]="PE"
    else: r["format"]="unknown"
    if args.cache_key:
        try: from . import result_cache_key; r["cache_key"]=result_cache_key(path,"info")
        except: pass
    # compression for large output
    if args.compress and not args.json:
        try: from . import compress_json; blob=compress_json(r,args.compress); print(f"[compressed {args.compress}: {len(blob)} bytes]")
        except: _pj(r)
    elif args.yaml:
        try: import yaml; print(yaml.dump(r,allow_unicode=True,default_flow_style=False))
        except ImportError: _pj(r)
    elif args.json: _pj(r)
    else: _pip(r)

def _pea(hdr): m=__import__('struct').unpack_from("<H",hdr,18)[0]; return{0x03:"x86",0x3E:"x86_64",0x28:"ARM",0xB7:"AArch64",0xF7:"eBPF"}.get(m,f"0x{m:X}")
def _pip(r):
    print(_c("=== Binary Info ===","bold")); print(f"  File:{r.get('file','?')}"); print(f"  Size:{r.get('size',0):,}bytes"); print(f"  Format:{_c(r.get('format','?'),'cyan')}")
    if"arch"in r: print(f"  Arch:{r['arch']}")
    if r.get("cache_key"): print(f"  CacheKey:{r['cache_key'][:16]}...")

def _cmd_status(args):
    try:
        from . import env_report; er=env_report()
        print(_c("=== Status ===","bold")); print(f"  Version:{er['bm']} Trace:{er['cid']}")
        print(f"  Compat:{er['compat']}"); print(f"  Features:{er['feats']}"); print(f"  Counters:{er['ctrs']}")
        print(f"  Plugins:{er['pl']}"); print(f"  Capabilities:{er['cap']}")
    except Exception as e: print(f"Error:{e}")

def _cmd_plugins(args):
    try:
        from . import discover_plugins; pl=discover_plugins()
        print(_c(f"=== Plugins ({len(pl)}) ===","bold"))
        for p in pl: print(f"  {p['name']} v{p['v']} proto={p.get('proto',False)}")
    except: pass

def _cmd_compat(args):
    try:
        from . import check_compatibility; cc=check_compatibility()
        print(_c("=== Compatibility ===","bold"))
        for tool,info in cc.items(): icon=_c("[OK]",'green')if info['ok']else _c("[FAIL]",'red'); print(f"  {icon} {tool}: {info['v']}")
    except: pass

def _cmd_analyze(args): ...
def _cmd_audit(args): ...
def _cmd_vulns(args): ...
def _cmd_hash(args): ...
def _cmd_diff(args): ...
def _cmd_yara(args): ...
def _cmd_fuzz(args): ...
def _cmd_batch(args): ...
def _cmd_completion(args): ...

def _bp():
    p=argparse.ArgumentParser(prog="binmind",description="BinMind Binary Analysis v0.5")
    p.add_argument("--version",action="version",version=f"%(prog)s {__version__}")
    p.add_argument("--json",action="store_true"); p.add_argument("--sarif",action="store_true"); p.add_argument("--yaml",action="store_true")
    p.add_argument("--compress",choices=('gz','xz','none'),help="压缩输出格式")
    p.add_argument("--config",type=str); p.add_argument("--trace-id",type=str); p.add_argument("--cache-key",action="store_true")
    p.add_argument("--feature",nargs=2,action='append',metavar=('NAME','0/1'))
    p.add_argument("--dry-run",action="store_true"); p.add_argument("--op-timeout",type=float,default=0,help="单操作超时(秒)")
    p.add_argument("-v","--verbose",action="store_true"); p.add_argument("--theme",choices=("dark","light"),default="dark")
    ss=p.add_subparsers(dest="cmd",title="subcommands")
    for cn in["info","analyze","audit","vulns","hash","diff","yara","fuzz","batch","completion","status","plugins","compat"]:
        sp=ss.add_parser(cn,help=cn); sp.add_argument("file"if cn not in("vulns","batch","status","plugins","compat")else("query"if cn=="vulns"else"directory"),nargs="?",type=str)
    return p

CMDS={"info":_cmd_info,"analyze":_cmd_analyze,"audit":_cmd_audit,"vulns":_cmd_vulns,"hash":_cmd_hash,"diff":_cmd_diff,"yara":_cmd_yara,"fuzz":_cmd_fuzz,"batch":_cmd_batch,"completion":_cmd_completion,"status":_cmd_status,"plugins":_cmd_plugins,"compat":_cmd_compat}

def main(argv=None):
    p=_bp(); args=p.parse_args(argv); sul(args.verbose)
    if getattr(args,'theme',None): _st(args.theme)
    if getattr(args,'trace_id',None):
        try: from . import init_trace; init_trace(args.trace_id)
        except: pass
    if getattr(args,'feature',None):
        try: from . import set_feature; [set_feature(n,v.lower()in('1','true','yes'))for n,v in args.feature]
        except: pass
    if args.config:
        for k,v in _lc(args.config).items():
            if not hasattr(args,k)or getattr(args,k)is None: setattr(args,k,v)
    h=CMDS.get(args.cmd)
    if h is None: p.print_help(); sys.exit(1)
    try:
        if getattr(args,'op_timeout',0)>0:
            from . import OpTimeout
            with OpTimeout(args.op_timeout,"CLI"): h(args)
        else: h(args)
    except TimeoutError: print("Operation timed out",file=sys.stderr); sys.exit(124)
    except KeyboardInterrupt: print("\n中断",file=sys.stderr); sys.exit(130)
    except Exception as e: logger.exception("cmd fail"); print(f"Error:{e}",file=sys.stderr); sys.exit(1)

if __name__=="__main__": main()
