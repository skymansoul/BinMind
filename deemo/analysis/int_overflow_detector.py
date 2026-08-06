# v3 int overflow detector
from __future__ import annotations
import re
from typing import Dict, List

class V:
 def __init__(s,l=None,h=None):
  if l is None: s.l=-1e308;s.h=1e308;s.t=True;s.b=False
  else: s.l=float(l);s.h=float(h);s.t=False;s.b=False
 @staticmethod
 def c(v): return V(v,v)
 @staticmethod
 def t(): return V()
 def m(s,o):
  if s.t or o.t: return V.t()
  if s.b or o.b: return V.t()
  p=[s.l*o.l,s.l*o.h,s.h*o.l,s.h*o.h];return V(min(p),max(p))
 def a(s,o):
  if s.t or o.t: return V.t()
  return V(s.l+o.l,s.h+o.h)
 def of(s,b=32):
  if s.t: return False
  l=0 if s.l<-1e100 else s.l;return s.h>((1<<b)-1) or l<0
 def __repr__(s): return "T" if s.t else f"[{s.l:.0f},{s.h:.0f}]"

def _r(code):
 r={}
 for m in re.finditer(r"(\w+)\s*=\s*(\d+)\s*;",code): r[m.group(1)]=V.c(int(m.group(2)))
 for m in re.finditer(r"(\w+)\s*=\s*(\w+)\s*;",code):
  if m.group(2) in r: r[m.group(1)]=r[m.group(2)]
 for m in re.finditer(r"(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)\s*;",code):
  a=r.get(m.group(2),V.t());b=r.get(m.group(3),V.t());r[m.group(1)]=a.m(b)
 for m in re.finditer(r"(\w+)\s*=\s*(\w+)\s*\*\s*(\d+)\s*\+\s*(\d+)\s*;",code):
  a=r.get(m.group(2),V.t());r[m.group(1)]=a.m(V.c(int(m.group(3)))).a(V.c(int(m.group(4))))
 for m in re.finditer(r"(?:unsigned\s+(?:int|short|long)\s+)?(\w+)\s*=\s*(\w+)\s*\*\s*(\d+)\s*\+\s*(\d+)\s*;",code):
  a=r.get(m.group(2),V.t());r[m.group(1)]=a.m(V.c(int(m.group(3)))).a(V.c(int(m.group(4))))
 for m in re.finditer(r"(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)\s*\*\s*(\d+)\s*;",code):
  a=r.get(m.group(2),V.t());b=r.get(m.group(3),V.t());r[m.group(1)]=a.m(b).m(V.c(int(m.group(4))))
 for m in re.finditer(r"(\w+)\s*=\s*(\w+)\s*\*\s*sizeof\s*\(\s*(\w+\**)\s*\)\s*;",code):
  v=r.get(m.group(2),V.t());sz=8 if chr(42) in m.group(3) else 4;r[m.group(1)]=v.m(V.c(sz))
 for m in re.finditer(r"(\w+)\s*=\s*(\w+)\s*\+\s*(\d+)\s*;",code):
  a=r.get(m.group(2),V.t());r[m.group(1)]=a.a(V.c(int(m.group(3))))
 for m in re.finditer(r"(\w+)\s*=\s*(\w+)\s*\+\s*(\d+)\s*\*\s*(\d+)\s*;",code):
  a=r.get(m.group(2),V.t());r[m.group(1)]=a.a(V.c(int(m.group(3))*int(m.group(4))))
 for m in re.finditer(r"(?:malloc|calloc)\s*\(\s*(\w+)\s*\)",code):
  if m.group(1) in r and r[m.group(1)].of(32): r["__s"]=r[m.group(1)]
 for m in re.finditer(r"atoi\s*\(\s*v\[(\d+)\]\)",code):
  r[m.group(0).split(chr(40))[1].split(chr(41))[0]]=V.t()
 for m in re.finditer(r"if\s*\(\s*(\w+)\s*<=\s*0\s*\)\s*\s*=\s*(\d+)\s*;",code):
  vn=m.group(1)
  if vn in r and r[vn].of(32): r["__c_"+vn]=r[vn]
 return r

def detect_int_overflow(code,func=""):
 f=[];r=_r(code)
 for m in re.finditer(r"(?:malloc|calloc)\s*\(\s*(\w+)\s*\*\s*(\w+)\s*\)",code):
  a,b=m.group(1),m.group(2);ra=r.get(a,V.t());rb=r.get(b,V.t());p=ra.m(rb)
  if p.of(32): f.append({"type":"int-ovf","func":func,"expr":a+chr(42)+b,"sev":"H","cwe":"CWE-190","conf":0.85})
  elif p.t: f.append({"type":"int-ovf","func":func,"expr":a+chr(42)+b,"sev":"M","cwe":"CWE-190","conf":0.3})
 for m in re.finditer(r"(?:malloc|calloc)\s*\(\s*(\w+)\s*\)",code):
  vn=m.group(1)
  if vn in r and r[vn].of(32) and not r[vn].t:
   if not any(x.get("expr","")==vn for x in f): f.append({"type":"int-ovf","func":func,"expr":vn,"sev":"H","cwe":"CWE-190","conf":0.7})
  elif vn in r and r[vn].t: f.append({"type":"int-ovf","func":func,"expr":vn,"sev":"M","cwe":"CWE-190","conf":0.3})
 for k in list(r.keys()):
  if k.startswith("__c_"): f.append({"type":"int-ovf","func":func,"expr":k[4:],"sev":"H","cwe":"CWE-190","conf":0.65})
 return f
