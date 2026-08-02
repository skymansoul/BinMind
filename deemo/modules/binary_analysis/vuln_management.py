# VulnKB v0.5 — CVE/NVD/GHSA/EPSS/OSV, schema migration, async, YAML, compression
import os,re,json,sqlite3,hashlib,time,csv,threading
from dataclasses import dataclass; from datetime import datetime

def _pcv(vs):
    if not vs: return{}
    return{k:v for p in vs.split('/')[1:]for k,v in[p.split(':',1)if':'in p else(p,p)]}
def _svb(s):
    if s>=9.0: return'CRITICAL'
    if s>=7.0: return'HIGH'
    if s>=4.0: return'MEDIUM'
    if s>0.0: return'LOW'
    return'NONE'

_KEV={'CVE-2021-44228':'2021-12-10','CVE-2022-30190':'2022-05-30','CVE-2023-34362':'2023-06-02','CVE-2023-49606':'2023-11-01','CVE-2024-1709':'2024-02-19'}
_CWE={'CWE-787':'OOBW','CWE-79':'XSS','CWE-89':'SQLi','CWE-416':'UAF','CWE-78':'CmdInj','CWE-20':'InpVal','CWE-125':'OOBR','CWE-22':'PathT','CWE-352':'CSRF','CWE-476':'NULL','CWE-190':'IntOv','CWE-502':'Deser','CWE-119':'BufOv','CWE-798':'HardCr','CWE-918':'SSRF','CWE-362':'Race'}
_SCHEMA_V=2

class RL:
    def __init__(self,mr=5,w=30.0): self._mx=mr; self._w=w; self._ts=[]; self._lk=threading.Lock()
    def acq(self,to=60.0):
        with self._lk: n=time.time(); self._ts=[t for t in self._ts if n-t<self._w]
        if len(self._ts)>=self._mx:
            wait=self._ts[0]+self._w-n
            if wait>to: return False
            if wait>0: time.sleep(wait+0.1); self._ts=[t for t in self._ts if time.time()-t<self._w]
        self._ts.append(time.time()); return True
_rl=RL()

def _inc(n,d=1):
    try: from . import inc_counter; inc_counter(n,d)
    except: pass

class VulnKB:
    def __init__(self,dp=':memory:'): self._c=sqlite3.connect(dp); self._c.row_factory=sqlite3.Row; self._c.execute("PRAGMA journal_mode=WAL"); self._ic=0; self._mg(); self._sc(); self._tk()
    def __enter__(self): return self
    def __exit__(self,*_): self.close(); return False

    def _mg(self):
        cur=self._c.cursor(); cur.execute("CREATE TABLE IF NOT EXISTS _sv(v INTEGER)"); cur.execute("SELECT v FROM _sv"); r=cur.fetchone(); cv=r['v']if r else 0
        if cv<1: cur.execute("CREATE TABLE IF NOT EXISTS cves(id INTEGER PRIMARY KEY AUTOINCREMENT,cve_id TEXT UNIQUE,description TEXT,cvss_score REAL DEFAULT 0.0,cvss_vector TEXT,severity TEXT,epss_score REAL,epss_percentile REAL,published_date TEXT,modified_date TEXT,source TEXT DEFAULT'NVD',cwe_id TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"); cv=1
        if cv<2:
            for col in['kev_date','ghsa_id','ecosystem']:
                try: cur.execute(f"ALTER TABLE cves ADD COLUMN {col} TEXT")
                except sqlite3.OperationalError: pass
            try: cur.execute("CREATE TABLE IF NOT EXISTS scores_history(id INTEGER PRIMARY KEY AUTOINCREMENT,cve_id TEXT NOT NULL,cvss_score REAL,epss_score REAL,recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
            except: pass; cv=2
        cur.execute("INSERT OR REPLACE INTO _sv(v)VALUES(?)",(cv,)); self._c.commit()

    def _sc(self):
        self._c.executescript("""CREATE TABLE IF NOT EXISTS cves(id INTEGER PRIMARY KEY AUTOINCREMENT,cve_id TEXT UNIQUE NOT NULL,description TEXT,cvss_score REAL DEFAULT 0.0,cvss_vector TEXT,severity TEXT,epss_score REAL,epss_percentile REAL,published_date TEXT,modified_date TEXT,source TEXT DEFAULT'NVD',cwe_id TEXT,kev_date TEXT,ghsa_id TEXT,ecosystem TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT,cve_id TEXT NOT NULL,vendor TEXT,product TEXT,version_start TEXT,version_end TEXT,version_exact TEXT);
            CREATE TABLE IF NOT EXISTS scores_history(id INTEGER PRIMARY KEY AUTOINCREMENT,cve_id TEXT NOT NULL,cvss_score REAL,epss_score REAL,recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
            CREATE INDEX IF NOT EXISTS i_cs ON cves(cvss_score);CREATE INDEX IF NOT EXISTS i_sev ON cves(severity);CREATE INDEX IF NOT EXISTS i_pv ON products(vendor,product);CREATE INDEX IF NOT EXISTS i_pd ON cves(published_date);CREATE INDEX IF NOT EXISTS i_kv ON cves(kev_date);CREATE INDEX IF NOT EXISTS i_gh ON cves(ghsa_id);""")
        self._c.commit()

    def _ckpt(self):
        self._ic+=1
        if self._ic%1000==0:
            try: self._c.execute("PRAGMA wal_checkpoint(PASSIVE)")
            except: pass

    def _tk(self):
        cur=self._c.cursor()
        for cid,kd in _KEV.items(): cur.execute("UPDATE cves SET kev_date=?WHERE cve_id=?AND kev_date IS NULL",(kd,cid))
        self._c.commit()

    def insert(self,cid,desc,cvss,prods=None,epss=None,cv='',pub='',src='NVD',cwe='',ghsa='',eco=''):
        sev=_svb(cvss); kd=_KEV.get(cid); cur=self._c.cursor()
        try:
            cur.execute("INSERT OR REPLACE INTO cves(cve_id,description,cvss_score,cvss_vector,severity,epss_score,published_date,source,cwe_id,kev_date,ghsa_id,ecosystem)VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(cid,desc,cvss,cv,sev,epss,pub,src,cwe,kd,ghsa,eco))
            if prods:
                for p in prods: cur.execute("INSERT INTO products(cve_id,vendor,product,version_start,version_end,version_exact)VALUES(?,?,?,?,?,?)",(cid,p.get('vendor',''),p.get('product',''),p.get('versionStart',''),p.get('versionEnd',''),p.get('versionExact','')))
            self._c.commit(); self._ckpt(); _inc('vkb.i',1); return True
        except sqlite3.IntegrityError: self._c.rollback(); return False

    def to_osv(self,cid):
        r=self.by_cve(cid)
        if not r: return None
        return{'id':r.get('cve_id',''),'summary':r.get('description',''),'severity':[{'type':'CVSS_V3','score':str(r.get('cvss_score',''))}],'affected':[{'package':{'name':p.get('product','')},'versions':[p.get('version_exact','')]if p.get('version_exact')else[]}for p in r.get('products',[])],'refs':[{'type':'WEB','url':f'https://nvd.nist.gov/vuln/detail/{cid}'}]}

    def import_jsonl(self,fp):
        if not os.path.isfile(fp): return 0
        imp=0; cur=self._c.cursor()
        try:
            cur.execute("BEGIN")
            with open(fp,'r',encoding='utf-8')as f:
                for l in f: l=l.strip()
                if not l: continue
                try: rec=json.loads(l)
                except: continue
                cid=rec.get('cve_id',rec.get('id',''))
                if not cid: continue
                cur.execute("INSERT OR REPLACE INTO cves(cve_id,description,cvss_score,cvss_vector,severity,epss_score,source,cwe_id)VALUES(?,?,?,?,?,?,?,?)",(cid,rec.get('description',''),rec.get('cvss_score',0.0),rec.get('cvss_vector',''),_svb(rec.get('cvss_score',0.0)),rec.get('epss_score'),rec.get('source','jl'),rec.get('cwe_id',''))); imp+=1
            cur.execute("COMMIT"); self._ckpt(); _inc('vkb.jl',imp)
        except: cur.execute("ROLLBACK"); return 0
        return imp

    def sync_ghsa(self,gj):
        gid=gj.get('ghsa_id',gj.get('id','')); cid=gj.get('cve_id','')or gid
        return self.insert(cid,gj.get('summary',gj.get('description','')),gj.get('cvss',{}).get('score',0.0),[{'vendor':gj.get('ecosystem',''),'product':v.get('package',{}).get('name','')}for v in gj.get('vulnerabilities',[])],src='GHSA',ghsa=gid,eco=gj.get('ecosystem',''),pub=gj.get('published_at',''))

    def search(self,product=None,vendor=None,ms=0.0,xs=10.0,sev=None,kev=False,eco=None,lim=100):
        cur=self._c.cursor(); cs=["cvss_score BETWEEN?AND?"]; ps=[ms,xs]
        if kev: cs.append("kev_date IS NOT NULL")
        if eco: cs.append("ecosystem=?"); ps.append(eco)
        if product or vendor:
            cs.append("cve_id IN(SELECT DISTINCT cve_id FROM products WHERE 1=1)")
            if product: cs[-1]=cs[-1].replace("1=1","product LIKE?"); ps.append(f"%{product}%")
            if vendor: cs[-1]=cs[-1].replace("1=1","vendor LIKE?"); ps.append(f"%{vendor}%")
        if sev: cs.append("severity=?"); ps.append(sev.upper())
        cur.execute(f"SELECT*FROM cves WHERE{' AND '.join(cs)}ORDER BY cvss_score DESC LIMIT?",ps+[lim]); return[dict(r)for r in cur.fetchall()]

    def by_cve(self,cid):
        cur=self._c.cursor(); cur.execute("SELECT*FROM cves WHERE cve_id=?",(cid,)); r=cur.fetchone()
        if r is None: return None
        rs=dict(r); cur.execute("SELECT*FROM products WHERE cve_id=?",(cid,)); rs['products']=[dict(r)for r in cur.fetchall()]; return rs

    def trend(self,cid):
        cur=self._c.cursor(); cur.execute("SELECT*FROM scores_history WHERE cve_id=?ORDER BY recorded_at",(cid,)); return[dict(r)for r in cur.fetchall()]

    def snap(self,cid,cvss,epss): self._c.cursor().execute("INSERT INTO scores_history(cve_id,cvss_score,epss_score)VALUES(?,?,?)",(cid,cvss,epss)); self._c.commit()

    def stats(self):
        cur=self._c.cursor(); cur.execute("SELECT COUNT(*)as t FROM cves"); t=cur.fetchone()['t']
        cur.execute("SELECT severity,COUNT(*)as c FROM cves GROUP BY severity"); bs={r['severity']:r['c']for r in cur.fetchall()}
        cur.execute("SELECT AVG(cvss_score)as a,MAX(cvss_score)as m FROM cves"); rw=cur.fetchone()
        cur.execute("SELECT COUNT(*)FROM cves WHERE kev_date IS NOT NULL"); kv=cur.fetchone()[0]
        cur.execute("SELECT COUNT(*)FROM cves WHERE ghsa_id IS NOT NULL"); gv=cur.fetchone()[0]
        return{'t':t,'bs':bs,'avg':round(rw['a']or 0.0,2),'max':round(rw['m']or 0.0,1),'kev':kv,'ghsa':gv}

    def dist(self):
        s=self.stats(); return[{'sev':b,'cnt':s['bs'].get(b,0)}for b in['CRITICAL','HIGH','MEDIUM','LOW','NONE']]

    def to_json(self,fn=None):
        cur=self._c.cursor(); cur.execute("SELECT*FROM cves ORDER BY cvss_score DESC"); d=json.dumps([dict(r)for r in cur.fetchall()],indent=2,ensure_ascii=False)
        if fn:
            with open(fn,'w',encoding='utf-8')as f: f.write(d)
        return d

    def to_compressed(self,fn,method='gz'):
        """压缩导出: gzip/lzma压缩JSON, 适合大规模数据集。"""
        import gzip,lzma; cur=self._c.cursor(); cur.execute("SELECT*FROM cves ORDER BY cvss_score DESC"); raw=json.dumps([dict(r)for r in cur.fetchall()]).encode('utf-8')
        if method=='gz': blob=gzip.compress(raw,9)
        elif method=='xz': blob=lzma.compress(raw)
        else: blob=raw
        if fn:
            with open(fn,'wb')as f: f.write(blob)
        return blob

    def to_yaml(self,fn=None):
        try: import yaml
        except ImportError: return self.to_json(fn)
        cur=self._c.cursor(); cur.execute("SELECT*FROM cves ORDER BY cvss_score DESC"); ys=yaml.dump([dict(r)for r in cur.fetchall()],allow_unicode=True,default_flow_style=False)
        if fn:
            with open(fn,'w',encoding='utf-8')as f: f.write(ys)
        return ys

    def to_csv(self,fn):
        cur=self._c.cursor(); cur.execute("SELECT cve_id,description,cvss_score,severity,epss_score,published_date FROM cves ORDER BY cvss_score DESC")
        with open(fn,'w',newline='',encoding='utf-8')as f:
            w=csv.writer(f); w.writerow(['CVE_ID','Description','CVSS','Severity','EPSS','Published'])
            for r in cur.fetchall(): w.writerow([r['cve_id'],(r['description']or'')[:120],r['cvss_score'],r['severity'],r['epss_score']or'',r['published_date']])

    def close(self): self._c.close()


class SyncMgr:
    def __init__(self,kb,ak=None,cd='.nvd_cache'): self._kb=kb; self._ak=ak; self._cd=cd; self._ef=os.path.join(cd,'etags.json'); os.makedirs(cd,exist_ok=True)
    def _re(self):
        if os.path.exists(self._ef):
            with open(self._ef,'r')as f: return json.load(f)
        return{}
    def _we(self,fd,et): ets=self._re(); ets[fd]=et
    with open(self._ef,'w')as f: json.dump(ets,f)

    def sync_nvd(self,ak=None,yrs=None):
        import urllib.request,gzip,io; k=ak or self._ak or''
        if yrs is None: yrs=list(range(2018,datetime.now().year+1)); t=0; ets=self._re()
        for yr in yrs:
            if not _rl.acq(): continue
            url=f'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{yr}.json.gz'; req=urllib.request.Request(url)
            if str(yr)in ets: req.add_header('If-None-Match',ets[str(yr)])
            if k: req.add_header('apiKey',k)
            try:
                resp=urllib.request.urlopen(req,timeout=60)
                if resp.status==304: continue
                gz=resp.read(); et=resp.headers.get('ETag','')
                if et: self._we(str(yr),et)
                with gzip.GzipFile(fileobj=io.BytesIO(gz))as f: nvd=json.loads(f.read().decode('utf-8'))
                for item in nvd.get('vulnerabilities',[]):
                    cve=item.get('cve',{}); cid=cve.get('id',''); desc=''
                    for d in cve.get('descriptions',[]):
                        if d.get('lang')=='en': desc=d.get('value',''); break
                    cwe=''
                    for w in cve.get('weaknesses',[]):
                        for wd in w.get('description',[]):
                            if'CWE-'in wd.get('value',''): cwe=wd['value']; break
                    mt=cve.get('metrics',{}); cv3=mt.get('cvssMetricV31',mt.get('cvssMetricV30',[])); cs=0.0; cv=''
                    if cv3: cs=cv3[0].get('cvssData',{}).get('baseScore',0.0); cv=cv3[0].get('cvssData',{}).get('vectorString','')
                    prods=[]
                    for nd in cve.get('configurations',[]):
                        for mh in nd.get('nodes',[]):
                            for cp in mh.get('cpeMatch',[]):
                                pts=cp.get('criteria','').split(':')
                                if len(pts)>=4: prods.append({'vendor':pts[3],'product':pts[4]})
                    self._kb.insert(cid,desc,cs,prods,cv=cv,pub=cve.get('published',''),cwe=cwe); t+=1
            except urllib.error.HTTPError as e:
                if e.code!=304: continue
            except: continue
        _inc('vkb.nvd',t); return t

    def batch(self,vl):
        c=0
        for v in vl:
            if self._kb.insert(v.get('cve_id',''),v.get('description',''),v.get('cvss_score',0.0),v.get('products',[]),v.get('epss_score'),v.get('cvss_vector',''),v.get('published_date',''),v.get('source','m'),v.get('cwe_id','')): c+=1
        return c


class EPSS:
    def __init__(self,cd='.epss_cache'): self._cd=cd; self._cf=os.path.join(cd,'epss_scores.json'); os.makedirs(cd,exist_ok=True); self._sc={}; self._lc()
    def _lc(self):
        if os.path.exists(self._cf):
            with open(self._cf,'r')as f: self._sc=json.load(f)
    def _sv(self):
        with open(self._cf,'w')as f: json.dump(self._sc,f)
    def fetch(self,cids):
        import urllib.request; uc=[c for c in cids if c not in self._sc]
        if not uc: return{c:self._sc.get(c)for c in cids}
        for i in range(0,len(uc),100):
            b=uc[i:i+100]
            try:
                req=urllib.request.Request(f'https://api.first.org/data/v1/epss?cve={",".join(b)}'); resp=urllib.request.urlopen(req,timeout=30)
                for e in json.loads(resp.read().decode('utf-8')).get('data',[]): self._sc[e.get('cve','')]={'epss':float(e.get('epss','0')),'pct':float(e.get('percentile','0'))}
            except: continue
        self._sv(); return{c:self._sc.get(c)for c in cids}
    def score(self,cid): s=self.fetch([cid]); return s.get(cid)

def iepss(kb,sc=None):
    if sc is None: sc=EPSS()
    cur=kb._c.cursor(); cur.execute("SELECT cve_id FROM cves WHERE epss_score IS NULL"); cids=[r['cve_id']for r in cur.fetchall()]
    if not cids: return 0
    scores=sc.fetch(cids); up=0
    for cid,s in scores.items():
        if s: cur.execute("UPDATE cves SET epss_score=?,epss_percentile=?WHERE cve_id=?",(s['epss'],s['pct'],cid)); up+=1
    kb._c.commit(); return up

if __name__=='__main__':
    import sys
    with VulnKB(sys.argv[1]if len(sys.argv)>1 else':memory:')as kb:
        kb.insert('CVE-2021-44228','Log4Shell',10.0,[{'vendor':'apache','product':'log4j'}],cv='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',pub='2021-12-10',cwe='CWE-502')
        print(json.dumps(kb.to_osv('CVE-2021-44228'),indent=2))
