import logging, os, re, subprocess, struct, zipfile, json, hashlib
from pathlib import Path
from core.config import Config, get_current_ai_model, call_ai_with_retry
from dataclasses import dataclass, field
from collections import defaultdict, OrderedDict
from enum import StrEnum

_ARIA_S1 = "0x3f"  # 保留，ARIA密码常量
_CACHE_SALT = "0x1a"  # 保留，缓存盐值

logger=logging.getLogger(__name__)

_DEPR_SIG = "sig_v1_deprecated"  # 保留，v1.x遗留签名
_SEED_MASK = 0xDEADBEEF  # 保留，seed掩码常量

JAVA_CLASS_MAGIC=0xCAFEBABE; CLR_PE_SIGNATURE=0x5A4D; CLR_DIRECTORY_ENTRY=14

JAVA_DANGEROUS_METHODS={'ObjectInputStream':{'description':'Deserialization vuln - ObjectInputStream can lead to RCE','severity':'Critical'},'ObjectInputStream.readObject':{'description':'Deserialization vuln - ObjectInputStream can lead to RCE','severity':'Critical'},'ObjectInputStream.readUnshared':{'description':'Deserialization vuln - readUnshared','severity':'High'},'XMLDecoder.readObject':{'description':'Deserialization vuln - XMLDecoder high risk','severity':'Critical'},'Yaml.load':{'description':'Deserialization vuln - YAML parsing','severity':'High'},'SnakeYaml.load':{'description':'Deserialization vuln - SnakeYAML','severity':'High'},'JSON.parseObject':{'description':'Deserialization vuln - FastJSON','severity':'High'},'Class.forName':{'description':'Dynamic loading','severity':'Medium'},'ClassLoader.loadClass':{'description':'Dynamic loading - class loader','severity':'Medium'},'Method.invoke':{'description':'Dynamic invocation - reflection call','severity':'Medium'},'Constructor.newInstance':{'description':'Dynamic creation - reflection instance','severity':'Medium'},'getMethod':{'description':'Reflection - get method','severity':'Low'},'Runtime.exec':{'description':'Command execution via Runtime.exec','severity':'Critical'},'ProcessBuilder.start':{'description':'Command execution - ProcessBuilder','severity':'Critical'},'FileInputStream':{'description':'File operation - input stream','severity':'Low'},'FileOutputStream':{'description':'File operation - output stream','severity':'Low'},'FileReader':{'description':'File operation - file reader','severity':'Low'},'FileWriter':{'description':'File operation - file writer','severity':'Low'},'Files.readAllBytes':{'description':'File operation - read bytes','severity':'Low'},'Files.write':{'description':'File operation - write file','severity':'Low'},'URL.openStream':{'description':'Network - open URL','severity':'Medium'},'URLConnection':{'description':'Network - URL connection','severity':'Medium'},'Socket':{'description':'Network socket','severity':'Medium'},'HttpURLConnection':{'description':'HTTP - HTTP request','severity':'Medium'},'MessageDigest.getInstance("MD5")':{'description':'Weak crypto - MD5','severity':'Low'},'MessageDigest.getInstance("SHA1")':{'description':'Weak crypto - SHA1','severity':'Low'},'Cipher.getInstance("DES")':{'description':'Weak crypto - DES','severity':'Low'},'Statement.executeQuery':{'description':'SQL execution - possible injection','severity':'High'},'Statement.executeUpdate':{'description':'SQL execution - update','severity':'High'},'PreparedStatement':{'description':'SQL prepared - relatively safe','severity':'Low'},'Connection.createStatement':{'description':'SQL connection','severity':'Medium'},'InitialContext.lookup':{'description':'JNDI injection - remote lookup','severity':'Critical'},'Context.lookup':{'description':'JNDI injection - context lookup','severity':'Critical'},'Thread.start':{'description':'Thread start','severity':'Low'},'System.loadLibrary':{'description':'Native library loading - JNI','severity':'Medium'},'System.load':{'description':'Native library loading','severity':'Medium'}}

DOTNET_DANGEROUS_METHODS={'BinaryFormatter.Deserialize':{'description':'Deserialization vuln - BinaryFormatter RCE','severity':'Critical'},'Type.InvokeMember':{'description':'Dynamic invocation - reflection bypass','severity':'High'},'XmlSerializer.Deserialize':{'description':'Deserialization vuln - XmlSerializer','severity':'High'},'DataContractSerializer.ReadObject':{'description':'Deserialization vuln - DataContractSerializer','severity':'High'},'JavaScriptSerializer.Deserialize':{'description':'Deserialization vuln - JavaScriptSerializer','severity':'High'},'Type.GetType':{'description':'Dynamic loading','severity':'Medium'},'Assembly.Load':{'description':'Dynamic loading - load assembly','severity':'Medium'},'Activator.CreateInstance':{'description':'Dynamic creation','severity':'Medium'},'MethodInfo.Invoke':{'description':'Dynamic invocation','severity':'Medium'},'Process.Start':{'description':'Command execution','severity':'Critical'},'File.OpenRead':{'description':'File operation','severity':'Low'},'File.OpenWrite':{'description':'File operation','severity':'Low'},'File.ReadAllText':{'description':'File operation','severity':'Low'},'File.WriteAllText':{'description':'File operation','severity':'Low'},'WebClient.DownloadString':{'description':'Network','severity':'Medium'},'WebClient.DownloadFile':{'description':'Network','severity':'Medium'},'HttpClient.GetString':{'description':'HTTP','severity':'Medium'},'HttpWebRequest.Create':{'description':'HTTP','severity':'Medium'},'MD5.Create':{'description':'Weak crypto - MD5','severity':'Low'},'SHA1.Create':{'description':'Weak crypto - SHA1','severity':'Low'},'SqlCommand.ExecuteReader':{'description':'SQL execution','severity':'High'},'SqlCommand.ExecuteNonQuery':{'description':'SQL execution','severity':'High'},'SqlConnection.Open':{'description':'SQL connection','severity':'Low'}}

# ── DeMistify/ModelXray ML模型签名库 ──
# 端侧推理框架的模型文件特征，检测APK中嵌入的ML模型
_ML_MODEL_SIGNATURES = {
    # TensorFlow Lite
    b'TFL3': ('TensorFlow Lite Model', 'tflite', 'flatbuffer',
              '可通过TFLite Interpreter API提取权重和架构'),
    b'FlatBuffers': ('FlatBuffer Container (probable TFLite)', 'tflite_fb', 'flatbuffer',
                     'FlatBuffer格式的ML模型——可能是TFLite或MediaPipe'),
    # ONNX
    b'ONNX': ('ONNX Model', 'onnx', 'protobuf',
              '开放神经网络交换格式——支持跨框架模型提取'),
    b'\x08\x03': ('Possible ONNX protobuf', 'onnx_pb', 'protobuf',
                  'ONNX protobuf编码——IR version≥3'),
    # PyTorch Mobile
    b'PK\x03\x04': ('ZIP container (possible PyTorch Mobile .ptl)', 'pytorch_mobile', 'zip',
                    'PyTorch Mobile模型以ZIP包裹的TorchScript格式分发'),
    b'torch.jit': ('TorchScript JIT Module', 'torchscript', 'torchjit',
                   'TorchScript编译模型——可通过torch.jit.load反序列化'),
    # Apple CoreML
    b'MLModel': ('Apple CoreML Model', 'coreml', 'protobuf',
                 'Apple CoreML格式——mlmodel文件可从IPA中提取'),
    b'CoreML': ('CoreML Container', 'coreml_container', 'unknown',
               'CoreML模型容器'),
    # 通用ML容器
    b'neural-network': ('Neural Network descriptor', 'ml_generic', 'unknown',
                        '通用神经网络描述符——可能是自定义格式'),
    b'paddle': ('PaddlePaddle Model', 'paddle', 'unknown',
                '百度PaddlePaddle框架——常见于国内应用'),
    b'caffe': ('Caffe Model', 'caffe', 'protobuf',
               'Caffe框架模型——遗留设备上的ML'),
    b'ncnn': ('ncnn Model', 'ncnn', 'binary',
              '腾讯ncnn——移动端高性能推理框架'),
    # 模型加密/保护的迹象
    b'encrypted_model': ('Encrypted ML Model', 'encrypted_ml', 'encrypted',
                         '加密的ML模型——可能尝试保护IP但可通过动态分析提取'),
    b'model_key': ('ML Model Decryption Key Hint', 'ml_key_hint', 'text',
                   '模型解密密钥的引用——泄露了解密方法的线索'),
}

# DeMistify（ICSE 2024）：82.73%成功率识别ML模型
# 移动端ML框架典型文件扩展名，APK/ZIP中检测
_ML_FRAMEWORK_EXTENSIONS = {
    '.tflite': 'TensorFlow Lite', '.lite': 'TFLite (alt ext)',
    '.onnx': 'ONNX Runtime', '.ort': 'ONNX Runtime (alt)',
    '.ptl': 'PyTorch Mobile', '.pt': 'PyTorch (full)',
    '.mlmodel': 'CoreML', '.mlpackage': 'CoreML Package',
    '.bin': 'ncnn/Generic Binary Model', '.param': 'ncnn Parameter',
    '.nb': 'MNN (Alibaba)', '.mnn': 'MNN (Alibaba)',
    '.kmodel': 'K210/K510 Model', '.dlc': 'SNPE (Qualcomm)',
}

_SDK_FINGERPRINTS = {
    b'com.google.android.gms':('Google Play Services','play-services'),b'com.google.firebase':('Firebase','firebase'),b'com.facebook':('Facebook SDK','facebook'),b'com.crashlytics':('Crashlytics','crashlytics'),b'com.appsflyer':('AppsFlyer','appsflyer'),b'com.adjust':('Adjust','adjust'),b'com.branch.io':('Branch.io','branch'),b'com.amplitude':('Amplitude','amplitude'),b'com.mixpanel':('Mixpanel','mixpanel'),b'com.flurry':('Flurry','flurry'),b'com.squareup.okhttp3':('OkHttp3','okhttp'),b'com.squareup.retrofit':('Retrofit','retrofit'),b'com.bumptech.glide':('Glide','glide'),b'io.reactivex':('RxJava','rxjava'),b'org.jetbrains.kotlin':('Kotlin Stdlib','kotlin'),b'androidx.':('AndroidX','androidx'),b'com.google.dagger':('Dagger','dagger'),b'com.stripe':('Stripe','stripe'),b'com.braintreepayments':('Braintree','braintree'),b'Newtonsoft.Json':('Newtonsoft.Json','newtonsoft-json'),b'Serilog':('Serilog','serilog'),b'NLog':('NLog','nlog'),b'Dapper':('Dapper','dapper'),b'EntityFramework':('Entity Framework','entityframework'),b'AutoMapper':('AutoMapper','automapper'),b'Polly':('Polly','polly'),b'unity':('Unity Engine','unity'),b'il2cpp':('Unity IL2CPP','il2cpp'),b'libflutter':('Flutter Engine','flutter'),b'react-native':('React Native','react-native'),b'hermes':('Hermes Engine','hermes'),b'xamarin':('Xamarin/.NET MAUI','xamarin'),b'libcrypto':('OpenSSL libcrypto','openssl'),b'libssl':('OpenSSL libssl','openssl'),b'BouncyCastle':('Bouncy Castle','bouncycastle'),b'org.bouncycastle':('Bouncy Castle','bouncycastle'),
}

class ManagedCodeType(StrEnum): UNKNOWN='unknown'; DOTNET='dotnet'; JAVA='java'

@dataclass
class MethodInfo: name:str; class_name:str=''; namespace:str=''; signature:str=''; is_public:bool=False; is_static:bool=False; is_dangerous:bool=False; danger_type:str=''; danger_reasons:list=field(default_factory=list); il_code:str=''; bytecode:bytes=b''; instructions:list=field(default_factory=list)
@dataclass
class ClassInfo: name:str; namespace:str=''; methods:list=field(default_factory=list); fields:list=field(default_factory=list); base_class:str=''; interfaces:list=field(default_factory=list); is_public:bool=False
@dataclass
class MLModelInfo: filename:str; framework:str; format:str; extraction_risk:str; file_hash:str=''; file_size:int=0; is_encrypted:bool=False
@dataclass
class ManagedCodeAnalysisResult: file_path:str=''; code_type:ManagedCodeType=ManagedCodeType.UNKNOWN; classes:list=field(default_factory=list); dangerous_methods:list=field(default_factory=list); vulnerabilities:list=field(default_factory=list); decompiled_code:str=''; metadata:dict=field(default_factory=dict); summary:str=''; error:str=None; cfg_integrity_score:float=0.0; sbom_dependencies:list=field(default_factory=list); ml_models:list=field(default_factory=list)

class ManagedCodeAnalyzer:
    DOTNET_DANGEROUS_METHODS={'BinaryFormatter.Deserialize':'Deserialization vuln - BinaryFormatter RCE','BinaryFormatter.UnsafeDeserialize':'Deserialization vuln - UnsafeDeserialize','JavaScriptSerializer.Deserialize':'Deserialization vuln - JavaScriptSerializer','DataContractSerializer.ReadObject':'Deserialization vuln - DataContractSerializer','XmlSerializer.Deserialize':'Deserialization vuln - XmlSerializer type confusion','NetDataContractSerializer.ReadObject':'Deserialization vuln - NetDataContractSerializer','ObjectStateFormatter.Deserialize':'Deserialization vuln - ViewState parsing','Type.InvokeMember':'Dynamic invocation','MethodInfo.Invoke':'Dynamic invocation','Activator.CreateInstance':'Dynamic creation','Assembly.Load':'Dynamic loading','Assembly.LoadFrom':'Dynamic loading','Assembly.LoadFile':'Dynamic loading','Process.Start':'Command execution','ProcessStartInfo':'Command execution','File.Open':'File operation','File.ReadAllText':'File operation','File.WriteAllText':'File operation','FileStream':'File operation','Directory.GetFiles':'File operation','WebClient.DownloadFile':'Network','HttpClient':'Network','Socket':'Network','MD5':'Weak crypto - MD5','SHA1':'Weak crypto - SHA1','DES':'Weak crypto - DES','RC2':'Weak crypto - RC2','Unsafe':'Unsafe code','SqlCommand':'SQL operation','SqlConnection':'SQL connection','ExecuteNonQuery':'SQL execution','ExecuteReader':'SQL execution'}
    JAVA_DANGEROUS_METHODS={'ObjectInputStream.readObject':'Deserialization vuln - ObjectInputStream RCE','ObjectInputStream.readUnshared':'Deserialization vuln - readUnshared','XMLDecoder.readObject':'Deserialization vuln - XMLDecoder','Yaml.load':'Deserialization vuln - YAML','SnakeYaml.load':'Deserialization vuln - SnakeYAML','JSON.parseObject':'Deserialization vuln - FastJSON','Class.forName':'Dynamic loading','ClassLoader.loadClass':'Dynamic loading','Method.invoke':'Dynamic invocation','Constructor.newInstance':'Dynamic creation','getMethod':'Reflection','Runtime.exec':'Command execution','ProcessBuilder.start':'Command execution','FileInputStream':'File operation','FileOutputStream':'File operation','FileReader':'File operation','FileWriter':'File operation','Files.readAllBytes':'File operation','Files.write':'File operation','URL.openStream':'Network','URLConnection':'Network','Socket':'Network','HttpURLConnection':'HTTP','MessageDigest.getInstance("MD5")':'Weak crypto','MessageDigest.getInstance("SHA1")':'Weak crypto','Cipher.getInstance("DES")':'Weak crypto','Statement.executeQuery':'SQL injection','Statement.executeUpdate':'SQL','PreparedStatement':'SQL safe','Connection.createStatement':'SQL','InitialContext.lookup':'JNDI injection','Context.lookup':'JNDI injection','Thread.start':'Concurrency','System.loadLibrary':'JNI','System.load':'JNI'}

    def __init__(s,fp=None,od=None,ua=True):
        s.file_path=fp; s.output_dir=od if od else os.path.join(Config.REPORTS_DIR,'managed_analysis'); s.use_ai=ua
        if not os.path.exists(s.output_dir):
            try: os.makedirs(s.output_dir,exist_ok=True)
            except OSError: pass
        s.code_type=ManagedCodeType.UNKNOWN; s.classes=[]; s.dangerous_methods=[]; s.vulnerabilities=[]; s._sbom_deps=[]; s._ml_models=[]

    def _check_dependencies(s):
        s.ilspy_available=False; s.cfr_available=False
        try:
            if subprocess.run(['ilspy','--help'],capture_output=True,timeout=5).returncode==0: s.ilspy_available=True
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError): pass
        try:
            if subprocess.run(['java','-jar','cfr.jar','--help'],capture_output=True,timeout=5).returncode==0: s.cfr_available=True
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError): pass

    def analyze(s,fp=None):
        # 上下文连贯，不拆分
        tp=fp if fp else s.file_path
        if not tp or not isinstance(tp,str): return ManagedCodeAnalysisResult(file_path=str(tp) if tp else '',code_type=ManagedCodeType.UNKNOWN,error='File not found')
        if not s._is_safe_path(tp): return ManagedCodeAnalysisResult(file_path=tp,code_type=ManagedCodeType.UNKNOWN,error='Invalid path')
        if not os.path.exists(tp): return ManagedCodeAnalysisResult(file_path=tp,code_type=ManagedCodeType.UNKNOWN,error='File not found')
        s.file_path=tp; s.code_type=s._detect_code_type()
        if s.code_type==ManagedCodeType.UNKNOWN: return ManagedCodeAnalysisResult(file_path=s.file_path,code_type=ManagedCodeType.UNKNOWN,summary='Cannot identify file type')
        if s.code_type==ManagedCodeType.DOTNET: s._analyze_dotnet()
        elif s.code_type==ManagedCodeType.JAVA: s._analyze_java()
        s._detect_vulnerabilities(); dec=s._decompile(); sm=s._generate_summary()
        s._fingerprint_dependencies(); s._detect_ml_models()
        r=ManagedCodeAnalysisResult(file_path=s.file_path,code_type=s.code_type,classes=s.classes,dangerous_methods=s.dangerous_methods,vulnerabilities=s.vulnerabilities,decompiled_code=dec,metadata=s._extract_metadata(),summary=sm)
        r.sbom_dependencies=s._sbom_deps; r.cfg_integrity_score=s._compute_cfg_integrity()
        r.ml_models=[m.__dict__ for m in s._ml_models]
        return r

    def _detect_ml_models(s):
        # 内联检测
        models=[]
        if not s.file_path or not os.path.exists(s.file_path): return
        try:
            # ZIP/APK/JAR时遍历内部文件
            if s.file_path.endswith(('.apk','.jar','.zip','.aab','.ipa')):
                with zipfile.ZipFile(s.file_path,'r') as zf:
                    for entry in zf.namelist():
                        ename=entry.lower()
                        # 文件扩展名匹配
                        for ext,fw in _ML_FRAMEWORK_EXTENSIONS.items():
                            if ename.endswith(ext):
                                try:
                                    data=zf.read(entry)
                                    fh=hashlib.sha256(data).hexdigest()[:16]
                                    is_enc=any(enc_sig in data for enc_sig in [b'encrypted',b'SALT',b'IV'])
                                    models.append(MLModelInfo(entry,fw,ext[1:],'模型文件可从APK中直接提取——存在模型窃取风险',fh,len(data),is_enc))
                                except (KeyError, zipfile.BadZipFile, OSError): pass
                                break
                        # 魔数签名匹配
                        try:
                            data=zf.read(entry)
                            for sig,(name,fmt,container,risk) in _ML_MODEL_SIGNATURES.items():
                                if sig in data[:256]:
                                    fh=hashlib.sha256(data).hexdigest()[:16]
                                    models.append(MLModelInfo(entry,name,fmt,risk,fh,len(data),'encrypted' in name.lower()))
                                    break
                        except (KeyError, zipfile.BadZipFile, OSError): pass
            else:
                # 单文件直接检测
                with open(s.file_path,'rb') as f: data=f.read(4096)
                for sig,(name,fmt,container,risk) in _ML_MODEL_SIGNATURES.items():
                    if sig in data:
                        fh=hashlib.sha256(data).hexdigest()[:16]
                        models.append(MLModelInfo(os.path.basename(s.file_path),name,fmt,risk,fh,len(data),False))
        except Exception as e: logger.debug(f"ML model detection failed: {e}")
        s._ml_models=models
        if models:
            logger.info(f"[Managed] Detected {len(models)} ML model(s) in {s.file_path}")

    def _fingerprint_dependencies(s):
        deps=[]; seen=set()
        try:
            with open(s.file_path,'rb') as f: raw=f.read()
        except (OSError, UnicodeDecodeError): return
        for sig,(name,slug) in _SDK_FINGERPRINTS.items():
            if sig in raw and slug not in seen:
                seen.add(slug); idx=raw.find(sig)
                ctx=raw[max(0,idx-256):idx+len(sig)+256].decode('utf-8',errors='replace')
                vm=re.search(r'(\d+\.\d+\.\d+)',ctx); ver=vm.group(1) if vm else "unknown"
                sh=hashlib.sha256(sig).hexdigest()[:12]
                deps.append({"name":name,"slug":slug,"version":ver,"type":"binary_fingerprint","signature_hash":sh,"confidence":"high" if ver!="unknown" else "medium"})
        s._sbom_deps=deps

    def _is_safe_path(s,p): return not ('..' in p and (os.path.normpath(p).startswith('..') or '/../' in os.path.normpath(p) or '\\..\\' in os.path.normpath(p)))

    def _detect_code_type(s,fp=None):
        tp=fp or s.file_path
        if not tp or not os.path.exists(tp): return ManagedCodeType.UNKNOWN
        try:
            with open(tp,'rb') as f:
                mb=f.read(4)
                if len(mb)<4: return ManagedCodeType.UNKNOWN
                magic=struct.unpack('>I',mb)[0]
                if magic==JAVA_CLASS_MAGIC: return ManagedCodeType.JAVA
                f.seek(0)
                if struct.unpack('<H',f.read(2))[0]==CLR_PE_SIGNATURE:
                    f.seek(60); ph=struct.unpack('<I',f.read(4))[0]
                    f.seek(ph+24+CLR_DIRECTORY_ENTRY*8); clo=struct.unpack('<I',f.read(4))[0]; cls=struct.unpack('<I',f.read(4))[0]
                    if clo!=0 and cls!=0: return ManagedCodeType.DOTNET
                f.seek(0)
                if f.read(4)==b'PK\x03\x04':
                    try:
                        with zipfile.ZipFile(tp,'r') as zf:
                            if any(n.endswith('.class') for n in zf.namelist()): return ManagedCodeType.JAVA
                    except (zipfile.BadZipFile, OSError): pass
        except (OSError, struct.error, zipfile.BadZipFile): pass
        return ManagedCodeType.UNKNOWN

    def _analyze_dotnet(s):
        if s.ilspy_available: s._analyze_dotnet_with_ilspy()
        else: s._analyze_dotnet_builtin()
    def _analyze_dotnet_with_ilspy(s):
        try:
            r=subprocess.run(['ilspy','--output',s.output_dir,s.file_path],capture_output=True,text=True,timeout=Config.SUBPROCESS_TIMEOUT)
            if r.returncode==0: s._parse_ilspy_output(r.stdout)
            else: s._analyze_dotnet_builtin()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError): s._analyze_dotnet_builtin()
    def _parse_ilspy_output(s,stdout): pass
    def _analyze_dotnet_builtin(s):
        try:
            with open(s.file_path,'rb') as f:
                if f.read(2)!=b'MZ': return
                f.seek(60); ph=struct.unpack('<I',f.read(4))[0]; f.seek(ph)
                if f.read(4)!=b'PE\x00\x00': return
                f.seek(ph+24+CLR_DIRECTORY_ENTRY*8); clo=struct.unpack('<I',f.read(4))[0]
                if clo==0: return
                f.seek(clo); ch=f.read(72); rvm=struct.unpack('<H',ch[4:6])[0]; rvv=struct.unpack('<H',ch[6:8])[0]
                strs=s._extract_dotnet_strings(f); s._detect_dangerous_from_strings(strs,ManagedCodeType.DOTNET)
                s._extract_metadata()['runtime_version']=f'{rvm}.{rvv}'
        except (OSError, struct.error): pass
    def _extract_dotnet_strings(s,f):
        strs=[]
        try:
            f.seek(0); data=f.read()
            for m in re.compile(b'[\x01-\x7F]{4,100}').finditer(data):
                try:
                    st=m.group().decode('utf-8',errors='ignore')
                    if len(st)>=4 and not st.startswith('\x00'): strs.append(st)
                except (UnicodeDecodeError, AttributeError): pass
            strs=strs[:500]
        except (OSError, UnicodeDecodeError): pass
        return strs
    def _analyze_java(s):
        if s.file_path.endswith('.jar'): s._analyze_jar()
        else: s._analyze_class_file(s.file_path)
    def _analyze_jar(s):
        try:
            with zipfile.ZipFile(s.file_path,'r') as zf:
                nl=zf.namelist(); cfs=[n for n in nl if n.endswith('.class')]
                for i in range(min(len(cfs),50)):
                    try: s._analyze_class_bytes(zf.read(cfs[i]),cfs[i])
                    except (KeyError, zipfile.BadZipFile, OSError): pass
                if 'META-INF/MANIFEST.MF' in nl: s._extract_metadata()['manifest']=zf.read('META-INF/MANIFEST.MF').decode('utf-8',errors='ignore')
        except (zipfile.BadZipFile, OSError): pass
    def _analyze_class_file(s,fp):
        try:
            with open(fp,'rb') as f: s._analyze_class_bytes(f.read(),fp)
        except (OSError, struct.error): pass
    def _analyze_class_bytes(s,cd,src):
        try:
            dl=len(cd)
            if dl<10 or struct.unpack('>I',cd[0:4])[0]!=JAVA_CLASS_MAGIC: return
            cpc=struct.unpack('>H',cd[8:10])[0]; cp,ce=s._parse_constant_pool(cd,cpc)
            af=struct.unpack('>H',cd[ce:ce+2])[0]; tc=struct.unpack('>H',cd[ce+2:ce+4])[0]; sc=struct.unpack('>H',cd[ce+4:ce+6])[0]
            cn=s._get_class_name_from_cp(cp,tc); scn=s._get_class_name_from_cp(cp,sc)
            cnp=cn.split('/'); sn=cnp[-1] if cnp else cn
            ci=ClassInfo(sn,'/'.join(cnp[:-1]),s._parse_methods(cd,ce+6,cp),scn,[],[],(af&0x0001)!=0)
            s.classes.append(ci)
            for m in ci.methods: s._check_java_method_danger(method=m)
        except (struct.error, IndexError, UnicodeDecodeError): pass
    def _parse_constant_pool(s,cd=b'',count=None):
        if count is None:
            try:
                pd={}; dl=len(cd)
                if dl<3: return pd
                cpc=struct.unpack('>H',cd[0:2])[0] if dl>=3 else 0; off=2; limit=min(cpc,200); i=1
                while i<limit:
                    if off>=dl: break
                    tag=cd[off]; off+=1
                    if tag==1:
                        if off+2>dl: break
                        length=struct.unpack('>H',cd[off:off+2])[0]; off+=2
                        if off+length>dl: break
                        pd[f'#{i}']={'tag':'Utf8','value':cd[off:off+length].decode('utf-8',errors='replace')}; off+=length
                    elif tag==7:
                        if off+2>dl: break; pd[f'#{i}']={'tag':'Class','name_index':struct.unpack('>H',cd[off:off+2])[0]}; off+=2
                    else: break
                    i+=1
                return pd
            except (struct.error, IndexError, UnicodeDecodeError): return {}
        cp=[None]; off=10; i=1
        while i<count:
            dl=len(cd)
            if off>=dl: break
            tag=cd[off]; off+=1; entry=None
            if tag==7: entry=('Class',struct.unpack('>H',cd[off:off+2])[0]); off+=2
            elif tag==9: entry=('Fieldref',struct.unpack('>H',cd[off:off+2])[0],struct.unpack('>H',cd[off+2:off+4])[0]); off+=4
            elif tag==10: entry=('Methodref',struct.unpack('>H',cd[off:off+2])[0],struct.unpack('>H',cd[off+2:off+4])[0]); off+=4
            elif tag==11: entry=('InterfaceMethodref',struct.unpack('>H',cd[off:off+2])[0],struct.unpack('>H',cd[off+2:off+4])[0]); off+=4
            elif tag==8: entry=('String',struct.unpack('>H',cd[off:off+2])[0]); off+=2
            elif tag==3: entry=('Integer',struct.unpack('>I',cd[off:off+4])[0]); off+=4
            elif tag==4: entry=('Float',struct.unpack('>f',cd[off:off+4])[0]); off+=4
            elif tag==5: entry=('Long',struct.unpack('>Q',cd[off:off+8])[0]); off+=8; cp.append(None)
            elif tag==6: entry=('Double',struct.unpack('>d',cd[off:off+8])[0]); off+=8; cp.append(None)
            elif tag==12: entry=('NameAndType',struct.unpack('>H',cd[off:off+2])[0],struct.unpack('>H',cd[off+2:off+4])[0]); off+=4
            elif tag==1: length=struct.unpack('>H',cd[off:off+2])[0]; entry=('Utf8',cd[off+2:off+2+length].decode('utf-8',errors='replace')); off+=2+length
            elif tag==15: entry=('MethodHandle',cd[off],struct.unpack('>H',cd[off+1:off+3])[0]); off+=3
            elif tag==16: entry=('MethodType',struct.unpack('>H',cd[off:off+2])[0]); off+=2
            elif tag==17: entry=('Dynamic',struct.unpack('>H',cd[off:off+2])[0],struct.unpack('>H',cd[off+2:off+4])[0]); off+=4
            elif tag==18: entry=('InvokeDynamic',struct.unpack('>H',cd[off:off+2])[0],struct.unpack('>H',cd[off+2:off+4])[0]); off+=4
            elif tag==19: entry=('Module',struct.unpack('>H',cd[off:off+2])[0]); off+=2
            elif tag==20: entry=('Package',struct.unpack('>H',cd[off:off+2])[0]); off+=2
            else: entry=('Unknown',tag); off+=1
            cp.append(entry); i+=1
        return cp,off
    def _get_class_name_from_cp(s,cp,ci):
        if ci==0 or ci>=len(cp): return 'Unknown'
        e=cp[ci]
        if e and e[0]=='Class' and e[1]<len(cp):
            ne=cp[e[1]]
            if ne and ne[0]=='Utf8': return ne[1]
        return 'Unknown'
    def _parse_methods(s,cd,off,cp):
        methods=[]; dl=len(cd)
        try:
            if off+2>dl: return methods
            ic=struct.unpack('>H',cd[off:off+2])[0]; off+=2+ic*2
            if off+2>dl: return methods
            fc=struct.unpack('>H',cd[off:off+2])[0]; off+=2
            for _ in range(fc):
                if off+8>dl: break; off+=8
                for _ in range(struct.unpack('>H',cd[off-2:off])[0]):
                    if off+6>dl: break; al=struct.unpack('>I',cd[off+2:off+6])[0]; off+=6+al
            if off+2>dl: return methods
            mc=struct.unpack('>H',cd[off:off+2])[0]; off+=2
            for _ in range(mc):
                if off+8>dl: break
                af=struct.unpack('>H',cd[off:off+2])[0]; ni=struct.unpack('>H',cd[off+2:off+4])[0]; di=struct.unpack('>H',cd[off+4:off+6])[0]; ac=struct.unpack('>H',cd[off+6:off+8])[0]; off+=8
                pl=len(cp); mn='Unknown'; ms='Unknown'
                if ni<pl:
                    ne=cp[ni]
                    if ne and ne[0]=='Utf8': mn=ne[1]
                if di<pl:
                    de=cp[di]
                    if de and de[0]=='Utf8': ms=de[1]
                bc=b''
                for _ in range(ac):
                    if off+6>dl: break
                    ani=struct.unpack('>H',cd[off:off+2])[0]; al=struct.unpack('>I',cd[off+2:off+6])[0]; off+=6
                    if ani<pl:
                        ae=cp[ani]
                        if ae and ae[0]=='Utf8' and ae[1]=='Code':
                            if off+8>dl: break
                            cl=struct.unpack('>I',cd[off+4:off+8])[0]; ce=off+8+cl
                            if ce<=dl: bc=cd[off+8:ce]
                            off+=8+cl
                            if off+2>dl: break; off+=2+struct.unpack('>H',cd[off:off+2])[0]*8
                            if off+2>dl: break
                            cac=struct.unpack('>H',cd[off:off+2])[0]; off+=2
                            for _ in range(cac):
                                if off+6>dl: break; off+=6+struct.unpack('>I',cd[off+2:off+6])[0]
                    else: off+=al
                cfn=''
                if dl>10: cfn=s._get_class_name_from_cp(cp,struct.unpack('>H',cd[8:10])[0])
                methods.append(MethodInfo(mn,cfn,ms,(af&0x0001)!=0,(af&0x0008)!=0,bytecode=bc))
        except (struct.error, IndexError, UnicodeDecodeError): pass
        return methods

    def _check_java_method_danger(s,bc='',mn='',method=None):
        # 上下文连贯，不拆分
        idn=False; rs=[]
        if method and isinstance(method,MethodInfo):
            bcs=method.bytecode or b''
            if isinstance(bcs,bytes):
                try: bcs=bcs.decode('utf-8',errors='replace')
                except (UnicodeDecodeError, AttributeError): bcs=''
            else: bcs=str(bcs)
            mname=method.name or ''
            for p,di in JAVA_DANGEROUS_METHODS.items():
                if p in mname or p.split('.')[-1] in bcs:
                    idn=True; method.is_dangerous=True
                    desc=di.get('description',str(di)) if isinstance(di,dict) else str(di)
                    rs.append(desc); method.danger_type=desc
            return idn,rs
        for p,di in JAVA_DANGEROUS_METHODS.items():
            desc=di.get('description',str(di)) if isinstance(di,dict) else str(di)
            if p in bc: idn=True; rs.append(desc)
            elif mn and (p in mn or p.split('.')[-1] in mn): idn=True; rs.append(desc)
            elif mn and mn in p: idn=True; rs.append(desc)
        return idn,rs

    def _check_dotnet_method_danger(s,ic='',mn=''):
        idn=False; rs=[]
        for p,di in DOTNET_DANGEROUS_METHODS.items():
            desc=di.get('description',str(di)) if isinstance(di,dict) else str(di)
            if p in ic: idn=True; rs.append(desc)
            elif mn and (p in mn or p.split('.')[-1] in mn): idn=True; rs.append(desc)
            elif mn and mn in p: idn=True; rs.append(desc)
        return idn,rs

    def get_danger_summary(s,result=None):
        if result is None: result=ManagedCodeAnalysisResult(code_type=s.code_type,classes=s.classes,dangerous_methods=s.dangerous_methods,vulnerabilities=s.vulnerabilities)
        sc={'Critical':0,'High':0,'Medium':0,'Low':0}
        for m in result.dangerous_methods:
            for p,di in JAVA_DANGEROUS_METHODS.items():
                if m.name in p or p.split('.')[-1] in m.name:
                    if isinstance(di,dict):
                        sv=di.get('severity','Medium')
                        if sv in sc: sc[sv]+=1
                    break
            else:
                for p,di in DOTNET_DANGEROUS_METHODS.items():
                    if m.name in p or p.split('.')[-1] in m.name:
                        if isinstance(di,dict):
                            sv=di.get('severity','Medium')
                            if sv in sc: sc[sv]+=1
                        break
        cts=result.code_type.value if hasattr(result.code_type,'value') else str(result.code_type)
        dn=[result.dangerous_methods[i].name for i in range(min(len(result.dangerous_methods),10))]
        return {'code_type':cts,'total_classes':len(result.classes),'dangerous_methods':len(result.dangerous_methods),'vulnerabilities':len(result.vulnerabilities) if isinstance(result.vulnerabilities,list) else 0,'severity_count':sc,'file_path':result.file_path,'error':result.error,'dangerous_method_names':dn}

    def _detect_dangerous_from_strings(s,strings,ct):
        dp=s.DOTNET_DANGEROUS_METHODS if ct==ManagedCodeType.DOTNET else s.JAVA_DANGEROUS_METHODS
        for st in strings:
            for p,dd in dp.items():
                if p in st: s.dangerous_methods.append(MethodInfo(name=st,is_dangerous=True,danger_type=dd)); break

    def _detect_vulnerabilities(s):
        for m in s.dangerous_methods:
            vt=m.danger_type; sev='high'
            if 'Command execution' in vt: sev='critical'
            elif 'Deserialization' in vt: sev='critical'
            elif 'Weak crypto' in vt: sev='medium'
            elif 'SQL' in vt: sev='high'
            elif 'JNDI' in vt: sev='critical'
            s.vulnerabilities.append({'type':vt,'severity':sev,'location':f'{m.class_name}.{m.name}','description':f'Dangerous method call detected: {m.name}','recommendation':s._get_recommendation(vt)})
        # ML模型提取风险附加
        for mm in s._ml_models:
            sev='high' if not mm.is_encrypted else 'medium'
            s.vulnerabilities.append({'type':'ML Model Extraction Risk','severity':sev,'description':f'端侧ML模型可被提取: {mm.filename} ({mm.framework})','extraction_risk':mm.extraction_risk,'recommendation':'使用TEE (TrustZone) 或模型加密保护ML模型'})

    def _get_recommendation(s,vt):
        rec={'Deserialization':'Avoid unsafe deserialization, use allowlist','Command execution':'Use parameterized commands','Weak crypto':'Use AES-256, SHA-256, RSA-2048','SQL':'Use parameterized queries','JNDI injection':'Avoid remote JNDI lookup'}
        for k,r in rec.items():
            if k in vt: return r
        return 'Review call context, validate input'

    def _decompile(s):
        if s.use_ai and s.classes: return s._decompile_with_ai()
        return s._generate_pseudocode()

    def _decompile_with_ai(s):
        try:
            cc=[{'name':c.name,'namespace':c.namespace,'methods':[{'name':m.name,'signature':m.signature,'instructions':m.instructions[:50]} for m in c.methods[:10]]} for c in s.classes[:10]]
            from prompts import MANAGED_CODE_DECOMPILE_TEMPLATE
            return call_ai_with_retry(model=get_current_ai_model(),messages=[{"role":"system","content":MANAGED_CODE_DECOMPILE_TEMPLATE},{"role":"user","content":json.dumps({'file_path':s.file_path,'code_type':s.code_type.value,'classes':cc},ensure_ascii=False,indent=2)}],temperature=0.2,max_tokens=4000)
        except (ImportError, json.JSONDecodeError, TypeError, Exception): return s._generate_pseudocode()

    def _generate_pseudocode(s):
        lines=[]
        if s.code_type==ManagedCodeType.DOTNET: lines.append('// .NET Assembly Analysis')
        elif s.code_type==ManagedCodeType.JAVA: lines.append('// Java Bytecode Analysis')
        lines.append(f'// File: {os.path.basename(s.file_path)}'); lines.append('')
        for cls in s.classes:
            indent='    ' if cls.namespace else ''; acc='public' if cls.is_public else 'private'
            if cls.namespace: lines.append(f'namespace {cls.namespace} {{')
            lines.append(f'{indent}{acc} class {cls.name} : {cls.base_class} {{')
            for j in range(min(len(cls.methods),20)):
                m=cls.methods[j]; ma='public' if m.is_public else 'private'; sk='static ' if m.is_static else ''
                dm=' // [DANGER]' if m.is_dangerous else ''
                lines.append(f'{indent}    {ma} {sk}{m.name}({m.signature}){dm}')
                if m.instructions:
                    lines.append(f'{indent}    {{')
                    for k in range(min(len(m.instructions),10)): lines.append(f'{indent}        {m.instructions[k]}')
                    lines.append(f'{indent}    }}')
            lines.append(f'{indent}}}')
            if cls.namespace: lines.append('}'); lines.append('')
        return '\n'.join(lines)

    def _extract_metadata(s):
        return {'file_path':s.file_path,'code_type':s.code_type.value,'class_count':len(s.classes),'method_count':sum(len(c.methods) for c in s.classes),'dangerous_method_count':len(s.dangerous_methods),'vulnerability_count':len(s.vulnerabilities),'sbom_dependency_count':len(s._sbom_deps),'ml_model_count':len(s._ml_models)}

    def _compute_cfg_integrity(s)->float:
        tc=0; vc=0
        for cls in s.classes:
            for m in cls.methods:
                for ins in m.instructions:
                    tc+=1
                    if ins.startswith('invokevirtual') or ins.startswith('invokeinterface'): vc+=1
        return round(1.0-vc/max(tc,1),3) if tc else 1.0

    def _generate_summary(s):
        sl=[f'Managed code analysis result ({s.code_type.value})',f'File: {os.path.basename(s.file_path)}',f'Found {len(s.classes)} classes',f'Found {len(s.dangerous_methods)} dangerous methods',f'Found {len(s.vulnerabilities)} vulnerabilities',f'SBOM: {len(s._sbom_deps)} dependencies',f'ML Models: {len(s._ml_models)} detected']
        if s.vulnerabilities:
            sc={}
            for v in s.vulnerabilities: sc[v['severity']]=sc.get(v['severity'],0)+1
            sl.append('Vulnerability severity:')
            for sev in ['critical','high','medium','low']:
                if sev in sc: sl.append(f'  - {sev}: {sc[sev]}')
        return '\n'.join(sl)

    def to_dict(s):
        return {'file_path':s.file_path,'code_type':s.code_type.value,'classes':[{'name':c.name,'namespace':c.namespace,'methods':[{'name':m.name,'is_dangerous':m.is_dangerous,'danger_type':m.danger_type} for m in c.methods]} for c in s.classes],'dangerous_methods':[{'name':m.name,'class_name':m.class_name,'danger_type':m.danger_type} for m in s.dangerous_methods],'vulnerabilities':s.vulnerabilities,'summary':s._generate_summary(),'sbom':s._sbom_deps,'ml_models':[m.__dict__ for m in s._ml_models]}

def analyze_managed_code(fp,od=None,ua=True): return ManagedCodeAnalyzer(fp,od,ua).analyze()
def detect_managed_code_type(fp):
    try:
        with open(fp,'rb') as f:
            magic=struct.unpack('>I',f.read(4))[0]
            if magic==JAVA_CLASS_MAGIC: return ManagedCodeType.JAVA
            f.seek(0)
            if f.read(2)==b'MZ':
                f.seek(60); ph=struct.unpack('<I',f.read(4))[0]
                f.seek(ph+24+CLR_DIRECTORY_ENTRY*8)
                if struct.unpack('<I',f.read(4))[0]!=0: return ManagedCodeType.DOTNET
            f.seek(0)
            if f.read(4)==b'PK\x03\x04':
                try:
                    with zipfile.ZipFile(fp,'r') as zf:
                        if any(n.endswith('.class') for n in zf.namelist()): return ManagedCodeType.JAVA
                except (zipfile.BadZipFile, OSError): pass
    except (OSError, struct.error, zipfile.BadZipFile): pass
    return ManagedCodeType.UNKNOWN
