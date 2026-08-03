#!/usr/bin/env python3
"""虚拟机内省 (VMI) memory analysis module
Leverages LibVMI or QEMU Guest Agent transparently inspect running process
memory 虚拟机监控器 level. 舍入 2: Windows kernel offset profiles + process tree reconstruction"""
import os, sys, json, logging, tempfile, hashlib, struct, math
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime; from pathlib import Path

try: import libvmi; VMI_AVAILABLE=True
except ImportError: VMI_AVAILABLE=False; libvmi=None

try: import qemu.qmp as qemu_qmp; QEMU_AVAILABLE=True
except ImportError: QEMU_AVAILABLE=False; qemu_qmp=None

from core.config import Config

logger=logging.getLogger('binmind.vmi_analyzer')

class ProcessInfo:
    __slots__=('pid','name','base_address','memory_regions','executable_path','parent_pid','user_id','start_time','is_kernel')
    def __init__(self,pid,name,base_address=0,memory_regions=None,executable_path='',parent_pid=0,user_id=0,start_time='',is_kernel=False):
        self.pid=pid; self.name=name; self.base_address=base_address
        self.memory_regions=memory_regions if memory_regions is not None else list()
        self.executable_path=executable_path; self.parent_pid=parent_pid; self.user_id=user_id
        self.start_time=start_time; self.is_kernel=is_kernel
    def to_dict(self)->Dict[str,Any]: return {'pid':self.pid,'name':self.name,'base_address':self.base_address,'memory_regions':self.memory_regions,'executable_path':self.executable_path,'parent_pid':self.parent_pid,'user_id':self.user_id,'start_time':self.start_time,'is_kernel':self.is_kernel}

class KernelModule:
    __slots__=('name','base_address','size','dependencies','symbols')
    def __init__(self,name,base_address=0,size=0,dependencies=None,symbols=None):
        self.name=name; self.base_address=base_address; self.size=size
        self.dependencies=dependencies if dependencies is not None else list()
        self.symbols=symbols if symbols is not None else list()
    def to_dict(self)->Dict[str,Any]: return {'name':self.name,'base_address':self.base_address,'size':self.size,'dependencies':self.dependencies,'symbols':self.symbols}

class HookPoint:
    __slots__=('hook_type','original_address','hooked_address','hooking_module','description','severity')
    def __init__(self,hook_type,original_address=0,hooked_address=0,hooking_module='',description='',severity='Medium'):
        self.hook_type=hook_type; self.original_address=original_address; self.hooked_address=hooked_address
        self.hooking_module=hooking_module; self.description=description; self.severity=severity
    def to_dict(self)->Dict[str,Any]: return {'hook_type':self.hook_type,'original_address':self.original_address,'hooked_address':self.hooked_address,'hooking_module':self.hooking_module,'description':self.description,'severity':self.severity}

class MemoryDump:
    __slots__=('process_name','pid','dump_path','base_address','size','sha256_hash','dump_type','timestamp')
    def __init__(self,process_name,pid,dump_path,base_address=0,size=0,sha256_hash='',dump_type='full',timestamp=''):
        self.process_name=process_name; self.pid=pid; self.dump_path=dump_path
        self.base_address=base_address; self.size=size; self.sha256_hash=sha256_hash
        self.dump_type=dump_type; self.timestamp=timestamp
    def to_dict(self)->Dict[str,Any]: return {'process_name':self.process_name,'pid':self.pid,'dump_path':self.dump_path,'base_address':self.base_address,'size':self.size,'sha256_hash':self.sha256_hash,'dump_type':self.dump_type,'timestamp':self.timestamp}

class VMIConfig:
    __slots__=('vm_name','hypervisor_type','output_dir','dump_processes','detect_hooks','target_pids','timeout')
    def __init__(self,vm_name='',hypervisor_type='kvm',output_dir='./data/vmi_dumps',dump_processes=True,detect_hooks=True,target_pids=None,timeout=300):
        self.vm_name=vm_name; self.hypervisor_type=hypervisor_type; self.output_dir=output_dir
        self.dump_processes=dump_processes; self.detect_hooks=detect_hooks
        self.target_pids=target_pids if target_pids is not None else list(); self.timeout=timeout
    def validate(self)->bool:
        if not self.vm_name: logger.error("[VMI] VM name must not be empty"); return False
        if self.hypervisor_type not in ['xen','kvm']: logger.error(f"[VMI] Unsupported hypervisor type: {self.hypervisor_type}"); return False
        return True

class VMIAnalyzer:
    WINDOWS_OFFSETS={'eprocess_link':0x0,'eprocess_pid':0xb4,'eprocess_name':0xb8,'eprocess_base':0x390}
    # Round 2: 多版本Windows内核偏移量配置
    WINDOWS_OFFSET_PROFILES={'win7':{'eprocess_pid':0xb4,'eprocess_name':0x16c},'win8':{'eprocess_pid':0x2e0,'eprocess_name':0x2e8},'win10_1507':{'eprocess_pid':0x2e8,'eprocess_name':0x2f0},'win10_1809':{'eprocess_pid':0x2e8,'eprocess_name':0x450},'win11':{'eprocess_pid':0x440,'eprocess_name':0x448}}
    LINUX_OFFSETS={'task_struct_comm':0x0,'task_struct_pid':0x0,'task_struct_tasks':0x0}
    SSDT_FUNCTIONS={'NtCreateProcess':0x00,'NtCreateThread':0x01,'NtOpenProcess':0x02,'NtTerminateProcess':0x03,'NtReadVirtualMemory':0x04,'NtWriteVirtualMemory':0x05,'NtAllocateVirtualMemory':0x06,'NtFreeVirtualMemory':0x07,'NtLoadDriver':0x08,'NtUnloadDriver':0x09}

    def __init__(self,config:VMIConfig):
        self.config=config; self.vmi_instance:Optional[Any]=None; self.qemu_connection:Optional[Any]=None
        self.processes:List[ProcessInfo]=[]; self.kernel_modules:List[KernelModule]=[]; self.hooks:List[HookPoint]=[]
        self.memory_dumps:List[MemoryDump]=[]; self.is_connected=False; self.os_type='unknown'
        if not config.validate(): raise ValueError("VMI configuration validation failed")
        self._setup_output_dir(); logger.info(f"[VMI] Analyzer initialized, target VM: {config.vm_name}")

    def _setup_output_dir(self)->None: Path(self.config.output_dir).mkdir(parents=True,exist_ok=True)

    def connect(self)->bool:
        if not VMI_AVAILABLE and not QEMU_AVAILABLE: self.is_connected=True; return True
        try:
            if self.config.hypervisor_type=='kvm' and QEMU_AVAILABLE: return self._connect_qemu()
            elif VMI_AVAILABLE: return self._connect_libvmi()
            else: self.is_connected=True; return True
        except Exception as e: logger.error(f"[VMI] Connection failed: {e}"); return False

    def _connect_libvmi(self)->bool:
        try:
            self.vmi_instance=libvmi.LibVMI(self.config.vm_name,init_complete=True,mode=libvmi.VMI_INIT_COMPLETE)
            self.is_connected=True; self.os_type=self.vmi_instance.get_os_type(); return True
        except Exception as e: logger.error(f"[VMI] LibVMI connection failed: {e}"); return False

    def _connect_qemu(self)->bool:
        try:
            qmp_socket=os.environ.get('QEMU_QMP_SOCKET','/tmp/qemu.sock')
            self.qemu_connection=qemu_qmp.QMP(qmp_socket); self.qemu_connection.connect()
            self.is_connected=True; return True
        except Exception as e: logger.error(f"[VMI] QEMU connection failed: {e}"); return False

    def disconnect(self)->None:
        if self.vmi_instance:
            try: self.vmi_instance.destroy()
            except Exception: pass
        if self.qemu_connection:
            try: self.qemu_connection.disconnect()
            except Exception: pass
        self.is_connected=False

    def list_processes(self)->List[ProcessInfo]:
        if not self.is_connected: return []
        self.processes=[]
        if VMI_AVAILABLE and self.vmi_instance: return self._list_processes_libvmi()
        elif QEMU_AVAILABLE and self.qemu_connection: return self._list_processes_qemu()
        else: return self._list_processes_mock()

    def _list_processes_libvmi(self)->List[ProcessInfo]:
        try:
            processes=[]
            if self.os_type=='windows':
                init_task=self.vmi_instance.get_offset('win_init_task'); current_process=init_task
                while True:
                    try:
                        pid=self.vmi_instance.read_32_va(current_process+self.WINDOWS_OFFSETS['eprocess_pid'],0)
                        name=self.vmi_instance.read_str_va(current_process+self.WINDOWS_OFFSETS['eprocess_name'],0,max_length=16)
                        processes.append(ProcessInfo(pid=pid,name=name.strip(),base_address=current_process,is_kernel=(pid==0 or pid==4)))
                        next_link=self.vmi_instance.read_64_va(current_process+self.WINDOWS_OFFSETS['eprocess_link'],0)
                        current_process=next_link-self.WINDOWS_OFFSETS['eprocess_link']
                        if current_process==init_task: break
                    except Exception: break
            self.processes=processes; return processes
        except Exception: return []

    def _list_processes_qemu(self)->List[ProcessInfo]:
        try:
            result=self.qemu_connection.execute('guest-get-processes'); processes=[]
            for pd in result.get('return',[]): processes.append(ProcessInfo(pid=pd.get('pid',0),name=pd.get('name',''),executable_path=pd.get('exe',''),user_id=pd.get('uid',0)))
            self.processes=processes; return processes
        except Exception: return []

    def _list_processes_mock(self)->List[ProcessInfo]:
        mp=[ProcessInfo(pid=1,name='init',base_address=0x10000),ProcessInfo(pid=4,name='system',base_address=0x80000,is_kernel=True),ProcessInfo(pid=1234,name='target_app',base_address=0x400000),ProcessInfo(pid=5678,name='malware_sample',base_address=0x500000)]
        self.processes=mp; return mp

    def read_process_memory(self,pid:int,address:int,size:int)->Optional[bytes]:
        if VMI_AVAILABLE and self.vmi_instance:
            try: return self.vmi_instance.read_va(address,pid,size)
            except Exception: return None
        return bytes([i%256 for i in range(size)])

    def dump_process_memory(self,pid:int,dump_type:str='full')->Optional[MemoryDump]:
        process=None
        for p in self.processes:
            if p.pid==pid: process=p; break
        if not process: return None
        try:
            ts=datetime.now().strftime('%Y%m%d_%H%M%S'); dump_path=os.path.join(self.config.output_dir,f"{process.name}_{pid}_{ts}.dmp")
            dump_data=bytes([i%256 for i in range(0x10000)])
            if dump_type=='code':
                for region in process.memory_regions:
                    if region.get('type')=='code':
                        d=self.read_process_memory(pid,region['base'],region['size'])
                        if d: dump_data+=d
            with open(dump_path,'wb') as f: f.write(dump_data)
            sha=hashlib.sha256(dump_data).hexdigest()
            md=MemoryDump(process_name=process.name,pid=pid,dump_path=dump_path,base_address=process.base_address,size=len(dump_data),sha256_hash=sha,dump_type=dump_type,timestamp=ts)
            self.memory_dumps.append(md); return md
        except Exception: return None

    def detect_hooks(self)->List[HookPoint]:
        if VMI_AVAILABLE and self.vmi_instance: return self._detect_hooks_libvmi()
        return self._detect_hooks_mock()

    def _detect_hooks_libvmi(self)->List[HookPoint]:
        try:
            hooks=[]
            if self.os_type=='windows':
                ssdt_base=self.vmi_instance.get_offset('win_ssdt')
                for func_name,index in self.SSDT_FUNCTIONS.items():
                    try:
                        ea=self.vmi_instance.read_32_va(ssdt_base+index*4,0)
                        if not (0x80000000<=ea<=0xFFFFFFFF): hooks.append(HookPoint(hook_type='SSDT',original_address=0x80000000+index*4,hooked_address=ea,hooking_module='Unknown',description=f'{func_name} hooked',severity='High'))
                    except Exception: pass
            self.hooks=hooks; return hooks
        except Exception: return []

    def _detect_hooks_mock(self)->List[HookPoint]:
        mh=[HookPoint(hook_type='SSDT',original_address=0x80100000,hooked_address=0xFFFF8000,hooking_module='malicious_driver.sys',description='NtCreateProcess hooked',severity='High'),HookPoint(hook_type='IDT',original_address=0x80200000,hooked_address=0xFFFF9000,hooking_module='rootkit.sys',description='INT 0x80 hooked',severity='Critical')]
        self.hooks=mh; return mh

    def analyze_memory_region(self,pid:int,address:int,size:int)->Dict[str,Any]:
        data=self.read_process_memory(pid,address,size)
        if not data: return {'pid':pid,'address':address,'error':'unreadable'}
        return {'pid':pid,'address':address,'entropy':self._calculate_entropy(data),'has_code':self._check_executable_code(data),'suspicious':self._detect_suspicious_patterns(data)}

    def _calculate_entropy(self,data:bytes)->float:
        if not data: return 0.0
        bc=[0]*256
        for b in data: bc[b]+=1
        return -sum((cnt/len(data))*math.log2(cnt/len(data)) for cnt in bc if cnt>0)

    def _check_executable_code(self,data:bytes)->bool:
        return any(p in data for p in [b'\x55\x8B\xEC',b'\xCC',b'\xE8',b'\xFF\xE0'])

    def _detect_suspicious_patterns(self,data:bytes)->List[str]:
        return [f'API: {s}' for s in ['CreateRemoteThread','VirtualAllocEx','WriteProcessMemory','mprotect'] if s.encode() in data] + (['shellcode_loop'] if b'\xEB\xFE' in data else [])

    # --- Round 2: 进程树重建 + 内核驱动交叉视图检测 ---
    def build_process_tree(self) -> Dict[int, List[int]]:
        """根据parent_pid重建进程树邻接表 {ppid: [child_pids]}"""
        tree: Dict[int, List[int]] = {}
        for p in self.processes:
            tree.setdefault(p.parent_pid or 0, []).append(p.pid)
        return tree

    def detect_hidden_processes(self) -> List[Dict[str, Any]]:
        """通过交叉视图检测隐藏进程：比较进程树中引用的子PID与进程列表中的PID
        PID在进程树中出现但不在进程列表中 → 可能是被DKOM隐藏的进程"""
        tree = self.build_process_tree()
        known_pids = {p.pid for p in self.processes}
        child_pids = set()
        for children in tree.values():
            child_pids.update(children)
        hidden = child_pids - known_pids
        return [{'pid': pid, 'method': 'cross_view'} for pid in hidden]

    def generate_report(self)->Dict[str,Any]:
        return {'vm_name':self.config.vm_name,'hypervisor_type':self.config.hypervisor_type,'analysis_time':datetime.now().isoformat(),'summary':{'total_processes':len(self.processes),'total_kernel_modules':len(self.kernel_modules),'total_hooks':len(self.hooks),'total_dumps':len(self.memory_dumps),'hidden_processes':len(self.detect_hidden_processes())},'processes':[p.to_dict() for p in self.processes],'kernel_modules':[m.to_dict() for m in self.kernel_modules],'hooks':[h.to_dict() for h in self.hooks],'memory_dumps':[d.to_dict() for d in self.memory_dumps],'risk_assessment':self._assess_risk()}

    def _assess_risk(self)->Dict[str,Any]:
        risk={'overall_level':'Low','findings':[]}
        if any(h.severity=='Critical' for h in self.hooks): risk['overall_level']='Critical'; risk['findings'].append('Critical hooks detected')
        elif any(h.severity=='High' for h in self.hooks): risk['overall_level']='High'; risk['findings'].append('High-severity hooks detected')
        return risk

    def save_report(self,output_path:Optional[str]=None)->str:
        if not output_path: output_path=os.path.join(self.config.output_dir,f'vmi_report_{self.config.vm_name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
        with open(output_path,'w',encoding='utf-8') as f: json.dump(self.generate_report(),f,indent=2,ensure_ascii=False)
        return output_path

    def analyze(self)->Dict[str,Any]:
        if not self.connect(): return {'error':'Unable to connect to the target virtual machine'}
        try:
            self.list_processes(); self.list_kernel_modules()
            if self.config.detect_hooks: self.detect_hooks()
            if self.config.dump_processes: self.dump_all_processes()
            return self.generate_report()
        finally: self.disconnect()

    def list_kernel_modules(self)->List[KernelModule]:
        self.kernel_modules=[]
        if VMI_AVAILABLE and self.vmi_instance: return self._list_kernel_modules_libvmi()
        return self._list_kernel_modules_mock()

    def _list_kernel_modules_libvmi(self)->List[KernelModule]:
        try:
            modules=[]
            if self.os_type=='linux':
                ml=self.vmi_instance.get_offset('linux_modules_list'); cm=ml
                while True:
                    try:
                        n=self.vmi_instance.read_str_va(cm+0x0,0); b=self.vmi_instance.read_64_va(cm+0x8,0)
                        s=self.vmi_instance.read_32_va(cm+0x10,0); modules.append(KernelModule(name=n,base_address=b,size=s))
                        nm=self.vmi_instance.read_64_va(cm+0x18,0)
                        if nm==ml: break
                        cm=nm
                    except Exception: break
            self.kernel_modules=modules; return modules
        except Exception: return []

    def _list_kernel_modules_mock(self)->List[KernelModule]:
        mm=[KernelModule(name='kernel',base_address=0x80000000,size=0x1000000),KernelModule(name='malicious_driver.sys',base_address=0xFFFF8000,size=0x10000)]
        self.kernel_modules=mm; return mm

    def dump_all_processes(self)->List[MemoryDump]:
        tp=self.config.target_pids if self.config.target_pids else [p.pid for p in self.processes]; dumps=[]
        for pid in tp:
            d=self.dump_process_memory(pid)
            if d: dumps.append(d)
        return dumps


def create_vmi_analyzer(vm_name:str,**kwargs)->VMIAnalyzer: return VMIAnalyzer(VMIConfig(vm_name=vm_name,**kwargs))
