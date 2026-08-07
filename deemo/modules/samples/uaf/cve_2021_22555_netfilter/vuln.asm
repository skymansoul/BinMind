
C:\Users\Administrator\Desktop\BinMind\round2\samples\uaf\cve_2021_22555_netfilter\vuln.exe:     file format pei-x86-64


Disassembly of section .text:

0000000140001000 <__mingw_invalidParameterHandler>:
   140001000:	55                   	push   rbp
   140001001:	48 89 e5             	mov    rbp,rsp
   140001004:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001008:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000100c:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001010:	44 89 4d 28          	mov    DWORD PTR [rbp+0x28],r9d
   140001014:	90                   	nop
   140001015:	5d                   	pop    rbp
   140001016:	c3                   	ret

0000000140001017 <safe_flush>:
   140001017:	55                   	push   rbp
   140001018:	48 89 e5             	mov    rbp,rsp
   14000101b:	48 83 ec 20          	sub    rsp,0x20
   14000101f:	b9 00 00 00 00       	mov    ecx,0x0
   140001024:	e8 df 86 00 00       	call   140009708 <fflush>
   140001029:	90                   	nop
   14000102a:	48 83 c4 20          	add    rsp,0x20
   14000102e:	5d                   	pop    rbp
   14000102f:	c3                   	ret

0000000140001030 <WinMainCRTStartup>:
   140001030:	55                   	push   rbp
   140001031:	48 89 e5             	mov    rbp,rsp
   140001034:	48 83 ec 30          	sub    rsp,0x30
   140001038:	c7 45 fc ff 00 00 00 	mov    DWORD PTR [rbp-0x4],0xff

000000014000103f <.l_startw>:
   14000103f:	48 8b 05 ca a5 00 00 	mov    rax,QWORD PTR [rip+0xa5ca]        # 14000b610 <.refptr.__mingw_app_type>
   140001046:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000104c:	e8 3d 00 00 00       	call   14000108e <__tmainCRTStartup>
   140001051:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001054:	90                   	nop

0000000140001055 <.l_endw>:
   140001055:	90                   	nop
   140001056:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001059:	48 83 c4 30          	add    rsp,0x30
   14000105d:	5d                   	pop    rbp
   14000105e:	c3                   	ret

000000014000105f <mainCRTStartup>:
   14000105f:	55                   	push   rbp
   140001060:	48 89 e5             	mov    rbp,rsp
   140001063:	48 83 ec 30          	sub    rsp,0x30
   140001067:	c7 45 fc ff 00 00 00 	mov    DWORD PTR [rbp-0x4],0xff

000000014000106e <.l_start>:
   14000106e:	48 8b 05 9b a5 00 00 	mov    rax,QWORD PTR [rip+0xa59b]        # 14000b610 <.refptr.__mingw_app_type>
   140001075:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   14000107b:	e8 0e 00 00 00       	call   14000108e <__tmainCRTStartup>
   140001080:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001083:	90                   	nop

0000000140001084 <.l_end>:
   140001084:	90                   	nop
   140001085:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001088:	48 83 c4 30          	add    rsp,0x30
   14000108c:	5d                   	pop    rbp
   14000108d:	c3                   	ret

000000014000108e <__tmainCRTStartup>:
   14000108e:	55                   	push   rbp
   14000108f:	48 89 e5             	mov    rbp,rsp
   140001092:	48 81 ec 90 00 00 00 	sub    rsp,0x90
   140001099:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
   1400010a0:	00 
   1400010a1:	c7 45 e0 30 00 00 00 	mov    DWORD PTR [rbp-0x20],0x30
   1400010a8:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   1400010ab:	65 67 48 8b 00       	mov    rax,QWORD PTR gs:[eax]
   1400010b0:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400010b4:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400010b8:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   1400010bc:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400010c0:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400010c7:	c7 45 e4 00 00 00 00 	mov    DWORD PTR [rbp-0x1c],0x0
   1400010ce:	eb 21                	jmp    1400010f1 <__tmainCRTStartup+0x63>
   1400010d0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400010d4:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400010d8:	75 09                	jne    1400010e3 <__tmainCRTStartup+0x55>
   1400010da:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400010e1:	eb 45                	jmp    140001128 <__tmainCRTStartup+0x9a>
   1400010e3:	b9 e8 03 00 00       	mov    ecx,0x3e8
   1400010e8:	48 8b 05 59 f1 00 00 	mov    rax,QWORD PTR [rip+0xf159]        # 140010248 <__imp_Sleep>
   1400010ef:	ff d0                	call   rax
   1400010f1:	48 8b 05 68 a5 00 00 	mov    rax,QWORD PTR [rip+0xa568]        # 14000b660 <.refptr.__native_startup_lock>
   1400010f8:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400010fc:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001100:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140001104:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
   14000110b:	00 
   14000110c:	48 8b 4d c8          	mov    rcx,QWORD PTR [rbp-0x38]
   140001110:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001114:	48 8b 55 d0          	mov    rdx,QWORD PTR [rbp-0x30]
   140001118:	f0 48 0f b1 0a       	lock cmpxchg QWORD PTR [rdx],rcx
   14000111d:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001121:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001126:	75 a8                	jne    1400010d0 <__tmainCRTStartup+0x42>
   140001128:	48 8b 05 41 a5 00 00 	mov    rax,QWORD PTR [rip+0xa541]        # 14000b670 <.refptr.__native_startup_state>
   14000112f:	8b 00                	mov    eax,DWORD PTR [rax]
   140001131:	83 f8 01             	cmp    eax,0x1
   140001134:	75 0a                	jne    140001140 <__tmainCRTStartup+0xb2>
   140001136:	b9 1f 00 00 00       	mov    ecx,0x1f
   14000113b:	e8 78 85 00 00       	call   1400096b8 <_amsg_exit>
   140001140:	48 8b 05 29 a5 00 00 	mov    rax,QWORD PTR [rip+0xa529]        # 14000b670 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 18 a5 00 00 	mov    rax,QWORD PTR [rip+0xa518]        # 14000b670 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 78 7f 00 00       	call   1400090e0 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 bf 85 00 00       	call   140009740 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 57 85 00 00       	call   1400096f0 <abort>
   140001199:	e8 42 12 00 00       	call   1400023e0 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 5b a5 00 00 	mov    rax,QWORD PTR [rip+0xa55b]        # 14000b700 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 91 f0 00 00 	mov    rax,QWORD PTR [rip+0xf091]        # 140010240 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 98 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa498]        # 14000b650 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 b6 7e 00 00       	call   140009080 <_set_invalid_parameter_handler>
   1400011ca:	e8 21 1b 00 00       	call   140002cf0 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e de 00 00    	mov    DWORD PTR [rip+0xde3e],eax        # 14000f018 <managedapp>
   1400011da:	48 8b 05 2f a4 00 00 	mov    rax,QWORD PTR [rip+0xa42f]        # 14000b610 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 b7 84 00 00       	call   1400096a8 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 ab 84 00 00       	call   1400096a8 <__set_app_type>
   1400011fd:	e8 2e 7d 00 00       	call   140008f30 <__p__fmode>
   140001202:	48 8b 15 e7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4e7]        # 14000b6f0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 2e 7d 00 00       	call   140008f40 <__p__commode>
   140001212:	48 8b 15 b7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4b7]        # 14000b6d0 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 9e 07 00 00       	call   1400019c0 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 83 84 00 00       	call   1400096b8 <_amsg_exit>
   140001235:	48 8b 05 24 a3 00 00 	mov    rax,QWORD PTR [rip+0xa324]        # 14000b560 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 c6 a4 00 00 	mov    rax,QWORD PTR [rip+0xa4c6]        # 14000b710 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 a8 12 00 00       	call   1400024fa <__mingw_setusermatherr>
   140001252:	48 8b 05 77 a3 00 00 	mov    rax,QWORD PTR [rip+0xa377]        # 14000b5d0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 56 7e 00 00       	call   1400090c0 <_configthreadlocale>
   14000126a:	48 8b 15 4f a4 00 00 	mov    rdx,QWORD PTR [rip+0xa44f]        # 14000b6c0 <.refptr.__xi_z>
   140001271:	48 8b 05 38 a4 00 00 	mov    rax,QWORD PTR [rip+0xa438]        # 14000b6b0 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 50 7c 00 00       	call   140008ed0 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 2a 84 00 00       	call   1400096b8 <_amsg_exit>
   14000128e:	48 8b 05 8b a4 00 00 	mov    rax,QWORD PTR [rip+0xa48b]        # 14000b720 <.refptr._newmode>
   140001295:	8b 00                	mov    eax,DWORD PTR [rax]
   140001297:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000129a:	48 8b 05 3f a4 00 00 	mov    rax,QWORD PTR [rip+0xa43f]        # 14000b6e0 <.refptr._dowildcard>
   1400012a1:	44 8b 00             	mov    r8d,DWORD PTR [rax]
   1400012a4:	4c 8d 15 65 dd 00 00 	lea    r10,[rip+0xdd65]        # 14000f010 <envp>
   1400012ab:	48 8d 15 56 dd 00 00 	lea    rdx,[rip+0xdd56]        # 14000f008 <argv>
   1400012b2:	48 8d 05 4b dd 00 00 	lea    rax,[rip+0xdd4b]        # 14000f004 <argc>
   1400012b9:	48 8d 4d ac          	lea    rcx,[rbp-0x54]
   1400012bd:	48 89 4c 24 20       	mov    QWORD PTR [rsp+0x20],rcx
   1400012c2:	45 89 c1             	mov    r9d,r8d
   1400012c5:	4d 89 d0             	mov    r8,r10
   1400012c8:	48 89 c1             	mov    rcx,rax
   1400012cb:	e8 c8 83 00 00       	call   140009698 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 d5 83 00 00       	call   1400096b8 <_amsg_exit>
   1400012e3:	8b 05 1b dd 00 00    	mov    eax,DWORD PTR [rip+0xdd1b]        # 14000f004 <argc>
   1400012e9:	48 8d 15 18 dd 00 00 	lea    rdx,[rip+0xdd18]        # 14000f008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 ae 83 00 00       	call   1400096b8 <_amsg_exit>
   14000130a:	48 8b 15 8f a3 00 00 	mov    rdx,QWORD PTR [rip+0xa38f]        # 14000b6a0 <.refptr.__xc_z>
   140001311:	48 8b 05 78 a3 00 00 	mov    rax,QWORD PTR [rip+0xa378]        # 14000b690 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 b0 83 00 00       	call   1400096d0 <_initterm>
   140001320:	e8 72 06 00 00       	call   140001997 <__main>
   140001325:	48 8b 05 44 a3 00 00 	mov    rax,QWORD PTR [rip+0xa344]        # 14000b670 <.refptr.__native_startup_state>
   14000132c:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   140001332:	eb 0a                	jmp    14000133e <__tmainCRTStartup+0x2b0>
   140001334:	c7 05 de dc 00 00 01 	mov    DWORD PTR [rip+0xdcde],0x1        # 14000f01c <has_cctor>
   14000133b:	00 00 00 
   14000133e:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140001342:	75 1e                	jne    140001362 <__tmainCRTStartup+0x2d4>
   140001344:	48 8b 05 15 a3 00 00 	mov    rax,QWORD PTR [rip+0xa315]        # 14000b660 <.refptr.__native_startup_lock>
   14000134b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000134f:	48 c7 45 b0 00 00 00 	mov    QWORD PTR [rbp-0x50],0x0
   140001356:	00 
   140001357:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   14000135b:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000135f:	48 87 10             	xchg   QWORD PTR [rax],rdx
   140001362:	48 8b 05 57 a2 00 00 	mov    rax,QWORD PTR [rip+0xa257]        # 14000b5c0 <.refptr.__dyn_tls_init_callback>
   140001369:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000136c:	48 85 c0             	test   rax,rax
   14000136f:	74 1c                	je     14000138d <__tmainCRTStartup+0x2ff>
   140001371:	48 8b 05 48 a2 00 00 	mov    rax,QWORD PTR [rip+0xa248]        # 14000b5c0 <.refptr.__dyn_tls_init_callback>
   140001378:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000137b:	41 b8 00 00 00 00    	mov    r8d,0x0
   140001381:	ba 02 00 00 00       	mov    edx,0x2
   140001386:	b9 00 00 00 00       	mov    ecx,0x0
   14000138b:	ff d0                	call   rax
   14000138d:	e8 be 7b 00 00       	call   140008f50 <__p___initenv>
   140001392:	48 8b 15 77 dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc77]        # 14000f010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d dc 00 00 	mov    rcx,QWORD PTR [rip+0xdc6d]        # 14000f010 <envp>
   1400013a3:	48 8b 15 5e dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc5e]        # 14000f008 <argv>
   1400013aa:	8b 05 54 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc54]        # 14000f004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 34 04 00 00       	call   1400017ee <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc55]        # 14000f018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 2f 83 00 00       	call   140009700 <exit>
   1400013d1:	8b 05 45 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc45]        # 14000f01c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 e0 82 00 00       	call   1400096c0 <_cexit>
   1400013e0:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013e3:	48 81 c4 90 00 00 00 	add    rsp,0x90
   1400013ea:	5d                   	pop    rbp
   1400013eb:	c3                   	ret

00000001400013ec <check_managed_app>:
   1400013ec:	55                   	push   rbp
   1400013ed:	48 89 e5             	mov    rbp,rsp
   1400013f0:	48 83 ec 20          	sub    rsp,0x20
   1400013f4:	48 8b 05 25 a2 00 00 	mov    rax,QWORD PTR [rip+0xa225]        # 14000b620 <.refptr.__mingw_initltsdrot_force>
   1400013fb:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   140001401:	48 8b 05 28 a2 00 00 	mov    rax,QWORD PTR [rip+0xa228]        # 14000b630 <.refptr.__mingw_initltsdyn_force>
   140001408:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000140e:	48 8b 05 2b a2 00 00 	mov    rax,QWORD PTR [rip+0xa22b]        # 14000b640 <.refptr.__mingw_initltssuo_force>
   140001415:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000141b:	48 8b 05 5e a1 00 00 	mov    rax,QWORD PTR [rip+0xa15e]        # 14000b580 <.refptr.__ImageBase>
   140001422:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001426:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000142a:	0f b7 00             	movzx  eax,WORD PTR [rax]
   14000142d:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140001431:	74 0a                	je     14000143d <check_managed_app+0x51>
   140001433:	b8 00 00 00 00       	mov    eax,0x0
   140001438:	e9 ad 00 00 00       	jmp    1400014ea <check_managed_app+0xfe>
   14000143d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001441:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140001444:	48 63 d0             	movsxd rdx,eax
   140001447:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000144b:	48 01 d0             	add    rax,rdx
   14000144e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001452:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001456:	8b 00                	mov    eax,DWORD PTR [rax]
   140001458:	3d 50 45 00 00       	cmp    eax,0x4550
   14000145d:	74 0a                	je     140001469 <check_managed_app+0x7d>
   14000145f:	b8 00 00 00 00       	mov    eax,0x0
   140001464:	e9 81 00 00 00       	jmp    1400014ea <check_managed_app+0xfe>
   140001469:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000146d:	48 83 c0 18          	add    rax,0x18
   140001471:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140001475:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001479:	0f b7 00             	movzx  eax,WORD PTR [rax]
   14000147c:	0f b7 c0             	movzx  eax,ax
   14000147f:	3d 0b 01 00 00       	cmp    eax,0x10b
   140001484:	74 09                	je     14000148f <check_managed_app+0xa3>
   140001486:	3d 0b 02 00 00       	cmp    eax,0x20b
   14000148b:	74 29                	je     1400014b6 <check_managed_app+0xca>
   14000148d:	eb 56                	jmp    1400014e5 <check_managed_app+0xf9>
   14000148f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001493:	8b 40 5c             	mov    eax,DWORD PTR [rax+0x5c]
   140001496:	83 f8 0e             	cmp    eax,0xe
   140001499:	77 07                	ja     1400014a2 <check_managed_app+0xb6>
   14000149b:	b8 00 00 00 00       	mov    eax,0x0
   1400014a0:	eb 48                	jmp    1400014ea <check_managed_app+0xfe>
   1400014a2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400014a6:	8b 80 d0 00 00 00    	mov    eax,DWORD PTR [rax+0xd0]
   1400014ac:	85 c0                	test   eax,eax
   1400014ae:	0f 95 c0             	setne  al
   1400014b1:	0f b6 c0             	movzx  eax,al
   1400014b4:	eb 34                	jmp    1400014ea <check_managed_app+0xfe>
   1400014b6:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400014ba:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400014be:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400014c2:	8b 40 6c             	mov    eax,DWORD PTR [rax+0x6c]
   1400014c5:	83 f8 0e             	cmp    eax,0xe
   1400014c8:	77 07                	ja     1400014d1 <check_managed_app+0xe5>
   1400014ca:	b8 00 00 00 00       	mov    eax,0x0
   1400014cf:	eb 19                	jmp    1400014ea <check_managed_app+0xfe>
   1400014d1:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400014d5:	8b 80 e0 00 00 00    	mov    eax,DWORD PTR [rax+0xe0]
   1400014db:	85 c0                	test   eax,eax
   1400014dd:	0f 95 c0             	setne  al
   1400014e0:	0f b6 c0             	movzx  eax,al
   1400014e3:	eb 05                	jmp    1400014ea <check_managed_app+0xfe>
   1400014e5:	b8 00 00 00 00       	mov    eax,0x0
   1400014ea:	48 83 c4 20          	add    rsp,0x20
   1400014ee:	5d                   	pop    rbp
   1400014ef:	c3                   	ret

00000001400014f0 <duplicate_ppstrings>:
   1400014f0:	55                   	push   rbp
   1400014f1:	53                   	push   rbx
   1400014f2:	48 83 ec 48          	sub    rsp,0x48
   1400014f6:	48 8d 6c 24 40       	lea    rbp,[rsp+0x40]
   1400014fb:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   1400014fe:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001502:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140001505:	83 c0 01             	add    eax,0x1
   140001508:	48 98                	cdqe
   14000150a:	48 c1 e0 03          	shl    rax,0x3
   14000150e:	48 89 c1             	mov    rcx,rax
   140001511:	e8 1a 82 00 00       	call   140009730 <malloc>
   140001516:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000151a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000151f:	75 0a                	jne    14000152b <duplicate_ppstrings+0x3b>
   140001521:	b8 01 00 00 00       	mov    eax,0x1
   140001526:	e9 fd 00 00 00       	jmp    140001628 <duplicate_ppstrings+0x138>
   14000152b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000152f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001532:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140001536:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000153d:	e9 af 00 00 00       	jmp    1400015f1 <duplicate_ppstrings+0x101>
   140001542:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001545:	48 98                	cdqe
   140001547:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   14000154e:	00 
   14000154f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140001553:	48 01 d0             	add    rax,rdx
   140001556:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001559:	48 89 c1             	mov    rcx,rax
   14000155c:	e8 f7 81 00 00       	call   140009758 <strlen>
   140001561:	48 83 c0 01          	add    rax,0x1
   140001565:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140001569:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000156c:	48 98                	cdqe
   14000156e:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140001575:	00 
   140001576:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000157a:	48 8d 1c 02          	lea    rbx,[rdx+rax*1]
   14000157e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140001582:	48 89 c1             	mov    rcx,rax
   140001585:	e8 a6 81 00 00       	call   140009730 <malloc>
   14000158a:	48 89 03             	mov    QWORD PTR [rbx],rax
   14000158d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001590:	48 98                	cdqe
   140001592:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140001599:	00 
   14000159a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000159e:	48 01 d0             	add    rax,rdx
   1400015a1:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400015a4:	48 85 c0             	test   rax,rax
   1400015a7:	75 07                	jne    1400015b0 <duplicate_ppstrings+0xc0>
   1400015a9:	b8 01 00 00 00       	mov    eax,0x1
   1400015ae:	eb 78                	jmp    140001628 <duplicate_ppstrings+0x138>
   1400015b0:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400015b3:	48 98                	cdqe
   1400015b5:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   1400015bc:	00 
   1400015bd:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400015c1:	48 01 d0             	add    rax,rdx
   1400015c4:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   1400015c7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400015ca:	48 98                	cdqe
   1400015cc:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
   1400015d3:	00 
   1400015d4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400015d8:	48 01 c8             	add    rax,rcx
   1400015db:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400015de:	48 8b 4d e0          	mov    rcx,QWORD PTR [rbp-0x20]
   1400015e2:	49 89 c8             	mov    r8,rcx
   1400015e5:	48 89 c1             	mov    rcx,rax
   1400015e8:	e8 4b 81 00 00       	call   140009738 <memcpy>
   1400015ed:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400015f1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400015f4:	3b 45 20             	cmp    eax,DWORD PTR [rbp+0x20]
   1400015f7:	0f 8c 45 ff ff ff    	jl     140001542 <duplicate_ppstrings+0x52>
   1400015fd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001600:	48 98                	cdqe
   140001602:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140001609:	00 
   14000160a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000160e:	48 01 d0             	add    rax,rdx
   140001611:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   140001618:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000161c:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140001620:	48 89 10             	mov    QWORD PTR [rax],rdx
   140001623:	b8 00 00 00 00       	mov    eax,0x0
   140001628:	48 83 c4 48          	add    rsp,0x48
   14000162c:	5b                   	pop    rbx
   14000162d:	5d                   	pop    rbp
   14000162e:	c3                   	ret

000000014000162f <atexit>:
   14000162f:	55                   	push   rbp
   140001630:	48 89 e5             	mov    rbp,rsp
   140001633:	48 83 ec 20          	sub    rsp,0x20
   140001637:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000163b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000163f:	48 89 c1             	mov    rcx,rax
   140001642:	e8 a1 80 00 00       	call   1400096e8 <_crt_atexit>
   140001647:	48 83 c4 20          	add    rsp,0x20
   14000164b:	5d                   	pop    rbp
   14000164c:	c3                   	ret
   14000164d:	90                   	nop
   14000164e:	90                   	nop
   14000164f:	90                   	nop

0000000140001650 <.weak.__register_frame_info.hmod_libgcc>:
   140001650:	c3                   	ret
   140001651:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
   140001655:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
   14000165c:	00 00 00 00 

0000000140001660 <.weak.__deregister_frame_info.hmod_libgcc>:
   140001660:	31 c0                	xor    eax,eax
   140001662:	c3                   	ret
   140001663:	66 90                	xchg   ax,ax
   140001665:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
   14000166c:	00 00 00 00 

0000000140001670 <__gcc_register_frame>:
   140001670:	55                   	push   rbp
   140001671:	53                   	push   rbx
   140001672:	48 83 ec 38          	sub    rsp,0x38
   140001676:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   14000167b:	48 8d 0d 7e 99 00 00 	lea    rcx,[rip+0x997e]        # 14000b000 <.rdata>
   140001682:	ff 15 88 eb 00 00    	call   QWORD PTR [rip+0xeb88]        # 140010210 <__imp_GetModuleHandleA>
   140001688:	48 89 c3             	mov    rbx,rax
   14000168b:	48 85 c0             	test   rax,rax
   14000168e:	74 70                	je     140001700 <__gcc_register_frame+0x90>
   140001690:	48 8d 0d 69 99 00 00 	lea    rcx,[rip+0x9969]        # 14000b000 <.rdata>
   140001697:	ff 15 93 eb 00 00    	call   QWORD PTR [rip+0xeb93]        # 140010230 <__imp_LoadLibraryA>
   14000169d:	4c 8b 0d 74 eb 00 00 	mov    r9,QWORD PTR [rip+0xeb74]        # 140010218 <__imp_GetProcAddress>
   1400016a4:	48 8d 15 68 99 00 00 	lea    rdx,[rip+0x9968]        # 14000b013 <.rdata+0x13>
   1400016ab:	48 89 d9             	mov    rcx,rbx
   1400016ae:	48 89 05 6b d9 00 00 	mov    QWORD PTR [rip+0xd96b],rax        # 14000f020 <hmod_libgcc>
   1400016b5:	4c 89 4d f0          	mov    QWORD PTR [rbp-0x10],r9
   1400016b9:	41 ff d1             	call   r9
   1400016bc:	48 8d 15 66 99 00 00 	lea    rdx,[rip+0x9966]        # 14000b029 <.rdata+0x29>
   1400016c3:	48 89 d9             	mov    rcx,rbx
   1400016c6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400016ca:	ff 55 f0             	call   QWORD PTR [rbp-0x10]
   1400016cd:	4c 8b 45 f8          	mov    r8,QWORD PTR [rbp-0x8]
   1400016d1:	48 89 05 28 89 00 00 	mov    QWORD PTR [rip+0x8928],rax        # 14000a000 <__data_start__>
   1400016d8:	4d 85 c0             	test   r8,r8
   1400016db:	74 11                	je     1400016ee <__gcc_register_frame+0x7e>
   1400016dd:	48 8d 15 5c d9 00 00 	lea    rdx,[rip+0xd95c]        # 14000f040 <obj>
   1400016e4:	48 8d 0d 15 a9 00 00 	lea    rcx,[rip+0xa915]        # 14000c000 <__EH_FRAME_BEGIN__>
   1400016eb:	41 ff d0             	call   r8
   1400016ee:	48 8d 0d 2b 00 00 00 	lea    rcx,[rip+0x2b]        # 140001720 <__gcc_deregister_frame>
   1400016f5:	48 83 c4 38          	add    rsp,0x38
   1400016f9:	5b                   	pop    rbx
   1400016fa:	5d                   	pop    rbp
   1400016fb:	e9 2f ff ff ff       	jmp    14000162f <atexit>
   140001700:	48 8d 05 59 ff ff ff 	lea    rax,[rip+0xffffffffffffff59]        # 140001660 <.weak.__deregister_frame_info.hmod_libgcc>
   140001707:	4c 8d 05 42 ff ff ff 	lea    r8,[rip+0xffffffffffffff42]        # 140001650 <.weak.__register_frame_info.hmod_libgcc>
   14000170e:	48 89 05 eb 88 00 00 	mov    QWORD PTR [rip+0x88eb],rax        # 14000a000 <__data_start__>
   140001715:	eb c6                	jmp    1400016dd <__gcc_register_frame+0x6d>
   140001717:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
   14000171e:	00 00 

0000000140001720 <__gcc_deregister_frame>:
   140001720:	55                   	push   rbp
   140001721:	48 89 e5             	mov    rbp,rsp
   140001724:	48 83 ec 20          	sub    rsp,0x20
   140001728:	48 8b 05 d1 88 00 00 	mov    rax,QWORD PTR [rip+0x88d1]        # 14000a000 <__data_start__>
   14000172f:	48 85 c0             	test   rax,rax
   140001732:	74 09                	je     14000173d <__gcc_deregister_frame+0x1d>
   140001734:	48 8d 0d c5 a8 00 00 	lea    rcx,[rip+0xa8c5]        # 14000c000 <__EH_FRAME_BEGIN__>
   14000173b:	ff d0                	call   rax
   14000173d:	48 8b 0d dc d8 00 00 	mov    rcx,QWORD PTR [rip+0xd8dc]        # 14000f020 <hmod_libgcc>
   140001744:	48 85 c9             	test   rcx,rcx
   140001747:	74 0f                	je     140001758 <__gcc_deregister_frame+0x38>
   140001749:	48 83 c4 20          	add    rsp,0x20
   14000174d:	5d                   	pop    rbp
   14000174e:	48 ff 25 a3 ea 00 00 	rex.W jmp QWORD PTR [rip+0xeaa3]        # 1400101f8 <__imp_FreeLibrary>
   140001755:	0f 1f 00             	nop    DWORD PTR [rax]
   140001758:	48 83 c4 20          	add    rsp,0x20
   14000175c:	5d                   	pop    rbp
   14000175d:	c3                   	ret
   14000175e:	90                   	nop
   14000175f:	90                   	nop

0000000140001760 <nft_expr_destroy>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 20          	sub    rsp,0x20
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001770:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001774:	48 85 c0             	test   rax,rax
   140001777:	74 25                	je     14000179e <nft_expr_destroy+0x3e>
   140001779:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000177d:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001781:	8b 10                	mov    edx,DWORD PTR [rax]
   140001783:	83 ea 01             	sub    edx,0x1
   140001786:	89 10                	mov    DWORD PTR [rax],edx
   140001788:	8b 00                	mov    eax,DWORD PTR [rax]
   14000178a:	85 c0                	test   eax,eax
   14000178c:	75 10                	jne    14000179e <nft_expr_destroy+0x3e>
   14000178e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001792:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001796:	48 89 c1             	mov    rcx,rax
   140001799:	e8 82 7f 00 00       	call   140009720 <free>
   14000179e:	90                   	nop
   14000179f:	48 83 c4 20          	add    rsp,0x20
   1400017a3:	5d                   	pop    rbp
   1400017a4:	c3                   	ret

00000001400017a5 <nft_rule_release>:
   1400017a5:	55                   	push   rbp
   1400017a6:	48 89 e5             	mov    rbp,rsp
   1400017a9:	48 83 ec 30          	sub    rsp,0x30
   1400017ad:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400017b1:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400017b8:	eb 20                	jmp    1400017da <nft_rule_release+0x35>
   1400017ba:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017be:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400017c1:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400017c4:	48 63 d2             	movsxd rdx,edx
   1400017c7:	48 c1 e2 05          	shl    rdx,0x5
   1400017cb:	48 01 d0             	add    rax,rdx
   1400017ce:	48 89 c1             	mov    rcx,rax
   1400017d1:	e8 8a ff ff ff       	call   140001760 <nft_expr_destroy>
   1400017d6:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400017da:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017de:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400017e1:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   1400017e4:	7c d4                	jl     1400017ba <nft_rule_release+0x15>
   1400017e6:	90                   	nop
   1400017e7:	90                   	nop
   1400017e8:	48 83 c4 30          	add    rsp,0x30
   1400017ec:	5d                   	pop    rbp
   1400017ed:	c3                   	ret

00000001400017ee <main>:
   1400017ee:	55                   	push   rbp
   1400017ef:	53                   	push   rbx
   1400017f0:	48 83 ec 38          	sub    rsp,0x38
   1400017f4:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   1400017f9:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   1400017fc:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001800:	e8 92 01 00 00       	call   140001997 <__main>
   140001805:	b9 10 00 00 00       	mov    ecx,0x10
   14000180a:	e8 21 7f 00 00       	call   140009730 <malloc>
   14000180f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001813:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001817:	c7 40 08 01 00 00 00 	mov    DWORD PTR [rax+0x8],0x1
   14000181e:	b9 20 00 00 00       	mov    ecx,0x20
   140001823:	e8 08 7f 00 00       	call   140009730 <malloc>
   140001828:	48 89 c2             	mov    rdx,rax
   14000182b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000182f:	48 89 10             	mov    QWORD PTR [rax],rdx
   140001832:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001836:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001839:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000183f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001843:	48 8b 18             	mov    rbx,QWORD PTR [rax]
   140001846:	b9 0c 00 00 00       	mov    ecx,0xc
   14000184b:	e8 e0 7e 00 00       	call   140009730 <malloc>
   140001850:	48 89 43 08          	mov    QWORD PTR [rbx+0x8],rax
   140001854:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001858:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000185b:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   14000185f:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001865:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001869:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000186c:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001870:	48 83 c0 04          	add    rax,0x4
   140001874:	66 c7 00 73 30       	mov    WORD PTR [rax],0x3073
   140001879:	c6 40 02 00          	mov    BYTE PTR [rax+0x2],0x0
   14000187d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001881:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001884:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001888:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000188c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001890:	48 89 c1             	mov    rcx,rax
   140001893:	e8 0d ff ff ff       	call   1400017a5 <nft_rule_release>
   140001898:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000189c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000189e:	85 c0                	test   eax,eax
   1400018a0:	75 17                	jne    1400018b9 <main+0xcb>
   1400018a2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400018a6:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400018aa:	48 8d 05 9f 97 00 00 	lea    rax,[rip+0x979f]        # 14000b050 <.rdata>
   1400018b1:	48 89 c1             	mov    rcx,rax
   1400018b4:	e8 37 19 00 00       	call   1400031f0 <__mingw_printf>
   1400018b9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400018bd:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018c0:	48 89 c1             	mov    rcx,rax
   1400018c3:	e8 58 7e 00 00       	call   140009720 <free>
   1400018c8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400018cc:	48 89 c1             	mov    rcx,rax
   1400018cf:	e8 4c 7e 00 00       	call   140009720 <free>
   1400018d4:	b8 00 00 00 00       	mov    eax,0x0
   1400018d9:	48 83 c4 38          	add    rsp,0x38
   1400018dd:	5b                   	pop    rbx
   1400018de:	5d                   	pop    rbp
   1400018df:	c3                   	ret

00000001400018e0 <__do_global_dtors>:
   1400018e0:	55                   	push   rbp
   1400018e1:	48 89 e5             	mov    rbp,rsp
   1400018e4:	48 83 ec 20          	sub    rsp,0x20
   1400018e8:	eb 1e                	jmp    140001908 <__do_global_dtors+0x28>
   1400018ea:	48 8b 05 1f 87 00 00 	mov    rax,QWORD PTR [rip+0x871f]        # 14000a010 <p.0>
   1400018f1:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018f4:	ff d0                	call   rax
   1400018f6:	48 8b 05 13 87 00 00 	mov    rax,QWORD PTR [rip+0x8713]        # 14000a010 <p.0>
   1400018fd:	48 83 c0 08          	add    rax,0x8
   140001901:	48 89 05 08 87 00 00 	mov    QWORD PTR [rip+0x8708],rax        # 14000a010 <p.0>
   140001908:	48 8b 05 01 87 00 00 	mov    rax,QWORD PTR [rip+0x8701]        # 14000a010 <p.0>
   14000190f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001912:	48 85 c0             	test   rax,rax
   140001915:	75 d3                	jne    1400018ea <__do_global_dtors+0xa>
   140001917:	90                   	nop
   140001918:	90                   	nop
   140001919:	48 83 c4 20          	add    rsp,0x20
   14000191d:	5d                   	pop    rbp
   14000191e:	c3                   	ret

000000014000191f <__do_global_ctors>:
   14000191f:	55                   	push   rbp
   140001920:	48 89 e5             	mov    rbp,rsp
   140001923:	48 83 ec 30          	sub    rsp,0x30
   140001927:	48 8b 05 42 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c42]        # 14000b570 <.refptr.__CTOR_LIST__>
   14000192e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001931:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001934:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001938:	75 25                	jne    14000195f <__do_global_ctors+0x40>
   14000193a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001941:	eb 04                	jmp    140001947 <__do_global_ctors+0x28>
   140001943:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001947:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000194a:	8d 50 01             	lea    edx,[rax+0x1]
   14000194d:	48 8b 05 1c 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c1c]        # 14000b570 <.refptr.__CTOR_LIST__>
   140001954:	89 d2                	mov    edx,edx
   140001956:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000195a:	48 85 c0             	test   rax,rax
   14000195d:	75 e4                	jne    140001943 <__do_global_ctors+0x24>
   14000195f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001962:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001965:	eb 14                	jmp    14000197b <__do_global_ctors+0x5c>
   140001967:	48 8b 05 02 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c02]        # 14000b570 <.refptr.__CTOR_LIST__>
   14000196e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001971:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001975:	ff d0                	call   rax
   140001977:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000197b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000197f:	75 e6                	jne    140001967 <__do_global_ctors+0x48>
   140001981:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 1400018e0 <__do_global_dtors>
   140001988:	48 89 c1             	mov    rcx,rax
   14000198b:	e8 9f fc ff ff       	call   14000162f <atexit>
   140001990:	90                   	nop
   140001991:	48 83 c4 30          	add    rsp,0x30
   140001995:	5d                   	pop    rbp
   140001996:	c3                   	ret

0000000140001997 <__main>:
   140001997:	55                   	push   rbp
   140001998:	48 89 e5             	mov    rbp,rsp
   14000199b:	48 83 ec 20          	sub    rsp,0x20
   14000199f:	8b 05 db d6 00 00    	mov    eax,DWORD PTR [rip+0xd6db]        # 14000f080 <initialized>
   1400019a5:	85 c0                	test   eax,eax
   1400019a7:	75 0f                	jne    1400019b8 <__main+0x21>
   1400019a9:	c7 05 cd d6 00 00 01 	mov    DWORD PTR [rip+0xd6cd],0x1        # 14000f080 <initialized>
   1400019b0:	00 00 00 
   1400019b3:	e8 67 ff ff ff       	call   14000191f <__do_global_ctors>
   1400019b8:	90                   	nop
   1400019b9:	48 83 c4 20          	add    rsp,0x20
   1400019bd:	5d                   	pop    rbp
   1400019be:	c3                   	ret
   1400019bf:	90                   	nop

00000001400019c0 <_setargv>:
   1400019c0:	55                   	push   rbp
   1400019c1:	48 89 e5             	mov    rbp,rsp
   1400019c4:	b8 00 00 00 00       	mov    eax,0x0
   1400019c9:	5d                   	pop    rbp
   1400019ca:	c3                   	ret
   1400019cb:	90                   	nop
   1400019cc:	90                   	nop
   1400019cd:	90                   	nop
   1400019ce:	90                   	nop
   1400019cf:	90                   	nop

00000001400019d0 <__dyn_tls_init>:
   1400019d0:	55                   	push   rbp
   1400019d1:	48 89 e5             	mov    rbp,rsp
   1400019d4:	48 83 ec 30          	sub    rsp,0x30
   1400019d8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019dc:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400019df:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400019e3:	48 8b 05 66 9b 00 00 	mov    rax,QWORD PTR [rip+0x9b66]        # 14000b550 <.refptr._CRT_MT>
   1400019ea:	8b 00                	mov    eax,DWORD PTR [rax]
   1400019ec:	83 f8 02             	cmp    eax,0x2
   1400019ef:	74 0d                	je     1400019fe <__dyn_tls_init+0x2e>
   1400019f1:	48 8b 05 58 9b 00 00 	mov    rax,QWORD PTR [rip+0x9b58]        # 14000b550 <.refptr._CRT_MT>
   1400019f8:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   1400019fe:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140001a02:	74 1e                	je     140001a22 <__dyn_tls_init+0x52>
   140001a04:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140001a08:	75 5b                	jne    140001a65 <__dyn_tls_init+0x95>
   140001a0a:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001a0e:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001a11:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001a15:	49 89 c8             	mov    r8,rcx
   140001a18:	48 89 c1             	mov    rcx,rax
   140001a1b:	e8 d1 11 00 00       	call   140002bf1 <__mingw_TLScallback>
   140001a20:	eb 43                	jmp    140001a65 <__dyn_tls_init+0x95>
   140001a22:	48 8d 05 af 9e 00 00 	lea    rax,[rip+0x9eaf]        # 14000b8d8 <___crt_xd_start__>
   140001a29:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a2d:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001a32:	eb 22                	jmp    140001a56 <__dyn_tls_init+0x86>
   140001a34:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001a38:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001a3c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001a40:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001a43:	48 85 c0             	test   rax,rax
   140001a46:	74 09                	je     140001a51 <__dyn_tls_init+0x81>
   140001a48:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001a4c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001a4f:	ff d0                	call   rax
   140001a51:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001a56:	48 8d 05 83 9e 00 00 	lea    rax,[rip+0x9e83]        # 14000b8e0 <__xd_z>
   140001a5d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001a61:	75 d1                	jne    140001a34 <__dyn_tls_init+0x64>
   140001a63:	eb 01                	jmp    140001a66 <__dyn_tls_init+0x96>
   140001a65:	90                   	nop
   140001a66:	48 83 c4 30          	add    rsp,0x30
   140001a6a:	5d                   	pop    rbp
   140001a6b:	c3                   	ret

0000000140001a6c <__tlregdtor>:
   140001a6c:	55                   	push   rbp
   140001a6d:	48 89 e5             	mov    rbp,rsp
   140001a70:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a74:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001a79:	75 07                	jne    140001a82 <__tlregdtor+0x16>
   140001a7b:	b8 00 00 00 00       	mov    eax,0x0
   140001a80:	eb 05                	jmp    140001a87 <__tlregdtor+0x1b>
   140001a82:	b8 00 00 00 00       	mov    eax,0x0
   140001a87:	5d                   	pop    rbp
   140001a88:	c3                   	ret

0000000140001a89 <__dyn_tls_dtor>:
   140001a89:	55                   	push   rbp
   140001a8a:	48 89 e5             	mov    rbp,rsp
   140001a8d:	48 83 ec 20          	sub    rsp,0x20
   140001a91:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a95:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001a98:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001a9c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001aa0:	74 06                	je     140001aa8 <__dyn_tls_dtor+0x1f>
   140001aa2:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001aa6:	75 18                	jne    140001ac0 <__dyn_tls_dtor+0x37>
   140001aa8:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001aac:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001aaf:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001ab3:	49 89 c8             	mov    r8,rcx
   140001ab6:	48 89 c1             	mov    rcx,rax
   140001ab9:	e8 33 11 00 00       	call   140002bf1 <__mingw_TLScallback>
   140001abe:	eb 01                	jmp    140001ac1 <__dyn_tls_dtor+0x38>
   140001ac0:	90                   	nop
   140001ac1:	48 83 c4 20          	add    rsp,0x20
   140001ac5:	5d                   	pop    rbp
   140001ac6:	c3                   	ret
   140001ac7:	90                   	nop
   140001ac8:	90                   	nop
   140001ac9:	90                   	nop
   140001aca:	90                   	nop
   140001acb:	90                   	nop
   140001acc:	90                   	nop
   140001acd:	90                   	nop
   140001ace:	90                   	nop
   140001acf:	90                   	nop

0000000140001ad0 <_matherr>:
   140001ad0:	55                   	push   rbp
   140001ad1:	53                   	push   rbx
   140001ad2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001ad9:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001ade:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001ae2:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001ae6:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001aeb:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001aef:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001af3:	8b 00                	mov    eax,DWORD PTR [rax]
   140001af5:	83 f8 06             	cmp    eax,0x6
   140001af8:	74 56                	je     140001b50 <_matherr+0x80>
   140001afa:	83 f8 06             	cmp    eax,0x6
   140001afd:	7f 78                	jg     140001b77 <_matherr+0xa7>
   140001aff:	83 f8 05             	cmp    eax,0x5
   140001b02:	74 59                	je     140001b5d <_matherr+0x8d>
   140001b04:	83 f8 05             	cmp    eax,0x5
   140001b07:	7f 6e                	jg     140001b77 <_matherr+0xa7>
   140001b09:	83 f8 04             	cmp    eax,0x4
   140001b0c:	74 5c                	je     140001b6a <_matherr+0x9a>
   140001b0e:	83 f8 04             	cmp    eax,0x4
   140001b11:	7f 64                	jg     140001b77 <_matherr+0xa7>
   140001b13:	83 f8 03             	cmp    eax,0x3
   140001b16:	74 2b                	je     140001b43 <_matherr+0x73>
   140001b18:	83 f8 03             	cmp    eax,0x3
   140001b1b:	7f 5a                	jg     140001b77 <_matherr+0xa7>
   140001b1d:	83 f8 01             	cmp    eax,0x1
   140001b20:	74 07                	je     140001b29 <_matherr+0x59>
   140001b22:	83 f8 02             	cmp    eax,0x2
   140001b25:	74 0f                	je     140001b36 <_matherr+0x66>
   140001b27:	eb 4e                	jmp    140001b77 <_matherr+0xa7>
   140001b29:	48 8d 05 70 95 00 00 	lea    rax,[rip+0x9570]        # 14000b0a0 <.rdata>
   140001b30:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b34:	eb 4d                	jmp    140001b83 <_matherr+0xb3>
   140001b36:	48 8d 05 82 95 00 00 	lea    rax,[rip+0x9582]        # 14000b0bf <.rdata+0x1f>
   140001b3d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b41:	eb 40                	jmp    140001b83 <_matherr+0xb3>
   140001b43:	48 8d 05 96 95 00 00 	lea    rax,[rip+0x9596]        # 14000b0e0 <.rdata+0x40>
   140001b4a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b4e:	eb 33                	jmp    140001b83 <_matherr+0xb3>
   140001b50:	48 8d 05 a9 95 00 00 	lea    rax,[rip+0x95a9]        # 14000b100 <.rdata+0x60>
   140001b57:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b5b:	eb 26                	jmp    140001b83 <_matherr+0xb3>
   140001b5d:	48 8d 05 c4 95 00 00 	lea    rax,[rip+0x95c4]        # 14000b128 <.rdata+0x88>
   140001b64:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b68:	eb 19                	jmp    140001b83 <_matherr+0xb3>
   140001b6a:	48 8d 05 df 95 00 00 	lea    rax,[rip+0x95df]        # 14000b150 <.rdata+0xb0>
   140001b71:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b75:	eb 0c                	jmp    140001b83 <_matherr+0xb3>
   140001b77:	48 8d 05 08 96 00 00 	lea    rax,[rip+0x9608]        # 14000b186 <.rdata+0xe6>
   140001b7e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b82:	90                   	nop
   140001b83:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b87:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001b8d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b91:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001b96:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b9a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001b9f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ba3:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001ba7:	b9 02 00 00 00       	mov    ecx,0x2
   140001bac:	e8 2f 75 00 00       	call   1400090e0 <__acrt_iob_func>
   140001bb1:	48 89 c1             	mov    rcx,rax
   140001bb4:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001bb8:	48 8d 05 d9 95 00 00 	lea    rax,[rip+0x95d9]        # 14000b198 <.rdata+0xf8>
   140001bbf:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001bc6:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001bcc:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001bd2:	49 89 d9             	mov    r9,rbx
   140001bd5:	49 89 d0             	mov    r8,rdx
   140001bd8:	48 89 c2             	mov    rdx,rax
   140001bdb:	e8 30 7b 00 00       	call   140009710 <fprintf>
   140001be0:	b8 00 00 00 00       	mov    eax,0x0
   140001be5:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001be9:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001bed:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001bf2:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001bf9:	5b                   	pop    rbx
   140001bfa:	5d                   	pop    rbp
   140001bfb:	c3                   	ret
   140001bfc:	90                   	nop
   140001bfd:	90                   	nop
   140001bfe:	90                   	nop
   140001bff:	90                   	nop

0000000140001c00 <__report_error>:
   140001c00:	55                   	push   rbp
   140001c01:	53                   	push   rbx
   140001c02:	48 83 ec 38          	sub    rsp,0x38
   140001c06:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001c0b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001c0f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001c13:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001c17:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001c1b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001c1f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001c23:	b9 02 00 00 00       	mov    ecx,0x2
   140001c28:	e8 b3 74 00 00       	call   1400090e0 <__acrt_iob_func>
   140001c2d:	48 89 c1             	mov    rcx,rax
   140001c30:	48 8d 05 99 95 00 00 	lea    rax,[rip+0x9599]        # 14000b1d0 <.rdata>
   140001c37:	48 89 c2             	mov    rdx,rax
   140001c3a:	e8 d1 7a 00 00       	call   140009710 <fprintf>
   140001c3f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001c43:	b9 02 00 00 00       	mov    ecx,0x2
   140001c48:	e8 93 74 00 00       	call   1400090e0 <__acrt_iob_func>
   140001c4d:	48 89 c1             	mov    rcx,rax
   140001c50:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001c54:	49 89 d8             	mov    r8,rbx
   140001c57:	48 89 c2             	mov    rdx,rax
   140001c5a:	e8 09 7b 00 00       	call   140009768 <vfprintf>
   140001c5f:	e8 8c 7a 00 00       	call   1400096f0 <abort>
   140001c64:	90                   	nop

0000000140001c65 <mark_section_writable>:
   140001c65:	55                   	push   rbp
   140001c66:	48 89 e5             	mov    rbp,rsp
   140001c69:	48 83 ec 60          	sub    rsp,0x60
   140001c6d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001c71:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001c78:	e9 82 00 00 00       	jmp    140001cff <mark_section_writable+0x9a>
   140001c7d:	48 8b 0d 5c d4 00 00 	mov    rcx,QWORD PTR [rip+0xd45c]        # 14000f0e0 <the_secs>
   140001c84:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c87:	48 63 d0             	movsxd rdx,eax
   140001c8a:	48 89 d0             	mov    rax,rdx
   140001c8d:	48 c1 e0 02          	shl    rax,0x2
   140001c91:	48 01 d0             	add    rax,rdx
   140001c94:	48 c1 e0 03          	shl    rax,0x3
   140001c98:	48 01 c8             	add    rax,rcx
   140001c9b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001c9f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001ca3:	72 56                	jb     140001cfb <mark_section_writable+0x96>
   140001ca5:	48 8b 0d 34 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd434]        # 14000f0e0 <the_secs>
   140001cac:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001caf:	48 63 d0             	movsxd rdx,eax
   140001cb2:	48 89 d0             	mov    rax,rdx
   140001cb5:	48 c1 e0 02          	shl    rax,0x2
   140001cb9:	48 01 d0             	add    rax,rdx
   140001cbc:	48 c1 e0 03          	shl    rax,0x3
   140001cc0:	48 01 c8             	add    rax,rcx
   140001cc3:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001cc7:	4c 8b 05 12 d4 00 00 	mov    r8,QWORD PTR [rip+0xd412]        # 14000f0e0 <the_secs>
   140001cce:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cd1:	48 63 d0             	movsxd rdx,eax
   140001cd4:	48 89 d0             	mov    rax,rdx
   140001cd7:	48 c1 e0 02          	shl    rax,0x2
   140001cdb:	48 01 d0             	add    rax,rdx
   140001cde:	48 c1 e0 03          	shl    rax,0x3
   140001ce2:	4c 01 c0             	add    rax,r8
   140001ce5:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001ce9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001cec:	89 c0                	mov    eax,eax
   140001cee:	48 01 c8             	add    rax,rcx
   140001cf1:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001cf5:	0f 82 41 02 00 00    	jb     140001f3c <mark_section_writable+0x2d7>
   140001cfb:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001cff:	8b 05 e3 d3 00 00    	mov    eax,DWORD PTR [rip+0xd3e3]        # 14000f0e8 <maxSections>
   140001d05:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001d08:	0f 8c 6f ff ff ff    	jl     140001c7d <mark_section_writable+0x18>
   140001d0e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001d12:	48 89 c1             	mov    rcx,rax
   140001d15:	e8 c1 11 00 00       	call   140002edb <__mingw_GetSectionForAddress>
   140001d1a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001d1e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001d23:	75 13                	jne    140001d38 <mark_section_writable+0xd3>
   140001d25:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001d29:	48 8d 0d c0 94 00 00 	lea    rcx,[rip+0x94c0]        # 14000b1f0 <.rdata+0x20>
   140001d30:	48 89 c2             	mov    rdx,rax
   140001d33:	e8 c8 fe ff ff       	call   140001c00 <__report_error>
   140001d38:	48 8b 0d a1 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd3a1]        # 14000f0e0 <the_secs>
   140001d3f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d42:	48 63 d0             	movsxd rdx,eax
   140001d45:	48 89 d0             	mov    rax,rdx
   140001d48:	48 c1 e0 02          	shl    rax,0x2
   140001d4c:	48 01 d0             	add    rax,rdx
   140001d4f:	48 c1 e0 03          	shl    rax,0x3
   140001d53:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001d57:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d5b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001d5f:	48 8b 0d 7a d3 00 00 	mov    rcx,QWORD PTR [rip+0xd37a]        # 14000f0e0 <the_secs>
   140001d66:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d69:	48 63 d0             	movsxd rdx,eax
   140001d6c:	48 89 d0             	mov    rax,rdx
   140001d6f:	48 c1 e0 02          	shl    rax,0x2
   140001d73:	48 01 d0             	add    rax,rdx
   140001d76:	48 c1 e0 03          	shl    rax,0x3
   140001d7a:	48 01 c8             	add    rax,rcx
   140001d7d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001d83:	e8 9f 12 00 00       	call   140003027 <_GetPEImageBase>
   140001d88:	48 89 c1             	mov    rcx,rax
   140001d8b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d8f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001d92:	41 89 c1             	mov    r9d,eax
   140001d95:	4c 8b 05 44 d3 00 00 	mov    r8,QWORD PTR [rip+0xd344]        # 14000f0e0 <the_secs>
   140001d9c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d9f:	48 63 d0             	movsxd rdx,eax
   140001da2:	48 89 d0             	mov    rax,rdx
   140001da5:	48 c1 e0 02          	shl    rax,0x2
   140001da9:	48 01 d0             	add    rax,rdx
   140001dac:	48 c1 e0 03          	shl    rax,0x3
   140001db0:	4c 01 c0             	add    rax,r8
   140001db3:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001db7:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001dbb:	48 8b 0d 1e d3 00 00 	mov    rcx,QWORD PTR [rip+0xd31e]        # 14000f0e0 <the_secs>
   140001dc2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001dc5:	48 63 d0             	movsxd rdx,eax
   140001dc8:	48 89 d0             	mov    rax,rdx
   140001dcb:	48 c1 e0 02          	shl    rax,0x2
   140001dcf:	48 01 d0             	add    rax,rdx
   140001dd2:	48 c1 e0 03          	shl    rax,0x3
   140001dd6:	48 01 c8             	add    rax,rcx
   140001dd9:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001ddd:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001de1:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001de7:	48 89 c1             	mov    rcx,rax
   140001dea:	48 8b 05 6f e4 00 00 	mov    rax,QWORD PTR [rip+0xe46f]        # 140010260 <__imp_VirtualQuery>
   140001df1:	ff d0                	call   rax
   140001df3:	48 85 c0             	test   rax,rax
   140001df6:	75 3f                	jne    140001e37 <mark_section_writable+0x1d2>
   140001df8:	48 8b 0d e1 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd2e1]        # 14000f0e0 <the_secs>
   140001dff:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e02:	48 63 d0             	movsxd rdx,eax
   140001e05:	48 89 d0             	mov    rax,rdx
   140001e08:	48 c1 e0 02          	shl    rax,0x2
   140001e0c:	48 01 d0             	add    rax,rdx
   140001e0f:	48 c1 e0 03          	shl    rax,0x3
   140001e13:	48 01 c8             	add    rax,rcx
   140001e16:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001e1a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001e1e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001e21:	89 c1                	mov    ecx,eax
   140001e23:	48 8d 05 e6 93 00 00 	lea    rax,[rip+0x93e6]        # 14000b210 <.rdata+0x40>
   140001e2a:	49 89 d0             	mov    r8,rdx
   140001e2d:	89 ca                	mov    edx,ecx
   140001e2f:	48 89 c1             	mov    rcx,rax
   140001e32:	e8 c9 fd ff ff       	call   140001c00 <__report_error>
   140001e37:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e3a:	83 f8 40             	cmp    eax,0x40
   140001e3d:	0f 84 e8 00 00 00    	je     140001f2b <mark_section_writable+0x2c6>
   140001e43:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e46:	83 f8 04             	cmp    eax,0x4
   140001e49:	0f 84 dc 00 00 00    	je     140001f2b <mark_section_writable+0x2c6>
   140001e4f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e52:	3d 80 00 00 00       	cmp    eax,0x80
   140001e57:	0f 84 ce 00 00 00    	je     140001f2b <mark_section_writable+0x2c6>
   140001e5d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e60:	83 f8 08             	cmp    eax,0x8
   140001e63:	0f 84 c2 00 00 00    	je     140001f2b <mark_section_writable+0x2c6>
   140001e69:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e6c:	83 f8 02             	cmp    eax,0x2
   140001e6f:	75 09                	jne    140001e7a <mark_section_writable+0x215>
   140001e71:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001e78:	eb 07                	jmp    140001e81 <mark_section_writable+0x21c>
   140001e7a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001e81:	48 8b 0d 58 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd258]        # 14000f0e0 <the_secs>
   140001e88:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e8b:	48 63 d0             	movsxd rdx,eax
   140001e8e:	48 89 d0             	mov    rax,rdx
   140001e91:	48 c1 e0 02          	shl    rax,0x2
   140001e95:	48 01 d0             	add    rax,rdx
   140001e98:	48 c1 e0 03          	shl    rax,0x3
   140001e9c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001ea0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001ea4:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001ea8:	48 8b 0d 31 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd231]        # 14000f0e0 <the_secs>
   140001eaf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001eb2:	48 63 d0             	movsxd rdx,eax
   140001eb5:	48 89 d0             	mov    rax,rdx
   140001eb8:	48 c1 e0 02          	shl    rax,0x2
   140001ebc:	48 01 d0             	add    rax,rdx
   140001ebf:	48 c1 e0 03          	shl    rax,0x3
   140001ec3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001ec7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001ecb:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001ecf:	48 8b 0d 0a d2 00 00 	mov    rcx,QWORD PTR [rip+0xd20a]        # 14000f0e0 <the_secs>
   140001ed6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ed9:	48 63 d0             	movsxd rdx,eax
   140001edc:	48 89 d0             	mov    rax,rdx
   140001edf:	48 c1 e0 02          	shl    rax,0x2
   140001ee3:	48 01 d0             	add    rax,rdx
   140001ee6:	48 c1 e0 03          	shl    rax,0x3
   140001eea:	48 01 c8             	add    rax,rcx
   140001eed:	49 89 c0             	mov    r8,rax
   140001ef0:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001ef4:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001ef8:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001efb:	4d 89 c1             	mov    r9,r8
   140001efe:	41 89 c8             	mov    r8d,ecx
   140001f01:	48 89 c1             	mov    rcx,rax
   140001f04:	48 8b 05 4d e3 00 00 	mov    rax,QWORD PTR [rip+0xe34d]        # 140010258 <__imp_VirtualProtect>
   140001f0b:	ff d0                	call   rax
   140001f0d:	85 c0                	test   eax,eax
   140001f0f:	75 1a                	jne    140001f2b <mark_section_writable+0x2c6>
   140001f11:	48 8b 05 f0 e2 00 00 	mov    rax,QWORD PTR [rip+0xe2f0]        # 140010208 <__imp_GetLastError>
   140001f18:	ff d0                	call   rax
   140001f1a:	89 c2                	mov    edx,eax
   140001f1c:	48 8d 05 25 93 00 00 	lea    rax,[rip+0x9325]        # 14000b248 <.rdata+0x78>
   140001f23:	48 89 c1             	mov    rcx,rax
   140001f26:	e8 d5 fc ff ff       	call   140001c00 <__report_error>
   140001f2b:	8b 05 b7 d1 00 00    	mov    eax,DWORD PTR [rip+0xd1b7]        # 14000f0e8 <maxSections>
   140001f31:	83 c0 01             	add    eax,0x1
   140001f34:	89 05 ae d1 00 00    	mov    DWORD PTR [rip+0xd1ae],eax        # 14000f0e8 <maxSections>
   140001f3a:	eb 01                	jmp    140001f3d <mark_section_writable+0x2d8>
   140001f3c:	90                   	nop
   140001f3d:	48 83 c4 60          	add    rsp,0x60
   140001f41:	5d                   	pop    rbp
   140001f42:	c3                   	ret

0000000140001f43 <restore_modified_sections>:
   140001f43:	55                   	push   rbp
   140001f44:	48 89 e5             	mov    rbp,rsp
   140001f47:	48 83 ec 30          	sub    rsp,0x30
   140001f4b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001f52:	e9 ad 00 00 00       	jmp    140002004 <restore_modified_sections+0xc1>
   140001f57:	48 8b 0d 82 d1 00 00 	mov    rcx,QWORD PTR [rip+0xd182]        # 14000f0e0 <the_secs>
   140001f5e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f61:	48 63 d0             	movsxd rdx,eax
   140001f64:	48 89 d0             	mov    rax,rdx
   140001f67:	48 c1 e0 02          	shl    rax,0x2
   140001f6b:	48 01 d0             	add    rax,rdx
   140001f6e:	48 c1 e0 03          	shl    rax,0x3
   140001f72:	48 01 c8             	add    rax,rcx
   140001f75:	8b 00                	mov    eax,DWORD PTR [rax]
   140001f77:	85 c0                	test   eax,eax
   140001f79:	0f 84 80 00 00 00    	je     140001fff <restore_modified_sections+0xbc>
   140001f7f:	48 8b 0d 5a d1 00 00 	mov    rcx,QWORD PTR [rip+0xd15a]        # 14000f0e0 <the_secs>
   140001f86:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f89:	48 63 d0             	movsxd rdx,eax
   140001f8c:	48 89 d0             	mov    rax,rdx
   140001f8f:	48 c1 e0 02          	shl    rax,0x2
   140001f93:	48 01 d0             	add    rax,rdx
   140001f96:	48 c1 e0 03          	shl    rax,0x3
   140001f9a:	48 01 c8             	add    rax,rcx
   140001f9d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001fa0:	48 8b 0d 39 d1 00 00 	mov    rcx,QWORD PTR [rip+0xd139]        # 14000f0e0 <the_secs>
   140001fa7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001faa:	48 63 d0             	movsxd rdx,eax
   140001fad:	48 89 d0             	mov    rax,rdx
   140001fb0:	48 c1 e0 02          	shl    rax,0x2
   140001fb4:	48 01 d0             	add    rax,rdx
   140001fb7:	48 c1 e0 03          	shl    rax,0x3
   140001fbb:	48 01 c8             	add    rax,rcx
   140001fbe:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001fc2:	4c 8b 05 17 d1 00 00 	mov    r8,QWORD PTR [rip+0xd117]        # 14000f0e0 <the_secs>
   140001fc9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001fcc:	48 63 d0             	movsxd rdx,eax
   140001fcf:	48 89 d0             	mov    rax,rdx
   140001fd2:	48 c1 e0 02          	shl    rax,0x2
   140001fd6:	48 01 d0             	add    rax,rdx
   140001fd9:	48 c1 e0 03          	shl    rax,0x3
   140001fdd:	4c 01 c0             	add    rax,r8
   140001fe0:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001fe4:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001fe8:	49 89 d1             	mov    r9,rdx
   140001feb:	45 89 d0             	mov    r8d,r10d
   140001fee:	48 89 ca             	mov    rdx,rcx
   140001ff1:	48 89 c1             	mov    rcx,rax
   140001ff4:	48 8b 05 5d e2 00 00 	mov    rax,QWORD PTR [rip+0xe25d]        # 140010258 <__imp_VirtualProtect>
   140001ffb:	ff d0                	call   rax
   140001ffd:	eb 01                	jmp    140002000 <restore_modified_sections+0xbd>
   140001fff:	90                   	nop
   140002000:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140002004:	8b 05 de d0 00 00    	mov    eax,DWORD PTR [rip+0xd0de]        # 14000f0e8 <maxSections>
   14000200a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   14000200d:	0f 8c 44 ff ff ff    	jl     140001f57 <restore_modified_sections+0x14>
   140002013:	90                   	nop
   140002014:	90                   	nop
   140002015:	48 83 c4 30          	add    rsp,0x30
   140002019:	5d                   	pop    rbp
   14000201a:	c3                   	ret

000000014000201b <__write_memory>:
   14000201b:	55                   	push   rbp
   14000201c:	48 89 e5             	mov    rbp,rsp
   14000201f:	48 83 ec 20          	sub    rsp,0x20
   140002023:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002027:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000202b:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000202f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140002034:	74 25                	je     14000205b <__write_memory+0x40>
   140002036:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000203a:	48 89 c1             	mov    rcx,rax
   14000203d:	e8 23 fc ff ff       	call   140001c65 <mark_section_writable>
   140002042:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140002046:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000204a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000204e:	49 89 c8             	mov    r8,rcx
   140002051:	48 89 c1             	mov    rcx,rax
   140002054:	e8 df 76 00 00       	call   140009738 <memcpy>
   140002059:	eb 01                	jmp    14000205c <__write_memory+0x41>
   14000205b:	90                   	nop
   14000205c:	48 83 c4 20          	add    rsp,0x20
   140002060:	5d                   	pop    rbp
   140002061:	c3                   	ret

0000000140002062 <do_pseudo_reloc>:
   140002062:	55                   	push   rbp
   140002063:	48 89 e5             	mov    rbp,rsp
   140002066:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   14000206a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000206e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002072:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002076:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000207a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   14000207e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002082:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002086:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000208a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   14000208f:	0f 8e 44 03 00 00    	jle    1400023d9 <do_pseudo_reloc+0x377>
   140002095:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   14000209a:	7e 25                	jle    1400020c1 <do_pseudo_reloc+0x5f>
   14000209c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020a0:	8b 00                	mov    eax,DWORD PTR [rax]
   1400020a2:	85 c0                	test   eax,eax
   1400020a4:	75 1b                	jne    1400020c1 <do_pseudo_reloc+0x5f>
   1400020a6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020aa:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020ad:	85 c0                	test   eax,eax
   1400020af:	75 10                	jne    1400020c1 <do_pseudo_reloc+0x5f>
   1400020b1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020b5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020b8:	85 c0                	test   eax,eax
   1400020ba:	75 05                	jne    1400020c1 <do_pseudo_reloc+0x5f>
   1400020bc:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   1400020c1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020c5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400020c7:	85 c0                	test   eax,eax
   1400020c9:	75 0b                	jne    1400020d6 <do_pseudo_reloc+0x74>
   1400020cb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020cf:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020d2:	85 c0                	test   eax,eax
   1400020d4:	74 59                	je     14000212f <do_pseudo_reloc+0xcd>
   1400020d6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020da:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400020de:	eb 40                	jmp    140002120 <do_pseudo_reloc+0xbe>
   1400020e0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020e4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020e7:	89 c2                	mov    edx,eax
   1400020e9:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400020ed:	48 01 d0             	add    rax,rdx
   1400020f0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400020f4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020f8:	8b 10                	mov    edx,DWORD PTR [rax]
   1400020fa:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020fe:	8b 00                	mov    eax,DWORD PTR [rax]
   140002100:	01 d0                	add    eax,edx
   140002102:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   140002105:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002109:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   14000210d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002113:	48 89 c1             	mov    rcx,rax
   140002116:	e8 00 ff ff ff       	call   14000201b <__write_memory>
   14000211b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140002120:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002124:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002128:	72 b6                	jb     1400020e0 <do_pseudo_reloc+0x7e>
   14000212a:	e9 ab 02 00 00       	jmp    1400023da <do_pseudo_reloc+0x378>
   14000212f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002133:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002136:	83 f8 01             	cmp    eax,0x1
   140002139:	74 18                	je     140002153 <do_pseudo_reloc+0xf1>
   14000213b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000213f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002142:	89 c2                	mov    edx,eax
   140002144:	48 8d 05 25 91 00 00 	lea    rax,[rip+0x9125]        # 14000b270 <.rdata+0xa0>
   14000214b:	48 89 c1             	mov    rcx,rax
   14000214e:	e8 ad fa ff ff       	call   140001c00 <__report_error>
   140002153:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002157:	48 83 c0 0c          	add    rax,0xc
   14000215b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000215f:	e9 65 02 00 00       	jmp    1400023c9 <do_pseudo_reloc+0x367>
   140002164:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002168:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000216b:	89 c2                	mov    edx,eax
   14000216d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002171:	48 01 d0             	add    rax,rdx
   140002174:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002178:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000217c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000217e:	89 c2                	mov    edx,eax
   140002180:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002184:	48 01 d0             	add    rax,rdx
   140002187:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000218b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000218f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002192:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002196:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000219a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000219d:	0f b6 c0             	movzx  eax,al
   1400021a0:	83 f8 40             	cmp    eax,0x40
   1400021a3:	0f 84 b6 00 00 00    	je     14000225f <do_pseudo_reloc+0x1fd>
   1400021a9:	83 f8 40             	cmp    eax,0x40
   1400021ac:	0f 87 ba 00 00 00    	ja     14000226c <do_pseudo_reloc+0x20a>
   1400021b2:	83 f8 20             	cmp    eax,0x20
   1400021b5:	74 77                	je     14000222e <do_pseudo_reloc+0x1cc>
   1400021b7:	83 f8 20             	cmp    eax,0x20
   1400021ba:	0f 87 ac 00 00 00    	ja     14000226c <do_pseudo_reloc+0x20a>
   1400021c0:	83 f8 08             	cmp    eax,0x8
   1400021c3:	74 0a                	je     1400021cf <do_pseudo_reloc+0x16d>
   1400021c5:	83 f8 10             	cmp    eax,0x10
   1400021c8:	74 38                	je     140002202 <do_pseudo_reloc+0x1a0>
   1400021ca:	e9 9d 00 00 00       	jmp    14000226c <do_pseudo_reloc+0x20a>
   1400021cf:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021d3:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400021d6:	0f b6 c0             	movzx  eax,al
   1400021d9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021dd:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021e1:	25 80 00 00 00       	and    eax,0x80
   1400021e6:	48 85 c0             	test   rax,rax
   1400021e9:	0f 84 9d 00 00 00    	je     14000228c <do_pseudo_reloc+0x22a>
   1400021ef:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021f3:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   1400021f9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021fd:	e9 8a 00 00 00       	jmp    14000228c <do_pseudo_reloc+0x22a>
   140002202:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002206:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002209:	0f b7 c0             	movzx  eax,ax
   14000220c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002210:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002214:	25 00 80 00 00       	and    eax,0x8000
   140002219:	48 85 c0             	test   rax,rax
   14000221c:	74 71                	je     14000228f <do_pseudo_reloc+0x22d>
   14000221e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002222:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   140002228:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000222c:	eb 61                	jmp    14000228f <do_pseudo_reloc+0x22d>
   14000222e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002232:	8b 00                	mov    eax,DWORD PTR [rax]
   140002234:	89 c0                	mov    eax,eax
   140002236:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000223a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000223e:	25 00 00 00 80       	and    eax,0x80000000
   140002243:	48 85 c0             	test   rax,rax
   140002246:	74 4a                	je     140002292 <do_pseudo_reloc+0x230>
   140002248:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000224c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002253:	ff ff ff 
   140002256:	48 09 d0             	or     rax,rdx
   140002259:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000225d:	eb 33                	jmp    140002292 <do_pseudo_reloc+0x230>
   14000225f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002263:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002266:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000226a:	eb 27                	jmp    140002293 <do_pseudo_reloc+0x231>
   14000226c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002273:	00 
   140002274:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002278:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000227b:	0f b6 c0             	movzx  eax,al
   14000227e:	48 8d 0d 23 90 00 00 	lea    rcx,[rip+0x9023]        # 14000b2a8 <.rdata+0xd8>
   140002285:	89 c2                	mov    edx,eax
   140002287:	e8 74 f9 ff ff       	call   140001c00 <__report_error>
   14000228c:	90                   	nop
   14000228d:	eb 04                	jmp    140002293 <do_pseudo_reloc+0x231>
   14000228f:	90                   	nop
   140002290:	eb 01                	jmp    140002293 <do_pseudo_reloc+0x231>
   140002292:	90                   	nop
   140002293:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002297:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000229b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000229d:	89 c2                	mov    edx,eax
   14000229f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400022a3:	48 01 c2             	add    rdx,rax
   1400022a6:	48 89 c8             	mov    rax,rcx
   1400022a9:	48 29 d0             	sub    rax,rdx
   1400022ac:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022b0:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400022b4:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400022b8:	48 01 d0             	add    rax,rdx
   1400022bb:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022bf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022c3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400022c6:	25 ff 00 00 00       	and    eax,0xff
   1400022cb:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400022ce:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   1400022d2:	77 67                	ja     14000233b <do_pseudo_reloc+0x2d9>
   1400022d4:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022d7:	ba 01 00 00 00       	mov    edx,0x1
   1400022dc:	89 c1                	mov    ecx,eax
   1400022de:	48 d3 e2             	shl    rdx,cl
   1400022e1:	48 89 d0             	mov    rax,rdx
   1400022e4:	48 83 e8 01          	sub    rax,0x1
   1400022e8:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400022ec:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022ef:	83 e8 01             	sub    eax,0x1
   1400022f2:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   1400022f9:	89 c1                	mov    ecx,eax
   1400022fb:	48 d3 e2             	shl    rdx,cl
   1400022fe:	48 89 d0             	mov    rax,rdx
   140002301:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140002305:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002309:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   14000230d:	7c 0a                	jl     140002319 <do_pseudo_reloc+0x2b7>
   14000230f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002313:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002317:	7e 22                	jle    14000233b <do_pseudo_reloc+0x2d9>
   140002319:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000231d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   140002321:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   140002325:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002328:	48 8d 0d a9 8f 00 00 	lea    rcx,[rip+0x8fa9]        # 14000b2d8 <.rdata+0x108>
   14000232f:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002334:	89 c2                	mov    edx,eax
   140002336:	e8 c5 f8 ff ff       	call   140001c00 <__report_error>
   14000233b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000233f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002342:	0f b6 c0             	movzx  eax,al
   140002345:	83 f8 40             	cmp    eax,0x40
   140002348:	74 63                	je     1400023ad <do_pseudo_reloc+0x34b>
   14000234a:	83 f8 40             	cmp    eax,0x40
   14000234d:	77 75                	ja     1400023c4 <do_pseudo_reloc+0x362>
   14000234f:	83 f8 20             	cmp    eax,0x20
   140002352:	74 41                	je     140002395 <do_pseudo_reloc+0x333>
   140002354:	83 f8 20             	cmp    eax,0x20
   140002357:	77 6b                	ja     1400023c4 <do_pseudo_reloc+0x362>
   140002359:	83 f8 08             	cmp    eax,0x8
   14000235c:	74 07                	je     140002365 <do_pseudo_reloc+0x303>
   14000235e:	83 f8 10             	cmp    eax,0x10
   140002361:	74 1a                	je     14000237d <do_pseudo_reloc+0x31b>
   140002363:	eb 5f                	jmp    1400023c4 <do_pseudo_reloc+0x362>
   140002365:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002369:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000236d:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002373:	48 89 c1             	mov    rcx,rax
   140002376:	e8 a0 fc ff ff       	call   14000201b <__write_memory>
   14000237b:	eb 47                	jmp    1400023c4 <do_pseudo_reloc+0x362>
   14000237d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002381:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002385:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000238b:	48 89 c1             	mov    rcx,rax
   14000238e:	e8 88 fc ff ff       	call   14000201b <__write_memory>
   140002393:	eb 2f                	jmp    1400023c4 <do_pseudo_reloc+0x362>
   140002395:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002399:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000239d:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400023a3:	48 89 c1             	mov    rcx,rax
   1400023a6:	e8 70 fc ff ff       	call   14000201b <__write_memory>
   1400023ab:	eb 17                	jmp    1400023c4 <do_pseudo_reloc+0x362>
   1400023ad:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400023b1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400023b5:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400023bb:	48 89 c1             	mov    rcx,rax
   1400023be:	e8 58 fc ff ff       	call   14000201b <__write_memory>
   1400023c3:	90                   	nop
   1400023c4:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   1400023c9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400023cd:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400023d1:	0f 82 8d fd ff ff    	jb     140002164 <do_pseudo_reloc+0x102>
   1400023d7:	eb 01                	jmp    1400023da <do_pseudo_reloc+0x378>
   1400023d9:	90                   	nop
   1400023da:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   1400023de:	5d                   	pop    rbp
   1400023df:	c3                   	ret

00000001400023e0 <_pei386_runtime_relocator>:
   1400023e0:	55                   	push   rbp
   1400023e1:	48 89 e5             	mov    rbp,rsp
   1400023e4:	48 83 ec 30          	sub    rsp,0x30
   1400023e8:	8b 05 fe cc 00 00    	mov    eax,DWORD PTR [rip+0xccfe]        # 14000f0ec <was_init.0>
   1400023ee:	85 c0                	test   eax,eax
   1400023f0:	0f 85 88 00 00 00    	jne    14000247e <_pei386_runtime_relocator+0x9e>
   1400023f6:	8b 05 f0 cc 00 00    	mov    eax,DWORD PTR [rip+0xccf0]        # 14000f0ec <was_init.0>
   1400023fc:	83 c0 01             	add    eax,0x1
   1400023ff:	89 05 e7 cc 00 00    	mov    DWORD PTR [rip+0xcce7],eax        # 14000f0ec <was_init.0>
   140002405:	e8 21 0b 00 00       	call   140002f2b <__mingw_GetSectionCount>
   14000240a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000240d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002410:	48 63 d0             	movsxd rdx,eax
   140002413:	48 89 d0             	mov    rax,rdx
   140002416:	48 c1 e0 02          	shl    rax,0x2
   14000241a:	48 01 d0             	add    rax,rdx
   14000241d:	48 c1 e0 03          	shl    rax,0x3
   140002421:	48 83 c0 0f          	add    rax,0xf
   140002425:	48 c1 e8 04          	shr    rax,0x4
   140002429:	48 c1 e0 04          	shl    rax,0x4
   14000242d:	e8 7e 0d 00 00       	call   1400031b0 <___chkstk_ms>
   140002432:	48 29 c4             	sub    rsp,rax
   140002435:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000243a:	48 83 c0 0f          	add    rax,0xf
   14000243e:	48 c1 e8 04          	shr    rax,0x4
   140002442:	48 c1 e0 04          	shl    rax,0x4
   140002446:	48 89 05 93 cc 00 00 	mov    QWORD PTR [rip+0xcc93],rax        # 14000f0e0 <the_secs>
   14000244d:	c7 05 91 cc 00 00 00 	mov    DWORD PTR [rip+0xcc91],0x0        # 14000f0e8 <maxSections>
   140002454:	00 00 00 
   140002457:	48 8b 0d 22 91 00 00 	mov    rcx,QWORD PTR [rip+0x9122]        # 14000b580 <.refptr.__ImageBase>
   14000245e:	48 8b 15 2b 91 00 00 	mov    rdx,QWORD PTR [rip+0x912b]        # 14000b590 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002465:	48 8b 05 34 91 00 00 	mov    rax,QWORD PTR [rip+0x9134]        # 14000b5a0 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000246c:	49 89 c8             	mov    r8,rcx
   14000246f:	48 89 c1             	mov    rcx,rax
   140002472:	e8 eb fb ff ff       	call   140002062 <do_pseudo_reloc>
   140002477:	e8 c7 fa ff ff       	call   140001f43 <restore_modified_sections>
   14000247c:	eb 01                	jmp    14000247f <_pei386_runtime_relocator+0x9f>
   14000247e:	90                   	nop
   14000247f:	48 89 ec             	mov    rsp,rbp
   140002482:	5d                   	pop    rbp
   140002483:	c3                   	ret
   140002484:	90                   	nop
   140002485:	90                   	nop
   140002486:	90                   	nop
   140002487:	90                   	nop
   140002488:	90                   	nop
   140002489:	90                   	nop
   14000248a:	90                   	nop
   14000248b:	90                   	nop
   14000248c:	90                   	nop
   14000248d:	90                   	nop
   14000248e:	90                   	nop
   14000248f:	90                   	nop

0000000140002490 <__mingw_raise_matherr>:
   140002490:	55                   	push   rbp
   140002491:	48 89 e5             	mov    rbp,rsp
   140002494:	48 83 ec 50          	sub    rsp,0x50
   140002498:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000249b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000249f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   1400024a4:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   1400024a9:	48 8b 05 40 cc 00 00 	mov    rax,QWORD PTR [rip+0xcc40]        # 14000f0f0 <stUserMathErr>
   1400024b0:	48 85 c0             	test   rax,rax
   1400024b3:	74 3e                	je     1400024f3 <__mingw_raise_matherr+0x63>
   1400024b5:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400024b8:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400024bb:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400024bf:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400024c3:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   1400024c8:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400024cd:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   1400024d2:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   1400024d7:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   1400024dc:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   1400024e1:	48 8b 15 08 cc 00 00 	mov    rdx,QWORD PTR [rip+0xcc08]        # 14000f0f0 <stUserMathErr>
   1400024e8:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400024ec:	48 89 c1             	mov    rcx,rax
   1400024ef:	ff d2                	call   rdx
   1400024f1:	eb 01                	jmp    1400024f4 <__mingw_raise_matherr+0x64>
   1400024f3:	90                   	nop
   1400024f4:	48 83 c4 50          	add    rsp,0x50
   1400024f8:	5d                   	pop    rbp
   1400024f9:	c3                   	ret

00000001400024fa <__mingw_setusermatherr>:
   1400024fa:	55                   	push   rbp
   1400024fb:	48 89 e5             	mov    rbp,rsp
   1400024fe:	48 83 ec 20          	sub    rsp,0x20
   140002502:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002506:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000250a:	48 89 05 df cb 00 00 	mov    QWORD PTR [rip+0xcbdf],rax        # 14000f0f0 <stUserMathErr>
   140002511:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002515:	48 89 c1             	mov    rcx,rax
   140002518:	e8 93 71 00 00       	call   1400096b0 <__setusermatherr>
   14000251d:	90                   	nop
   14000251e:	48 83 c4 20          	add    rsp,0x20
   140002522:	5d                   	pop    rbp
   140002523:	c3                   	ret
   140002524:	90                   	nop
   140002525:	90                   	nop
   140002526:	90                   	nop
   140002527:	90                   	nop
   140002528:	90                   	nop
   140002529:	90                   	nop
   14000252a:	90                   	nop
   14000252b:	90                   	nop
   14000252c:	90                   	nop
   14000252d:	90                   	nop
   14000252e:	90                   	nop
   14000252f:	90                   	nop

0000000140002530 <__mingw_SEH_error_handler>:
   140002530:	55                   	push   rbp
   140002531:	48 89 e5             	mov    rbp,rsp
   140002534:	48 83 ec 30          	sub    rsp,0x30
   140002538:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000253c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002540:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002544:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002548:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000254f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002556:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000255a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000255d:	83 e0 02             	and    eax,0x2
   140002560:	85 c0                	test   eax,eax
   140002562:	74 0a                	je     14000256e <__mingw_SEH_error_handler+0x3e>
   140002564:	b8 01 00 00 00       	mov    eax,0x1
   140002569:	e9 16 02 00 00       	jmp    140002784 <__mingw_SEH_error_handler+0x254>
   14000256e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002572:	8b 00                	mov    eax,DWORD PTR [rax]
   140002574:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002579:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000257e:	75 18                	jne    140002598 <__mingw_SEH_error_handler+0x68>
   140002580:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002584:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002587:	83 e0 01             	and    eax,0x1
   14000258a:	85 c0                	test   eax,eax
   14000258c:	75 0a                	jne    140002598 <__mingw_SEH_error_handler+0x68>
   14000258e:	b8 00 00 00 00       	mov    eax,0x0
   140002593:	e9 ec 01 00 00       	jmp    140002784 <__mingw_SEH_error_handler+0x254>
   140002598:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000259c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000259e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400025a3:	0f 84 12 01 00 00    	je     1400026bb <__mingw_SEH_error_handler+0x18b>
   1400025a9:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400025ae:	0f 87 c3 01 00 00    	ja     140002777 <__mingw_SEH_error_handler+0x247>
   1400025b4:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400025b9:	0f 87 b8 01 00 00    	ja     140002777 <__mingw_SEH_error_handler+0x247>
   1400025bf:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400025c4:	0f 83 4c 01 00 00    	jae    140002716 <__mingw_SEH_error_handler+0x1e6>
   1400025ca:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400025cf:	0f 84 3a 01 00 00    	je     14000270f <__mingw_SEH_error_handler+0x1df>
   1400025d5:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400025da:	0f 87 97 01 00 00    	ja     140002777 <__mingw_SEH_error_handler+0x247>
   1400025e0:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400025e5:	0f 84 83 01 00 00    	je     14000276e <__mingw_SEH_error_handler+0x23e>
   1400025eb:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400025f0:	0f 87 81 01 00 00    	ja     140002777 <__mingw_SEH_error_handler+0x247>
   1400025f6:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400025fb:	0f 87 76 01 00 00    	ja     140002777 <__mingw_SEH_error_handler+0x247>
   140002601:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002606:	0f 83 03 01 00 00    	jae    14000270f <__mingw_SEH_error_handler+0x1df>
   14000260c:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002611:	0f 84 57 01 00 00    	je     14000276e <__mingw_SEH_error_handler+0x23e>
   140002617:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000261c:	0f 87 55 01 00 00    	ja     140002777 <__mingw_SEH_error_handler+0x247>
   140002622:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002627:	0f 84 8e 00 00 00    	je     1400026bb <__mingw_SEH_error_handler+0x18b>
   14000262d:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002632:	0f 87 3f 01 00 00    	ja     140002777 <__mingw_SEH_error_handler+0x247>
   140002638:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000263d:	0f 84 2b 01 00 00    	je     14000276e <__mingw_SEH_error_handler+0x23e>
   140002643:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002648:	0f 87 29 01 00 00    	ja     140002777 <__mingw_SEH_error_handler+0x247>
   14000264e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002653:	0f 84 15 01 00 00    	je     14000276e <__mingw_SEH_error_handler+0x23e>
   140002659:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000265e:	0f 85 13 01 00 00    	jne    140002777 <__mingw_SEH_error_handler+0x247>
   140002664:	ba 00 00 00 00       	mov    edx,0x0
   140002669:	b9 0b 00 00 00       	mov    ecx,0xb
   14000266e:	e8 d5 70 00 00       	call   140009748 <signal>
   140002673:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002677:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000267c:	75 1b                	jne    140002699 <__mingw_SEH_error_handler+0x169>
   14000267e:	ba 01 00 00 00       	mov    edx,0x1
   140002683:	b9 0b 00 00 00       	mov    ecx,0xb
   140002688:	e8 bb 70 00 00       	call   140009748 <signal>
   14000268d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002694:	e9 e1 00 00 00       	jmp    14000277a <__mingw_SEH_error_handler+0x24a>
   140002699:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000269e:	0f 84 d6 00 00 00    	je     14000277a <__mingw_SEH_error_handler+0x24a>
   1400026a4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400026a8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400026ad:	ff d0                	call   rax
   1400026af:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026b6:	e9 bf 00 00 00       	jmp    14000277a <__mingw_SEH_error_handler+0x24a>
   1400026bb:	ba 00 00 00 00       	mov    edx,0x0
   1400026c0:	b9 04 00 00 00       	mov    ecx,0x4
   1400026c5:	e8 7e 70 00 00       	call   140009748 <signal>
   1400026ca:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400026ce:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400026d3:	75 1b                	jne    1400026f0 <__mingw_SEH_error_handler+0x1c0>
   1400026d5:	ba 01 00 00 00       	mov    edx,0x1
   1400026da:	b9 04 00 00 00       	mov    ecx,0x4
   1400026df:	e8 64 70 00 00       	call   140009748 <signal>
   1400026e4:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026eb:	e9 8d 00 00 00       	jmp    14000277d <__mingw_SEH_error_handler+0x24d>
   1400026f0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400026f5:	0f 84 82 00 00 00    	je     14000277d <__mingw_SEH_error_handler+0x24d>
   1400026fb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400026ff:	b9 04 00 00 00       	mov    ecx,0x4
   140002704:	ff d0                	call   rax
   140002706:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000270d:	eb 6e                	jmp    14000277d <__mingw_SEH_error_handler+0x24d>
   14000270f:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002716:	ba 00 00 00 00       	mov    edx,0x0
   14000271b:	b9 08 00 00 00       	mov    ecx,0x8
   140002720:	e8 23 70 00 00       	call   140009748 <signal>
   140002725:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002729:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000272e:	75 23                	jne    140002753 <__mingw_SEH_error_handler+0x223>
   140002730:	ba 01 00 00 00       	mov    edx,0x1
   140002735:	b9 08 00 00 00       	mov    ecx,0x8
   14000273a:	e8 09 70 00 00       	call   140009748 <signal>
   14000273f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002743:	74 05                	je     14000274a <__mingw_SEH_error_handler+0x21a>
   140002745:	e8 a6 05 00 00       	call   140002cf0 <_fpreset>
   14000274a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002751:	eb 2d                	jmp    140002780 <__mingw_SEH_error_handler+0x250>
   140002753:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002758:	74 26                	je     140002780 <__mingw_SEH_error_handler+0x250>
   14000275a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000275e:	b9 08 00 00 00       	mov    ecx,0x8
   140002763:	ff d0                	call   rax
   140002765:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000276c:	eb 12                	jmp    140002780 <__mingw_SEH_error_handler+0x250>
   14000276e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002775:	eb 0a                	jmp    140002781 <__mingw_SEH_error_handler+0x251>
   140002777:	90                   	nop
   140002778:	eb 07                	jmp    140002781 <__mingw_SEH_error_handler+0x251>
   14000277a:	90                   	nop
   14000277b:	eb 04                	jmp    140002781 <__mingw_SEH_error_handler+0x251>
   14000277d:	90                   	nop
   14000277e:	eb 01                	jmp    140002781 <__mingw_SEH_error_handler+0x251>
   140002780:	90                   	nop
   140002781:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002784:	48 83 c4 30          	add    rsp,0x30
   140002788:	5d                   	pop    rbp
   140002789:	c3                   	ret

000000014000278a <_gnu_exception_handler>:
   14000278a:	55                   	push   rbp
   14000278b:	48 89 e5             	mov    rbp,rsp
   14000278e:	48 83 ec 30          	sub    rsp,0x30
   140002792:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002796:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000279d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400027a4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400027a8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400027ab:	8b 00                	mov    eax,DWORD PTR [rax]
   1400027ad:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400027b2:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400027b7:	75 1b                	jne    1400027d4 <_gnu_exception_handler+0x4a>
   1400027b9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400027bd:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400027c0:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400027c3:	83 e0 01             	and    eax,0x1
   1400027c6:	85 c0                	test   eax,eax
   1400027c8:	75 0a                	jne    1400027d4 <_gnu_exception_handler+0x4a>
   1400027ca:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400027cf:	e9 14 02 00 00       	jmp    1400029e8 <_gnu_exception_handler+0x25e>
   1400027d4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400027d8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400027db:	8b 00                	mov    eax,DWORD PTR [rax]
   1400027dd:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400027e2:	0f 84 12 01 00 00    	je     1400028fa <_gnu_exception_handler+0x170>
   1400027e8:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400027ed:	0f 87 c3 01 00 00    	ja     1400029b6 <_gnu_exception_handler+0x22c>
   1400027f3:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400027f8:	0f 87 b8 01 00 00    	ja     1400029b6 <_gnu_exception_handler+0x22c>
   1400027fe:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002803:	0f 83 4c 01 00 00    	jae    140002955 <_gnu_exception_handler+0x1cb>
   140002809:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000280e:	0f 84 3a 01 00 00    	je     14000294e <_gnu_exception_handler+0x1c4>
   140002814:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002819:	0f 87 97 01 00 00    	ja     1400029b6 <_gnu_exception_handler+0x22c>
   14000281f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002824:	0f 84 83 01 00 00    	je     1400029ad <_gnu_exception_handler+0x223>
   14000282a:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   14000282f:	0f 87 81 01 00 00    	ja     1400029b6 <_gnu_exception_handler+0x22c>
   140002835:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000283a:	0f 87 76 01 00 00    	ja     1400029b6 <_gnu_exception_handler+0x22c>
   140002840:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002845:	0f 83 03 01 00 00    	jae    14000294e <_gnu_exception_handler+0x1c4>
   14000284b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002850:	0f 84 57 01 00 00    	je     1400029ad <_gnu_exception_handler+0x223>
   140002856:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000285b:	0f 87 55 01 00 00    	ja     1400029b6 <_gnu_exception_handler+0x22c>
   140002861:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002866:	0f 84 8e 00 00 00    	je     1400028fa <_gnu_exception_handler+0x170>
   14000286c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002871:	0f 87 3f 01 00 00    	ja     1400029b6 <_gnu_exception_handler+0x22c>
   140002877:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000287c:	0f 84 2b 01 00 00    	je     1400029ad <_gnu_exception_handler+0x223>
   140002882:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002887:	0f 87 29 01 00 00    	ja     1400029b6 <_gnu_exception_handler+0x22c>
   14000288d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002892:	0f 84 15 01 00 00    	je     1400029ad <_gnu_exception_handler+0x223>
   140002898:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000289d:	0f 85 13 01 00 00    	jne    1400029b6 <_gnu_exception_handler+0x22c>
   1400028a3:	ba 00 00 00 00       	mov    edx,0x0
   1400028a8:	b9 0b 00 00 00       	mov    ecx,0xb
   1400028ad:	e8 96 6e 00 00       	call   140009748 <signal>
   1400028b2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400028b6:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028bb:	75 1b                	jne    1400028d8 <_gnu_exception_handler+0x14e>
   1400028bd:	ba 01 00 00 00       	mov    edx,0x1
   1400028c2:	b9 0b 00 00 00       	mov    ecx,0xb
   1400028c7:	e8 7c 6e 00 00       	call   140009748 <signal>
   1400028cc:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028d3:	e9 e1 00 00 00       	jmp    1400029b9 <_gnu_exception_handler+0x22f>
   1400028d8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028dd:	0f 84 d6 00 00 00    	je     1400029b9 <_gnu_exception_handler+0x22f>
   1400028e3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028e7:	b9 0b 00 00 00       	mov    ecx,0xb
   1400028ec:	ff d0                	call   rax
   1400028ee:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028f5:	e9 bf 00 00 00       	jmp    1400029b9 <_gnu_exception_handler+0x22f>
   1400028fa:	ba 00 00 00 00       	mov    edx,0x0
   1400028ff:	b9 04 00 00 00       	mov    ecx,0x4
   140002904:	e8 3f 6e 00 00       	call   140009748 <signal>
   140002909:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000290d:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002912:	75 1b                	jne    14000292f <_gnu_exception_handler+0x1a5>
   140002914:	ba 01 00 00 00       	mov    edx,0x1
   140002919:	b9 04 00 00 00       	mov    ecx,0x4
   14000291e:	e8 25 6e 00 00       	call   140009748 <signal>
   140002923:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000292a:	e9 8d 00 00 00       	jmp    1400029bc <_gnu_exception_handler+0x232>
   14000292f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002934:	0f 84 82 00 00 00    	je     1400029bc <_gnu_exception_handler+0x232>
   14000293a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000293e:	b9 04 00 00 00       	mov    ecx,0x4
   140002943:	ff d0                	call   rax
   140002945:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000294c:	eb 6e                	jmp    1400029bc <_gnu_exception_handler+0x232>
   14000294e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002955:	ba 00 00 00 00       	mov    edx,0x0
   14000295a:	b9 08 00 00 00       	mov    ecx,0x8
   14000295f:	e8 e4 6d 00 00       	call   140009748 <signal>
   140002964:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002968:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000296d:	75 23                	jne    140002992 <_gnu_exception_handler+0x208>
   14000296f:	ba 01 00 00 00       	mov    edx,0x1
   140002974:	b9 08 00 00 00       	mov    ecx,0x8
   140002979:	e8 ca 6d 00 00       	call   140009748 <signal>
   14000297e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002982:	74 05                	je     140002989 <_gnu_exception_handler+0x1ff>
   140002984:	e8 67 03 00 00       	call   140002cf0 <_fpreset>
   140002989:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002990:	eb 2d                	jmp    1400029bf <_gnu_exception_handler+0x235>
   140002992:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002997:	74 26                	je     1400029bf <_gnu_exception_handler+0x235>
   140002999:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000299d:	b9 08 00 00 00       	mov    ecx,0x8
   1400029a2:	ff d0                	call   rax
   1400029a4:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400029ab:	eb 12                	jmp    1400029bf <_gnu_exception_handler+0x235>
   1400029ad:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400029b4:	eb 0a                	jmp    1400029c0 <_gnu_exception_handler+0x236>
   1400029b6:	90                   	nop
   1400029b7:	eb 07                	jmp    1400029c0 <_gnu_exception_handler+0x236>
   1400029b9:	90                   	nop
   1400029ba:	eb 04                	jmp    1400029c0 <_gnu_exception_handler+0x236>
   1400029bc:	90                   	nop
   1400029bd:	eb 01                	jmp    1400029c0 <_gnu_exception_handler+0x236>
   1400029bf:	90                   	nop
   1400029c0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400029c4:	75 1f                	jne    1400029e5 <_gnu_exception_handler+0x25b>
   1400029c6:	48 8b 05 43 c7 00 00 	mov    rax,QWORD PTR [rip+0xc743]        # 14000f110 <__mingw_oldexcpt_handler>
   1400029cd:	48 85 c0             	test   rax,rax
   1400029d0:	74 13                	je     1400029e5 <_gnu_exception_handler+0x25b>
   1400029d2:	48 8b 15 37 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc737]        # 14000f110 <__mingw_oldexcpt_handler>
   1400029d9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400029dd:	48 89 c1             	mov    rcx,rax
   1400029e0:	ff d2                	call   rdx
   1400029e2:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400029e5:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400029e8:	48 83 c4 30          	add    rsp,0x30
   1400029ec:	5d                   	pop    rbp
   1400029ed:	c3                   	ret
   1400029ee:	90                   	nop
   1400029ef:	90                   	nop

00000001400029f0 <___w64_mingwthr_add_key_dtor>:
   1400029f0:	55                   	push   rbp
   1400029f1:	48 89 e5             	mov    rbp,rsp
   1400029f4:	48 83 ec 30          	sub    rsp,0x30
   1400029f8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400029fb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400029ff:	8b 05 43 c7 00 00    	mov    eax,DWORD PTR [rip+0xc743]        # 14000f148 <__mingwthr_cs_init>
   140002a05:	85 c0                	test   eax,eax
   140002a07:	75 07                	jne    140002a10 <___w64_mingwthr_add_key_dtor+0x20>
   140002a09:	b8 00 00 00 00       	mov    eax,0x0
   140002a0e:	eb 7b                	jmp    140002a8b <___w64_mingwthr_add_key_dtor+0x9b>
   140002a10:	ba 18 00 00 00       	mov    edx,0x18
   140002a15:	b9 01 00 00 00       	mov    ecx,0x1
   140002a1a:	e8 d9 6c 00 00       	call   1400096f8 <calloc>
   140002a1f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a23:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002a28:	75 07                	jne    140002a31 <___w64_mingwthr_add_key_dtor+0x41>
   140002a2a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140002a2f:	eb 5a                	jmp    140002a8b <___w64_mingwthr_add_key_dtor+0x9b>
   140002a31:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a35:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002a38:	89 10                	mov    DWORD PTR [rax],edx
   140002a3a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a3e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002a42:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002a46:	48 8d 05 d3 c6 00 00 	lea    rax,[rip+0xc6d3]        # 14000f120 <__mingwthr_cs>
   140002a4d:	48 89 c1             	mov    rcx,rax
   140002a50:	48 8b 05 99 d7 00 00 	mov    rax,QWORD PTR [rip+0xd799]        # 1400101f0 <__imp_EnterCriticalSection>
   140002a57:	ff d0                	call   rax
   140002a59:	48 8b 15 f0 c6 00 00 	mov    rdx,QWORD PTR [rip+0xc6f0]        # 14000f150 <key_dtor_list>
   140002a60:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a64:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a68:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a6c:	48 89 05 dd c6 00 00 	mov    QWORD PTR [rip+0xc6dd],rax        # 14000f150 <key_dtor_list>
   140002a73:	48 8d 05 a6 c6 00 00 	lea    rax,[rip+0xc6a6]        # 14000f120 <__mingwthr_cs>
   140002a7a:	48 89 c1             	mov    rcx,rax
   140002a7d:	48 8b 05 a4 d7 00 00 	mov    rax,QWORD PTR [rip+0xd7a4]        # 140010228 <__imp_LeaveCriticalSection>
   140002a84:	ff d0                	call   rax
   140002a86:	b8 00 00 00 00       	mov    eax,0x0
   140002a8b:	48 83 c4 30          	add    rsp,0x30
   140002a8f:	5d                   	pop    rbp
   140002a90:	c3                   	ret

0000000140002a91 <___w64_mingwthr_remove_key_dtor>:
   140002a91:	55                   	push   rbp
   140002a92:	48 89 e5             	mov    rbp,rsp
   140002a95:	48 83 ec 30          	sub    rsp,0x30
   140002a99:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002a9c:	8b 05 a6 c6 00 00    	mov    eax,DWORD PTR [rip+0xc6a6]        # 14000f148 <__mingwthr_cs_init>
   140002aa2:	85 c0                	test   eax,eax
   140002aa4:	75 0a                	jne    140002ab0 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002aa6:	b8 00 00 00 00       	mov    eax,0x0
   140002aab:	e9 9c 00 00 00       	jmp    140002b4c <___w64_mingwthr_remove_key_dtor+0xbb>
   140002ab0:	48 8d 05 69 c6 00 00 	lea    rax,[rip+0xc669]        # 14000f120 <__mingwthr_cs>
   140002ab7:	48 89 c1             	mov    rcx,rax
   140002aba:	48 8b 05 2f d7 00 00 	mov    rax,QWORD PTR [rip+0xd72f]        # 1400101f0 <__imp_EnterCriticalSection>
   140002ac1:	ff d0                	call   rax
   140002ac3:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002aca:	00 
   140002acb:	48 8b 05 7e c6 00 00 	mov    rax,QWORD PTR [rip+0xc67e]        # 14000f150 <key_dtor_list>
   140002ad2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002ad6:	eb 55                	jmp    140002b2d <___w64_mingwthr_remove_key_dtor+0x9c>
   140002ad8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002adc:	8b 00                	mov    eax,DWORD PTR [rax]
   140002ade:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002ae1:	75 36                	jne    140002b19 <___w64_mingwthr_remove_key_dtor+0x88>
   140002ae3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002ae8:	75 11                	jne    140002afb <___w64_mingwthr_remove_key_dtor+0x6a>
   140002aea:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aee:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002af2:	48 89 05 57 c6 00 00 	mov    QWORD PTR [rip+0xc657],rax        # 14000f150 <key_dtor_list>
   140002af9:	eb 10                	jmp    140002b0b <___w64_mingwthr_remove_key_dtor+0x7a>
   140002afb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aff:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002b03:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b07:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002b0b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b0f:	48 89 c1             	mov    rcx,rax
   140002b12:	e8 09 6c 00 00       	call   140009720 <free>
   140002b17:	eb 1b                	jmp    140002b34 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002b19:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b1d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b21:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b25:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b29:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b2d:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002b32:	75 a4                	jne    140002ad8 <___w64_mingwthr_remove_key_dtor+0x47>
   140002b34:	48 8d 05 e5 c5 00 00 	lea    rax,[rip+0xc5e5]        # 14000f120 <__mingwthr_cs>
   140002b3b:	48 89 c1             	mov    rcx,rax
   140002b3e:	48 8b 05 e3 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6e3]        # 140010228 <__imp_LeaveCriticalSection>
   140002b45:	ff d0                	call   rax
   140002b47:	b8 00 00 00 00       	mov    eax,0x0
   140002b4c:	48 83 c4 30          	add    rsp,0x30
   140002b50:	5d                   	pop    rbp
   140002b51:	c3                   	ret

0000000140002b52 <__mingwthr_run_key_dtors>:
   140002b52:	55                   	push   rbp
   140002b53:	48 89 e5             	mov    rbp,rsp
   140002b56:	48 83 ec 30          	sub    rsp,0x30
   140002b5a:	8b 05 e8 c5 00 00    	mov    eax,DWORD PTR [rip+0xc5e8]        # 14000f148 <__mingwthr_cs_init>
   140002b60:	85 c0                	test   eax,eax
   140002b62:	0f 84 82 00 00 00    	je     140002bea <__mingwthr_run_key_dtors+0x98>
   140002b68:	48 8d 05 b1 c5 00 00 	lea    rax,[rip+0xc5b1]        # 14000f120 <__mingwthr_cs>
   140002b6f:	48 89 c1             	mov    rcx,rax
   140002b72:	48 8b 05 77 d6 00 00 	mov    rax,QWORD PTR [rip+0xd677]        # 1400101f0 <__imp_EnterCriticalSection>
   140002b79:	ff d0                	call   rax
   140002b7b:	48 8b 05 ce c5 00 00 	mov    rax,QWORD PTR [rip+0xc5ce]        # 14000f150 <key_dtor_list>
   140002b82:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b86:	eb 46                	jmp    140002bce <__mingwthr_run_key_dtors+0x7c>
   140002b88:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b8c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002b8e:	89 c1                	mov    ecx,eax
   140002b90:	48 8b 05 b9 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6b9]        # 140010250 <__imp_TlsGetValue>
   140002b97:	ff d0                	call   rax
   140002b99:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b9d:	48 8b 05 64 d6 00 00 	mov    rax,QWORD PTR [rip+0xd664]        # 140010208 <__imp_GetLastError>
   140002ba4:	ff d0                	call   rax
   140002ba6:	85 c0                	test   eax,eax
   140002ba8:	75 18                	jne    140002bc2 <__mingwthr_run_key_dtors+0x70>
   140002baa:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002baf:	74 11                	je     140002bc2 <__mingwthr_run_key_dtors+0x70>
   140002bb1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002bb5:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002bb9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002bbd:	48 89 c1             	mov    rcx,rax
   140002bc0:	ff d2                	call   rdx
   140002bc2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002bc6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002bca:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002bce:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002bd3:	75 b3                	jne    140002b88 <__mingwthr_run_key_dtors+0x36>
   140002bd5:	48 8d 05 44 c5 00 00 	lea    rax,[rip+0xc544]        # 14000f120 <__mingwthr_cs>
   140002bdc:	48 89 c1             	mov    rcx,rax
   140002bdf:	48 8b 05 42 d6 00 00 	mov    rax,QWORD PTR [rip+0xd642]        # 140010228 <__imp_LeaveCriticalSection>
   140002be6:	ff d0                	call   rax
   140002be8:	eb 01                	jmp    140002beb <__mingwthr_run_key_dtors+0x99>
   140002bea:	90                   	nop
   140002beb:	48 83 c4 30          	add    rsp,0x30
   140002bef:	5d                   	pop    rbp
   140002bf0:	c3                   	ret

0000000140002bf1 <__mingw_TLScallback>:
   140002bf1:	55                   	push   rbp
   140002bf2:	48 89 e5             	mov    rbp,rsp
   140002bf5:	48 83 ec 30          	sub    rsp,0x30
   140002bf9:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002bfd:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002c00:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002c04:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002c08:	0f 84 cc 00 00 00    	je     140002cda <__mingw_TLScallback+0xe9>
   140002c0e:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002c12:	0f 87 ca 00 00 00    	ja     140002ce2 <__mingw_TLScallback+0xf1>
   140002c18:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002c1c:	0f 84 b1 00 00 00    	je     140002cd3 <__mingw_TLScallback+0xe2>
   140002c22:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002c26:	0f 87 b6 00 00 00    	ja     140002ce2 <__mingw_TLScallback+0xf1>
   140002c2c:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002c30:	74 33                	je     140002c65 <__mingw_TLScallback+0x74>
   140002c32:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002c36:	0f 85 a6 00 00 00    	jne    140002ce2 <__mingw_TLScallback+0xf1>
   140002c3c:	8b 05 06 c5 00 00    	mov    eax,DWORD PTR [rip+0xc506]        # 14000f148 <__mingwthr_cs_init>
   140002c42:	85 c0                	test   eax,eax
   140002c44:	75 13                	jne    140002c59 <__mingw_TLScallback+0x68>
   140002c46:	48 8d 05 d3 c4 00 00 	lea    rax,[rip+0xc4d3]        # 14000f120 <__mingwthr_cs>
   140002c4d:	48 89 c1             	mov    rcx,rax
   140002c50:	48 8b 05 c9 d5 00 00 	mov    rax,QWORD PTR [rip+0xd5c9]        # 140010220 <__imp_InitializeCriticalSection>
   140002c57:	ff d0                	call   rax
   140002c59:	c7 05 e5 c4 00 00 01 	mov    DWORD PTR [rip+0xc4e5],0x1        # 14000f148 <__mingwthr_cs_init>
   140002c60:	00 00 00 
   140002c63:	eb 7d                	jmp    140002ce2 <__mingw_TLScallback+0xf1>
   140002c65:	e8 e8 fe ff ff       	call   140002b52 <__mingwthr_run_key_dtors>
   140002c6a:	8b 05 d8 c4 00 00    	mov    eax,DWORD PTR [rip+0xc4d8]        # 14000f148 <__mingwthr_cs_init>
   140002c70:	83 f8 01             	cmp    eax,0x1
   140002c73:	75 6c                	jne    140002ce1 <__mingw_TLScallback+0xf0>
   140002c75:	48 8b 05 d4 c4 00 00 	mov    rax,QWORD PTR [rip+0xc4d4]        # 14000f150 <key_dtor_list>
   140002c7c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c80:	eb 20                	jmp    140002ca2 <__mingw_TLScallback+0xb1>
   140002c82:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c86:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c8a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c8e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c92:	48 89 c1             	mov    rcx,rax
   140002c95:	e8 86 6a 00 00       	call   140009720 <free>
   140002c9a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c9e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ca2:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002ca7:	75 d9                	jne    140002c82 <__mingw_TLScallback+0x91>
   140002ca9:	48 c7 05 9c c4 00 00 	mov    QWORD PTR [rip+0xc49c],0x0        # 14000f150 <key_dtor_list>
   140002cb0:	00 00 00 00 
   140002cb4:	c7 05 8a c4 00 00 00 	mov    DWORD PTR [rip+0xc48a],0x0        # 14000f148 <__mingwthr_cs_init>
   140002cbb:	00 00 00 
   140002cbe:	48 8d 05 5b c4 00 00 	lea    rax,[rip+0xc45b]        # 14000f120 <__mingwthr_cs>
   140002cc5:	48 89 c1             	mov    rcx,rax
   140002cc8:	48 8b 05 19 d5 00 00 	mov    rax,QWORD PTR [rip+0xd519]        # 1400101e8 <__IAT_start__>
   140002ccf:	ff d0                	call   rax
   140002cd1:	eb 0e                	jmp    140002ce1 <__mingw_TLScallback+0xf0>
   140002cd3:	e8 18 00 00 00       	call   140002cf0 <_fpreset>
   140002cd8:	eb 08                	jmp    140002ce2 <__mingw_TLScallback+0xf1>
   140002cda:	e8 73 fe ff ff       	call   140002b52 <__mingwthr_run_key_dtors>
   140002cdf:	eb 01                	jmp    140002ce2 <__mingw_TLScallback+0xf1>
   140002ce1:	90                   	nop
   140002ce2:	b8 01 00 00 00       	mov    eax,0x1
   140002ce7:	48 83 c4 30          	add    rsp,0x30
   140002ceb:	5d                   	pop    rbp
   140002cec:	c3                   	ret
   140002ced:	90                   	nop
   140002cee:	90                   	nop
   140002cef:	90                   	nop

0000000140002cf0 <_fpreset>:
   140002cf0:	55                   	push   rbp
   140002cf1:	48 89 e5             	mov    rbp,rsp
   140002cf4:	db e3                	fninit
   140002cf6:	90                   	nop
   140002cf7:	5d                   	pop    rbp
   140002cf8:	c3                   	ret
   140002cf9:	90                   	nop
   140002cfa:	90                   	nop
   140002cfb:	90                   	nop
   140002cfc:	90                   	nop
   140002cfd:	90                   	nop
   140002cfe:	90                   	nop
   140002cff:	90                   	nop

0000000140002d00 <_ValidateImageBase>:
   140002d00:	55                   	push   rbp
   140002d01:	48 89 e5             	mov    rbp,rsp
   140002d04:	48 83 ec 20          	sub    rsp,0x20
   140002d08:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d0c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d10:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d14:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d18:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002d1b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002d1f:	74 07                	je     140002d28 <_ValidateImageBase+0x28>
   140002d21:	b8 00 00 00 00       	mov    eax,0x0
   140002d26:	eb 4e                	jmp    140002d76 <_ValidateImageBase+0x76>
   140002d28:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d2c:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d2f:	48 63 d0             	movsxd rdx,eax
   140002d32:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d36:	48 01 d0             	add    rax,rdx
   140002d39:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002d3d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002d41:	8b 00                	mov    eax,DWORD PTR [rax]
   140002d43:	3d 50 45 00 00       	cmp    eax,0x4550
   140002d48:	74 07                	je     140002d51 <_ValidateImageBase+0x51>
   140002d4a:	b8 00 00 00 00       	mov    eax,0x0
   140002d4f:	eb 25                	jmp    140002d76 <_ValidateImageBase+0x76>
   140002d51:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002d55:	48 83 c0 18          	add    rax,0x18
   140002d59:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d5d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d61:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002d64:	66 3d 0b 02          	cmp    ax,0x20b
   140002d68:	74 07                	je     140002d71 <_ValidateImageBase+0x71>
   140002d6a:	b8 00 00 00 00       	mov    eax,0x0
   140002d6f:	eb 05                	jmp    140002d76 <_ValidateImageBase+0x76>
   140002d71:	b8 01 00 00 00       	mov    eax,0x1
   140002d76:	48 83 c4 20          	add    rsp,0x20
   140002d7a:	5d                   	pop    rbp
   140002d7b:	c3                   	ret

0000000140002d7c <_FindPESection>:
   140002d7c:	55                   	push   rbp
   140002d7d:	48 89 e5             	mov    rbp,rsp
   140002d80:	48 83 ec 20          	sub    rsp,0x20
   140002d84:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d88:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002d8c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d90:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d93:	48 63 d0             	movsxd rdx,eax
   140002d96:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d9a:	48 01 d0             	add    rax,rdx
   140002d9d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002da1:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002da8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dac:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002db0:	0f b7 d0             	movzx  edx,ax
   140002db3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002db7:	48 01 d0             	add    rax,rdx
   140002dba:	48 83 c0 18          	add    rax,0x18
   140002dbe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002dc2:	eb 36                	jmp    140002dfa <_FindPESection+0x7e>
   140002dc4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dc8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002dcb:	89 c0                	mov    eax,eax
   140002dcd:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002dd1:	72 1e                	jb     140002df1 <_FindPESection+0x75>
   140002dd3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dd7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002dda:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dde:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002de1:	01 d0                	add    eax,edx
   140002de3:	89 c0                	mov    eax,eax
   140002de5:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002de9:	73 06                	jae    140002df1 <_FindPESection+0x75>
   140002deb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002def:	eb 1e                	jmp    140002e0f <_FindPESection+0x93>
   140002df1:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002df5:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002dfa:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dfe:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e02:	0f b7 c0             	movzx  eax,ax
   140002e05:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002e08:	72 ba                	jb     140002dc4 <_FindPESection+0x48>
   140002e0a:	b8 00 00 00 00       	mov    eax,0x0
   140002e0f:	48 83 c4 20          	add    rsp,0x20
   140002e13:	5d                   	pop    rbp
   140002e14:	c3                   	ret

0000000140002e15 <_FindPESectionByName>:
   140002e15:	55                   	push   rbp
   140002e16:	48 89 e5             	mov    rbp,rsp
   140002e19:	48 83 ec 40          	sub    rsp,0x40
   140002e1d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e21:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e25:	48 89 c1             	mov    rcx,rax
   140002e28:	e8 2b 69 00 00       	call   140009758 <strlen>
   140002e2d:	48 83 f8 08          	cmp    rax,0x8
   140002e31:	76 0a                	jbe    140002e3d <_FindPESectionByName+0x28>
   140002e33:	b8 00 00 00 00       	mov    eax,0x0
   140002e38:	e9 98 00 00 00       	jmp    140002ed5 <_FindPESectionByName+0xc0>
   140002e3d:	48 8b 05 3c 87 00 00 	mov    rax,QWORD PTR [rip+0x873c]        # 14000b580 <.refptr.__ImageBase>
   140002e44:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002e48:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e4c:	48 89 c1             	mov    rcx,rax
   140002e4f:	e8 ac fe ff ff       	call   140002d00 <_ValidateImageBase>
   140002e54:	85 c0                	test   eax,eax
   140002e56:	75 07                	jne    140002e5f <_FindPESectionByName+0x4a>
   140002e58:	b8 00 00 00 00       	mov    eax,0x0
   140002e5d:	eb 76                	jmp    140002ed5 <_FindPESectionByName+0xc0>
   140002e5f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e63:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e66:	48 63 d0             	movsxd rdx,eax
   140002e69:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e6d:	48 01 d0             	add    rax,rdx
   140002e70:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002e74:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002e7b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e7f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002e83:	0f b7 d0             	movzx  edx,ax
   140002e86:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e8a:	48 01 d0             	add    rax,rdx
   140002e8d:	48 83 c0 18          	add    rax,0x18
   140002e91:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e95:	eb 29                	jmp    140002ec0 <_FindPESectionByName+0xab>
   140002e97:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e9b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002e9f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002ea5:	48 89 c1             	mov    rcx,rax
   140002ea8:	e8 b3 68 00 00       	call   140009760 <strncmp>
   140002ead:	85 c0                	test   eax,eax
   140002eaf:	75 06                	jne    140002eb7 <_FindPESectionByName+0xa2>
   140002eb1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002eb5:	eb 1e                	jmp    140002ed5 <_FindPESectionByName+0xc0>
   140002eb7:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002ebb:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002ec0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002ec4:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002ec8:	0f b7 c0             	movzx  eax,ax
   140002ecb:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002ece:	72 c7                	jb     140002e97 <_FindPESectionByName+0x82>
   140002ed0:	b8 00 00 00 00       	mov    eax,0x0
   140002ed5:	48 83 c4 40          	add    rsp,0x40
   140002ed9:	5d                   	pop    rbp
   140002eda:	c3                   	ret

0000000140002edb <__mingw_GetSectionForAddress>:
   140002edb:	55                   	push   rbp
   140002edc:	48 89 e5             	mov    rbp,rsp
   140002edf:	48 83 ec 30          	sub    rsp,0x30
   140002ee3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002ee7:	48 8b 05 92 86 00 00 	mov    rax,QWORD PTR [rip+0x8692]        # 14000b580 <.refptr.__ImageBase>
   140002eee:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ef2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ef6:	48 89 c1             	mov    rcx,rax
   140002ef9:	e8 02 fe ff ff       	call   140002d00 <_ValidateImageBase>
   140002efe:	85 c0                	test   eax,eax
   140002f00:	75 07                	jne    140002f09 <__mingw_GetSectionForAddress+0x2e>
   140002f02:	b8 00 00 00 00       	mov    eax,0x0
   140002f07:	eb 1c                	jmp    140002f25 <__mingw_GetSectionForAddress+0x4a>
   140002f09:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002f0d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002f11:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002f15:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002f19:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f1d:	48 89 c1             	mov    rcx,rax
   140002f20:	e8 57 fe ff ff       	call   140002d7c <_FindPESection>
   140002f25:	48 83 c4 30          	add    rsp,0x30
   140002f29:	5d                   	pop    rbp
   140002f2a:	c3                   	ret

0000000140002f2b <__mingw_GetSectionCount>:
   140002f2b:	55                   	push   rbp
   140002f2c:	48 89 e5             	mov    rbp,rsp
   140002f2f:	48 83 ec 30          	sub    rsp,0x30
   140002f33:	48 8b 05 46 86 00 00 	mov    rax,QWORD PTR [rip+0x8646]        # 14000b580 <.refptr.__ImageBase>
   140002f3a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f3e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f42:	48 89 c1             	mov    rcx,rax
   140002f45:	e8 b6 fd ff ff       	call   140002d00 <_ValidateImageBase>
   140002f4a:	85 c0                	test   eax,eax
   140002f4c:	75 07                	jne    140002f55 <__mingw_GetSectionCount+0x2a>
   140002f4e:	b8 00 00 00 00       	mov    eax,0x0
   140002f53:	eb 20                	jmp    140002f75 <__mingw_GetSectionCount+0x4a>
   140002f55:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f59:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f5c:	48 63 d0             	movsxd rdx,eax
   140002f5f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f63:	48 01 d0             	add    rax,rdx
   140002f66:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002f6a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002f6e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f72:	0f b7 c0             	movzx  eax,ax
   140002f75:	48 83 c4 30          	add    rsp,0x30
   140002f79:	5d                   	pop    rbp
   140002f7a:	c3                   	ret

0000000140002f7b <_FindPESectionExec>:
   140002f7b:	55                   	push   rbp
   140002f7c:	48 89 e5             	mov    rbp,rsp
   140002f7f:	48 83 ec 40          	sub    rsp,0x40
   140002f83:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f87:	48 8b 05 f2 85 00 00 	mov    rax,QWORD PTR [rip+0x85f2]        # 14000b580 <.refptr.__ImageBase>
   140002f8e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002f92:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f96:	48 89 c1             	mov    rcx,rax
   140002f99:	e8 62 fd ff ff       	call   140002d00 <_ValidateImageBase>
   140002f9e:	85 c0                	test   eax,eax
   140002fa0:	75 07                	jne    140002fa9 <_FindPESectionExec+0x2e>
   140002fa2:	b8 00 00 00 00       	mov    eax,0x0
   140002fa7:	eb 78                	jmp    140003021 <_FindPESectionExec+0xa6>
   140002fa9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002fad:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002fb0:	48 63 d0             	movsxd rdx,eax
   140002fb3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002fb7:	48 01 d0             	add    rax,rdx
   140002fba:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002fbe:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002fc5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002fc9:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002fcd:	0f b7 d0             	movzx  edx,ax
   140002fd0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002fd4:	48 01 d0             	add    rax,rdx
   140002fd7:	48 83 c0 18          	add    rax,0x18
   140002fdb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fdf:	eb 2b                	jmp    14000300c <_FindPESectionExec+0x91>
   140002fe1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fe5:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002fe8:	25 00 00 00 20       	and    eax,0x20000000
   140002fed:	85 c0                	test   eax,eax
   140002fef:	74 12                	je     140003003 <_FindPESectionExec+0x88>
   140002ff1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002ff6:	75 06                	jne    140002ffe <_FindPESectionExec+0x83>
   140002ff8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ffc:	eb 23                	jmp    140003021 <_FindPESectionExec+0xa6>
   140002ffe:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140003003:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140003007:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   14000300c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003010:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140003014:	0f b7 c0             	movzx  eax,ax
   140003017:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   14000301a:	72 c5                	jb     140002fe1 <_FindPESectionExec+0x66>
   14000301c:	b8 00 00 00 00       	mov    eax,0x0
   140003021:	48 83 c4 40          	add    rsp,0x40
   140003025:	5d                   	pop    rbp
   140003026:	c3                   	ret

0000000140003027 <_GetPEImageBase>:
   140003027:	55                   	push   rbp
   140003028:	48 89 e5             	mov    rbp,rsp
   14000302b:	48 83 ec 30          	sub    rsp,0x30
   14000302f:	48 8b 05 4a 85 00 00 	mov    rax,QWORD PTR [rip+0x854a]        # 14000b580 <.refptr.__ImageBase>
   140003036:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000303a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000303e:	48 89 c1             	mov    rcx,rax
   140003041:	e8 ba fc ff ff       	call   140002d00 <_ValidateImageBase>
   140003046:	85 c0                	test   eax,eax
   140003048:	75 07                	jne    140003051 <_GetPEImageBase+0x2a>
   14000304a:	b8 00 00 00 00       	mov    eax,0x0
   14000304f:	eb 04                	jmp    140003055 <_GetPEImageBase+0x2e>
   140003051:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003055:	48 83 c4 30          	add    rsp,0x30
   140003059:	5d                   	pop    rbp
   14000305a:	c3                   	ret

000000014000305b <_IsNonwritableInCurrentImage>:
   14000305b:	55                   	push   rbp
   14000305c:	48 89 e5             	mov    rbp,rsp
   14000305f:	48 83 ec 40          	sub    rsp,0x40
   140003063:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003067:	48 8b 05 12 85 00 00 	mov    rax,QWORD PTR [rip+0x8512]        # 14000b580 <.refptr.__ImageBase>
   14000306e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003072:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003076:	48 89 c1             	mov    rcx,rax
   140003079:	e8 82 fc ff ff       	call   140002d00 <_ValidateImageBase>
   14000307e:	85 c0                	test   eax,eax
   140003080:	75 07                	jne    140003089 <_IsNonwritableInCurrentImage+0x2e>
   140003082:	b8 00 00 00 00       	mov    eax,0x0
   140003087:	eb 3d                	jmp    1400030c6 <_IsNonwritableInCurrentImage+0x6b>
   140003089:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000308d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140003091:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003095:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003099:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000309d:	48 89 c1             	mov    rcx,rax
   1400030a0:	e8 d7 fc ff ff       	call   140002d7c <_FindPESection>
   1400030a5:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400030a9:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   1400030ae:	75 07                	jne    1400030b7 <_IsNonwritableInCurrentImage+0x5c>
   1400030b0:	b8 00 00 00 00       	mov    eax,0x0
   1400030b5:	eb 0f                	jmp    1400030c6 <_IsNonwritableInCurrentImage+0x6b>
   1400030b7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400030bb:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400030be:	f7 d0                	not    eax
   1400030c0:	c1 e8 1f             	shr    eax,0x1f
   1400030c3:	0f b6 c0             	movzx  eax,al
   1400030c6:	48 83 c4 40          	add    rsp,0x40
   1400030ca:	5d                   	pop    rbp
   1400030cb:	c3                   	ret

00000001400030cc <__mingw_enum_import_library_names>:
   1400030cc:	55                   	push   rbp
   1400030cd:	48 89 e5             	mov    rbp,rsp
   1400030d0:	48 83 ec 50          	sub    rsp,0x50
   1400030d4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400030d7:	48 8b 05 a2 84 00 00 	mov    rax,QWORD PTR [rip+0x84a2]        # 14000b580 <.refptr.__ImageBase>
   1400030de:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400030e2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030e6:	48 89 c1             	mov    rcx,rax
   1400030e9:	e8 12 fc ff ff       	call   140002d00 <_ValidateImageBase>
   1400030ee:	85 c0                	test   eax,eax
   1400030f0:	75 0a                	jne    1400030fc <__mingw_enum_import_library_names+0x30>
   1400030f2:	b8 00 00 00 00       	mov    eax,0x0
   1400030f7:	e9 ab 00 00 00       	jmp    1400031a7 <__mingw_enum_import_library_names+0xdb>
   1400030fc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003100:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140003103:	48 63 d0             	movsxd rdx,eax
   140003106:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000310a:	48 01 d0             	add    rax,rdx
   14000310d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003111:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003115:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000311b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000311e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140003122:	75 07                	jne    14000312b <__mingw_enum_import_library_names+0x5f>
   140003124:	b8 00 00 00 00       	mov    eax,0x0
   140003129:	eb 7c                	jmp    1400031a7 <__mingw_enum_import_library_names+0xdb>
   14000312b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000312e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003132:	48 89 c1             	mov    rcx,rax
   140003135:	e8 42 fc ff ff       	call   140002d7c <_FindPESection>
   14000313a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000313e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003143:	75 07                	jne    14000314c <__mingw_enum_import_library_names+0x80>
   140003145:	b8 00 00 00 00       	mov    eax,0x0
   14000314a:	eb 5b                	jmp    1400031a7 <__mingw_enum_import_library_names+0xdb>
   14000314c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000314f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003153:	48 01 d0             	add    rax,rdx
   140003156:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000315a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000315f:	75 07                	jne    140003168 <__mingw_enum_import_library_names+0x9c>
   140003161:	b8 00 00 00 00       	mov    eax,0x0
   140003166:	eb 3f                	jmp    1400031a7 <__mingw_enum_import_library_names+0xdb>
   140003168:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000316c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000316f:	85 c0                	test   eax,eax
   140003171:	75 0b                	jne    14000317e <__mingw_enum_import_library_names+0xb2>
   140003173:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003177:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000317a:	85 c0                	test   eax,eax
   14000317c:	74 23                	je     1400031a1 <__mingw_enum_import_library_names+0xd5>
   14000317e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003182:	7f 12                	jg     140003196 <__mingw_enum_import_library_names+0xca>
   140003184:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003188:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000318b:	89 c2                	mov    edx,eax
   14000318d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003191:	48 01 d0             	add    rax,rdx
   140003194:	eb 11                	jmp    1400031a7 <__mingw_enum_import_library_names+0xdb>
   140003196:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000319a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000319f:	eb c7                	jmp    140003168 <__mingw_enum_import_library_names+0x9c>
   1400031a1:	90                   	nop
   1400031a2:	b8 00 00 00 00       	mov    eax,0x0
   1400031a7:	48 83 c4 50          	add    rsp,0x50
   1400031ab:	5d                   	pop    rbp
   1400031ac:	c3                   	ret
   1400031ad:	90                   	nop
   1400031ae:	90                   	nop
   1400031af:	90                   	nop

00000001400031b0 <___chkstk_ms>:
   1400031b0:	51                   	push   rcx
   1400031b1:	50                   	push   rax
   1400031b2:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400031b8:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   1400031bd:	72 19                	jb     1400031d8 <___chkstk_ms+0x28>
   1400031bf:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   1400031c6:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400031ca:	48 2d 00 10 00 00    	sub    rax,0x1000
   1400031d0:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400031d6:	77 e7                	ja     1400031bf <___chkstk_ms+0xf>
   1400031d8:	48 29 c1             	sub    rcx,rax
   1400031db:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400031df:	58                   	pop    rax
   1400031e0:	59                   	pop    rcx
   1400031e1:	c3                   	ret
   1400031e2:	90                   	nop
   1400031e3:	90                   	nop
   1400031e4:	90                   	nop
   1400031e5:	90                   	nop
   1400031e6:	90                   	nop
   1400031e7:	90                   	nop
   1400031e8:	90                   	nop
   1400031e9:	90                   	nop
   1400031ea:	90                   	nop
   1400031eb:	90                   	nop
   1400031ec:	90                   	nop
   1400031ed:	90                   	nop
   1400031ee:	90                   	nop
   1400031ef:	90                   	nop

00000001400031f0 <__mingw_printf>:
   1400031f0:	55                   	push   rbp
   1400031f1:	53                   	push   rbx
   1400031f2:	48 83 ec 48          	sub    rsp,0x48
   1400031f6:	48 8d 6c 24 40       	lea    rbp,[rsp+0x40]
   1400031fb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   1400031ff:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140003203:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003207:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   14000320b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   14000320f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003213:	b9 01 00 00 00       	mov    ecx,0x1
   140003218:	e8 c3 5e 00 00       	call   1400090e0 <__acrt_iob_func>
   14000321d:	48 89 c1             	mov    rcx,rax
   140003220:	e8 3b 5d 00 00       	call   140008f60 <_lock_file>
   140003225:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140003229:	b9 01 00 00 00       	mov    ecx,0x1
   14000322e:	e8 ad 5e 00 00       	call   1400090e0 <__acrt_iob_func>
   140003233:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003237:	48 89 5c 24 20       	mov    QWORD PTR [rsp+0x20],rbx
   14000323c:	49 89 d1             	mov    r9,rdx
   14000323f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140003245:	48 89 c2             	mov    rdx,rax
   140003248:	b9 00 60 00 00       	mov    ecx,0x6000
   14000324d:	e8 b1 1f 00 00       	call   140005203 <__mingw_pformat>
   140003252:	89 c3                	mov    ebx,eax
   140003254:	b9 01 00 00 00       	mov    ecx,0x1
   140003259:	e8 82 5e 00 00       	call   1400090e0 <__acrt_iob_func>
   14000325e:	48 89 c1             	mov    rcx,rax
   140003261:	e8 84 5d 00 00       	call   140008fea <_unlock_file>
   140003266:	89 d8                	mov    eax,ebx
   140003268:	48 83 c4 48          	add    rsp,0x48
   14000326c:	5b                   	pop    rbx
   14000326d:	5d                   	pop    rbp
   14000326e:	c3                   	ret
   14000326f:	90                   	nop

0000000140003270 <__pformat_putc>:
   140003270:	55                   	push   rbp
   140003271:	48 89 e5             	mov    rbp,rsp
   140003274:	48 83 ec 20          	sub    rsp,0x20
   140003278:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000327b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000327f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003283:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003286:	25 00 40 00 00       	and    eax,0x4000
   14000328b:	85 c0                	test   eax,eax
   14000328d:	75 12                	jne    1400032a1 <__pformat_putc+0x31>
   14000328f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003293:	8b 50 28             	mov    edx,DWORD PTR [rax+0x28]
   140003296:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000329a:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000329d:	39 c2                	cmp    edx,eax
   14000329f:	7e 3b                	jle    1400032dc <__pformat_putc+0x6c>
   1400032a1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032a5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400032a8:	25 00 20 00 00       	and    eax,0x2000
   1400032ad:	85 c0                	test   eax,eax
   1400032af:	74 13                	je     1400032c4 <__pformat_putc+0x54>
   1400032b1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032b5:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   1400032b8:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400032bb:	89 c1                	mov    ecx,eax
   1400032bd:	e8 56 64 00 00       	call   140009718 <fputc>
   1400032c2:	eb 18                	jmp    1400032dc <__pformat_putc+0x6c>
   1400032c4:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032c8:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   1400032cb:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032cf:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400032d2:	48 98                	cdqe
   1400032d4:	48 01 d0             	add    rax,rdx
   1400032d7:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400032da:	88 10                	mov    BYTE PTR [rax],dl
   1400032dc:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032e0:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400032e3:	8d 50 01             	lea    edx,[rax+0x1]
   1400032e6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032ea:	89 50 24             	mov    DWORD PTR [rax+0x24],edx
   1400032ed:	90                   	nop
   1400032ee:	48 83 c4 20          	add    rsp,0x20
   1400032f2:	5d                   	pop    rbp
   1400032f3:	c3                   	ret

00000001400032f4 <__pformat_putchars>:
   1400032f4:	55                   	push   rbp
   1400032f5:	48 89 e5             	mov    rbp,rsp
   1400032f8:	48 83 ec 20          	sub    rsp,0x20
   1400032fc:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003300:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003303:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140003307:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000330b:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000330e:	85 c0                	test   eax,eax
   140003310:	78 16                	js     140003328 <__pformat_putchars+0x34>
   140003312:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003316:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003319:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   14000331c:	7e 0a                	jle    140003328 <__pformat_putchars+0x34>
   14000331e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003322:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003325:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   140003328:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000332c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000332f:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003332:	7d 15                	jge    140003349 <__pformat_putchars+0x55>
   140003334:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003338:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000333b:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000333e:	89 c2                	mov    edx,eax
   140003340:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003344:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003347:	eb 0b                	jmp    140003354 <__pformat_putchars+0x60>
   140003349:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000334d:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003354:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003358:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000335b:	85 c0                	test   eax,eax
   14000335d:	7e 57                	jle    1400033b6 <__pformat_putchars+0xc2>
   14000335f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003363:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003366:	25 00 04 00 00       	and    eax,0x400
   14000336b:	85 c0                	test   eax,eax
   14000336d:	75 47                	jne    1400033b6 <__pformat_putchars+0xc2>
   14000336f:	eb 11                	jmp    140003382 <__pformat_putchars+0x8e>
   140003371:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003375:	48 89 c2             	mov    rdx,rax
   140003378:	b9 20 00 00 00       	mov    ecx,0x20
   14000337d:	e8 ee fe ff ff       	call   140003270 <__pformat_putc>
   140003382:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003386:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003389:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000338c:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003390:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003393:	85 c0                	test   eax,eax
   140003395:	75 da                	jne    140003371 <__pformat_putchars+0x7d>
   140003397:	eb 1d                	jmp    1400033b6 <__pformat_putchars+0xc2>
   140003399:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000339d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400033a1:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   1400033a5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400033a8:	0f be c0             	movsx  eax,al
   1400033ab:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400033af:	89 c1                	mov    ecx,eax
   1400033b1:	e8 ba fe ff ff       	call   140003270 <__pformat_putc>
   1400033b6:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400033b9:	8d 50 ff             	lea    edx,[rax-0x1]
   1400033bc:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400033bf:	85 c0                	test   eax,eax
   1400033c1:	75 d6                	jne    140003399 <__pformat_putchars+0xa5>
   1400033c3:	eb 11                	jmp    1400033d6 <__pformat_putchars+0xe2>
   1400033c5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033c9:	48 89 c2             	mov    rdx,rax
   1400033cc:	b9 20 00 00 00       	mov    ecx,0x20
   1400033d1:	e8 9a fe ff ff       	call   140003270 <__pformat_putc>
   1400033d6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033da:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400033dd:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400033e0:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400033e4:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400033e7:	85 c0                	test   eax,eax
   1400033e9:	7f da                	jg     1400033c5 <__pformat_putchars+0xd1>
   1400033eb:	90                   	nop
   1400033ec:	90                   	nop
   1400033ed:	48 83 c4 20          	add    rsp,0x20
   1400033f1:	5d                   	pop    rbp
   1400033f2:	c3                   	ret

00000001400033f3 <__pformat_puts>:
   1400033f3:	55                   	push   rbp
   1400033f4:	48 89 e5             	mov    rbp,rsp
   1400033f7:	48 83 ec 20          	sub    rsp,0x20
   1400033fb:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400033ff:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003403:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140003408:	75 0b                	jne    140003415 <__pformat_puts+0x22>
   14000340a:	48 8d 05 1f 7f 00 00 	lea    rax,[rip+0x7f1f]        # 14000b330 <.rdata>
   140003411:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140003415:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003419:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000341c:	85 c0                	test   eax,eax
   14000341e:	78 2f                	js     14000344f <__pformat_puts+0x5c>
   140003420:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003424:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003427:	48 63 d0             	movsxd rdx,eax
   14000342a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000342e:	48 89 c1             	mov    rcx,rax
   140003431:	e8 4a 5a 00 00       	call   140008e80 <strnlen>
   140003436:	89 c1                	mov    ecx,eax
   140003438:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000343c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003440:	49 89 d0             	mov    r8,rdx
   140003443:	89 ca                	mov    edx,ecx
   140003445:	48 89 c1             	mov    rcx,rax
   140003448:	e8 a7 fe ff ff       	call   1400032f4 <__pformat_putchars>
   14000344d:	eb 23                	jmp    140003472 <__pformat_puts+0x7f>
   14000344f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003453:	48 89 c1             	mov    rcx,rax
   140003456:	e8 fd 62 00 00       	call   140009758 <strlen>
   14000345b:	89 c1                	mov    ecx,eax
   14000345d:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003461:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003465:	49 89 d0             	mov    r8,rdx
   140003468:	89 ca                	mov    edx,ecx
   14000346a:	48 89 c1             	mov    rcx,rax
   14000346d:	e8 82 fe ff ff       	call   1400032f4 <__pformat_putchars>
   140003472:	90                   	nop
   140003473:	48 83 c4 20          	add    rsp,0x20
   140003477:	5d                   	pop    rbp
   140003478:	c3                   	ret

0000000140003479 <__pformat_wputchars>:
   140003479:	55                   	push   rbp
   14000347a:	48 89 e5             	mov    rbp,rsp
   14000347d:	48 83 ec 50          	sub    rsp,0x50
   140003481:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003485:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003488:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000348c:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   140003493:	00 
   140003494:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003498:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000349b:	85 c0                	test   eax,eax
   14000349d:	78 16                	js     1400034b5 <__pformat_wputchars+0x3c>
   14000349f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034a3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400034a6:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400034a9:	7e 0a                	jle    1400034b5 <__pformat_wputchars+0x3c>
   1400034ab:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034af:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400034b2:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   1400034b5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034b9:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400034bc:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400034bf:	7d 15                	jge    1400034d6 <__pformat_wputchars+0x5d>
   1400034c1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034c5:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400034c8:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400034cb:	89 c2                	mov    edx,eax
   1400034cd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034d1:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400034d4:	eb 0b                	jmp    1400034e1 <__pformat_wputchars+0x68>
   1400034d6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034da:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400034e1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034e5:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400034e8:	85 c0                	test   eax,eax
   1400034ea:	7e 6e                	jle    14000355a <__pformat_wputchars+0xe1>
   1400034ec:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034f0:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400034f3:	25 00 04 00 00       	and    eax,0x400
   1400034f8:	85 c0                	test   eax,eax
   1400034fa:	75 5e                	jne    14000355a <__pformat_wputchars+0xe1>
   1400034fc:	eb 11                	jmp    14000350f <__pformat_wputchars+0x96>
   1400034fe:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003502:	48 89 c2             	mov    rdx,rax
   140003505:	b9 20 00 00 00       	mov    ecx,0x20
   14000350a:	e8 61 fd ff ff       	call   140003270 <__pformat_putc>
   14000350f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003513:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003516:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003519:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000351d:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003520:	85 c0                	test   eax,eax
   140003522:	75 da                	jne    1400034fe <__pformat_wputchars+0x85>
   140003524:	eb 34                	jmp    14000355a <__pformat_wputchars+0xe1>
   140003526:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   14000352a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000352e:	eb 1d                	jmp    14000354d <__pformat_wputchars+0xd4>
   140003530:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003534:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003538:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000353c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000353f:	0f be c0             	movsx  eax,al
   140003542:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003546:	89 c1                	mov    ecx,eax
   140003548:	e8 23 fd ff ff       	call   140003270 <__pformat_putc>
   14000354d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003550:	8d 50 ff             	lea    edx,[rax-0x1]
   140003553:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003556:	85 c0                	test   eax,eax
   140003558:	7f d6                	jg     140003530 <__pformat_wputchars+0xb7>
   14000355a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000355d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003560:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003563:	85 c0                	test   eax,eax
   140003565:	7e 41                	jle    1400035a8 <__pformat_wputchars+0x12f>
   140003567:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000356b:	48 8d 50 02          	lea    rdx,[rax+0x2]
   14000356f:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003573:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140003576:	48 8d 4d d8          	lea    rcx,[rbp-0x28]
   14000357a:	0f b7 d0             	movzx  edx,ax
   14000357d:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003581:	49 89 c8             	mov    r8,rcx
   140003584:	48 89 c1             	mov    rcx,rax
   140003587:	e8 84 5b 00 00       	call   140009110 <wcrtomb>
   14000358c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000358f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003593:	7f 91                	jg     140003526 <__pformat_wputchars+0xad>
   140003595:	eb 11                	jmp    1400035a8 <__pformat_wputchars+0x12f>
   140003597:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000359b:	48 89 c2             	mov    rdx,rax
   14000359e:	b9 20 00 00 00       	mov    ecx,0x20
   1400035a3:	e8 c8 fc ff ff       	call   140003270 <__pformat_putc>
   1400035a8:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400035ac:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400035af:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400035b2:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400035b6:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400035b9:	85 c0                	test   eax,eax
   1400035bb:	7f da                	jg     140003597 <__pformat_wputchars+0x11e>
   1400035bd:	90                   	nop
   1400035be:	90                   	nop
   1400035bf:	48 83 c4 50          	add    rsp,0x50
   1400035c3:	5d                   	pop    rbp
   1400035c4:	c3                   	ret

00000001400035c5 <__pformat_wcputs>:
   1400035c5:	55                   	push   rbp
   1400035c6:	48 89 e5             	mov    rbp,rsp
   1400035c9:	48 83 ec 20          	sub    rsp,0x20
   1400035cd:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400035d1:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400035d5:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400035da:	75 0b                	jne    1400035e7 <__pformat_wcputs+0x22>
   1400035dc:	48 8d 05 55 7d 00 00 	lea    rax,[rip+0x7d55]        # 14000b338 <.rdata+0x8>
   1400035e3:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400035e7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400035eb:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400035ee:	85 c0                	test   eax,eax
   1400035f0:	78 2f                	js     140003621 <__pformat_wcputs+0x5c>
   1400035f2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400035f6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400035f9:	48 63 d0             	movsxd rdx,eax
   1400035fc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003600:	48 89 c1             	mov    rcx,rax
   140003603:	e8 28 58 00 00       	call   140008e30 <wcsnlen>
   140003608:	89 c1                	mov    ecx,eax
   14000360a:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000360e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003612:	49 89 d0             	mov    r8,rdx
   140003615:	89 ca                	mov    edx,ecx
   140003617:	48 89 c1             	mov    rcx,rax
   14000361a:	e8 5a fe ff ff       	call   140003479 <__pformat_wputchars>
   14000361f:	eb 23                	jmp    140003644 <__pformat_wcputs+0x7f>
   140003621:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003625:	48 89 c1             	mov    rcx,rax
   140003628:	e8 43 61 00 00       	call   140009770 <wcslen>
   14000362d:	89 c1                	mov    ecx,eax
   14000362f:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003633:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003637:	49 89 d0             	mov    r8,rdx
   14000363a:	89 ca                	mov    edx,ecx
   14000363c:	48 89 c1             	mov    rcx,rax
   14000363f:	e8 35 fe ff ff       	call   140003479 <__pformat_wputchars>
   140003644:	90                   	nop
   140003645:	48 83 c4 20          	add    rsp,0x20
   140003649:	5d                   	pop    rbp
   14000364a:	c3                   	ret

000000014000364b <__pformat_int_bufsiz>:
   14000364b:	55                   	push   rbp
   14000364c:	48 89 e5             	mov    rbp,rsp
   14000364f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003652:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003655:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140003659:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000365c:	83 e8 01             	sub    eax,0x1
   14000365f:	48 98                	cdqe
   140003661:	48 83 c0 40          	add    rax,0x40
   140003665:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140003668:	48 63 ca             	movsxd rcx,edx
   14000366b:	ba 00 00 00 00       	mov    edx,0x0
   140003670:	48 f7 f1             	div    rcx
   140003673:	89 c2                	mov    edx,eax
   140003675:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140003678:	01 d0                	add    eax,edx
   14000367a:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   14000367d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003681:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003684:	ba 00 00 00 00       	mov    edx,0x0
   140003689:	85 c0                	test   eax,eax
   14000368b:	0f 48 c2             	cmovs  eax,edx
   14000368e:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   140003691:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003695:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003698:	25 00 10 00 00       	and    eax,0x1000
   14000369d:	85 c0                	test   eax,eax
   14000369f:	74 29                	je     1400036ca <__pformat_int_bufsiz+0x7f>
   1400036a1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400036a5:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400036a9:	66 85 c0             	test   ax,ax
   1400036ac:	74 1c                	je     1400036ca <__pformat_int_bufsiz+0x7f>
   1400036ae:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400036b1:	48 63 d0             	movsxd rdx,eax
   1400036b4:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   1400036bb:	48 89 d1             	mov    rcx,rdx
   1400036be:	48 c1 e9 20          	shr    rcx,0x20
   1400036c2:	99                   	cdq
   1400036c3:	89 c8                	mov    eax,ecx
   1400036c5:	29 d0                	sub    eax,edx
   1400036c7:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   1400036ca:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400036ce:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400036d1:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400036d4:	39 c2                	cmp    edx,eax
   1400036d6:	0f 4d c2             	cmovge eax,edx
   1400036d9:	5d                   	pop    rbp
   1400036da:	c3                   	ret

00000001400036db <__pformat_int>:
   1400036db:	55                   	push   rbp
   1400036dc:	53                   	push   rbx
   1400036dd:	48 83 ec 58          	sub    rsp,0x58
   1400036e1:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400036e6:	48 89 cb             	mov    rbx,rcx
   1400036e9:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
   1400036ec:	48 8b 5b 08          	mov    rbx,QWORD PTR [rbx+0x8]
   1400036f0:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
   1400036f4:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
   1400036f8:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400036fc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003700:	49 89 c0             	mov    r8,rax
   140003703:	ba 03 00 00 00       	mov    edx,0x3
   140003708:	b9 01 00 00 00       	mov    ecx,0x1
   14000370d:	e8 39 ff ff ff       	call   14000364b <__pformat_int_bufsiz>
   140003712:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140003715:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
   14000371c:	00 
   14000371d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140003720:	48 98                	cdqe
   140003722:	48 83 c0 0f          	add    rax,0xf
   140003726:	48 c1 e8 04          	shr    rax,0x4
   14000372a:	48 c1 e0 04          	shl    rax,0x4
   14000372e:	e8 7d fa ff ff       	call   1400031b0 <___chkstk_ms>
   140003733:	48 29 c4             	sub    rsp,rax
   140003736:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000373b:	48 83 c0 0f          	add    rax,0xf
   14000373f:	48 c1 e8 04          	shr    rax,0x4
   140003743:	48 c1 e0 04          	shl    rax,0x4
   140003747:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000374b:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000374f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003753:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003757:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000375a:	25 80 00 00 00       	and    eax,0x80
   14000375f:	85 c0                	test   eax,eax
   140003761:	0f 84 ea 00 00 00    	je     140003851 <__pformat_int+0x176>
   140003767:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000376b:	48 85 c0             	test   rax,rax
   14000376e:	79 10                	jns    140003780 <__pformat_int+0xa5>
   140003770:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003774:	48 f7 d8             	neg    rax
   140003777:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000377b:	e9 d1 00 00 00       	jmp    140003851 <__pformat_int+0x176>
   140003780:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003784:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003787:	24 7f                	and    al,0x7f
   140003789:	89 c2                	mov    edx,eax
   14000378b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000378f:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003792:	e9 ba 00 00 00       	jmp    140003851 <__pformat_int+0x176>
   140003797:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000379b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000379f:	74 54                	je     1400037f5 <__pformat_int+0x11a>
   1400037a1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037a5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400037a8:	25 00 10 00 00       	and    eax,0x1000
   1400037ad:	85 c0                	test   eax,eax
   1400037af:	74 44                	je     1400037f5 <__pformat_int+0x11a>
   1400037b1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037b5:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400037b9:	66 85 c0             	test   ax,ax
   1400037bc:	74 37                	je     1400037f5 <__pformat_int+0x11a>
   1400037be:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037c2:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   1400037c6:	48 89 c2             	mov    rdx,rax
   1400037c9:	48 89 d0             	mov    rax,rdx
   1400037cc:	48 c1 f8 3f          	sar    rax,0x3f
   1400037d0:	48 c1 e8 3e          	shr    rax,0x3e
   1400037d4:	48 01 c2             	add    rdx,rax
   1400037d7:	83 e2 03             	and    edx,0x3
   1400037da:	48 29 c2             	sub    rdx,rax
   1400037dd:	48 89 d0             	mov    rax,rdx
   1400037e0:	48 83 f8 03          	cmp    rax,0x3
   1400037e4:	75 0f                	jne    1400037f5 <__pformat_int+0x11a>
   1400037e6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037ea:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400037ee:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400037f2:	c6 00 2c             	mov    BYTE PTR [rax],0x2c
   1400037f5:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
   1400037f9:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   140003800:	cc cc cc 
   140003803:	48 89 c8             	mov    rax,rcx
   140003806:	48 f7 e2             	mul    rdx
   140003809:	48 c1 ea 03          	shr    rdx,0x3
   14000380d:	48 89 d0             	mov    rax,rdx
   140003810:	48 c1 e0 02          	shl    rax,0x2
   140003814:	48 01 d0             	add    rax,rdx
   140003817:	48 01 c0             	add    rax,rax
   14000381a:	48 29 c1             	sub    rcx,rax
   14000381d:	48 89 ca             	mov    rdx,rcx
   140003820:	89 d0                	mov    eax,edx
   140003822:	8d 48 30             	lea    ecx,[rax+0x30]
   140003825:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003829:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000382d:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003831:	89 ca                	mov    edx,ecx
   140003833:	88 10                	mov    BYTE PTR [rax],dl
   140003835:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003839:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   140003840:	cc cc cc 
   140003843:	48 f7 e2             	mul    rdx
   140003846:	48 89 d0             	mov    rax,rdx
   140003849:	48 c1 e8 03          	shr    rax,0x3
   14000384d:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140003851:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003855:	48 85 c0             	test   rax,rax
   140003858:	0f 85 39 ff ff ff    	jne    140003797 <__pformat_int+0xbc>
   14000385e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003862:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003865:	85 c0                	test   eax,eax
   140003867:	7e 3e                	jle    1400038a7 <__pformat_int+0x1cc>
   140003869:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000386d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003870:	89 c1                	mov    ecx,eax
   140003872:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003876:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   14000387a:	89 c2                	mov    edx,eax
   14000387c:	89 c8                	mov    eax,ecx
   14000387e:	29 d0                	sub    eax,edx
   140003880:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003883:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003887:	7e 1e                	jle    1400038a7 <__pformat_int+0x1cc>
   140003889:	eb 0f                	jmp    14000389a <__pformat_int+0x1bf>
   14000388b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000388f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003893:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003897:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000389a:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000389d:	8d 50 ff             	lea    edx,[rax-0x1]
   1400038a0:	89 55 f4             	mov    DWORD PTR [rbp-0xc],edx
   1400038a3:	85 c0                	test   eax,eax
   1400038a5:	7f e4                	jg     14000388b <__pformat_int+0x1b0>
   1400038a7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038ab:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400038af:	75 1a                	jne    1400038cb <__pformat_int+0x1f0>
   1400038b1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038b5:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400038b8:	85 c0                	test   eax,eax
   1400038ba:	74 0f                	je     1400038cb <__pformat_int+0x1f0>
   1400038bc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038c0:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400038c4:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400038c8:	c6 00 30             	mov    BYTE PTR [rax],0x30
   1400038cb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038cf:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038d2:	85 c0                	test   eax,eax
   1400038d4:	0f 8e ce 00 00 00    	jle    1400039a8 <__pformat_int+0x2cd>
   1400038da:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038de:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038e1:	89 c1                	mov    ecx,eax
   1400038e3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038e7:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   1400038eb:	89 c2                	mov    edx,eax
   1400038ed:	89 c8                	mov    eax,ecx
   1400038ef:	29 d0                	sub    eax,edx
   1400038f1:	89 c2                	mov    edx,eax
   1400038f3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038f7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400038fa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038fe:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003901:	85 c0                	test   eax,eax
   140003903:	0f 8e 9f 00 00 00    	jle    1400039a8 <__pformat_int+0x2cd>
   140003909:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000390d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003910:	25 c0 01 00 00       	and    eax,0x1c0
   140003915:	85 c0                	test   eax,eax
   140003917:	74 11                	je     14000392a <__pformat_int+0x24f>
   140003919:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000391d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003920:	8d 50 ff             	lea    edx,[rax-0x1]
   140003923:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003927:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000392a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000392e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003931:	85 c0                	test   eax,eax
   140003933:	79 3b                	jns    140003970 <__pformat_int+0x295>
   140003935:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003939:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000393c:	25 00 06 00 00       	and    eax,0x600
   140003941:	3d 00 02 00 00       	cmp    eax,0x200
   140003946:	75 28                	jne    140003970 <__pformat_int+0x295>
   140003948:	eb 0f                	jmp    140003959 <__pformat_int+0x27e>
   14000394a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000394e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003952:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003956:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003959:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000395d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003960:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003963:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003967:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000396a:	85 c0                	test   eax,eax
   14000396c:	7f dc                	jg     14000394a <__pformat_int+0x26f>
   14000396e:	eb 38                	jmp    1400039a8 <__pformat_int+0x2cd>
   140003970:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003974:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003977:	25 00 04 00 00       	and    eax,0x400
   14000397c:	85 c0                	test   eax,eax
   14000397e:	75 28                	jne    1400039a8 <__pformat_int+0x2cd>
   140003980:	eb 11                	jmp    140003993 <__pformat_int+0x2b8>
   140003982:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003986:	48 89 c2             	mov    rdx,rax
   140003989:	b9 20 00 00 00       	mov    ecx,0x20
   14000398e:	e8 dd f8 ff ff       	call   140003270 <__pformat_putc>
   140003993:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003997:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000399a:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000399d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400039a1:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400039a4:	85 c0                	test   eax,eax
   1400039a6:	7f da                	jg     140003982 <__pformat_int+0x2a7>
   1400039a8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400039ac:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400039af:	25 80 00 00 00       	and    eax,0x80
   1400039b4:	85 c0                	test   eax,eax
   1400039b6:	74 11                	je     1400039c9 <__pformat_int+0x2ee>
   1400039b8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039bc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400039c0:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400039c4:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   1400039c7:	eb 5a                	jmp    140003a23 <__pformat_int+0x348>
   1400039c9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400039cd:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400039d0:	25 00 01 00 00       	and    eax,0x100
   1400039d5:	85 c0                	test   eax,eax
   1400039d7:	74 11                	je     1400039ea <__pformat_int+0x30f>
   1400039d9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039dd:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400039e1:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400039e5:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   1400039e8:	eb 39                	jmp    140003a23 <__pformat_int+0x348>
   1400039ea:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400039ee:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400039f1:	83 e0 40             	and    eax,0x40
   1400039f4:	85 c0                	test   eax,eax
   1400039f6:	74 2b                	je     140003a23 <__pformat_int+0x348>
   1400039f8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039fc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003a00:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003a04:	c6 00 20             	mov    BYTE PTR [rax],0x20
   140003a07:	eb 1a                	jmp    140003a23 <__pformat_int+0x348>
   140003a09:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   140003a0e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003a12:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003a15:	0f be c0             	movsx  eax,al
   140003a18:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003a1c:	89 c1                	mov    ecx,eax
   140003a1e:	e8 4d f8 ff ff       	call   140003270 <__pformat_putc>
   140003a23:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003a27:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   140003a2b:	72 dc                	jb     140003a09 <__pformat_int+0x32e>
   140003a2d:	eb 11                	jmp    140003a40 <__pformat_int+0x365>
   140003a2f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003a33:	48 89 c2             	mov    rdx,rax
   140003a36:	b9 20 00 00 00       	mov    ecx,0x20
   140003a3b:	e8 30 f8 ff ff       	call   140003270 <__pformat_putc>
   140003a40:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003a44:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003a47:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003a4a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003a4e:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003a51:	85 c0                	test   eax,eax
   140003a53:	7f da                	jg     140003a2f <__pformat_int+0x354>
   140003a55:	90                   	nop
   140003a56:	90                   	nop
   140003a57:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003a5b:	5b                   	pop    rbx
   140003a5c:	5d                   	pop    rbp
   140003a5d:	c3                   	ret

0000000140003a5e <__pformat_xint>:
   140003a5e:	55                   	push   rbp
   140003a5f:	53                   	push   rbx
   140003a60:	48 83 ec 68          	sub    rsp,0x68
   140003a64:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003a69:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003a6c:	48 89 d3             	mov    rbx,rdx
   140003a6f:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140003a72:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
   140003a76:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003a7a:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   140003a7e:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003a82:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003a86:	74 1e                	je     140003aa6 <__pformat_xint+0x48>
   140003a88:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003a8c:	74 06                	je     140003a94 <__pformat_xint+0x36>
   140003a8e:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003a92:	75 09                	jne    140003a9d <__pformat_xint+0x3f>
   140003a94:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003a9b:	eb 10                	jmp    140003aad <__pformat_xint+0x4f>
   140003a9d:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140003aa4:	eb 07                	jmp    140003aad <__pformat_xint+0x4f>
   140003aa6:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140003aad:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003ab1:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003ab4:	49 89 d0             	mov    r8,rdx
   140003ab7:	89 c2                	mov    edx,eax
   140003ab9:	b9 02 00 00 00       	mov    ecx,0x2
   140003abe:	e8 88 fb ff ff       	call   14000364b <__pformat_int_bufsiz>
   140003ac3:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140003ac6:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
   140003acd:	00 
   140003ace:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140003ad1:	48 98                	cdqe
   140003ad3:	48 83 c0 0f          	add    rax,0xf
   140003ad7:	48 c1 e8 04          	shr    rax,0x4
   140003adb:	48 c1 e0 04          	shl    rax,0x4
   140003adf:	e8 cc f6 ff ff       	call   1400031b0 <___chkstk_ms>
   140003ae4:	48 29 c4             	sub    rsp,rax
   140003ae7:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003aec:	48 83 c0 0f          	add    rax,0xf
   140003af0:	48 c1 e8 04          	shr    rax,0x4
   140003af4:	48 c1 e0 04          	shl    rax,0x4
   140003af8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140003afc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003b00:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003b04:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003b08:	74 1e                	je     140003b28 <__pformat_xint+0xca>
   140003b0a:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003b0e:	74 06                	je     140003b16 <__pformat_xint+0xb8>
   140003b10:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003b14:	75 09                	jne    140003b1f <__pformat_xint+0xc1>
   140003b16:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140003b1d:	eb 10                	jmp    140003b2f <__pformat_xint+0xd1>
   140003b1f:	c7 45 ec 0f 00 00 00 	mov    DWORD PTR [rbp-0x14],0xf
   140003b26:	eb 67                	jmp    140003b8f <__pformat_xint+0x131>
   140003b28:	c7 45 ec 07 00 00 00 	mov    DWORD PTR [rbp-0x14],0x7
   140003b2f:	eb 5e                	jmp    140003b8f <__pformat_xint+0x131>
   140003b31:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003b35:	89 c2                	mov    edx,eax
   140003b37:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140003b3a:	21 d0                	and    eax,edx
   140003b3c:	8d 48 30             	lea    ecx,[rax+0x30]
   140003b3f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b43:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b47:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b4b:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003b4f:	89 ca                	mov    edx,ecx
   140003b51:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b55:	88 10                	mov    BYTE PTR [rax],dl
   140003b57:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b5b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003b5e:	3c 39                	cmp    al,0x39
   140003b60:	7e 1a                	jle    140003b7c <__pformat_xint+0x11e>
   140003b62:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b66:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003b69:	83 c0 07             	add    eax,0x7
   140003b6c:	89 c2                	mov    edx,eax
   140003b6e:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140003b71:	83 e0 20             	and    eax,0x20
   140003b74:	09 c2                	or     edx,eax
   140003b76:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b7a:	88 10                	mov    BYTE PTR [rax],dl
   140003b7c:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140003b80:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003b83:	89 c1                	mov    ecx,eax
   140003b85:	48 d3 ea             	shr    rdx,cl
   140003b88:	48 89 d0             	mov    rax,rdx
   140003b8b:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003b8f:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003b93:	48 85 c0             	test   rax,rax
   140003b96:	75 99                	jne    140003b31 <__pformat_xint+0xd3>
   140003b98:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b9c:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003ba0:	75 13                	jne    140003bb5 <__pformat_xint+0x157>
   140003ba2:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ba6:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003ba9:	80 e4 f7             	and    ah,0xf7
   140003bac:	89 c2                	mov    edx,eax
   140003bae:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bb2:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003bb5:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bb9:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003bbc:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003bbf:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003bc3:	7e 3a                	jle    140003bff <__pformat_xint+0x1a1>
   140003bc5:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140003bc8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bcc:	48 2b 45 e0          	sub    rax,QWORD PTR [rbp-0x20]
   140003bd0:	89 c1                	mov    ecx,eax
   140003bd2:	89 d0                	mov    eax,edx
   140003bd4:	29 c8                	sub    eax,ecx
   140003bd6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003bd9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003bdd:	7e 20                	jle    140003bff <__pformat_xint+0x1a1>
   140003bdf:	eb 0f                	jmp    140003bf0 <__pformat_xint+0x192>
   140003be1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003be5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003be9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bed:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003bf0:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003bf3:	8d 50 ff             	lea    edx,[rax-0x1]
   140003bf6:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003bf9:	85 c0                	test   eax,eax
   140003bfb:	7f e4                	jg     140003be1 <__pformat_xint+0x183>
   140003bfd:	eb 25                	jmp    140003c24 <__pformat_xint+0x1c6>
   140003bff:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003c03:	75 1f                	jne    140003c24 <__pformat_xint+0x1c6>
   140003c05:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c09:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c0c:	25 00 08 00 00       	and    eax,0x800
   140003c11:	85 c0                	test   eax,eax
   140003c13:	74 0f                	je     140003c24 <__pformat_xint+0x1c6>
   140003c15:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c19:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c1d:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c21:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c24:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c28:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003c2c:	75 1a                	jne    140003c48 <__pformat_xint+0x1ea>
   140003c2e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c32:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003c35:	85 c0                	test   eax,eax
   140003c37:	74 0f                	je     140003c48 <__pformat_xint+0x1ea>
   140003c39:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c3d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c41:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c45:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c48:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c4c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003c4f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003c53:	48 2b 55 e0          	sub    rdx,QWORD PTR [rbp-0x20]
   140003c57:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c5a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140003c5d:	7d 15                	jge    140003c74 <__pformat_xint+0x216>
   140003c5f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c63:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003c66:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140003c69:	89 c2                	mov    edx,eax
   140003c6b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c6f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003c72:	eb 0b                	jmp    140003c7f <__pformat_xint+0x221>
   140003c74:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c78:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003c7f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c83:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003c86:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003c89:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c8d:	7e 1a                	jle    140003ca9 <__pformat_xint+0x24b>
   140003c8f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003c93:	74 14                	je     140003ca9 <__pformat_xint+0x24b>
   140003c95:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c99:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c9c:	25 00 08 00 00       	and    eax,0x800
   140003ca1:	85 c0                	test   eax,eax
   140003ca3:	74 04                	je     140003ca9 <__pformat_xint+0x24b>
   140003ca5:	83 6d fc 02          	sub    DWORD PTR [rbp-0x4],0x2
   140003ca9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003cad:	7e 3c                	jle    140003ceb <__pformat_xint+0x28d>
   140003caf:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003cb3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003cb6:	85 c0                	test   eax,eax
   140003cb8:	79 31                	jns    140003ceb <__pformat_xint+0x28d>
   140003cba:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003cbe:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003cc1:	25 00 06 00 00       	and    eax,0x600
   140003cc6:	3d 00 02 00 00       	cmp    eax,0x200
   140003ccb:	75 1e                	jne    140003ceb <__pformat_xint+0x28d>
   140003ccd:	eb 0f                	jmp    140003cde <__pformat_xint+0x280>
   140003ccf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003cd3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003cd7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003cdb:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003cde:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003ce1:	8d 50 ff             	lea    edx,[rax-0x1]
   140003ce4:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003ce7:	85 c0                	test   eax,eax
   140003ce9:	7f e4                	jg     140003ccf <__pformat_xint+0x271>
   140003ceb:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003cef:	74 30                	je     140003d21 <__pformat_xint+0x2c3>
   140003cf1:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003cf5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003cf8:	25 00 08 00 00       	and    eax,0x800
   140003cfd:	85 c0                	test   eax,eax
   140003cff:	74 20                	je     140003d21 <__pformat_xint+0x2c3>
   140003d01:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d05:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003d09:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003d0d:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003d10:	88 10                	mov    BYTE PTR [rax],dl
   140003d12:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d16:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003d1a:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003d1e:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003d21:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003d25:	7e 4c                	jle    140003d73 <__pformat_xint+0x315>
   140003d27:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003d2b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003d2e:	25 00 04 00 00       	and    eax,0x400
   140003d33:	85 c0                	test   eax,eax
   140003d35:	75 3c                	jne    140003d73 <__pformat_xint+0x315>
   140003d37:	eb 11                	jmp    140003d4a <__pformat_xint+0x2ec>
   140003d39:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003d3d:	48 89 c2             	mov    rdx,rax
   140003d40:	b9 20 00 00 00       	mov    ecx,0x20
   140003d45:	e8 26 f5 ff ff       	call   140003270 <__pformat_putc>
   140003d4a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003d4d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003d50:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003d53:	85 c0                	test   eax,eax
   140003d55:	7f e2                	jg     140003d39 <__pformat_xint+0x2db>
   140003d57:	eb 1a                	jmp    140003d73 <__pformat_xint+0x315>
   140003d59:	48 83 6d f0 01       	sub    QWORD PTR [rbp-0x10],0x1
   140003d5e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d62:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003d65:	0f be c0             	movsx  eax,al
   140003d68:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003d6c:	89 c1                	mov    ecx,eax
   140003d6e:	e8 fd f4 ff ff       	call   140003270 <__pformat_putc>
   140003d73:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d77:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140003d7b:	72 dc                	jb     140003d59 <__pformat_xint+0x2fb>
   140003d7d:	eb 11                	jmp    140003d90 <__pformat_xint+0x332>
   140003d7f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003d83:	48 89 c2             	mov    rdx,rax
   140003d86:	b9 20 00 00 00       	mov    ecx,0x20
   140003d8b:	e8 e0 f4 ff ff       	call   140003270 <__pformat_putc>
   140003d90:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003d93:	8d 50 ff             	lea    edx,[rax-0x1]
   140003d96:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003d99:	85 c0                	test   eax,eax
   140003d9b:	7f e2                	jg     140003d7f <__pformat_xint+0x321>
   140003d9d:	90                   	nop
   140003d9e:	90                   	nop
   140003d9f:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003da3:	5b                   	pop    rbx
   140003da4:	5d                   	pop    rbp
   140003da5:	c3                   	ret

0000000140003da6 <init_fpreg_ldouble>:
   140003da6:	55                   	push   rbp
   140003da7:	53                   	push   rbx
   140003da8:	48 83 ec 28          	sub    rsp,0x28
   140003dac:	48 8d 6c 24 20       	lea    rbp,[rsp+0x20]
   140003db1:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003db5:	48 89 d3             	mov    rbx,rdx
   140003db8:	db 2b                	fld    TBYTE PTR [rbx]
   140003dba:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003dbd:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140003dc0:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003dc3:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140003dc7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003dcb:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140003dcf:	48 89 01             	mov    QWORD PTR [rcx],rax
   140003dd2:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
   140003dd6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003dda:	48 83 c4 28          	add    rsp,0x28
   140003dde:	5b                   	pop    rbx
   140003ddf:	5d                   	pop    rbp
   140003de0:	c3                   	ret

0000000140003de1 <__pformat_cvt>:
   140003de1:	55                   	push   rbp
   140003de2:	53                   	push   rbx
   140003de3:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140003dea:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140003df1:	00 
   140003df2:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003df5:	48 89 d3             	mov    rbx,rdx
   140003df8:	db 2b                	fld    TBYTE PTR [rbx]
   140003dfa:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140003dfd:	44 89 45 30          	mov    DWORD PTR [rbp+0x30],r8d
   140003e01:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003e05:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140003e0c:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003e10:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003e13:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003e16:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140003e1a:	48 89 c1             	mov    rcx,rax
   140003e1d:	e8 84 ff ff ff       	call   140003da6 <init_fpreg_ldouble>
   140003e22:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003e25:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003e28:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140003e2c:	48 89 c1             	mov    rcx,rax
   140003e2f:	e8 9c 4e 00 00       	call   140008cd0 <__fpclassifyl>
   140003e34:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003e37:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e3a:	25 00 01 00 00       	and    eax,0x100
   140003e3f:	85 c0                	test   eax,eax
   140003e41:	74 1d                	je     140003e60 <__pformat_cvt+0x7f>
   140003e43:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e46:	25 00 04 00 00       	and    eax,0x400
   140003e4b:	85 c0                	test   eax,eax
   140003e4d:	74 07                	je     140003e56 <__pformat_cvt+0x75>
   140003e4f:	b8 03 00 00 00       	mov    eax,0x3
   140003e54:	eb 05                	jmp    140003e5b <__pformat_cvt+0x7a>
   140003e56:	b8 04 00 00 00       	mov    eax,0x4
   140003e5b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003e5e:	eb 4a                	jmp    140003eaa <__pformat_cvt+0xc9>
   140003e60:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e63:	25 00 04 00 00       	and    eax,0x400
   140003e68:	85 c0                	test   eax,eax
   140003e6a:	74 37                	je     140003ea3 <__pformat_cvt+0xc2>
   140003e6c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e6f:	25 00 40 00 00       	and    eax,0x4000
   140003e74:	85 c0                	test   eax,eax
   140003e76:	74 10                	je     140003e88 <__pformat_cvt+0xa7>
   140003e78:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140003e7f:	c7 45 fc c3 bf ff ff 	mov    DWORD PTR [rbp-0x4],0xffffbfc3
   140003e86:	eb 22                	jmp    140003eaa <__pformat_cvt+0xc9>
   140003e88:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003e8f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003e93:	98                   	cwde
   140003e94:	25 ff 7f 00 00       	and    eax,0x7fff
   140003e99:	2d 3e 40 00 00       	sub    eax,0x403e
   140003e9e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003ea1:	eb 07                	jmp    140003eaa <__pformat_cvt+0xc9>
   140003ea3:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140003eaa:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003ead:	83 f8 04             	cmp    eax,0x4
   140003eb0:	74 0e                	je     140003ec0 <__pformat_cvt+0xdf>
   140003eb2:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003eb6:	98                   	cwde
   140003eb7:	25 00 80 00 00       	and    eax,0x8000
   140003ebc:	89 c2                	mov    edx,eax
   140003ebe:	eb 05                	jmp    140003ec5 <__pformat_cvt+0xe4>
   140003ec0:	ba 00 00 00 00       	mov    edx,0x0
   140003ec5:	48 8b 45 40          	mov    rax,QWORD PTR [rbp+0x40]
   140003ec9:	89 10                	mov    DWORD PTR [rax],edx
   140003ecb:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003ece:	4c 8d 4d f8          	lea    r9,[rbp-0x8]
   140003ed2:	4c 8d 45 e0          	lea    r8,[rbp-0x20]
   140003ed6:	48 8d 0d 93 61 00 00 	lea    rcx,[rip+0x6193]        # 14000a070 <fpi.0>
   140003edd:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
   140003ee1:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140003ee6:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003eea:	48 89 54 24 30       	mov    QWORD PTR [rsp+0x30],rdx
   140003eef:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   140003ef2:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140003ef6:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003ef9:	89 54 24 20          	mov    DWORD PTR [rsp+0x20],edx
   140003efd:	89 c2                	mov    edx,eax
   140003eff:	e8 96 24 00 00       	call   14000639a <__gdtoa>
   140003f04:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140003f0b:	5b                   	pop    rbx
   140003f0c:	5d                   	pop    rbp
   140003f0d:	c3                   	ret

0000000140003f0e <__pformat_ecvt>:
   140003f0e:	55                   	push   rbp
   140003f0f:	53                   	push   rbx
   140003f10:	48 83 ec 58          	sub    rsp,0x58
   140003f14:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003f19:	48 89 cb             	mov    rbx,rcx
   140003f1c:	db 2b                	fld    TBYTE PTR [rbx]
   140003f1e:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003f21:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003f24:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003f28:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003f2c:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003f2f:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003f32:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003f36:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003f39:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003f3d:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003f41:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003f46:	4d 89 c1             	mov    r9,r8
   140003f49:	41 89 c8             	mov    r8d,ecx
   140003f4c:	48 89 c2             	mov    rdx,rax
   140003f4f:	b9 02 00 00 00       	mov    ecx,0x2
   140003f54:	e8 88 fe ff ff       	call   140003de1 <__pformat_cvt>
   140003f59:	48 83 c4 58          	add    rsp,0x58
   140003f5d:	5b                   	pop    rbx
   140003f5e:	5d                   	pop    rbp
   140003f5f:	c3                   	ret

0000000140003f60 <__pformat_fcvt>:
   140003f60:	55                   	push   rbp
   140003f61:	53                   	push   rbx
   140003f62:	48 83 ec 58          	sub    rsp,0x58
   140003f66:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003f6b:	48 89 cb             	mov    rbx,rcx
   140003f6e:	db 2b                	fld    TBYTE PTR [rbx]
   140003f70:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003f73:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003f76:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003f7a:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003f7e:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003f81:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003f84:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003f88:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003f8b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003f8f:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003f93:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003f98:	4d 89 c1             	mov    r9,r8
   140003f9b:	41 89 c8             	mov    r8d,ecx
   140003f9e:	48 89 c2             	mov    rdx,rax
   140003fa1:	b9 03 00 00 00       	mov    ecx,0x3
   140003fa6:	e8 36 fe ff ff       	call   140003de1 <__pformat_cvt>
   140003fab:	48 83 c4 58          	add    rsp,0x58
   140003faf:	5b                   	pop    rbx
   140003fb0:	5d                   	pop    rbp
   140003fb1:	c3                   	ret

0000000140003fb2 <__pformat_emit_radix_point>:
   140003fb2:	55                   	push   rbp
   140003fb3:	53                   	push   rbx
   140003fb4:	48 83 ec 68          	sub    rsp,0x68
   140003fb8:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003fbd:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003fc1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fc5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003fc8:	83 f8 fd             	cmp    eax,0xfffffffd
   140003fcb:	75 48                	jne    140004015 <__pformat_emit_radix_point+0x63>
   140003fcd:	48 c7 45 cc 00 00 00 	mov    QWORD PTR [rbp-0x34],0x0
   140003fd4:	00 
   140003fd5:	e8 4e 57 00 00       	call   140009728 <localeconv>
   140003fda:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003fdd:	48 8d 4d cc          	lea    rcx,[rbp-0x34]
   140003fe1:	48 8d 45 d6          	lea    rax,[rbp-0x2a]
   140003fe5:	49 89 c9             	mov    r9,rcx
   140003fe8:	41 b8 10 00 00 00    	mov    r8d,0x10
   140003fee:	48 89 c1             	mov    rcx,rax
   140003ff1:	e8 6a 51 00 00       	call   140009160 <mbrtowc>
   140003ff6:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140003ff9:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   140003ffd:	7e 0c                	jle    14000400b <__pformat_emit_radix_point+0x59>
   140003fff:	0f b7 55 d6          	movzx  edx,WORD PTR [rbp-0x2a]
   140004003:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004007:	66 89 50 18          	mov    WORD PTR [rax+0x18],dx
   14000400b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000400f:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140004012:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140004015:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004019:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   14000401d:	66 85 c0             	test   ax,ax
   140004020:	0f 84 b8 00 00 00    	je     1400040de <__pformat_emit_radix_point+0x12c>
   140004026:	48 89 e0             	mov    rax,rsp
   140004029:	48 89 c3             	mov    rbx,rax
   14000402c:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004030:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140004033:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004036:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004039:	48 63 d0             	movsxd rdx,eax
   14000403c:	48 83 ea 01          	sub    rdx,0x1
   140004040:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140004044:	48 98                	cdqe
   140004046:	48 83 c0 0f          	add    rax,0xf
   14000404a:	48 c1 e8 04          	shr    rax,0x4
   14000404e:	48 c1 e0 04          	shl    rax,0x4
   140004052:	e8 59 f1 ff ff       	call   1400031b0 <___chkstk_ms>
   140004057:	48 29 c4             	sub    rsp,rax
   14000405a:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000405f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140004063:	48 c7 45 c4 00 00 00 	mov    QWORD PTR [rbp-0x3c],0x0
   14000406a:	00 
   14000406b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000406f:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140004073:	48 8d 4d c4          	lea    rcx,[rbp-0x3c]
   140004077:	0f b7 d0             	movzx  edx,ax
   14000407a:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000407e:	49 89 c8             	mov    r8,rcx
   140004081:	48 89 c1             	mov    rcx,rax
   140004084:	e8 87 50 00 00       	call   140009110 <wcrtomb>
   140004089:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000408c:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004090:	7e 36                	jle    1400040c8 <__pformat_emit_radix_point+0x116>
   140004092:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140004096:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000409a:	eb 1d                	jmp    1400040b9 <__pformat_emit_radix_point+0x107>
   14000409c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400040a0:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400040a4:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400040a8:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400040ab:	0f be c0             	movsx  eax,al
   1400040ae:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400040b2:	89 c1                	mov    ecx,eax
   1400040b4:	e8 b7 f1 ff ff       	call   140003270 <__pformat_putc>
   1400040b9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400040bc:	8d 50 ff             	lea    edx,[rax-0x1]
   1400040bf:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   1400040c2:	85 c0                	test   eax,eax
   1400040c4:	7f d6                	jg     14000409c <__pformat_emit_radix_point+0xea>
   1400040c6:	eb 11                	jmp    1400040d9 <__pformat_emit_radix_point+0x127>
   1400040c8:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400040cc:	48 89 c2             	mov    rdx,rax
   1400040cf:	b9 2e 00 00 00       	mov    ecx,0x2e
   1400040d4:	e8 97 f1 ff ff       	call   140003270 <__pformat_putc>
   1400040d9:	48 89 dc             	mov    rsp,rbx
   1400040dc:	eb 11                	jmp    1400040ef <__pformat_emit_radix_point+0x13d>
   1400040de:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400040e2:	48 89 c2             	mov    rdx,rax
   1400040e5:	b9 2e 00 00 00       	mov    ecx,0x2e
   1400040ea:	e8 81 f1 ff ff       	call   140003270 <__pformat_putc>
   1400040ef:	90                   	nop
   1400040f0:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   1400040f4:	5b                   	pop    rbx
   1400040f5:	5d                   	pop    rbp
   1400040f6:	c3                   	ret

00000001400040f7 <__pformat_emit_numeric_value>:
   1400040f7:	55                   	push   rbp
   1400040f8:	48 89 e5             	mov    rbp,rsp
   1400040fb:	48 83 ec 30          	sub    rsp,0x30
   1400040ff:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140004102:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004106:	83 7d 10 2e          	cmp    DWORD PTR [rbp+0x10],0x2e
   14000410a:	75 0e                	jne    14000411a <__pformat_emit_numeric_value+0x23>
   14000410c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004110:	48 89 c1             	mov    rcx,rax
   140004113:	e8 9a fe ff ff       	call   140003fb2 <__pformat_emit_radix_point>
   140004118:	eb 43                	jmp    14000415d <__pformat_emit_numeric_value+0x66>
   14000411a:	83 7d 10 2c          	cmp    DWORD PTR [rbp+0x10],0x2c
   14000411e:	75 2f                	jne    14000414f <__pformat_emit_numeric_value+0x58>
   140004120:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004124:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140004128:	66 89 45 fe          	mov    WORD PTR [rbp-0x2],ax
   14000412c:	0f b7 45 fe          	movzx  eax,WORD PTR [rbp-0x2]
   140004130:	66 85 c0             	test   ax,ax
   140004133:	74 28                	je     14000415d <__pformat_emit_numeric_value+0x66>
   140004135:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004139:	48 8d 45 fe          	lea    rax,[rbp-0x2]
   14000413d:	49 89 d0             	mov    r8,rdx
   140004140:	ba 01 00 00 00       	mov    edx,0x1
   140004145:	48 89 c1             	mov    rcx,rax
   140004148:	e8 2c f3 ff ff       	call   140003479 <__pformat_wputchars>
   14000414d:	eb 0e                	jmp    14000415d <__pformat_emit_numeric_value+0x66>
   14000414f:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004153:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140004156:	89 c1                	mov    ecx,eax
   140004158:	e8 13 f1 ff ff       	call   140003270 <__pformat_putc>
   14000415d:	90                   	nop
   14000415e:	48 83 c4 30          	add    rsp,0x30
   140004162:	5d                   	pop    rbp
   140004163:	c3                   	ret

0000000140004164 <__pformat_emit_inf_or_nan>:
   140004164:	55                   	push   rbp
   140004165:	48 89 e5             	mov    rbp,rsp
   140004168:	48 83 ec 40          	sub    rsp,0x40
   14000416c:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000416f:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004173:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140004177:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000417b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000417f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004183:	c7 40 10 ff ff ff ff 	mov    DWORD PTR [rax+0x10],0xffffffff
   14000418a:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   14000418e:	74 11                	je     1400041a1 <__pformat_emit_inf_or_nan+0x3d>
   140004190:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004194:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004198:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000419c:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   14000419f:	eb 3e                	jmp    1400041df <__pformat_emit_inf_or_nan+0x7b>
   1400041a1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400041a5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400041a8:	25 00 01 00 00       	and    eax,0x100
   1400041ad:	85 c0                	test   eax,eax
   1400041af:	74 11                	je     1400041c2 <__pformat_emit_inf_or_nan+0x5e>
   1400041b1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400041b5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400041b9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400041bd:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   1400041c0:	eb 1d                	jmp    1400041df <__pformat_emit_inf_or_nan+0x7b>
   1400041c2:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400041c6:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400041c9:	83 e0 40             	and    eax,0x40
   1400041cc:	85 c0                	test   eax,eax
   1400041ce:	74 0f                	je     1400041df <__pformat_emit_inf_or_nan+0x7b>
   1400041d0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400041d4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400041d8:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400041dc:	c6 00 20             	mov    BYTE PTR [rax],0x20
   1400041df:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   1400041e6:	eb 38                	jmp    140004220 <__pformat_emit_inf_or_nan+0xbc>
   1400041e8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400041ec:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400041f0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400041f4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400041f7:	83 e0 df             	and    eax,0xffffffdf
   1400041fa:	41 89 c0             	mov    r8d,eax
   1400041fd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004201:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004204:	83 e0 20             	and    eax,0x20
   140004207:	89 c1                	mov    ecx,eax
   140004209:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000420d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004211:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140004215:	44 89 c2             	mov    edx,r8d
   140004218:	09 ca                	or     edx,ecx
   14000421a:	88 10                	mov    BYTE PTR [rax],dl
   14000421c:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004220:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004224:	7f c2                	jg     1400041e8 <__pformat_emit_inf_or_nan+0x84>
   140004226:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000422a:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   14000422e:	48 29 c2             	sub    rdx,rax
   140004231:	89 d1                	mov    ecx,edx
   140004233:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140004237:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000423b:	49 89 d0             	mov    r8,rdx
   14000423e:	89 ca                	mov    edx,ecx
   140004240:	48 89 c1             	mov    rcx,rax
   140004243:	e8 ac f0 ff ff       	call   1400032f4 <__pformat_putchars>
   140004248:	90                   	nop
   140004249:	48 83 c4 40          	add    rsp,0x40
   14000424d:	5d                   	pop    rbp
   14000424e:	c3                   	ret

000000014000424f <__pformat_emit_float>:
   14000424f:	55                   	push   rbp
   140004250:	48 89 e5             	mov    rbp,rsp
   140004253:	48 83 ec 30          	sub    rsp,0x30
   140004257:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000425a:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000425e:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140004262:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004266:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000426a:	7e 2e                	jle    14000429a <__pformat_emit_float+0x4b>
   14000426c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004270:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004273:	39 45 20             	cmp    DWORD PTR [rbp+0x20],eax
   140004276:	7f 15                	jg     14000428d <__pformat_emit_float+0x3e>
   140004278:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000427c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000427f:	2b 45 20             	sub    eax,DWORD PTR [rbp+0x20]
   140004282:	89 c2                	mov    edx,eax
   140004284:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004288:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000428b:	eb 29                	jmp    1400042b6 <__pformat_emit_float+0x67>
   14000428d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004291:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004298:	eb 1c                	jmp    1400042b6 <__pformat_emit_float+0x67>
   14000429a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000429e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042a1:	85 c0                	test   eax,eax
   1400042a3:	7e 11                	jle    1400042b6 <__pformat_emit_float+0x67>
   1400042a5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042a9:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042ac:	8d 50 ff             	lea    edx,[rax-0x1]
   1400042af:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042b3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400042b6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042ba:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042bd:	85 c0                	test   eax,eax
   1400042bf:	78 2b                	js     1400042ec <__pformat_emit_float+0x9d>
   1400042c1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042c5:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400042c8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042cc:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400042cf:	39 c2                	cmp    edx,eax
   1400042d1:	7e 19                	jle    1400042ec <__pformat_emit_float+0x9d>
   1400042d3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042d7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400042da:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042de:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400042e1:	29 c2                	sub    edx,eax
   1400042e3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042e7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400042ea:	eb 0b                	jmp    1400042f7 <__pformat_emit_float+0xa8>
   1400042ec:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042f0:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400042f7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042fb:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042fe:	85 c0                	test   eax,eax
   140004300:	7e 2c                	jle    14000432e <__pformat_emit_float+0xdf>
   140004302:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004306:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004309:	85 c0                	test   eax,eax
   14000430b:	7f 10                	jg     14000431d <__pformat_emit_float+0xce>
   14000430d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004311:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004314:	25 00 08 00 00       	and    eax,0x800
   140004319:	85 c0                	test   eax,eax
   14000431b:	74 11                	je     14000432e <__pformat_emit_float+0xdf>
   14000431d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004321:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004324:	8d 50 ff             	lea    edx,[rax-0x1]
   140004327:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000432b:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000432e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004332:	7e 64                	jle    140004398 <__pformat_emit_float+0x149>
   140004334:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004338:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000433b:	25 00 10 00 00       	and    eax,0x1000
   140004340:	85 c0                	test   eax,eax
   140004342:	74 54                	je     140004398 <__pformat_emit_float+0x149>
   140004344:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004348:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   14000434c:	66 85 c0             	test   ax,ax
   14000434f:	74 47                	je     140004398 <__pformat_emit_float+0x149>
   140004351:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004354:	83 c0 02             	add    eax,0x2
   140004357:	48 63 d0             	movsxd rdx,eax
   14000435a:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   140004361:	48 c1 ea 20          	shr    rdx,0x20
   140004365:	c1 f8 1f             	sar    eax,0x1f
   140004368:	29 c2                	sub    edx,eax
   14000436a:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000436d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004370:	eb 15                	jmp    140004387 <__pformat_emit_float+0x138>
   140004372:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004376:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000437a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000437d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004380:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004384:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004387:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000438b:	7e 0b                	jle    140004398 <__pformat_emit_float+0x149>
   14000438d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004391:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004394:	85 c0                	test   eax,eax
   140004396:	7f da                	jg     140004372 <__pformat_emit_float+0x123>
   140004398:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000439c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000439f:	85 c0                	test   eax,eax
   1400043a1:	7e 27                	jle    1400043ca <__pformat_emit_float+0x17b>
   1400043a3:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400043a7:	75 10                	jne    1400043b9 <__pformat_emit_float+0x16a>
   1400043a9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043ad:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043b0:	25 c0 01 00 00       	and    eax,0x1c0
   1400043b5:	85 c0                	test   eax,eax
   1400043b7:	74 11                	je     1400043ca <__pformat_emit_float+0x17b>
   1400043b9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043bd:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400043c0:	8d 50 ff             	lea    edx,[rax-0x1]
   1400043c3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043c7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400043ca:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043ce:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400043d1:	85 c0                	test   eax,eax
   1400043d3:	7e 38                	jle    14000440d <__pformat_emit_float+0x1be>
   1400043d5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043d9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043dc:	25 00 06 00 00       	and    eax,0x600
   1400043e1:	85 c0                	test   eax,eax
   1400043e3:	75 28                	jne    14000440d <__pformat_emit_float+0x1be>
   1400043e5:	eb 11                	jmp    1400043f8 <__pformat_emit_float+0x1a9>
   1400043e7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043eb:	48 89 c2             	mov    rdx,rax
   1400043ee:	b9 20 00 00 00       	mov    ecx,0x20
   1400043f3:	e8 78 ee ff ff       	call   140003270 <__pformat_putc>
   1400043f8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043fc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400043ff:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004402:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004406:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004409:	85 c0                	test   eax,eax
   14000440b:	7f da                	jg     1400043e7 <__pformat_emit_float+0x198>
   14000440d:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004411:	74 13                	je     140004426 <__pformat_emit_float+0x1d7>
   140004413:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004417:	48 89 c2             	mov    rdx,rax
   14000441a:	b9 2d 00 00 00       	mov    ecx,0x2d
   14000441f:	e8 4c ee ff ff       	call   140003270 <__pformat_putc>
   140004424:	eb 42                	jmp    140004468 <__pformat_emit_float+0x219>
   140004426:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000442a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000442d:	25 00 01 00 00       	and    eax,0x100
   140004432:	85 c0                	test   eax,eax
   140004434:	74 13                	je     140004449 <__pformat_emit_float+0x1fa>
   140004436:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000443a:	48 89 c2             	mov    rdx,rax
   14000443d:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004442:	e8 29 ee ff ff       	call   140003270 <__pformat_putc>
   140004447:	eb 1f                	jmp    140004468 <__pformat_emit_float+0x219>
   140004449:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000444d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004450:	83 e0 40             	and    eax,0x40
   140004453:	85 c0                	test   eax,eax
   140004455:	74 11                	je     140004468 <__pformat_emit_float+0x219>
   140004457:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000445b:	48 89 c2             	mov    rdx,rax
   14000445e:	b9 20 00 00 00       	mov    ecx,0x20
   140004463:	e8 08 ee ff ff       	call   140003270 <__pformat_putc>
   140004468:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000446c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000446f:	85 c0                	test   eax,eax
   140004471:	7e 3b                	jle    1400044ae <__pformat_emit_float+0x25f>
   140004473:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004477:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000447a:	25 00 06 00 00       	and    eax,0x600
   14000447f:	3d 00 02 00 00       	cmp    eax,0x200
   140004484:	75 28                	jne    1400044ae <__pformat_emit_float+0x25f>
   140004486:	eb 11                	jmp    140004499 <__pformat_emit_float+0x24a>
   140004488:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000448c:	48 89 c2             	mov    rdx,rax
   14000448f:	b9 30 00 00 00       	mov    ecx,0x30
   140004494:	e8 d7 ed ff ff       	call   140003270 <__pformat_putc>
   140004499:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000449d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400044a0:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400044a3:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400044a7:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400044aa:	85 c0                	test   eax,eax
   1400044ac:	7f da                	jg     140004488 <__pformat_emit_float+0x239>
   1400044ae:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400044b2:	0f 8e a7 00 00 00    	jle    14000455f <__pformat_emit_float+0x310>
   1400044b8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400044bc:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400044bf:	84 c0                	test   al,al
   1400044c1:	74 14                	je     1400044d7 <__pformat_emit_float+0x288>
   1400044c3:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400044c7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400044cb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400044cf:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400044d2:	0f be c0             	movsx  eax,al
   1400044d5:	eb 05                	jmp    1400044dc <__pformat_emit_float+0x28d>
   1400044d7:	b8 30 00 00 00       	mov    eax,0x30
   1400044dc:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400044e0:	89 c1                	mov    ecx,eax
   1400044e2:	e8 89 ed ff ff       	call   140003270 <__pformat_putc>
   1400044e7:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   1400044eb:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400044ef:	74 62                	je     140004553 <__pformat_emit_float+0x304>
   1400044f1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044f5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400044f8:	25 00 10 00 00       	and    eax,0x1000
   1400044fd:	85 c0                	test   eax,eax
   1400044ff:	74 52                	je     140004553 <__pformat_emit_float+0x304>
   140004501:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004505:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140004509:	66 85 c0             	test   ax,ax
   14000450c:	74 45                	je     140004553 <__pformat_emit_float+0x304>
   14000450e:	8b 4d 20             	mov    ecx,DWORD PTR [rbp+0x20]
   140004511:	48 63 c1             	movsxd rax,ecx
   140004514:	48 69 c0 56 55 55 55 	imul   rax,rax,0x55555556
   14000451b:	48 c1 e8 20          	shr    rax,0x20
   14000451f:	48 89 c2             	mov    rdx,rax
   140004522:	89 c8                	mov    eax,ecx
   140004524:	c1 f8 1f             	sar    eax,0x1f
   140004527:	29 c2                	sub    edx,eax
   140004529:	89 d0                	mov    eax,edx
   14000452b:	01 c0                	add    eax,eax
   14000452d:	01 d0                	add    eax,edx
   14000452f:	29 c1                	sub    ecx,eax
   140004531:	89 ca                	mov    edx,ecx
   140004533:	85 d2                	test   edx,edx
   140004535:	75 1c                	jne    140004553 <__pformat_emit_float+0x304>
   140004537:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000453b:	48 83 c0 20          	add    rax,0x20
   14000453f:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004543:	49 89 d0             	mov    r8,rdx
   140004546:	ba 01 00 00 00       	mov    edx,0x1
   14000454b:	48 89 c1             	mov    rcx,rax
   14000454e:	e8 26 ef ff ff       	call   140003479 <__pformat_wputchars>
   140004553:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004557:	0f 8f 5b ff ff ff    	jg     1400044b8 <__pformat_emit_float+0x269>
   14000455d:	eb 11                	jmp    140004570 <__pformat_emit_float+0x321>
   14000455f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004563:	48 89 c2             	mov    rdx,rax
   140004566:	b9 30 00 00 00       	mov    ecx,0x30
   14000456b:	e8 00 ed ff ff       	call   140003270 <__pformat_putc>
   140004570:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004574:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004577:	85 c0                	test   eax,eax
   140004579:	7f 10                	jg     14000458b <__pformat_emit_float+0x33c>
   14000457b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000457f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004582:	25 00 08 00 00       	and    eax,0x800
   140004587:	85 c0                	test   eax,eax
   140004589:	74 0c                	je     140004597 <__pformat_emit_float+0x348>
   14000458b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000458f:	48 89 c1             	mov    rcx,rax
   140004592:	e8 1b fa ff ff       	call   140003fb2 <__pformat_emit_radix_point>
   140004597:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000459b:	79 5f                	jns    1400045fc <__pformat_emit_float+0x3ad>
   14000459d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045a1:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400045a4:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400045a7:	01 c2                	add    edx,eax
   1400045a9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045ad:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400045b0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045b4:	48 89 c2             	mov    rdx,rax
   1400045b7:	b9 30 00 00 00       	mov    ecx,0x30
   1400045bc:	e8 af ec ff ff       	call   140003270 <__pformat_putc>
   1400045c1:	83 45 20 01          	add    DWORD PTR [rbp+0x20],0x1
   1400045c5:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400045c9:	78 e5                	js     1400045b0 <__pformat_emit_float+0x361>
   1400045cb:	eb 2f                	jmp    1400045fc <__pformat_emit_float+0x3ad>
   1400045cd:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400045d1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400045d4:	84 c0                	test   al,al
   1400045d6:	74 14                	je     1400045ec <__pformat_emit_float+0x39d>
   1400045d8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400045dc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400045e0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400045e4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400045e7:	0f be c0             	movsx  eax,al
   1400045ea:	eb 05                	jmp    1400045f1 <__pformat_emit_float+0x3a2>
   1400045ec:	b8 30 00 00 00       	mov    eax,0x30
   1400045f1:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400045f5:	89 c1                	mov    ecx,eax
   1400045f7:	e8 74 ec ff ff       	call   140003270 <__pformat_putc>
   1400045fc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004600:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004603:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004606:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000460a:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   14000460d:	85 c0                	test   eax,eax
   14000460f:	7f bc                	jg     1400045cd <__pformat_emit_float+0x37e>
   140004611:	90                   	nop
   140004612:	90                   	nop
   140004613:	48 83 c4 30          	add    rsp,0x30
   140004617:	5d                   	pop    rbp
   140004618:	c3                   	ret

0000000140004619 <__pformat_emit_efloat>:
   140004619:	55                   	push   rbp
   14000461a:	48 89 e5             	mov    rbp,rsp
   14000461d:	48 83 ec 50          	sub    rsp,0x50
   140004621:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140004624:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004628:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   14000462c:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004630:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140004637:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   14000463b:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000463f:	79 09                	jns    14000464a <__pformat_emit_efloat+0x31>
   140004641:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004648:	eb 05                	jmp    14000464f <__pformat_emit_efloat+0x36>
   14000464a:	b8 00 00 00 00       	mov    eax,0x0
   14000464f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140004653:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004656:	48 98                	cdqe
   140004658:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000465c:	eb 04                	jmp    140004662 <__pformat_emit_efloat+0x49>
   14000465e:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140004662:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004665:	48 63 d0             	movsxd rdx,eax
   140004668:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   14000466f:	48 c1 ea 20          	shr    rdx,0x20
   140004673:	89 d1                	mov    ecx,edx
   140004675:	c1 f9 02             	sar    ecx,0x2
   140004678:	99                   	cdq
   140004679:	89 c8                	mov    eax,ecx
   14000467b:	29 d0                	sub    eax,edx
   14000467d:	89 45 20             	mov    DWORD PTR [rbp+0x20],eax
   140004680:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004684:	75 d8                	jne    14000465e <__pformat_emit_efloat+0x45>
   140004686:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000468a:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   14000468d:	83 f8 ff             	cmp    eax,0xffffffff
   140004690:	75 0b                	jne    14000469d <__pformat_emit_efloat+0x84>
   140004692:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004696:	c7 40 2c 02 00 00 00 	mov    DWORD PTR [rax+0x2c],0x2
   14000469d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046a1:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   1400046a4:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   1400046a7:	7d 0a                	jge    1400046b3 <__pformat_emit_efloat+0x9a>
   1400046a9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046ad:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   1400046b0:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400046b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046b7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400046ba:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   1400046be:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   1400046c1:	7d 15                	jge    1400046d8 <__pformat_emit_efloat+0xbf>
   1400046c3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046c7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400046ca:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   1400046cd:	89 c2                	mov    edx,eax
   1400046cf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046d3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400046d6:	eb 0b                	jmp    1400046e3 <__pformat_emit_efloat+0xca>
   1400046d8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046dc:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400046e3:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400046e7:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400046eb:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400046ee:	49 89 c9             	mov    r9,rcx
   1400046f1:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400046f7:	89 c1                	mov    ecx,eax
   1400046f9:	e8 51 fb ff ff       	call   14000424f <__pformat_emit_float>
   1400046fe:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004702:	8b 50 2c             	mov    edx,DWORD PTR [rax+0x2c]
   140004705:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004709:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000470c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004710:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004713:	0d c0 01 00 00       	or     eax,0x1c0
   140004718:	89 c2                	mov    edx,eax
   14000471a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000471e:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004721:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004725:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004728:	83 e0 20             	and    eax,0x20
   14000472b:	83 c8 45             	or     eax,0x45
   14000472e:	89 c1                	mov    ecx,eax
   140004730:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004734:	48 89 c2             	mov    rdx,rax
   140004737:	e8 34 eb ff ff       	call   140003270 <__pformat_putc>
   14000473c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004740:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004743:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140004746:	83 ea 01             	sub    edx,0x1
   140004749:	01 c2                	add    edx,eax
   14000474b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000474f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004752:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004756:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   14000475a:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000475e:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140004762:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004766:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000476a:	48 89 c1             	mov    rcx,rax
   14000476d:	e8 69 ef ff ff       	call   1400036db <__pformat_int>
   140004772:	90                   	nop
   140004773:	48 83 c4 50          	add    rsp,0x50
   140004777:	5d                   	pop    rbp
   140004778:	c3                   	ret

0000000140004779 <__pformat_float>:
   140004779:	55                   	push   rbp
   14000477a:	53                   	push   rbx
   14000477b:	48 83 ec 58          	sub    rsp,0x58
   14000477f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004784:	48 89 cb             	mov    rbx,rcx
   140004787:	db 2b                	fld    TBYTE PTR [rbx]
   140004789:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000478c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004790:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004794:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004797:	85 c0                	test   eax,eax
   140004799:	79 0b                	jns    1400047a6 <__pformat_float+0x2d>
   14000479b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000479f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   1400047a6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047aa:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400047ad:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   1400047b0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   1400047b3:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   1400047b7:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   1400047bb:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400047bf:	4d 89 c1             	mov    r9,r8
   1400047c2:	49 89 c8             	mov    r8,rcx
   1400047c5:	48 89 c1             	mov    rcx,rax
   1400047c8:	e8 93 f7 ff ff       	call   140003f60 <__pformat_fcvt>
   1400047cd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400047d1:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400047d4:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   1400047d9:	75 17                	jne    1400047f2 <__pformat_float+0x79>
   1400047db:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400047de:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400047e2:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400047e6:	49 89 c8             	mov    r8,rcx
   1400047e9:	89 c1                	mov    ecx,eax
   1400047eb:	e8 74 f9 ff ff       	call   140004164 <__pformat_emit_inf_or_nan>
   1400047f0:	eb 43                	jmp    140004835 <__pformat_float+0xbc>
   1400047f2:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400047f5:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400047f8:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400047fc:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004800:	4d 89 c1             	mov    r9,r8
   140004803:	41 89 c8             	mov    r8d,ecx
   140004806:	89 c1                	mov    ecx,eax
   140004808:	e8 42 fa ff ff       	call   14000424f <__pformat_emit_float>
   14000480d:	eb 11                	jmp    140004820 <__pformat_float+0xa7>
   14000480f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004813:	48 89 c2             	mov    rdx,rax
   140004816:	b9 20 00 00 00       	mov    ecx,0x20
   14000481b:	e8 50 ea ff ff       	call   140003270 <__pformat_putc>
   140004820:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004824:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004827:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000482a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000482e:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004831:	85 c0                	test   eax,eax
   140004833:	7f da                	jg     14000480f <__pformat_float+0x96>
   140004835:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004839:	48 89 c1             	mov    rcx,rax
   14000483c:	e8 4e 17 00 00       	call   140005f8f <__freedtoa>
   140004841:	90                   	nop
   140004842:	48 83 c4 58          	add    rsp,0x58
   140004846:	5b                   	pop    rbx
   140004847:	5d                   	pop    rbp
   140004848:	c3                   	ret

0000000140004849 <__pformat_efloat>:
   140004849:	55                   	push   rbp
   14000484a:	53                   	push   rbx
   14000484b:	48 83 ec 58          	sub    rsp,0x58
   14000484f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004854:	48 89 cb             	mov    rbx,rcx
   140004857:	db 2b                	fld    TBYTE PTR [rbx]
   140004859:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000485c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004860:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004864:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004867:	85 c0                	test   eax,eax
   140004869:	79 0b                	jns    140004876 <__pformat_efloat+0x2d>
   14000486b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000486f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004876:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000487a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000487d:	8d 50 01             	lea    edx,[rax+0x1]
   140004880:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004883:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004886:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000488a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000488e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004892:	4d 89 c1             	mov    r9,r8
   140004895:	49 89 c8             	mov    r8,rcx
   140004898:	48 89 c1             	mov    rcx,rax
   14000489b:	e8 6e f6 ff ff       	call   140003f0e <__pformat_ecvt>
   1400048a0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400048a4:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048a7:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   1400048ac:	75 17                	jne    1400048c5 <__pformat_efloat+0x7c>
   1400048ae:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400048b1:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400048b5:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400048b9:	49 89 c8             	mov    r8,rcx
   1400048bc:	89 c1                	mov    ecx,eax
   1400048be:	e8 a1 f8 ff ff       	call   140004164 <__pformat_emit_inf_or_nan>
   1400048c3:	eb 1b                	jmp    1400048e0 <__pformat_efloat+0x97>
   1400048c5:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400048c8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400048cb:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400048cf:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400048d3:	4d 89 c1             	mov    r9,r8
   1400048d6:	41 89 c8             	mov    r8d,ecx
   1400048d9:	89 c1                	mov    ecx,eax
   1400048db:	e8 39 fd ff ff       	call   140004619 <__pformat_emit_efloat>
   1400048e0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400048e4:	48 89 c1             	mov    rcx,rax
   1400048e7:	e8 a3 16 00 00       	call   140005f8f <__freedtoa>
   1400048ec:	90                   	nop
   1400048ed:	48 83 c4 58          	add    rsp,0x58
   1400048f1:	5b                   	pop    rbx
   1400048f2:	5d                   	pop    rbp
   1400048f3:	c3                   	ret

00000001400048f4 <__pformat_gfloat>:
   1400048f4:	55                   	push   rbp
   1400048f5:	53                   	push   rbx
   1400048f6:	48 83 ec 58          	sub    rsp,0x58
   1400048fa:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400048ff:	48 89 cb             	mov    rbx,rcx
   140004902:	db 2b                	fld    TBYTE PTR [rbx]
   140004904:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140004907:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000490b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000490f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004912:	85 c0                	test   eax,eax
   140004914:	79 0d                	jns    140004923 <__pformat_gfloat+0x2f>
   140004916:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000491a:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004921:	eb 16                	jmp    140004939 <__pformat_gfloat+0x45>
   140004923:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004927:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000492a:	85 c0                	test   eax,eax
   14000492c:	75 0b                	jne    140004939 <__pformat_gfloat+0x45>
   14000492e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004932:	c7 40 10 01 00 00 00 	mov    DWORD PTR [rax+0x10],0x1
   140004939:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000493d:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004940:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004943:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004946:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000494a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000494e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004952:	4d 89 c1             	mov    r9,r8
   140004955:	49 89 c8             	mov    r8,rcx
   140004958:	48 89 c1             	mov    rcx,rax
   14000495b:	e8 ae f5 ff ff       	call   140003f0e <__pformat_ecvt>
   140004960:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004964:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004967:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000496c:	75 1a                	jne    140004988 <__pformat_gfloat+0x94>
   14000496e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004971:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004975:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004979:	49 89 c8             	mov    r8,rcx
   14000497c:	89 c1                	mov    ecx,eax
   14000497e:	e8 e1 f7 ff ff       	call   140004164 <__pformat_emit_inf_or_nan>
   140004983:	e9 14 01 00 00       	jmp    140004a9c <__pformat_gfloat+0x1a8>
   140004988:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000498b:	83 f8 fd             	cmp    eax,0xfffffffd
   14000498e:	0f 8c b2 00 00 00    	jl     140004a46 <__pformat_gfloat+0x152>
   140004994:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004998:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000499b:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000499e:	39 c2                	cmp    edx,eax
   1400049a0:	0f 8c a0 00 00 00    	jl     140004a46 <__pformat_gfloat+0x152>
   1400049a6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049aa:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400049ad:	25 00 08 00 00       	and    eax,0x800
   1400049b2:	85 c0                	test   eax,eax
   1400049b4:	74 15                	je     1400049cb <__pformat_gfloat+0xd7>
   1400049b6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049ba:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400049bd:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400049c0:	29 c2                	sub    edx,eax
   1400049c2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049c6:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400049c9:	eb 20                	jmp    1400049eb <__pformat_gfloat+0xf7>
   1400049cb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400049cf:	48 89 c1             	mov    rcx,rax
   1400049d2:	e8 81 4d 00 00       	call   140009758 <strlen>
   1400049d7:	89 c1                	mov    ecx,eax
   1400049d9:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400049dc:	89 c2                	mov    edx,eax
   1400049de:	89 c8                	mov    eax,ecx
   1400049e0:	29 d0                	sub    eax,edx
   1400049e2:	89 c2                	mov    edx,eax
   1400049e4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049e8:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400049eb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049ef:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400049f2:	85 c0                	test   eax,eax
   1400049f4:	79 0b                	jns    140004a01 <__pformat_gfloat+0x10d>
   1400049f6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049fa:	c7 40 10 00 00 00 00 	mov    DWORD PTR [rax+0x10],0x0
   140004a01:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004a04:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004a07:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   140004a0b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004a0f:	4d 89 c1             	mov    r9,r8
   140004a12:	41 89 c8             	mov    r8d,ecx
   140004a15:	89 c1                	mov    ecx,eax
   140004a17:	e8 33 f8 ff ff       	call   14000424f <__pformat_emit_float>
   140004a1c:	eb 11                	jmp    140004a2f <__pformat_gfloat+0x13b>
   140004a1e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a22:	48 89 c2             	mov    rdx,rax
   140004a25:	b9 20 00 00 00       	mov    ecx,0x20
   140004a2a:	e8 41 e8 ff ff       	call   140003270 <__pformat_putc>
   140004a2f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a33:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004a36:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004a39:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004a3d:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004a40:	85 c0                	test   eax,eax
   140004a42:	7f da                	jg     140004a1e <__pformat_gfloat+0x12a>
   140004a44:	eb 56                	jmp    140004a9c <__pformat_gfloat+0x1a8>
   140004a46:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a4a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004a4d:	25 00 08 00 00       	and    eax,0x800
   140004a52:	85 c0                	test   eax,eax
   140004a54:	74 13                	je     140004a69 <__pformat_gfloat+0x175>
   140004a56:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a5a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a5d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004a60:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a64:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004a67:	eb 18                	jmp    140004a81 <__pformat_gfloat+0x18d>
   140004a69:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004a6d:	48 89 c1             	mov    rcx,rax
   140004a70:	e8 e3 4c 00 00       	call   140009758 <strlen>
   140004a75:	83 e8 01             	sub    eax,0x1
   140004a78:	89 c2                	mov    edx,eax
   140004a7a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a7e:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004a81:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004a84:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004a87:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   140004a8b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004a8f:	4d 89 c1             	mov    r9,r8
   140004a92:	41 89 c8             	mov    r8d,ecx
   140004a95:	89 c1                	mov    ecx,eax
   140004a97:	e8 7d fb ff ff       	call   140004619 <__pformat_emit_efloat>
   140004a9c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004aa0:	48 89 c1             	mov    rcx,rax
   140004aa3:	e8 e7 14 00 00       	call   140005f8f <__freedtoa>
   140004aa8:	90                   	nop
   140004aa9:	48 83 c4 58          	add    rsp,0x58
   140004aad:	5b                   	pop    rbx
   140004aae:	5d                   	pop    rbp
   140004aaf:	c3                   	ret

0000000140004ab0 <__pformat_emit_xfloat>:
   140004ab0:	55                   	push   rbp
   140004ab1:	53                   	push   rbx
   140004ab2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140004ab9:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140004ac0:	00 
   140004ac1:	48 89 cb             	mov    rbx,rcx
   140004ac4:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004ac8:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004acc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004ad0:	66 c7 45 f6 02 00    	mov    WORD PTR [rbp-0xa],0x2
   140004ad6:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004ad9:	48 85 c0             	test   rax,rax
   140004adc:	75 09                	jne    140004ae7 <__pformat_emit_xfloat+0x37>
   140004ade:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004ae2:	66 85 c0             	test   ax,ax
   140004ae5:	74 0b                	je     140004af2 <__pformat_emit_xfloat+0x42>
   140004ae7:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004aeb:	83 e8 03             	sub    eax,0x3
   140004aee:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004af2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004af6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004af9:	85 c0                	test   eax,eax
   140004afb:	0f 88 90 00 00 00    	js     140004b91 <__pformat_emit_xfloat+0xe1>
   140004b01:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b05:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b08:	83 f8 0e             	cmp    eax,0xe
   140004b0b:	0f 8f 80 00 00 00    	jg     140004b91 <__pformat_emit_xfloat+0xe1>
   140004b11:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b14:	48 d1 e8             	shr    rax,1
   140004b17:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b1a:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004b1d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b21:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b24:	b9 0e 00 00 00       	mov    ecx,0xe
   140004b29:	29 c1                	sub    ecx,eax
   140004b2b:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004b32:	41 b8 04 00 00 00    	mov    r8d,0x4
   140004b38:	89 c1                	mov    ecx,eax
   140004b3a:	49 d3 e0             	shl    r8,cl
   140004b3d:	4c 89 c0             	mov    rax,r8
   140004b40:	48 01 d0             	add    rax,rdx
   140004b43:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b46:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b49:	48 85 c0             	test   rax,rax
   140004b4c:	78 0b                	js     140004b59 <__pformat_emit_xfloat+0xa9>
   140004b4e:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b51:	48 01 c0             	add    rax,rax
   140004b54:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b57:	eb 15                	jmp    140004b6e <__pformat_emit_xfloat+0xbe>
   140004b59:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004b5d:	83 c0 04             	add    eax,0x4
   140004b60:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004b64:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b67:	48 c1 e8 03          	shr    rax,0x3
   140004b6b:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b6e:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004b71:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b75:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b78:	b9 0f 00 00 00       	mov    ecx,0xf
   140004b7d:	29 c1                	sub    ecx,eax
   140004b7f:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004b86:	89 c1                	mov    ecx,eax
   140004b88:	48 d3 ea             	shr    rdx,cl
   140004b8b:	48 89 d0             	mov    rax,rdx
   140004b8e:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b91:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b94:	48 85 c0             	test   rax,rax
   140004b97:	75 0f                	jne    140004ba8 <__pformat_emit_xfloat+0xf8>
   140004b99:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b9d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ba0:	85 c0                	test   eax,eax
   140004ba2:	0f 8e f8 00 00 00    	jle    140004ca0 <__pformat_emit_xfloat+0x1f0>
   140004ba8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bac:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004baf:	83 f8 0e             	cmp    eax,0xe
   140004bb2:	7f 1a                	jg     140004bce <__pformat_emit_xfloat+0x11e>
   140004bb4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bb8:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bbb:	85 c0                	test   eax,eax
   140004bbd:	78 0f                	js     140004bce <__pformat_emit_xfloat+0x11e>
   140004bbf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bc3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bc6:	83 c0 01             	add    eax,0x1
   140004bc9:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140004bcc:	eb 07                	jmp    140004bd5 <__pformat_emit_xfloat+0x125>
   140004bce:	c7 45 f0 10 00 00 00 	mov    DWORD PTR [rbp-0x10],0x10
   140004bd5:	e9 bc 00 00 00       	jmp    140004c96 <__pformat_emit_xfloat+0x1e6>
   140004bda:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004bdd:	83 e0 0f             	and    eax,0xf
   140004be0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140004be3:	83 7d f0 01          	cmp    DWORD PTR [rbp-0x10],0x1
   140004be7:	75 36                	jne    140004c1f <__pformat_emit_xfloat+0x16f>
   140004be9:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004bed:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004bf1:	72 1b                	jb     140004c0e <__pformat_emit_xfloat+0x15e>
   140004bf3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bf7:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004bfa:	25 00 08 00 00       	and    eax,0x800
   140004bff:	85 c0                	test   eax,eax
   140004c01:	75 0b                	jne    140004c0e <__pformat_emit_xfloat+0x15e>
   140004c03:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c07:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c0a:	85 c0                	test   eax,eax
   140004c0c:	7e 2d                	jle    140004c3b <__pformat_emit_xfloat+0x18b>
   140004c0e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c12:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c16:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c1a:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004c1d:	eb 1c                	jmp    140004c3b <__pformat_emit_xfloat+0x18b>
   140004c1f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c23:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c26:	85 c0                	test   eax,eax
   140004c28:	7e 11                	jle    140004c3b <__pformat_emit_xfloat+0x18b>
   140004c2a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c2e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c31:	8d 50 ff             	lea    edx,[rax-0x1]
   140004c34:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c38:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004c3b:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140004c3f:	75 15                	jne    140004c56 <__pformat_emit_xfloat+0x1a6>
   140004c41:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c45:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004c49:	72 0b                	jb     140004c56 <__pformat_emit_xfloat+0x1a6>
   140004c4b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c4f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c52:	85 c0                	test   eax,eax
   140004c54:	78 32                	js     140004c88 <__pformat_emit_xfloat+0x1d8>
   140004c56:	83 7d e4 09          	cmp    DWORD PTR [rbp-0x1c],0x9
   140004c5a:	76 16                	jbe    140004c72 <__pformat_emit_xfloat+0x1c2>
   140004c5c:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004c5f:	8d 50 37             	lea    edx,[rax+0x37]
   140004c62:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c66:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c69:	83 e0 20             	and    eax,0x20
   140004c6c:	09 d0                	or     eax,edx
   140004c6e:	89 c1                	mov    ecx,eax
   140004c70:	eb 08                	jmp    140004c7a <__pformat_emit_xfloat+0x1ca>
   140004c72:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004c75:	83 c0 30             	add    eax,0x30
   140004c78:	89 c1                	mov    ecx,eax
   140004c7a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c7e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c82:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c86:	88 08                	mov    BYTE PTR [rax],cl
   140004c88:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004c8b:	48 c1 e8 04          	shr    rax,0x4
   140004c8f:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004c92:	83 6d f0 01          	sub    DWORD PTR [rbp-0x10],0x1
   140004c96:	83 7d f0 00          	cmp    DWORD PTR [rbp-0x10],0x0
   140004c9a:	0f 8f 3a ff ff ff    	jg     140004bda <__pformat_emit_xfloat+0x12a>
   140004ca0:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004ca4:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140004ca8:	75 39                	jne    140004ce3 <__pformat_emit_xfloat+0x233>
   140004caa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cae:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004cb1:	85 c0                	test   eax,eax
   140004cb3:	7f 10                	jg     140004cc5 <__pformat_emit_xfloat+0x215>
   140004cb5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cb9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004cbc:	25 00 08 00 00       	and    eax,0x800
   140004cc1:	85 c0                	test   eax,eax
   140004cc3:	74 0f                	je     140004cd4 <__pformat_emit_xfloat+0x224>
   140004cc5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004cc9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004ccd:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004cd1:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004cd4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004cd8:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004cdc:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004ce0:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140004ce3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ce7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004cea:	85 c0                	test   eax,eax
   140004cec:	0f 8e e3 00 00 00    	jle    140004dd5 <__pformat_emit_xfloat+0x325>
   140004cf2:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004cf6:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004cfa:	48 29 c2             	sub    rdx,rax
   140004cfd:	89 55 ec             	mov    DWORD PTR [rbp-0x14],edx
   140004d00:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004d04:	98                   	cwde
   140004d05:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004d08:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d0c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004d0f:	85 c0                	test   eax,eax
   140004d11:	7e 0a                	jle    140004d1d <__pformat_emit_xfloat+0x26d>
   140004d13:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d17:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004d1a:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004d1d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d21:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d24:	25 c0 01 00 00       	and    eax,0x1c0
   140004d29:	85 c0                	test   eax,eax
   140004d2b:	74 07                	je     140004d34 <__pformat_emit_xfloat+0x284>
   140004d2d:	b8 06 00 00 00       	mov    eax,0x6
   140004d32:	eb 05                	jmp    140004d39 <__pformat_emit_xfloat+0x289>
   140004d34:	b8 05 00 00 00       	mov    eax,0x5
   140004d39:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004d3c:	eb 0f                	jmp    140004d4d <__pformat_emit_xfloat+0x29d>
   140004d3e:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
   140004d42:	0f b7 45 f6          	movzx  eax,WORD PTR [rbp-0xa]
   140004d46:	83 c0 01             	add    eax,0x1
   140004d49:	66 89 45 f6          	mov    WORD PTR [rbp-0xa],ax
   140004d4d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140004d50:	48 63 d0             	movsxd rdx,eax
   140004d53:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   140004d5a:	48 c1 ea 20          	shr    rdx,0x20
   140004d5e:	89 d1                	mov    ecx,edx
   140004d60:	c1 f9 02             	sar    ecx,0x2
   140004d63:	99                   	cdq
   140004d64:	89 c8                	mov    eax,ecx
   140004d66:	29 d0                	sub    eax,edx
   140004d68:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004d6b:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140004d6f:	75 cd                	jne    140004d3e <__pformat_emit_xfloat+0x28e>
   140004d71:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d75:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d78:	39 45 ec             	cmp    DWORD PTR [rbp-0x14],eax
   140004d7b:	7d 4d                	jge    140004dca <__pformat_emit_xfloat+0x31a>
   140004d7d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d81:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d84:	2b 45 ec             	sub    eax,DWORD PTR [rbp-0x14]
   140004d87:	89 c2                	mov    edx,eax
   140004d89:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d8d:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004d90:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d94:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d97:	25 00 06 00 00       	and    eax,0x600
   140004d9c:	85 c0                	test   eax,eax
   140004d9e:	75 35                	jne    140004dd5 <__pformat_emit_xfloat+0x325>
   140004da0:	eb 11                	jmp    140004db3 <__pformat_emit_xfloat+0x303>
   140004da2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004da6:	48 89 c2             	mov    rdx,rax
   140004da9:	b9 20 00 00 00       	mov    ecx,0x20
   140004dae:	e8 bd e4 ff ff       	call   140003270 <__pformat_putc>
   140004db3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004db7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004dba:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004dbd:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004dc1:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004dc4:	85 c0                	test   eax,eax
   140004dc6:	7f da                	jg     140004da2 <__pformat_emit_xfloat+0x2f2>
   140004dc8:	eb 0b                	jmp    140004dd5 <__pformat_emit_xfloat+0x325>
   140004dca:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dce:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004dd5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dd9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004ddc:	25 80 00 00 00       	and    eax,0x80
   140004de1:	85 c0                	test   eax,eax
   140004de3:	74 13                	je     140004df8 <__pformat_emit_xfloat+0x348>
   140004de5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004de9:	48 89 c2             	mov    rdx,rax
   140004dec:	b9 2d 00 00 00       	mov    ecx,0x2d
   140004df1:	e8 7a e4 ff ff       	call   140003270 <__pformat_putc>
   140004df6:	eb 42                	jmp    140004e3a <__pformat_emit_xfloat+0x38a>
   140004df8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dfc:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004dff:	25 00 01 00 00       	and    eax,0x100
   140004e04:	85 c0                	test   eax,eax
   140004e06:	74 13                	je     140004e1b <__pformat_emit_xfloat+0x36b>
   140004e08:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e0c:	48 89 c2             	mov    rdx,rax
   140004e0f:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004e14:	e8 57 e4 ff ff       	call   140003270 <__pformat_putc>
   140004e19:	eb 1f                	jmp    140004e3a <__pformat_emit_xfloat+0x38a>
   140004e1b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e1f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e22:	83 e0 40             	and    eax,0x40
   140004e25:	85 c0                	test   eax,eax
   140004e27:	74 11                	je     140004e3a <__pformat_emit_xfloat+0x38a>
   140004e29:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e2d:	48 89 c2             	mov    rdx,rax
   140004e30:	b9 20 00 00 00       	mov    ecx,0x20
   140004e35:	e8 36 e4 ff ff       	call   140003270 <__pformat_putc>
   140004e3a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e3e:	48 89 c2             	mov    rdx,rax
   140004e41:	b9 30 00 00 00       	mov    ecx,0x30
   140004e46:	e8 25 e4 ff ff       	call   140003270 <__pformat_putc>
   140004e4b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e4f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e52:	83 e0 20             	and    eax,0x20
   140004e55:	83 c8 58             	or     eax,0x58
   140004e58:	89 c1                	mov    ecx,eax
   140004e5a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e5e:	48 89 c2             	mov    rdx,rax
   140004e61:	e8 0a e4 ff ff       	call   140003270 <__pformat_putc>
   140004e66:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e6a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004e6d:	85 c0                	test   eax,eax
   140004e6f:	7e 54                	jle    140004ec5 <__pformat_emit_xfloat+0x415>
   140004e71:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e75:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e78:	25 00 02 00 00       	and    eax,0x200
   140004e7d:	85 c0                	test   eax,eax
   140004e7f:	74 44                	je     140004ec5 <__pformat_emit_xfloat+0x415>
   140004e81:	eb 11                	jmp    140004e94 <__pformat_emit_xfloat+0x3e4>
   140004e83:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e87:	48 89 c2             	mov    rdx,rax
   140004e8a:	b9 30 00 00 00       	mov    ecx,0x30
   140004e8f:	e8 dc e3 ff ff       	call   140003270 <__pformat_putc>
   140004e94:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e98:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004e9b:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004e9e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004ea2:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004ea5:	85 c0                	test   eax,eax
   140004ea7:	7f da                	jg     140004e83 <__pformat_emit_xfloat+0x3d3>
   140004ea9:	eb 1a                	jmp    140004ec5 <__pformat_emit_xfloat+0x415>
   140004eab:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   140004eb0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004eb4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004eb7:	0f be c0             	movsx  eax,al
   140004eba:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004ebe:	89 c1                	mov    ecx,eax
   140004ec0:	e8 32 f2 ff ff       	call   1400040f7 <__pformat_emit_numeric_value>
   140004ec5:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004ec9:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004ecd:	72 dc                	jb     140004eab <__pformat_emit_xfloat+0x3fb>
   140004ecf:	eb 11                	jmp    140004ee2 <__pformat_emit_xfloat+0x432>
   140004ed1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ed5:	48 89 c2             	mov    rdx,rax
   140004ed8:	b9 30 00 00 00       	mov    ecx,0x30
   140004edd:	e8 8e e3 ff ff       	call   140003270 <__pformat_putc>
   140004ee2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ee6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ee9:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004eec:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004ef0:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   140004ef3:	85 c0                	test   eax,eax
   140004ef5:	7f da                	jg     140004ed1 <__pformat_emit_xfloat+0x421>
   140004ef7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004efb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004efe:	83 e0 20             	and    eax,0x20
   140004f01:	83 c8 50             	or     eax,0x50
   140004f04:	89 c1                	mov    ecx,eax
   140004f06:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f0a:	48 89 c2             	mov    rdx,rax
   140004f0d:	e8 5e e3 ff ff       	call   140003270 <__pformat_putc>
   140004f12:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f16:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004f19:	0f bf 45 f6          	movsx  eax,WORD PTR [rbp-0xa]
   140004f1d:	01 c2                	add    edx,eax
   140004f1f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f23:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004f26:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f2a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004f2d:	0d c0 01 00 00       	or     eax,0x1c0
   140004f32:	89 c2                	mov    edx,eax
   140004f34:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f38:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004f3b:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004f3f:	66 85 c0             	test   ax,ax
   140004f42:	79 09                	jns    140004f4d <__pformat_emit_xfloat+0x49d>
   140004f44:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004f4b:	eb 05                	jmp    140004f52 <__pformat_emit_xfloat+0x4a2>
   140004f4d:	b8 00 00 00 00       	mov    eax,0x0
   140004f52:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140004f56:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004f5a:	48 0f bf c0          	movsx  rax,ax
   140004f5e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004f62:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140004f66:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140004f6a:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   140004f6e:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
   140004f72:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004f76:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140004f7a:	48 89 c1             	mov    rcx,rax
   140004f7d:	e8 59 e7 ff ff       	call   1400036db <__pformat_int>
   140004f82:	90                   	nop
   140004f83:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140004f8a:	5b                   	pop    rbx
   140004f8b:	5d                   	pop    rbp
   140004f8c:	c3                   	ret

0000000140004f8d <__pformat_xldouble>:
   140004f8d:	55                   	push   rbp
   140004f8e:	53                   	push   rbx
   140004f8f:	48 83 ec 78          	sub    rsp,0x78
   140004f93:	48 8d 6c 24 70       	lea    rbp,[rsp+0x70]
   140004f98:	48 89 cb             	mov    rbx,rcx
   140004f9b:	db 2b                	fld    TBYTE PTR [rbx]
   140004f9d:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004fa0:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004fa4:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004fab:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004faf:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004fb2:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004fb5:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140004fb9:	48 89 c1             	mov    rcx,rax
   140004fbc:	e8 e5 ed ff ff       	call   140003da6 <init_fpreg_ldouble>
   140004fc1:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004fc4:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004fc7:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004fcb:	48 89 c1             	mov    rcx,rax
   140004fce:	e8 ed 3d 00 00       	call   140008dc0 <__isnanl>
   140004fd3:	85 c0                	test   eax,eax
   140004fd5:	74 1d                	je     140004ff4 <__pformat_xldouble+0x67>
   140004fd7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004fda:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004fde:	48 8d 15 61 63 00 00 	lea    rdx,[rip+0x6361]        # 14000b346 <.rdata+0x16>
   140004fe5:	49 89 c8             	mov    r8,rcx
   140004fe8:	89 c1                	mov    ecx,eax
   140004fea:	e8 75 f1 ff ff       	call   140004164 <__pformat_emit_inf_or_nan>
   140004fef:	e9 aa 00 00 00       	jmp    14000509e <__pformat_xldouble+0x111>
   140004ff4:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004ff8:	98                   	cwde
   140004ff9:	25 00 80 00 00       	and    eax,0x8000
   140004ffe:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005001:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005005:	74 12                	je     140005019 <__pformat_xldouble+0x8c>
   140005007:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000500b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000500e:	0c 80                	or     al,0x80
   140005010:	89 c2                	mov    edx,eax
   140005012:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005016:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005019:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   14000501c:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   14000501f:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140005023:	48 89 c1             	mov    rcx,rax
   140005026:	e8 a5 3c 00 00       	call   140008cd0 <__fpclassifyl>
   14000502b:	3d 00 05 00 00       	cmp    eax,0x500
   140005030:	75 1a                	jne    14000504c <__pformat_xldouble+0xbf>
   140005032:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005035:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140005039:	48 8d 15 0a 63 00 00 	lea    rdx,[rip+0x630a]        # 14000b34a <.rdata+0x1a>
   140005040:	49 89 c8             	mov    r8,rcx
   140005043:	89 c1                	mov    ecx,eax
   140005045:	e8 1a f1 ff ff       	call   140004164 <__pformat_emit_inf_or_nan>
   14000504a:	eb 52                	jmp    14000509e <__pformat_xldouble+0x111>
   14000504c:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005050:	66 25 ff 7f          	and    ax,0x7fff
   140005054:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005058:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000505c:	66 85 c0             	test   ax,ax
   14000505f:	75 11                	jne    140005072 <__pformat_xldouble+0xe5>
   140005061:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005065:	48 85 c0             	test   rax,rax
   140005068:	74 14                	je     14000507e <__pformat_xldouble+0xf1>
   14000506a:	66 c7 45 e8 02 c0    	mov    WORD PTR [rbp-0x18],0xc002
   140005070:	eb 0c                	jmp    14000507e <__pformat_xldouble+0xf1>
   140005072:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005076:	66 2d ff 3f          	sub    ax,0x3fff
   14000507a:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   14000507e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005082:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140005086:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   14000508a:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
   14000508e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140005092:	48 8d 45 b0          	lea    rax,[rbp-0x50]
   140005096:	48 89 c1             	mov    rcx,rax
   140005099:	e8 12 fa ff ff       	call   140004ab0 <__pformat_emit_xfloat>
   14000509e:	90                   	nop
   14000509f:	48 83 c4 78          	add    rsp,0x78
   1400050a3:	5b                   	pop    rbx
   1400050a4:	5d                   	pop    rbp
   1400050a5:	c3                   	ret

00000001400050a6 <__pformat_xdouble>:
   1400050a6:	55                   	push   rbp
   1400050a7:	48 89 e5             	mov    rbp,rsp
   1400050aa:	48 83 ec 60          	sub    rsp,0x60
   1400050ae:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   1400050b3:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400050b7:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400050be:	dd 45 10             	fld    QWORD PTR [rbp+0x10]
   1400050c1:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   1400050c5:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   1400050c8:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
   1400050cc:	48 89 c1             	mov    rcx,rax
   1400050cf:	e8 d2 ec ff ff       	call   140003da6 <init_fpreg_ldouble>
   1400050d4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400050d8:	66 48 0f 6e c0       	movq   xmm0,rax
   1400050dd:	e8 7e 3c 00 00       	call   140008d60 <__isnan>
   1400050e2:	85 c0                	test   eax,eax
   1400050e4:	74 1d                	je     140005103 <__pformat_xdouble+0x5d>
   1400050e6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400050e9:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   1400050ed:	48 8d 15 52 62 00 00 	lea    rdx,[rip+0x6252]        # 14000b346 <.rdata+0x16>
   1400050f4:	49 89 c8             	mov    r8,rcx
   1400050f7:	89 c1                	mov    ecx,eax
   1400050f9:	e8 66 f0 ff ff       	call   140004164 <__pformat_emit_inf_or_nan>
   1400050fe:	e9 f9 00 00 00       	jmp    1400051fc <__pformat_xdouble+0x156>
   140005103:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005107:	98                   	cwde
   140005108:	25 00 80 00 00       	and    eax,0x8000
   14000510d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005110:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005114:	74 12                	je     140005128 <__pformat_xdouble+0x82>
   140005116:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000511a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000511d:	0c 80                	or     al,0x80
   14000511f:	89 c2                	mov    edx,eax
   140005121:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005125:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005128:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000512c:	66 48 0f 6e c0       	movq   xmm0,rax
   140005131:	e8 1a 3b 00 00       	call   140008c50 <__fpclassify>
   140005136:	3d 00 05 00 00       	cmp    eax,0x500
   14000513b:	75 1d                	jne    14000515a <__pformat_xdouble+0xb4>
   14000513d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005140:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   140005144:	48 8d 15 ff 61 00 00 	lea    rdx,[rip+0x61ff]        # 14000b34a <.rdata+0x1a>
   14000514b:	49 89 c8             	mov    r8,rcx
   14000514e:	89 c1                	mov    ecx,eax
   140005150:	e8 0f f0 ff ff       	call   140004164 <__pformat_emit_inf_or_nan>
   140005155:	e9 a2 00 00 00       	jmp    1400051fc <__pformat_xdouble+0x156>
   14000515a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000515e:	66 25 ff 7f          	and    ax,0x7fff
   140005162:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005166:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000516a:	66 85 c0             	test   ax,ax
   14000516d:	74 3b                	je     1400051aa <__pformat_xdouble+0x104>
   14000516f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005173:	66 3d 00 3c          	cmp    ax,0x3c00
   140005177:	7f 31                	jg     1400051aa <__pformat_xdouble+0x104>
   140005179:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000517d:	98                   	cwde
   14000517e:	ba 01 3c 00 00       	mov    edx,0x3c01
   140005183:	29 c2                	sub    edx,eax
   140005185:	89 55 f8             	mov    DWORD PTR [rbp-0x8],edx
   140005188:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   14000518c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000518f:	89 c1                	mov    ecx,eax
   140005191:	48 d3 ea             	shr    rdx,cl
   140005194:	48 89 d0             	mov    rax,rdx
   140005197:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000519b:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000519f:	89 c2                	mov    edx,eax
   1400051a1:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400051a4:	01 d0                	add    eax,edx
   1400051a6:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   1400051aa:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400051ae:	66 85 c0             	test   ax,ax
   1400051b1:	75 11                	jne    1400051c4 <__pformat_xdouble+0x11e>
   1400051b3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400051b7:	48 85 c0             	test   rax,rax
   1400051ba:	74 14                	je     1400051d0 <__pformat_xdouble+0x12a>
   1400051bc:	66 c7 45 e8 05 fc    	mov    WORD PTR [rbp-0x18],0xfc05
   1400051c2:	eb 0c                	jmp    1400051d0 <__pformat_xdouble+0x12a>
   1400051c4:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400051c8:	66 2d fc 3f          	sub    ax,0x3ffc
   1400051cc:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   1400051d0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400051d4:	48 c1 e8 03          	shr    rax,0x3
   1400051d8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400051dc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400051e0:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400051e4:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400051e8:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   1400051ec:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400051f0:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   1400051f4:	48 89 c1             	mov    rcx,rax
   1400051f7:	e8 b4 f8 ff ff       	call   140004ab0 <__pformat_emit_xfloat>
   1400051fc:	90                   	nop
   1400051fd:	48 83 c4 60          	add    rsp,0x60
   140005201:	5d                   	pop    rbp
   140005202:	c3                   	ret

0000000140005203 <__mingw_pformat>:
   140005203:	55                   	push   rbp
   140005204:	48 89 e5             	mov    rbp,rsp
   140005207:	48 81 ec d0 00 00 00 	sub    rsp,0xd0
   14000520e:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005211:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005215:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005219:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   14000521d:	e8 a6 44 00 00       	call   1400096c8 <_errno>
   140005222:	8b 00                	mov    eax,DWORD PTR [rax]
   140005224:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140005227:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000522b:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   14000522f:	81 65 10 00 60 00 00 	and    DWORD PTR [rbp+0x10],0x6000
   140005236:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140005239:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000523c:	c7 45 ac ff ff ff ff 	mov    DWORD PTR [rbp-0x54],0xffffffff
   140005243:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   14000524a:	c7 45 b4 fd ff ff ff 	mov    DWORD PTR [rbp-0x4c],0xfffffffd
   140005251:	66 c7 45 b8 00 00    	mov    WORD PTR [rbp-0x48],0x0
   140005257:	c7 45 bc 00 00 00 00 	mov    DWORD PTR [rbp-0x44],0x0
   14000525e:	66 c7 45 c0 00 00    	mov    WORD PTR [rbp-0x40],0x0
   140005264:	c7 45 c4 00 00 00 00 	mov    DWORD PTR [rbp-0x3c],0x0
   14000526b:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   14000526e:	89 45 c8             	mov    DWORD PTR [rbp-0x38],eax
   140005271:	c7 45 cc ff ff ff ff 	mov    DWORD PTR [rbp-0x34],0xffffffff
   140005278:	e9 27 0c 00 00       	jmp    140005ea4 <__mingw_pformat+0xca1>
   14000527d:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005281:	0f 85 0f 0c 00 00    	jne    140005e96 <__mingw_pformat+0xc93>
   140005287:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000528e:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005295:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005299:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000529d:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   1400052a1:	48 83 c0 0c          	add    rax,0xc
   1400052a5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400052a9:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400052ac:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400052af:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   1400052b6:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400052b9:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   1400052bc:	e9 c4 0b 00 00       	jmp    140005e85 <__mingw_pformat+0xc82>
   1400052c1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400052c5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400052c9:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400052cd:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400052d0:	0f be c0             	movsx  eax,al
   1400052d3:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400052d6:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   1400052da:	0f 84 94 09 00 00    	je     140005c74 <__mingw_pformat+0xa71>
   1400052e0:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   1400052e4:	0f 8f 02 0b 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   1400052ea:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   1400052ee:	0f 84 eb 03 00 00    	je     1400056df <__mingw_pformat+0x4dc>
   1400052f4:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   1400052f8:	0f 8f ee 0a 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   1400052fe:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   140005302:	0f 84 31 09 00 00    	je     140005c39 <__mingw_pformat+0xa36>
   140005308:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   14000530c:	0f 8f da 0a 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   140005312:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   140005316:	0f 84 c3 03 00 00    	je     1400056df <__mingw_pformat+0x4dc>
   14000531c:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   140005320:	0f 8f c6 0a 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   140005326:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   14000532a:	0f 84 31 09 00 00    	je     140005c61 <__mingw_pformat+0xa5e>
   140005330:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   140005334:	0f 8f b2 0a 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   14000533a:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   14000533e:	0f 84 31 03 00 00    	je     140005675 <__mingw_pformat+0x472>
   140005344:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   140005348:	0f 8f 9e 0a 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   14000534e:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   140005352:	0f 84 28 05 00 00    	je     140005880 <__mingw_pformat+0x67d>
   140005358:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   14000535c:	0f 8f 8a 0a 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   140005362:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005366:	0f 84 73 03 00 00    	je     1400056df <__mingw_pformat+0x4dc>
   14000536c:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005370:	0f 8f 76 0a 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   140005376:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   14000537a:	0f 84 4d 07 00 00    	je     140005acd <__mingw_pformat+0x8ca>
   140005380:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   140005384:	0f 8f 62 0a 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   14000538a:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   14000538e:	0f 84 2d 03 00 00    	je     1400056c1 <__mingw_pformat+0x4be>
   140005394:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   140005398:	0f 8f 4e 0a 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   14000539e:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   1400053a2:	0f 84 65 08 00 00    	je     140005c0d <__mingw_pformat+0xa0a>
   1400053a8:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   1400053ac:	0f 8f 3a 0a 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   1400053b2:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   1400053b6:	0f 84 db 07 00 00    	je     140005b97 <__mingw_pformat+0x994>
   1400053bc:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   1400053c0:	0f 8f 26 0a 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   1400053c6:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   1400053ca:	0f 84 ee 03 00 00    	je     1400057be <__mingw_pformat+0x5bb>
   1400053d0:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   1400053d4:	0f 8f 12 0a 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   1400053da:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   1400053de:	0f 84 87 07 00 00    	je     140005b6b <__mingw_pformat+0x968>
   1400053e4:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   1400053e8:	0f 8f fe 09 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   1400053ee:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   1400053f2:	0f 84 f3 05 00 00    	je     1400059eb <__mingw_pformat+0x7e8>
   1400053f8:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   1400053fc:	0f 8f ea 09 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   140005402:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   140005406:	0f 84 61 05 00 00    	je     14000596d <__mingw_pformat+0x76a>
   14000540c:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   140005410:	0f 8f d6 09 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   140005416:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   14000541a:	0f 84 cf 04 00 00    	je     1400058ef <__mingw_pformat+0x6ec>
   140005420:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   140005424:	0f 8f c2 09 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   14000542a:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   14000542e:	0f 84 8a 03 00 00    	je     1400057be <__mingw_pformat+0x5bb>
   140005434:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   140005438:	0f 8f ae 09 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   14000543e:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   140005442:	0f 84 b5 01 00 00    	je     1400055fd <__mingw_pformat+0x3fa>
   140005448:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   14000544c:	0f 8f 9a 09 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   140005452:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005456:	0f 84 83 02 00 00    	je     1400056df <__mingw_pformat+0x4dc>
   14000545c:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005460:	0f 8f 86 09 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   140005466:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   14000546a:	0f 84 f9 05 00 00    	je     140005a69 <__mingw_pformat+0x866>
   140005470:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   140005474:	0f 8f 72 09 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   14000547a:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   14000547e:	0f 84 5b 02 00 00    	je     1400056df <__mingw_pformat+0x4dc>
   140005484:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   140005488:	0f 8f 5e 09 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   14000548e:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   140005492:	0f 84 d6 01 00 00    	je     14000566e <__mingw_pformat+0x46b>
   140005498:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   14000549c:	0f 8f 4a 09 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   1400054a2:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   1400054a6:	0f 84 a0 07 00 00    	je     140005c4c <__mingw_pformat+0xa49>
   1400054ac:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   1400054b0:	0f 8f 36 09 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   1400054b6:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   1400054ba:	0f 84 ea 06 00 00    	je     140005baa <__mingw_pformat+0x9a7>
   1400054c0:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   1400054c4:	0f 8f 22 09 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   1400054ca:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   1400054ce:	0f 84 20 05 00 00    	je     1400059f4 <__mingw_pformat+0x7f1>
   1400054d4:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   1400054d8:	0f 8f 0e 09 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   1400054de:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   1400054e2:	0f 84 8e 04 00 00    	je     140005976 <__mingw_pformat+0x773>
   1400054e8:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   1400054ec:	0f 8f fa 08 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   1400054f2:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   1400054f6:	0f 84 fc 03 00 00    	je     1400058f8 <__mingw_pformat+0x6f5>
   1400054fc:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   140005500:	0f 8f e6 08 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   140005506:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   14000550a:	0f 84 e6 00 00 00    	je     1400055f6 <__mingw_pformat+0x3f3>
   140005510:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   140005514:	0f 8f d2 08 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   14000551a:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   14000551e:	0f 84 bb 01 00 00    	je     1400056df <__mingw_pformat+0x4dc>
   140005524:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   140005528:	0f 8f be 08 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   14000552e:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   140005532:	0f 84 3a 05 00 00    	je     140005a72 <__mingw_pformat+0x86f>
   140005538:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   14000553c:	0f 8f aa 08 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   140005542:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005546:	0f 84 8c 08 00 00    	je     140005dd8 <__mingw_pformat+0xbd5>
   14000554c:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005550:	0f 8f 96 08 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   140005556:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   14000555a:	0f 84 27 07 00 00    	je     140005c87 <__mingw_pformat+0xa84>
   140005560:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   140005564:	0f 8f 82 08 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   14000556a:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   14000556e:	0f 84 db 07 00 00    	je     140005d4f <__mingw_pformat+0xb4c>
   140005574:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   140005578:	0f 8f 6e 08 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   14000557e:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   140005582:	0f 84 af 07 00 00    	je     140005d37 <__mingw_pformat+0xb34>
   140005588:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   14000558c:	0f 8f 5a 08 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   140005592:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005596:	0f 84 1c 07 00 00    	je     140005cb8 <__mingw_pformat+0xab5>
   14000559c:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   1400055a0:	0f 8f 46 08 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   1400055a6:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   1400055aa:	0f 84 b7 07 00 00    	je     140005d67 <__mingw_pformat+0xb64>
   1400055b0:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   1400055b4:	0f 8f 32 08 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   1400055ba:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   1400055be:	74 23                	je     1400055e3 <__mingw_pformat+0x3e0>
   1400055c0:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   1400055c4:	0f 8f 22 08 00 00    	jg     140005dec <__mingw_pformat+0xbe9>
   1400055ca:	83 7d e8 20          	cmp    DWORD PTR [rbp-0x18],0x20
   1400055ce:	0f 84 ec 07 00 00    	je     140005dc0 <__mingw_pformat+0xbbd>
   1400055d4:	83 7d e8 23          	cmp    DWORD PTR [rbp-0x18],0x23
   1400055d8:	0f 84 41 07 00 00    	je     140005d1f <__mingw_pformat+0xb1c>
   1400055de:	e9 09 08 00 00       	jmp    140005dec <__mingw_pformat+0xbe9>
   1400055e3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055e7:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400055ea:	89 c1                	mov    ecx,eax
   1400055ec:	e8 7f dc ff ff       	call   140003270 <__pformat_putc>
   1400055f1:	e9 82 fc ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   1400055f6:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   1400055fd:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005604:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005608:	74 06                	je     140005610 <__mingw_pformat+0x40d>
   14000560a:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000560e:	75 30                	jne    140005640 <__mingw_pformat+0x43d>
   140005610:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005614:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005618:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000561c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000561e:	66 89 45 8e          	mov    WORD PTR [rbp-0x72],ax
   140005622:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005626:	48 8d 45 8e          	lea    rax,[rbp-0x72]
   14000562a:	49 89 d0             	mov    r8,rdx
   14000562d:	ba 01 00 00 00       	mov    edx,0x1
   140005632:	48 89 c1             	mov    rcx,rax
   140005635:	e8 3f de ff ff       	call   140003479 <__pformat_wputchars>
   14000563a:	90                   	nop
   14000563b:	e9 38 fc ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   140005640:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005644:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005648:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000564c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000564e:	88 45 90             	mov    BYTE PTR [rbp-0x70],al
   140005651:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005655:	48 8d 45 90          	lea    rax,[rbp-0x70]
   140005659:	49 89 d0             	mov    r8,rdx
   14000565c:	ba 01 00 00 00       	mov    edx,0x1
   140005661:	48 89 c1             	mov    rcx,rax
   140005664:	e8 8b dc ff ff       	call   1400032f4 <__pformat_putchars>
   140005669:	e9 0a fc ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   14000566e:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005675:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005679:	74 06                	je     140005681 <__mingw_pformat+0x47e>
   14000567b:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000567f:	75 20                	jne    1400056a1 <__mingw_pformat+0x49e>
   140005681:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005685:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005689:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000568d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005690:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005694:	48 89 c1             	mov    rcx,rax
   140005697:	e8 29 df ff ff       	call   1400035c5 <__pformat_wcputs>
   14000569c:	e9 d7 fb ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   1400056a1:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056a5:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056a9:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056ad:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400056b0:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400056b4:	48 89 c1             	mov    rcx,rax
   1400056b7:	e8 37 dd ff ff       	call   1400033f3 <__pformat_puts>
   1400056bc:	e9 b7 fb ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   1400056c1:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400056c4:	89 c1                	mov    ecx,eax
   1400056c6:	e8 85 40 00 00       	call   140009750 <strerror>
   1400056cb:	48 89 c1             	mov    rcx,rax
   1400056ce:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   1400056d2:	48 89 c2             	mov    rdx,rax
   1400056d5:	e8 19 dd ff ff       	call   1400033f3 <__pformat_puts>
   1400056da:	e9 99 fb ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   1400056df:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400056e2:	80 e4 fe             	and    ah,0xfe
   1400056e5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400056e8:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400056ec:	75 15                	jne    140005703 <__mingw_pformat+0x500>
   1400056ee:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056f2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056f6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056fa:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400056fd:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005701:	eb 54                	jmp    140005757 <__mingw_pformat+0x554>
   140005703:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005707:	75 16                	jne    14000571f <__mingw_pformat+0x51c>
   140005709:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000570d:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005711:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005715:	8b 00                	mov    eax,DWORD PTR [rax]
   140005717:	89 c0                	mov    eax,eax
   140005719:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000571d:	eb 38                	jmp    140005757 <__mingw_pformat+0x554>
   14000571f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005723:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005727:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000572b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000572d:	89 c0                	mov    eax,eax
   14000572f:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005733:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005737:	75 0d                	jne    140005746 <__mingw_pformat+0x543>
   140005739:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   14000573d:	0f b7 c0             	movzx  eax,ax
   140005740:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005744:	eb 11                	jmp    140005757 <__mingw_pformat+0x554>
   140005746:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   14000574a:	75 0b                	jne    140005757 <__mingw_pformat+0x554>
   14000574c:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   140005750:	0f b6 c0             	movzx  eax,al
   140005753:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005757:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   14000575b:	75 2e                	jne    14000578b <__mingw_pformat+0x588>
   14000575d:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005761:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005765:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000576c:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005773:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005777:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   14000577e:	48 89 c1             	mov    rcx,rax
   140005781:	e8 55 df ff ff       	call   1400036db <__pformat_int>
   140005786:	e9 ed fa ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   14000578b:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000578f:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005793:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000579a:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   1400057a1:	48 8d 4d a0          	lea    rcx,[rbp-0x60]
   1400057a5:	48 8d 95 70 ff ff ff 	lea    rdx,[rbp-0x90]
   1400057ac:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400057af:	49 89 c8             	mov    r8,rcx
   1400057b2:	89 c1                	mov    ecx,eax
   1400057b4:	e8 a5 e2 ff ff       	call   140003a5e <__pformat_xint>
   1400057b9:	e9 ba fa ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   1400057be:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400057c1:	0c 80                	or     al,0x80
   1400057c3:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400057c6:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400057ca:	75 15                	jne    1400057e1 <__mingw_pformat+0x5de>
   1400057cc:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400057d0:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400057d4:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400057d8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400057db:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057df:	eb 56                	jmp    140005837 <__mingw_pformat+0x634>
   1400057e1:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400057e5:	75 16                	jne    1400057fd <__mingw_pformat+0x5fa>
   1400057e7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400057eb:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400057ef:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400057f3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400057f5:	48 98                	cdqe
   1400057f7:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057fb:	eb 3a                	jmp    140005837 <__mingw_pformat+0x634>
   1400057fd:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005801:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005805:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005809:	8b 00                	mov    eax,DWORD PTR [rax]
   14000580b:	48 98                	cdqe
   14000580d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005811:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005815:	75 0e                	jne    140005825 <__mingw_pformat+0x622>
   140005817:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   14000581b:	48 0f bf c0          	movsx  rax,ax
   14000581f:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005823:	eb 12                	jmp    140005837 <__mingw_pformat+0x634>
   140005825:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   140005829:	75 0c                	jne    140005837 <__mingw_pformat+0x634>
   14000582b:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   14000582f:	48 0f be c0          	movsx  rax,al
   140005833:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005837:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000583b:	48 85 c0             	test   rax,rax
   14000583e:	79 09                	jns    140005849 <__mingw_pformat+0x646>
   140005840:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140005847:	eb 05                	jmp    14000584e <__mingw_pformat+0x64b>
   140005849:	b8 00 00 00 00       	mov    eax,0x0
   14000584e:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   140005852:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005856:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   14000585a:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005861:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005868:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000586c:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   140005873:	48 89 c1             	mov    rcx,rax
   140005876:	e8 60 de ff ff       	call   1400036db <__pformat_int>
   14000587b:	e9 f8 f9 ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   140005880:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005884:	75 18                	jne    14000589e <__mingw_pformat+0x69b>
   140005886:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005889:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   14000588c:	75 10                	jne    14000589e <__mingw_pformat+0x69b>
   14000588e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005891:	80 cc 02             	or     ah,0x2
   140005894:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005897:	c7 45 b0 10 00 00 00 	mov    DWORD PTR [rbp-0x50],0x10
   14000589e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058a2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058a6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058aa:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400058ad:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400058b1:	48 c7 45 98 00 00 00 	mov    QWORD PTR [rbp-0x68],0x0
   1400058b8:	00 
   1400058b9:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400058bd:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400058c1:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   1400058c8:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   1400058cf:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058d3:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   1400058da:	49 89 d0             	mov    r8,rdx
   1400058dd:	48 89 c2             	mov    rdx,rax
   1400058e0:	b9 78 00 00 00       	mov    ecx,0x78
   1400058e5:	e8 74 e1 ff ff       	call   140003a5e <__pformat_xint>
   1400058ea:	e9 89 f9 ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   1400058ef:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058f2:	83 c8 20             	or     eax,0x20
   1400058f5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400058f8:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058fb:	83 e0 04             	and    eax,0x4
   1400058fe:	85 c0                	test   eax,eax
   140005900:	74 2f                	je     140005931 <__mingw_pformat+0x72e>
   140005902:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005906:	48 8d 50 08          	lea    rdx,[rax+0x8]
   14000590a:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000590e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005911:	db 28                	fld    TBYTE PTR [rax]
   140005913:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005919:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000591d:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005924:	48 89 c1             	mov    rcx,rax
   140005927:	e8 1d ef ff ff       	call   140004849 <__pformat_efloat>
   14000592c:	e9 47 f9 ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   140005931:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005935:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005939:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000593d:	f2 0f 10 08          	movsd  xmm1,QWORD PTR [rax]
   140005941:	f2 0f 11 8d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm1
   140005948:	ff 
   140005949:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000594f:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005955:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005959:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005960:	48 89 c1             	mov    rcx,rax
   140005963:	e8 e1 ee ff ff       	call   140004849 <__pformat_efloat>
   140005968:	e9 0b f9 ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   14000596d:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005970:	83 c8 20             	or     eax,0x20
   140005973:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005976:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005979:	83 e0 04             	and    eax,0x4
   14000597c:	85 c0                	test   eax,eax
   14000597e:	74 2f                	je     1400059af <__mingw_pformat+0x7ac>
   140005980:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005984:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005988:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000598c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000598f:	db 28                	fld    TBYTE PTR [rax]
   140005991:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005997:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000599b:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400059a2:	48 89 c1             	mov    rcx,rax
   1400059a5:	e8 cf ed ff ff       	call   140004779 <__pformat_float>
   1400059aa:	e9 c9 f8 ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   1400059af:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059b3:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059b7:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059bb:	f2 0f 10 10          	movsd  xmm2,QWORD PTR [rax]
   1400059bf:	f2 0f 11 95 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm2
   1400059c6:	ff 
   1400059c7:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   1400059cd:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400059d3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059d7:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400059de:	48 89 c1             	mov    rcx,rax
   1400059e1:	e8 93 ed ff ff       	call   140004779 <__pformat_float>
   1400059e6:	e9 8d f8 ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   1400059eb:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400059ee:	83 c8 20             	or     eax,0x20
   1400059f1:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400059f4:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400059f7:	83 e0 04             	and    eax,0x4
   1400059fa:	85 c0                	test   eax,eax
   1400059fc:	74 2f                	je     140005a2d <__mingw_pformat+0x82a>
   1400059fe:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a02:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a06:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a0a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a0d:	db 28                	fld    TBYTE PTR [rax]
   140005a0f:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005a15:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a19:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005a20:	48 89 c1             	mov    rcx,rax
   140005a23:	e8 cc ee ff ff       	call   1400048f4 <__pformat_gfloat>
   140005a28:	e9 4b f8 ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   140005a2d:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a31:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a35:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a39:	f2 0f 10 18          	movsd  xmm3,QWORD PTR [rax]
   140005a3d:	f2 0f 11 9d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm3
   140005a44:	ff 
   140005a45:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   140005a4b:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005a51:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a55:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005a5c:	48 89 c1             	mov    rcx,rax
   140005a5f:	e8 90 ee ff ff       	call   1400048f4 <__pformat_gfloat>
   140005a64:	e9 0f f8 ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   140005a69:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005a6c:	83 c8 20             	or     eax,0x20
   140005a6f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005a72:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005a75:	83 e0 04             	and    eax,0x4
   140005a78:	85 c0                	test   eax,eax
   140005a7a:	74 2f                	je     140005aab <__mingw_pformat+0x8a8>
   140005a7c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a80:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a84:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a88:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a8b:	db 28                	fld    TBYTE PTR [rax]
   140005a8d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005a93:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a97:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005a9e:	48 89 c1             	mov    rcx,rax
   140005aa1:	e8 e7 f4 ff ff       	call   140004f8d <__pformat_xldouble>
   140005aa6:	e9 cd f7 ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   140005aab:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005aaf:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005ab3:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005ab7:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005aba:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005abe:	66 48 0f 6e c0       	movq   xmm0,rax
   140005ac3:	e8 de f5 ff ff       	call   1400050a6 <__pformat_xdouble>
   140005ac8:	e9 ab f7 ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   140005acd:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   140005ad1:	75 1b                	jne    140005aee <__mingw_pformat+0x8eb>
   140005ad3:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005ad6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005ada:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005ade:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005ae2:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005ae5:	89 ca                	mov    edx,ecx
   140005ae7:	88 10                	mov    BYTE PTR [rax],dl
   140005ae9:	e9 8a f7 ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   140005aee:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005af2:	75 1c                	jne    140005b10 <__mingw_pformat+0x90d>
   140005af4:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005af7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005afb:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005aff:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005b03:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005b06:	89 ca                	mov    edx,ecx
   140005b08:	66 89 10             	mov    WORD PTR [rax],dx
   140005b0b:	e9 68 f7 ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   140005b10:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005b14:	75 19                	jne    140005b2f <__mingw_pformat+0x92c>
   140005b16:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005b1a:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005b1e:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005b22:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005b25:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005b28:	89 10                	mov    DWORD PTR [rax],edx
   140005b2a:	e9 49 f7 ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   140005b2f:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   140005b33:	75 1d                	jne    140005b52 <__mingw_pformat+0x94f>
   140005b35:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005b38:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005b3c:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005b40:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005b44:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005b47:	48 63 d1             	movsxd rdx,ecx
   140005b4a:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005b4d:	e9 26 f7 ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   140005b52:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005b56:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005b5a:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005b5e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005b61:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005b64:	89 10                	mov    DWORD PTR [rax],edx
   140005b66:	e9 0d f7 ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   140005b6b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b6f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b72:	3c 68                	cmp    al,0x68
   140005b74:	75 0e                	jne    140005b84 <__mingw_pformat+0x981>
   140005b76:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005b7b:	c7 45 f8 05 00 00 00 	mov    DWORD PTR [rbp-0x8],0x5
   140005b82:	eb 07                	jmp    140005b8b <__mingw_pformat+0x988>
   140005b84:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140005b8b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b92:	e9 ee 02 00 00       	jmp    140005e85 <__mingw_pformat+0xc82>
   140005b97:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b9e:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005ba5:	e9 db 02 00 00       	jmp    140005e85 <__mingw_pformat+0xc82>
   140005baa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005bae:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005bb1:	3c 36                	cmp    al,0x36
   140005bb3:	75 1d                	jne    140005bd2 <__mingw_pformat+0x9cf>
   140005bb5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005bb9:	48 83 c0 01          	add    rax,0x1
   140005bbd:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005bc0:	3c 34                	cmp    al,0x34
   140005bc2:	75 0e                	jne    140005bd2 <__mingw_pformat+0x9cf>
   140005bc4:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005bcb:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005bd0:	eb 2f                	jmp    140005c01 <__mingw_pformat+0x9fe>
   140005bd2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005bd6:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005bd9:	3c 33                	cmp    al,0x33
   140005bdb:	75 1d                	jne    140005bfa <__mingw_pformat+0x9f7>
   140005bdd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005be1:	48 83 c0 01          	add    rax,0x1
   140005be5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005be8:	3c 32                	cmp    al,0x32
   140005bea:	75 0e                	jne    140005bfa <__mingw_pformat+0x9f7>
   140005bec:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005bf3:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005bf8:	eb 07                	jmp    140005c01 <__mingw_pformat+0x9fe>
   140005bfa:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005c01:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c08:	e9 78 02 00 00       	jmp    140005e85 <__mingw_pformat+0xc82>
   140005c0d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005c11:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005c14:	3c 6c                	cmp    al,0x6c
   140005c16:	75 0e                	jne    140005c26 <__mingw_pformat+0xa23>
   140005c18:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005c1d:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005c24:	eb 07                	jmp    140005c2d <__mingw_pformat+0xa2a>
   140005c26:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005c2d:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c34:	e9 4c 02 00 00       	jmp    140005e85 <__mingw_pformat+0xc82>
   140005c39:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005c40:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c47:	e9 39 02 00 00       	jmp    140005e85 <__mingw_pformat+0xc82>
   140005c4c:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c4f:	83 c8 04             	or     eax,0x4
   140005c52:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c55:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c5c:	e9 24 02 00 00       	jmp    140005e85 <__mingw_pformat+0xc82>
   140005c61:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005c68:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c6f:	e9 11 02 00 00       	jmp    140005e85 <__mingw_pformat+0xc82>
   140005c74:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005c7b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c82:	e9 fe 01 00 00       	jmp    140005e85 <__mingw_pformat+0xc82>
   140005c87:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140005c8b:	77 1f                	ja     140005cac <__mingw_pformat+0xaa9>
   140005c8d:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140005c94:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005c98:	48 83 c0 10          	add    rax,0x10
   140005c9c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005ca0:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140005ca7:	e9 d9 01 00 00       	jmp    140005e85 <__mingw_pformat+0xc82>
   140005cac:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005cb3:	e9 cd 01 00 00       	jmp    140005e85 <__mingw_pformat+0xc82>
   140005cb8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005cbd:	74 4c                	je     140005d0b <__mingw_pformat+0xb08>
   140005cbf:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cc3:	74 06                	je     140005ccb <__mingw_pformat+0xac8>
   140005cc5:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005cc9:	75 40                	jne    140005d0b <__mingw_pformat+0xb08>
   140005ccb:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005ccf:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005cd3:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005cd7:	8b 10                	mov    edx,DWORD PTR [rax]
   140005cd9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005cdd:	89 10                	mov    DWORD PTR [rax],edx
   140005cdf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ce3:	8b 00                	mov    eax,DWORD PTR [rax]
   140005ce5:	85 c0                	test   eax,eax
   140005ce7:	79 29                	jns    140005d12 <__mingw_pformat+0xb0f>
   140005ce9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005ced:	75 13                	jne    140005d02 <__mingw_pformat+0xaff>
   140005cef:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cf2:	80 cc 04             	or     ah,0x4
   140005cf5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cf8:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140005cfb:	f7 d8                	neg    eax
   140005cfd:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140005d00:	eb 10                	jmp    140005d12 <__mingw_pformat+0xb0f>
   140005d02:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005d09:	eb 07                	jmp    140005d12 <__mingw_pformat+0xb0f>
   140005d0b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005d12:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
   140005d19:	00 
   140005d1a:	e9 66 01 00 00       	jmp    140005e85 <__mingw_pformat+0xc82>
   140005d1f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d23:	0f 85 4f 01 00 00    	jne    140005e78 <__mingw_pformat+0xc75>
   140005d29:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d2c:	80 cc 08             	or     ah,0x8
   140005d2f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d32:	e9 41 01 00 00       	jmp    140005e78 <__mingw_pformat+0xc75>
   140005d37:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d3b:	0f 85 3a 01 00 00    	jne    140005e7b <__mingw_pformat+0xc78>
   140005d41:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d44:	80 cc 01             	or     ah,0x1
   140005d47:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d4a:	e9 2c 01 00 00       	jmp    140005e7b <__mingw_pformat+0xc78>
   140005d4f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d53:	0f 85 25 01 00 00    	jne    140005e7e <__mingw_pformat+0xc7b>
   140005d59:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d5c:	80 cc 04             	or     ah,0x4
   140005d5f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d62:	e9 17 01 00 00       	jmp    140005e7e <__mingw_pformat+0xc7b>
   140005d67:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d6b:	0f 85 10 01 00 00    	jne    140005e81 <__mingw_pformat+0xc7e>
   140005d71:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d74:	80 cc 10             	or     ah,0x10
   140005d77:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d7a:	48 c7 45 84 00 00 00 	mov    QWORD PTR [rbp-0x7c],0x0
   140005d81:	00 
   140005d82:	e8 a1 39 00 00       	call   140009728 <localeconv>
   140005d87:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140005d8b:	48 8d 4d 84          	lea    rcx,[rbp-0x7c]
   140005d8f:	48 8d 45 8c          	lea    rax,[rbp-0x74]
   140005d93:	49 89 c9             	mov    r9,rcx
   140005d96:	41 b8 10 00 00 00    	mov    r8d,0x10
   140005d9c:	48 89 c1             	mov    rcx,rax
   140005d9f:	e8 bc 33 00 00       	call   140009160 <mbrtowc>
   140005da4:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140005da7:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   140005dab:	7e 08                	jle    140005db5 <__mingw_pformat+0xbb2>
   140005dad:	0f b7 45 8c          	movzx  eax,WORD PTR [rbp-0x74]
   140005db1:	66 89 45 c0          	mov    WORD PTR [rbp-0x40],ax
   140005db5:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140005db8:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
   140005dbb:	e9 c1 00 00 00       	jmp    140005e81 <__mingw_pformat+0xc7e>
   140005dc0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005dc4:	0f 85 ba 00 00 00    	jne    140005e84 <__mingw_pformat+0xc81>
   140005dca:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005dcd:	83 c8 40             	or     eax,0x40
   140005dd0:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005dd3:	e9 ac 00 00 00       	jmp    140005e84 <__mingw_pformat+0xc81>
   140005dd8:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005ddc:	75 0e                	jne    140005dec <__mingw_pformat+0xbe9>
   140005dde:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005de1:	80 cc 02             	or     ah,0x2
   140005de4:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005de7:	e9 99 00 00 00       	jmp    140005e85 <__mingw_pformat+0xc82>
   140005dec:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
   140005df0:	77 68                	ja     140005e5a <__mingw_pformat+0xc57>
   140005df2:	83 7d e8 39          	cmp    DWORD PTR [rbp-0x18],0x39
   140005df6:	7f 62                	jg     140005e5a <__mingw_pformat+0xc57>
   140005df8:	83 7d e8 2f          	cmp    DWORD PTR [rbp-0x18],0x2f
   140005dfc:	7e 5c                	jle    140005e5a <__mingw_pformat+0xc57>
   140005dfe:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005e02:	75 09                	jne    140005e0d <__mingw_pformat+0xc0a>
   140005e04:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140005e0b:	eb 0d                	jmp    140005e1a <__mingw_pformat+0xc17>
   140005e0d:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005e11:	75 07                	jne    140005e1a <__mingw_pformat+0xc17>
   140005e13:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140005e1a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005e1f:	74 64                	je     140005e85 <__mingw_pformat+0xc82>
   140005e21:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e25:	8b 00                	mov    eax,DWORD PTR [rax]
   140005e27:	85 c0                	test   eax,eax
   140005e29:	79 0e                	jns    140005e39 <__mingw_pformat+0xc36>
   140005e2b:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005e2e:	8d 50 d0             	lea    edx,[rax-0x30]
   140005e31:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e35:	89 10                	mov    DWORD PTR [rax],edx
   140005e37:	eb 4c                	jmp    140005e85 <__mingw_pformat+0xc82>
   140005e39:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e3d:	8b 10                	mov    edx,DWORD PTR [rax]
   140005e3f:	89 d0                	mov    eax,edx
   140005e41:	c1 e0 02             	shl    eax,0x2
   140005e44:	01 d0                	add    eax,edx
   140005e46:	01 c0                	add    eax,eax
   140005e48:	89 c2                	mov    edx,eax
   140005e4a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005e4d:	01 d0                	add    eax,edx
   140005e4f:	8d 50 d0             	lea    edx,[rax-0x30]
   140005e52:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e56:	89 10                	mov    DWORD PTR [rax],edx
   140005e58:	eb 2b                	jmp    140005e85 <__mingw_pformat+0xc82>
   140005e5a:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005e5e:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140005e62:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005e66:	48 89 c2             	mov    rdx,rax
   140005e69:	b9 25 00 00 00       	mov    ecx,0x25
   140005e6e:	e8 fd d3 ff ff       	call   140003270 <__pformat_putc>
   140005e73:	e9 00 f4 ff ff       	jmp    140005278 <__mingw_pformat+0x75>
   140005e78:	90                   	nop
   140005e79:	eb 0a                	jmp    140005e85 <__mingw_pformat+0xc82>
   140005e7b:	90                   	nop
   140005e7c:	eb 07                	jmp    140005e85 <__mingw_pformat+0xc82>
   140005e7e:	90                   	nop
   140005e7f:	eb 04                	jmp    140005e85 <__mingw_pformat+0xc82>
   140005e81:	90                   	nop
   140005e82:	eb 01                	jmp    140005e85 <__mingw_pformat+0xc82>
   140005e84:	90                   	nop
   140005e85:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005e89:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e8c:	84 c0                	test   al,al
   140005e8e:	0f 85 2d f4 ff ff    	jne    1400052c1 <__mingw_pformat+0xbe>
   140005e94:	eb 0e                	jmp    140005ea4 <__mingw_pformat+0xca1>
   140005e96:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005e9a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005e9d:	89 c1                	mov    ecx,eax
   140005e9f:	e8 cc d3 ff ff       	call   140003270 <__pformat_putc>
   140005ea4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005ea8:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005eac:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140005eb0:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005eb3:	0f be c0             	movsx  eax,al
   140005eb6:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005eb9:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140005ebd:	0f 85 ba f3 ff ff    	jne    14000527d <__mingw_pformat+0x7a>
   140005ec3:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140005ec6:	48 81 c4 d0 00 00 00 	add    rsp,0xd0
   140005ecd:	5d                   	pop    rbp
   140005ece:	c3                   	ret
   140005ecf:	90                   	nop

0000000140005ed0 <__rv_alloc_D2A>:
   140005ed0:	55                   	push   rbp
   140005ed1:	48 89 e5             	mov    rbp,rsp
   140005ed4:	48 83 ec 30          	sub    rsp,0x30
   140005ed8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005edb:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005ee2:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005ee9:	eb 07                	jmp    140005ef2 <__rv_alloc_D2A+0x22>
   140005eeb:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140005eef:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140005ef2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005ef5:	83 c0 17             	add    eax,0x17
   140005ef8:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140005efb:	7f ee                	jg     140005eeb <__rv_alloc_D2A+0x1b>
   140005efd:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005f00:	89 c1                	mov    ecx,eax
   140005f02:	e8 56 1e 00 00       	call   140007d5d <__Balloc_D2A>
   140005f07:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005f0b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f0f:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140005f12:	89 10                	mov    DWORD PTR [rax],edx
   140005f14:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f18:	48 83 c0 04          	add    rax,0x4
   140005f1c:	48 83 c4 30          	add    rsp,0x30
   140005f20:	5d                   	pop    rbp
   140005f21:	c3                   	ret

0000000140005f22 <__nrv_alloc_D2A>:
   140005f22:	55                   	push   rbp
   140005f23:	48 89 e5             	mov    rbp,rsp
   140005f26:	48 83 ec 30          	sub    rsp,0x30
   140005f2a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005f2e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005f32:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005f36:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140005f39:	89 c1                	mov    ecx,eax
   140005f3b:	e8 90 ff ff ff       	call   140005ed0 <__rv_alloc_D2A>
   140005f40:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005f44:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f48:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005f4c:	eb 05                	jmp    140005f53 <__nrv_alloc_D2A+0x31>
   140005f4e:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140005f53:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f57:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005f5b:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140005f5f:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140005f62:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f66:	88 10                	mov    BYTE PTR [rax],dl
   140005f68:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f6c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005f6f:	84 c0                	test   al,al
   140005f71:	75 db                	jne    140005f4e <__nrv_alloc_D2A+0x2c>
   140005f73:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140005f78:	74 0b                	je     140005f85 <__nrv_alloc_D2A+0x63>
   140005f7a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f7e:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140005f82:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005f85:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f89:	48 83 c4 30          	add    rsp,0x30
   140005f8d:	5d                   	pop    rbp
   140005f8e:	c3                   	ret

0000000140005f8f <__freedtoa>:
   140005f8f:	55                   	push   rbp
   140005f90:	48 89 e5             	mov    rbp,rsp
   140005f93:	48 83 ec 30          	sub    rsp,0x30
   140005f97:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005f9b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f9f:	48 83 e8 04          	sub    rax,0x4
   140005fa3:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005fa7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005fab:	8b 10                	mov    edx,DWORD PTR [rax]
   140005fad:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005fb1:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005fb4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005fb8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140005fbb:	ba 01 00 00 00       	mov    edx,0x1
   140005fc0:	89 c1                	mov    ecx,eax
   140005fc2:	d3 e2                	shl    edx,cl
   140005fc4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005fc8:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140005fcb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005fcf:	48 89 c1             	mov    rcx,rax
   140005fd2:	e8 c7 1e 00 00       	call   140007e9e <__Bfree_D2A>
   140005fd7:	90                   	nop
   140005fd8:	48 83 c4 30          	add    rsp,0x30
   140005fdc:	5d                   	pop    rbp
   140005fdd:	c3                   	ret

0000000140005fde <__quorem_D2A>:
   140005fde:	55                   	push   rbp
   140005fdf:	48 89 e5             	mov    rbp,rsp
   140005fe2:	48 83 ec 70          	sub    rsp,0x70
   140005fe6:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005fea:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005fee:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005ff2:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005ff5:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005ff8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005ffc:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005fff:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140006002:	7e 0a                	jle    14000600e <__quorem_D2A+0x30>
   140006004:	b8 00 00 00 00       	mov    eax,0x0
   140006009:	e9 3f 02 00 00       	jmp    14000624d <__quorem_D2A+0x26f>
   14000600e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006012:	48 83 c0 18          	add    rax,0x18
   140006016:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000601a:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000601e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006021:	48 98                	cdqe
   140006023:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000602a:	00 
   14000602b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000602f:	48 01 d0             	add    rax,rdx
   140006032:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140006036:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000603a:	48 83 c0 18          	add    rax,0x18
   14000603e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006042:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006045:	48 98                	cdqe
   140006047:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000604e:	00 
   14000604f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006053:	48 01 d0             	add    rax,rdx
   140006056:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000605a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000605e:	8b 00                	mov    eax,DWORD PTR [rax]
   140006060:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140006064:	8b 12                	mov    edx,DWORD PTR [rdx]
   140006066:	8d 4a 01             	lea    ecx,[rdx+0x1]
   140006069:	ba 00 00 00 00       	mov    edx,0x0
   14000606e:	f7 f1                	div    ecx
   140006070:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140006073:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140006077:	0f 84 c4 00 00 00    	je     140006141 <__quorem_D2A+0x163>
   14000607d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140006084:	00 
   140006085:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   14000608c:	00 
   14000608d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006091:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140006095:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006099:	8b 00                	mov    eax,DWORD PTR [rax]
   14000609b:	89 c2                	mov    edx,eax
   14000609d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400060a0:	48 0f af d0          	imul   rdx,rax
   1400060a4:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400060a8:	48 01 d0             	add    rax,rdx
   1400060ab:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400060af:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400060b3:	48 c1 e8 20          	shr    rax,0x20
   1400060b7:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400060bb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400060bf:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060c1:	89 c1                	mov    ecx,eax
   1400060c3:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400060c7:	89 c2                	mov    edx,eax
   1400060c9:	48 89 c8             	mov    rax,rcx
   1400060cc:	48 29 d0             	sub    rax,rdx
   1400060cf:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   1400060d3:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400060d7:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   1400060db:	48 c1 e8 20          	shr    rax,0x20
   1400060df:	83 e0 01             	and    eax,0x1
   1400060e2:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400060e6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400060ea:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400060ee:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400060f2:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400060f6:	89 10                	mov    DWORD PTR [rax],edx
   1400060f8:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400060fc:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140006100:	73 8b                	jae    14000608d <__quorem_D2A+0xaf>
   140006102:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006106:	8b 00                	mov    eax,DWORD PTR [rax]
   140006108:	85 c0                	test   eax,eax
   14000610a:	75 35                	jne    140006141 <__quorem_D2A+0x163>
   14000610c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006110:	48 83 c0 18          	add    rax,0x18
   140006114:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006118:	eb 04                	jmp    14000611e <__quorem_D2A+0x140>
   14000611a:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000611e:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   140006123:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006127:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   14000612b:	73 0a                	jae    140006137 <__quorem_D2A+0x159>
   14000612d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006131:	8b 00                	mov    eax,DWORD PTR [rax]
   140006133:	85 c0                	test   eax,eax
   140006135:	74 e3                	je     14000611a <__quorem_D2A+0x13c>
   140006137:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000613b:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000613e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006141:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140006145:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006149:	48 89 c1             	mov    rcx,rax
   14000614c:	e8 bc 24 00 00       	call   14000860d <__cmp_D2A>
   140006151:	85 c0                	test   eax,eax
   140006153:	0f 88 f1 00 00 00    	js     14000624a <__quorem_D2A+0x26c>
   140006159:	83 45 e4 01          	add    DWORD PTR [rbp-0x1c],0x1
   14000615d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140006164:	00 
   140006165:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   14000616c:	00 
   14000616d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006171:	48 83 c0 18          	add    rax,0x18
   140006175:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006179:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000617d:	48 83 c0 18          	add    rax,0x18
   140006181:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140006185:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006189:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000618d:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006191:	8b 00                	mov    eax,DWORD PTR [rax]
   140006193:	89 c2                	mov    edx,eax
   140006195:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006199:	48 01 d0             	add    rax,rdx
   14000619c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400061a0:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400061a4:	48 c1 e8 20          	shr    rax,0x20
   1400061a8:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400061ac:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400061b0:	8b 00                	mov    eax,DWORD PTR [rax]
   1400061b2:	89 c1                	mov    ecx,eax
   1400061b4:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400061b8:	89 c2                	mov    edx,eax
   1400061ba:	48 89 c8             	mov    rax,rcx
   1400061bd:	48 29 d0             	sub    rax,rdx
   1400061c0:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   1400061c4:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400061c8:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   1400061cc:	48 c1 e8 20          	shr    rax,0x20
   1400061d0:	83 e0 01             	and    eax,0x1
   1400061d3:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400061d7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400061db:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400061df:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400061e3:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400061e7:	89 10                	mov    DWORD PTR [rax],edx
   1400061e9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400061ed:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400061f1:	73 92                	jae    140006185 <__quorem_D2A+0x1a7>
   1400061f3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400061f7:	48 83 c0 18          	add    rax,0x18
   1400061fb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400061ff:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006202:	48 98                	cdqe
   140006204:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000620b:	00 
   14000620c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006210:	48 01 d0             	add    rax,rdx
   140006213:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140006217:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000621b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000621d:	85 c0                	test   eax,eax
   14000621f:	75 29                	jne    14000624a <__quorem_D2A+0x26c>
   140006221:	eb 04                	jmp    140006227 <__quorem_D2A+0x249>
   140006223:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140006227:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   14000622c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006230:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   140006234:	73 0a                	jae    140006240 <__quorem_D2A+0x262>
   140006236:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000623a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000623c:	85 c0                	test   eax,eax
   14000623e:	74 e3                	je     140006223 <__quorem_D2A+0x245>
   140006240:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006244:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006247:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000624a:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   14000624d:	48 83 c4 70          	add    rsp,0x70
   140006251:	5d                   	pop    rbp
   140006252:	c3                   	ret
   140006253:	90                   	nop
   140006254:	90                   	nop
   140006255:	90                   	nop
   140006256:	90                   	nop
   140006257:	90                   	nop
   140006258:	90                   	nop
   140006259:	90                   	nop
   14000625a:	90                   	nop
   14000625b:	90                   	nop
   14000625c:	90                   	nop
   14000625d:	90                   	nop
   14000625e:	90                   	nop
   14000625f:	90                   	nop

0000000140006260 <__hi0bits_D2A>:
   140006260:	55                   	push   rbp
   140006261:	48 89 e5             	mov    rbp,rsp
   140006264:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140006267:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   14000626b:	83 f0 1f             	xor    eax,0x1f
   14000626e:	5d                   	pop    rbp
   14000626f:	c3                   	ret

0000000140006270 <bitstob>:
   140006270:	55                   	push   rbp
   140006271:	53                   	push   rbx
   140006272:	48 83 ec 58          	sub    rsp,0x58
   140006276:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   14000627b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   14000627f:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140006282:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140006286:	c7 45 fc 20 00 00 00 	mov    DWORD PTR [rbp-0x4],0x20
   14000628d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140006294:	eb 07                	jmp    14000629d <bitstob+0x2d>
   140006296:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140006299:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   14000629d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400062a0:	3b 45 28             	cmp    eax,DWORD PTR [rbp+0x28]
   1400062a3:	7c f1                	jl     140006296 <bitstob+0x26>
   1400062a5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400062a8:	89 c1                	mov    ecx,eax
   1400062aa:	e8 ae 1a 00 00       	call   140007d5d <__Balloc_D2A>
   1400062af:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400062b3:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   1400062b6:	83 e8 01             	sub    eax,0x1
   1400062b9:	c1 f8 05             	sar    eax,0x5
   1400062bc:	48 98                	cdqe
   1400062be:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400062c5:	00 
   1400062c6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400062ca:	48 01 d0             	add    rax,rdx
   1400062cd:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400062d1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062d5:	48 83 c0 18          	add    rax,0x18
   1400062d9:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400062dd:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400062e1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400062e5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400062e9:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400062ed:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400062f1:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400062f5:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400062f7:	89 10                	mov    DWORD PTR [rax],edx
   1400062f9:	48 83 45 20 04       	add    QWORD PTR [rbp+0x20],0x4
   1400062fe:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006302:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140006306:	73 dd                	jae    1400062e5 <bitstob+0x75>
   140006308:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000630c:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   140006310:	48 c1 f8 02          	sar    rax,0x2
   140006314:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140006317:	eb 1d                	jmp    140006336 <bitstob+0xc6>
   140006319:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000631d:	75 17                	jne    140006336 <bitstob+0xc6>
   14000631f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006323:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   14000632a:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000632e:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140006334:	eb 59                	jmp    14000638f <bitstob+0x11f>
   140006336:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000633a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000633d:	48 98                	cdqe
   14000633f:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006346:	00 
   140006347:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000634b:	48 01 d0             	add    rax,rdx
   14000634e:	8b 00                	mov    eax,DWORD PTR [rax]
   140006350:	85 c0                	test   eax,eax
   140006352:	74 c5                	je     140006319 <bitstob+0xa9>
   140006354:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006357:	8d 50 01             	lea    edx,[rax+0x1]
   14000635a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000635e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006361:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006364:	83 c0 01             	add    eax,0x1
   140006367:	c1 e0 05             	shl    eax,0x5
   14000636a:	89 c3                	mov    ebx,eax
   14000636c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006370:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006373:	48 63 d2             	movsxd rdx,edx
   140006376:	48 83 c2 04          	add    rdx,0x4
   14000637a:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   14000637e:	89 c1                	mov    ecx,eax
   140006380:	e8 db fe ff ff       	call   140006260 <__hi0bits_D2A>
   140006385:	29 c3                	sub    ebx,eax
   140006387:	89 da                	mov    edx,ebx
   140006389:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000638d:	89 10                	mov    DWORD PTR [rax],edx
   14000638f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006393:	48 83 c4 58          	add    rsp,0x58
   140006397:	5b                   	pop    rbx
   140006398:	5d                   	pop    rbp
   140006399:	c3                   	ret

000000014000639a <__gdtoa>:
   14000639a:	55                   	push   rbp
   14000639b:	48 81 ec 00 01 00 00 	sub    rsp,0x100
   1400063a2:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   1400063a9:	00 
   1400063aa:	48 89 8d 90 00 00 00 	mov    QWORD PTR [rbp+0x90],rcx
   1400063b1:	89 95 98 00 00 00    	mov    DWORD PTR [rbp+0x98],edx
   1400063b7:	4c 89 85 a0 00 00 00 	mov    QWORD PTR [rbp+0xa0],r8
   1400063be:	4c 89 8d a8 00 00 00 	mov    QWORD PTR [rbp+0xa8],r9
   1400063c5:	c7 45 64 00 00 00 00 	mov    DWORD PTR [rbp+0x64],0x0
   1400063cc:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400063d3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400063d5:	83 e0 cf             	and    eax,0xffffffcf
   1400063d8:	89 c2                	mov    edx,eax
   1400063da:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400063e1:	89 10                	mov    DWORD PTR [rax],edx
   1400063e3:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400063ea:	8b 00                	mov    eax,DWORD PTR [rax]
   1400063ec:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400063ef:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400063f2:	83 e0 07             	and    eax,0x7
   1400063f5:	83 f8 04             	cmp    eax,0x4
   1400063f8:	0f 84 b0 00 00 00    	je     1400064ae <__gdtoa+0x114>
   1400063fe:	83 f8 04             	cmp    eax,0x4
   140006401:	0f 8f d5 00 00 00    	jg     1400064dc <__gdtoa+0x142>
   140006407:	83 f8 03             	cmp    eax,0x3
   14000640a:	74 74                	je     140006480 <__gdtoa+0xe6>
   14000640c:	83 f8 03             	cmp    eax,0x3
   14000640f:	0f 8f c7 00 00 00    	jg     1400064dc <__gdtoa+0x142>
   140006415:	85 c0                	test   eax,eax
   140006417:	0f 84 05 01 00 00    	je     140006522 <__gdtoa+0x188>
   14000641d:	85 c0                	test   eax,eax
   14000641f:	0f 88 b7 00 00 00    	js     1400064dc <__gdtoa+0x142>
   140006425:	83 e8 01             	sub    eax,0x1
   140006428:	83 f8 01             	cmp    eax,0x1
   14000642b:	0f 87 ab 00 00 00    	ja     1400064dc <__gdtoa+0x142>
   140006431:	90                   	nop
   140006432:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006439:	8b 00                	mov    eax,DWORD PTR [rax]
   14000643b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000643e:	48 8d 4d b4          	lea    rcx,[rbp-0x4c]
   140006442:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006445:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   14000644c:	49 89 c8             	mov    r8,rcx
   14000644f:	48 89 c1             	mov    rcx,rax
   140006452:	e8 19 fe ff ff       	call   140006270 <bitstob>
   140006457:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000645b:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006461:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140006464:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006468:	48 89 c1             	mov    rcx,rax
   14000646b:	e8 31 16 00 00       	call   140007aa1 <__trailz_D2A>
   140006470:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006473:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006476:	85 c0                	test   eax,eax
   140006478:	0f 84 8b 00 00 00    	je     140006509 <__gdtoa+0x16f>
   14000647e:	eb 66                	jmp    1400064e6 <__gdtoa+0x14c>
   140006480:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006487:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000648d:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006494:	48 8d 0d b5 4e 00 00 	lea    rcx,[rip+0x4eb5]        # 14000b350 <.rdata>
   14000649b:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400064a1:	48 89 c2             	mov    rdx,rax
   1400064a4:	e8 79 fa ff ff       	call   140005f22 <__nrv_alloc_D2A>
   1400064a9:	e9 4d 14 00 00       	jmp    1400078fb <__gdtoa+0x1561>
   1400064ae:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400064b5:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   1400064bb:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400064c2:	48 8d 0d 90 4e 00 00 	lea    rcx,[rip+0x4e90]        # 14000b359 <.rdata+0x9>
   1400064c9:	41 b8 03 00 00 00    	mov    r8d,0x3
   1400064cf:	48 89 c2             	mov    rdx,rax
   1400064d2:	e8 4b fa ff ff       	call   140005f22 <__nrv_alloc_D2A>
   1400064d7:	e9 1f 14 00 00       	jmp    1400078fb <__gdtoa+0x1561>
   1400064dc:	b8 00 00 00 00       	mov    eax,0x0
   1400064e1:	e9 15 14 00 00       	jmp    1400078fb <__gdtoa+0x1561>
   1400064e6:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400064e9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400064ed:	48 89 c1             	mov    rcx,rax
   1400064f0:	e8 50 14 00 00       	call   140007945 <__rshift_D2A>
   1400064f5:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400064f8:	01 85 98 00 00 00    	add    DWORD PTR [rbp+0x98],eax
   1400064fe:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   140006501:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006504:	29 c2                	sub    edx,eax
   140006506:	89 55 b4             	mov    DWORD PTR [rbp-0x4c],edx
   140006509:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000650d:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006510:	85 c0                	test   eax,eax
   140006512:	75 3d                	jne    140006551 <__gdtoa+0x1b7>
   140006514:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006518:	48 89 c1             	mov    rcx,rax
   14000651b:	e8 7e 19 00 00       	call   140007e9e <__Bfree_D2A>
   140006520:	eb 01                	jmp    140006523 <__gdtoa+0x189>
   140006522:	90                   	nop
   140006523:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   14000652a:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   140006530:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006537:	48 8d 0d 1f 4e 00 00 	lea    rcx,[rip+0x4e1f]        # 14000b35d <.rdata+0xd>
   14000653e:	41 b8 01 00 00 00    	mov    r8d,0x1
   140006544:	48 89 c2             	mov    rdx,rax
   140006547:	e8 d6 f9 ff ff       	call   140005f22 <__nrv_alloc_D2A>
   14000654c:	e9 aa 13 00 00       	jmp    1400078fb <__gdtoa+0x1561>
   140006551:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
   140006555:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006559:	48 89 c1             	mov    rcx,rax
   14000655c:	e8 75 23 00 00       	call   1400088d6 <__b2d_D2A>
   140006561:	66 48 0f 7e c0       	movq   rax,xmm0
   140006566:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   14000656a:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   14000656d:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006573:	01 d0                	add    eax,edx
   140006575:	83 e8 01             	sub    eax,0x1
   140006578:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000657b:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   14000657e:	25 ff ff 0f 00       	and    eax,0xfffff
   140006583:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006586:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006589:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   14000658e:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006591:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006596:	f2 0f 10 15 c2 4d 00 	movsd  xmm2,QWORD PTR [rip+0x4dc2]        # 14000b360 <.rdata+0x10>
   14000659d:	00 
   14000659e:	66 0f 28 c8          	movapd xmm1,xmm0
   1400065a2:	f2 0f 5c ca          	subsd  xmm1,xmm2
   1400065a6:	f2 0f 10 05 ba 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4dba]        # 14000b368 <.rdata+0x18>
   1400065ad:	00 
   1400065ae:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   1400065b2:	f2 0f 10 05 b6 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4db6]        # 14000b370 <.rdata+0x20>
   1400065b9:	00 
   1400065ba:	f2 0f 58 c8          	addsd  xmm1,xmm0
   1400065be:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400065c1:	66 0f ef d2          	pxor   xmm2,xmm2
   1400065c5:	f2 0f 2a d0          	cvtsi2sd xmm2,eax
   1400065c9:	f2 0f 10 05 a7 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4da7]        # 14000b378 <.rdata+0x28>
   1400065d0:	00 
   1400065d1:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   1400065d5:	f2 0f 58 c1          	addsd  xmm0,xmm1
   1400065d9:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400065de:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400065e1:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400065e4:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400065e8:	79 03                	jns    1400065ed <__gdtoa+0x253>
   1400065ea:	f7 5d 60             	neg    DWORD PTR [rbp+0x60]
   1400065ed:	81 6d 60 35 04 00 00 	sub    DWORD PTR [rbp+0x60],0x435
   1400065f4:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400065f8:	7e 23                	jle    14000661d <__gdtoa+0x283>
   1400065fa:	66 0f ef c9          	pxor   xmm1,xmm1
   1400065fe:	f2 0f 2a 4d 60       	cvtsi2sd xmm1,DWORD PTR [rbp+0x60]
   140006603:	f2 0f 10 05 75 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4d75]        # 14000b380 <.rdata+0x30>
   14000660a:	00 
   14000660b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000660f:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006614:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006618:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000661d:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006622:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006626:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006629:	66 0f ef c0          	pxor   xmm0,xmm0
   14000662d:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006632:	76 1b                	jbe    14000664f <__gdtoa+0x2b5>
   140006634:	66 0f ef c0          	pxor   xmm0,xmm0
   140006638:	f2 0f 2a 45 58       	cvtsi2sd xmm0,DWORD PTR [rbp+0x58]
   14000663d:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006642:	7a 07                	jp     14000664b <__gdtoa+0x2b1>
   140006644:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006649:	74 04                	je     14000664f <__gdtoa+0x2b5>
   14000664b:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000664f:	c7 45 54 01 00 00 00 	mov    DWORD PTR [rbp+0x54],0x1
   140006656:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006659:	8b 4d b4             	mov    ecx,DWORD PTR [rbp-0x4c]
   14000665c:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006662:	01 ca                	add    edx,ecx
   140006664:	83 ea 01             	sub    edx,0x1
   140006667:	c1 e2 14             	shl    edx,0x14
   14000666a:	01 d0                	add    eax,edx
   14000666c:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000666f:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   140006673:	78 2e                	js     1400066a3 <__gdtoa+0x309>
   140006675:	83 7d 58 16          	cmp    DWORD PTR [rbp+0x58],0x16
   140006679:	7f 28                	jg     1400066a3 <__gdtoa+0x309>
   14000667b:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006680:	48 8b 05 f9 4f 00 00 	mov    rax,QWORD PTR [rip+0x4ff9]        # 14000b680 <.refptr.__tens_D2A>
   140006687:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   14000668a:	48 63 d2             	movsxd rdx,edx
   14000668d:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006692:	66 0f 2f c1          	comisd xmm0,xmm1
   140006696:	76 04                	jbe    14000669c <__gdtoa+0x302>
   140006698:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000669c:	c7 45 54 00 00 00 00 	mov    DWORD PTR [rbp+0x54],0x0
   1400066a3:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   1400066a6:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400066a9:	29 c2                	sub    edx,eax
   1400066ab:	8d 42 ff             	lea    eax,[rdx-0x1]
   1400066ae:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400066b1:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400066b5:	78 0f                	js     1400066c6 <__gdtoa+0x32c>
   1400066b7:	c7 45 7c 00 00 00 00 	mov    DWORD PTR [rbp+0x7c],0x0
   1400066be:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400066c1:	89 45 40             	mov    DWORD PTR [rbp+0x40],eax
   1400066c4:	eb 0f                	jmp    1400066d5 <__gdtoa+0x33b>
   1400066c6:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400066c9:	f7 d8                	neg    eax
   1400066cb:	89 45 7c             	mov    DWORD PTR [rbp+0x7c],eax
   1400066ce:	c7 45 40 00 00 00 00 	mov    DWORD PTR [rbp+0x40],0x0
   1400066d5:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400066d9:	78 15                	js     1400066f0 <__gdtoa+0x356>
   1400066db:	c7 45 78 00 00 00 00 	mov    DWORD PTR [rbp+0x78],0x0
   1400066e2:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400066e5:	89 45 3c             	mov    DWORD PTR [rbp+0x3c],eax
   1400066e8:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400066eb:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   1400066ee:	eb 15                	jmp    140006705 <__gdtoa+0x36b>
   1400066f0:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400066f3:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   1400066f6:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400066f9:	f7 d8                	neg    eax
   1400066fb:	89 45 78             	mov    DWORD PTR [rbp+0x78],eax
   1400066fe:	c7 45 3c 00 00 00 00 	mov    DWORD PTR [rbp+0x3c],0x0
   140006705:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   14000670c:	78 09                	js     140006717 <__gdtoa+0x37d>
   14000670e:	83 bd b0 00 00 00 09 	cmp    DWORD PTR [rbp+0xb0],0x9
   140006715:	7e 0a                	jle    140006721 <__gdtoa+0x387>
   140006717:	c7 85 b0 00 00 00 00 	mov    DWORD PTR [rbp+0xb0],0x0
   14000671e:	00 00 00 
   140006721:	c7 45 34 01 00 00 00 	mov    DWORD PTR [rbp+0x34],0x1
   140006728:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   14000672f:	7e 10                	jle    140006741 <__gdtoa+0x3a7>
   140006731:	83 ad b0 00 00 00 04 	sub    DWORD PTR [rbp+0xb0],0x4
   140006738:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000673f:	eb 1b                	jmp    14000675c <__gdtoa+0x3c2>
   140006741:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006744:	3d f9 03 00 00       	cmp    eax,0x3f9
   140006749:	7f 0a                	jg     140006755 <__gdtoa+0x3bb>
   14000674b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000674e:	3d 02 fc ff ff       	cmp    eax,0xfffffc02
   140006753:	7d 07                	jge    14000675c <__gdtoa+0x3c2>
   140006755:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000675c:	c7 45 50 01 00 00 00 	mov    DWORD PTR [rbp+0x50],0x1
   140006763:	c7 45 68 ff ff ff ff 	mov    DWORD PTR [rbp+0x68],0xffffffff
   14000676a:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000676d:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006770:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006777:	0f 84 c5 00 00 00    	je     140006842 <__gdtoa+0x4a8>
   14000677d:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006784:	0f 8f e6 00 00 00    	jg     140006870 <__gdtoa+0x4d6>
   14000678a:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   140006791:	74 7e                	je     140006811 <__gdtoa+0x477>
   140006793:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   14000679a:	0f 8f d0 00 00 00    	jg     140006870 <__gdtoa+0x4d6>
   1400067a0:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   1400067a7:	0f 84 8e 00 00 00    	je     14000683b <__gdtoa+0x4a1>
   1400067ad:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   1400067b4:	0f 8f b6 00 00 00    	jg     140006870 <__gdtoa+0x4d6>
   1400067ba:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   1400067c1:	7f 0e                	jg     1400067d1 <__gdtoa+0x437>
   1400067c3:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400067ca:	79 13                	jns    1400067df <__gdtoa+0x445>
   1400067cc:	e9 9f 00 00 00       	jmp    140006870 <__gdtoa+0x4d6>
   1400067d1:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   1400067d8:	74 30                	je     14000680a <__gdtoa+0x470>
   1400067da:	e9 91 00 00 00       	jmp    140006870 <__gdtoa+0x4d6>
   1400067df:	66 0f ef c9          	pxor   xmm1,xmm1
   1400067e3:	f2 0f 2a 4d f8       	cvtsi2sd xmm1,DWORD PTR [rbp-0x8]
   1400067e8:	f2 0f 10 05 98 4b 00 	movsd  xmm0,QWORD PTR [rip+0x4b98]        # 14000b388 <.rdata+0x38>
   1400067ef:	00 
   1400067f0:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400067f4:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   1400067f8:	83 c0 03             	add    eax,0x3
   1400067fb:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400067fe:	c7 85 b8 00 00 00 00 	mov    DWORD PTR [rbp+0xb8],0x0
   140006805:	00 00 00 
   140006808:	eb 66                	jmp    140006870 <__gdtoa+0x4d6>
   14000680a:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   140006811:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006818:	7f 0a                	jg     140006824 <__gdtoa+0x48a>
   14000681a:	c7 85 b8 00 00 00 01 	mov    DWORD PTR [rbp+0xb8],0x1
   140006821:	00 00 00 
   140006824:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   14000682a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000682d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006830:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006833:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   140006836:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006839:	eb 35                	jmp    140006870 <__gdtoa+0x4d6>
   14000683b:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   140006842:	8b 95 b8 00 00 00    	mov    edx,DWORD PTR [rbp+0xb8]
   140006848:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000684b:	01 d0                	add    eax,edx
   14000684d:	83 c0 01             	add    eax,0x1
   140006850:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006853:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006856:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006859:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000685c:	83 e8 01             	sub    eax,0x1
   14000685f:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006862:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006865:	85 c0                	test   eax,eax
   140006867:	7f 07                	jg     140006870 <__gdtoa+0x4d6>
   140006869:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006870:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006873:	89 c1                	mov    ecx,eax
   140006875:	e8 56 f6 ff ff       	call   140005ed0 <__rv_alloc_D2A>
   14000687a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000687e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006882:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006886:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000688d:	7f 09                	jg     140006898 <__gdtoa+0x4fe>
   14000688f:	c7 45 44 00 00 00 00 	mov    DWORD PTR [rbp+0x44],0x0
   140006896:	eb 38                	jmp    1400068d0 <__gdtoa+0x536>
   140006898:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000689f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400068a2:	83 e8 01             	sub    eax,0x1
   1400068a5:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   1400068a8:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400068ac:	74 22                	je     1400068d0 <__gdtoa+0x536>
   1400068ae:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400068b2:	79 07                	jns    1400068bb <__gdtoa+0x521>
   1400068b4:	c7 45 44 02 00 00 00 	mov    DWORD PTR [rbp+0x44],0x2
   1400068bb:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400068be:	83 e0 08             	and    eax,0x8
   1400068c1:	85 c0                	test   eax,eax
   1400068c3:	74 0b                	je     1400068d0 <__gdtoa+0x536>
   1400068c5:	b8 03 00 00 00       	mov    eax,0x3
   1400068ca:	2b 45 44             	sub    eax,DWORD PTR [rbp+0x44]
   1400068cd:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   1400068d0:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400068d4:	0f 88 b9 04 00 00    	js     140006d93 <__gdtoa+0x9f9>
   1400068da:	83 7d 6c 0e          	cmp    DWORD PTR [rbp+0x6c],0xe
   1400068de:	0f 8f af 04 00 00    	jg     140006d93 <__gdtoa+0x9f9>
   1400068e4:	83 7d 34 00          	cmp    DWORD PTR [rbp+0x34],0x0
   1400068e8:	0f 84 a5 04 00 00    	je     140006d93 <__gdtoa+0x9f9>
   1400068ee:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400068f2:	0f 85 9b 04 00 00    	jne    140006d93 <__gdtoa+0x9f9>
   1400068f8:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400068fc:	0f 85 91 04 00 00    	jne    140006d93 <__gdtoa+0x9f9>
   140006902:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006909:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   14000690e:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   140006913:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006916:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140006919:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   14000691c:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   14000691f:	c7 45 70 02 00 00 00 	mov    DWORD PTR [rbp+0x70],0x2
   140006926:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   14000692a:	0f 8e 98 00 00 00    	jle    1400069c8 <__gdtoa+0x62e>
   140006930:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006933:	83 e0 0f             	and    eax,0xf
   140006936:	89 c2                	mov    edx,eax
   140006938:	48 8b 05 41 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d41]        # 14000b680 <.refptr.__tens_D2A>
   14000693f:	48 63 d2             	movsxd rdx,edx
   140006942:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006947:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000694c:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000694f:	c1 f8 04             	sar    eax,0x4
   140006952:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006955:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006958:	83 e0 10             	and    eax,0x10
   14000695b:	85 c0                	test   eax,eax
   14000695d:	74 5e                	je     1400069bd <__gdtoa+0x623>
   14000695f:	83 65 60 0f          	and    DWORD PTR [rbp+0x60],0xf
   140006963:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006968:	48 8b 05 41 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c41]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000696f:	f2 0f 10 48 20       	movsd  xmm1,QWORD PTR [rax+0x20]
   140006974:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006978:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   14000697d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006981:	eb 3a                	jmp    1400069bd <__gdtoa+0x623>
   140006983:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006986:	83 e0 01             	and    eax,0x1
   140006989:	85 c0                	test   eax,eax
   14000698b:	74 24                	je     1400069b1 <__gdtoa+0x617>
   14000698d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006991:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006994:	48 8b 05 15 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c15]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000699b:	48 63 d2             	movsxd rdx,edx
   14000699e:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400069a3:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   1400069a8:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400069ac:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400069b1:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   1400069b4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400069b7:	83 c0 01             	add    eax,0x1
   1400069ba:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400069bd:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400069c1:	75 c0                	jne    140006983 <__gdtoa+0x5e9>
   1400069c3:	e9 8b 00 00 00       	jmp    140006a53 <__gdtoa+0x6b9>
   1400069c8:	f2 0f 10 05 c0 49 00 	movsd  xmm0,QWORD PTR [rip+0x49c0]        # 14000b390 <.rdata+0x40>
   1400069cf:	00 
   1400069d0:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400069d5:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400069d8:	f7 d8                	neg    eax
   1400069da:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   1400069dd:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400069e1:	74 70                	je     140006a53 <__gdtoa+0x6b9>
   1400069e3:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069e8:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   1400069eb:	83 e0 0f             	and    eax,0xf
   1400069ee:	89 c2                	mov    edx,eax
   1400069f0:	48 8b 05 89 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c89]        # 14000b680 <.refptr.__tens_D2A>
   1400069f7:	48 63 d2             	movsxd rdx,edx
   1400069fa:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400069ff:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006a03:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a08:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   140006a0b:	c1 f8 04             	sar    eax,0x4
   140006a0e:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006a11:	eb 3a                	jmp    140006a4d <__gdtoa+0x6b3>
   140006a13:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006a16:	83 e0 01             	and    eax,0x1
   140006a19:	85 c0                	test   eax,eax
   140006a1b:	74 24                	je     140006a41 <__gdtoa+0x6a7>
   140006a1d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006a21:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a26:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006a29:	48 8b 05 80 4b 00 00 	mov    rax,QWORD PTR [rip+0x4b80]        # 14000b5b0 <.refptr.__bigtens_D2A>
   140006a30:	48 63 d2             	movsxd rdx,edx
   140006a33:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006a38:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006a3c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a41:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006a44:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006a47:	83 c0 01             	add    eax,0x1
   140006a4a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006a4d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006a51:	75 c0                	jne    140006a13 <__gdtoa+0x679>
   140006a53:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   140006a57:	74 47                	je     140006aa0 <__gdtoa+0x706>
   140006a59:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a5e:	f2 0f 10 05 2a 49 00 	movsd  xmm0,QWORD PTR [rip+0x492a]        # 14000b390 <.rdata+0x40>
   140006a65:	00 
   140006a66:	66 0f 2f c1          	comisd xmm0,xmm1
   140006a6a:	76 34                	jbe    140006aa0 <__gdtoa+0x706>
   140006a6c:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006a70:	7e 2e                	jle    140006aa0 <__gdtoa+0x706>
   140006a72:	83 7d 68 00          	cmp    DWORD PTR [rbp+0x68],0x0
   140006a76:	0f 8e f5 02 00 00    	jle    140006d71 <__gdtoa+0x9d7>
   140006a7c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   140006a7f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006a82:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140006a86:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a8b:	f2 0f 10 05 05 49 00 	movsd  xmm0,QWORD PTR [rip+0x4905]        # 14000b398 <.rdata+0x48>
   140006a92:	00 
   140006a93:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006a97:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a9c:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006aa0:	66 0f ef c9          	pxor   xmm1,xmm1
   140006aa4:	f2 0f 2a 4d 70       	cvtsi2sd xmm1,DWORD PTR [rbp+0x70]
   140006aa9:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006aae:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006ab2:	f2 0f 10 05 e6 48 00 	movsd  xmm0,QWORD PTR [rip+0x48e6]        # 14000b3a0 <.rdata+0x50>
   140006ab9:	00 
   140006aba:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006abe:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006ac3:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   140006ac6:	2d 00 00 40 03       	sub    eax,0x3400000
   140006acb:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   140006ace:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006ad2:	75 5f                	jne    140006b33 <__gdtoa+0x799>
   140006ad4:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006adb:	00 
   140006adc:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006ae0:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006ae4:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ae9:	f2 0f 10 0d b7 48 00 	movsd  xmm1,QWORD PTR [rip+0x48b7]        # 14000b3a8 <.rdata+0x58>
   140006af0:	00 
   140006af1:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006af5:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006afa:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006aff:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006b04:	66 0f 2f c1          	comisd xmm0,xmm1
   140006b08:	0f 87 ac 07 00 00    	ja     1400072ba <__gdtoa+0xf20>
   140006b0e:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006b13:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006b18:	f3 0f 7e 15 90 48 00 	movq   xmm2,QWORD PTR [rip+0x4890]        # 14000b3b0 <.rdata+0x60>
   140006b1f:	00 
   140006b20:	66 0f 57 c2          	xorpd  xmm0,xmm2
   140006b24:	66 0f 2f c1          	comisd xmm0,xmm1
   140006b28:	0f 87 6e 07 00 00    	ja     14000729c <__gdtoa+0xf02>
   140006b2e:	e9 42 02 00 00       	jmp    140006d75 <__gdtoa+0x9db>
   140006b33:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006b37:	0f 84 22 01 00 00    	je     140006c5f <__gdtoa+0x8c5>
   140006b3d:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006b42:	f2 0f 10 05 76 48 00 	movsd  xmm0,QWORD PTR [rip+0x4876]        # 14000b3c0 <.rdata+0x70>
   140006b49:	00 
   140006b4a:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b4e:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006b51:	8d 50 ff             	lea    edx,[rax-0x1]
   140006b54:	48 8b 05 25 4b 00 00 	mov    rax,QWORD PTR [rip+0x4b25]        # 14000b680 <.refptr.__tens_D2A>
   140006b5b:	48 63 d2             	movsxd rdx,edx
   140006b5e:	f2 0f 10 0c d0       	movsd  xmm1,QWORD PTR [rax+rdx*8]
   140006b63:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006b67:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006b6c:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006b70:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006b75:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006b7c:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b81:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006b86:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006b8a:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006b8d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b92:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b96:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006b9b:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006ba0:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006ba4:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006ba9:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006bac:	8d 48 30             	lea    ecx,[rax+0x30]
   140006baf:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006bb3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006bb7:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006bbb:	89 ca                	mov    edx,ecx
   140006bbd:	88 10                	mov    BYTE PTR [rax],dl
   140006bbf:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006bc4:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006bc9:	66 0f 2f c1          	comisd xmm0,xmm1
   140006bcd:	76 29                	jbe    140006bf8 <__gdtoa+0x85e>
   140006bcf:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006bd4:	66 0f ef c9          	pxor   xmm1,xmm1
   140006bd8:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006bdc:	7a 0e                	jp     140006bec <__gdtoa+0x852>
   140006bde:	66 0f ef c9          	pxor   xmm1,xmm1
   140006be2:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006be6:	0f 84 93 0c 00 00    	je     14000787f <__gdtoa+0x14e5>
   140006bec:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006bf3:	e9 87 0c 00 00       	jmp    14000787f <__gdtoa+0x14e5>
   140006bf8:	f2 0f 10 55 a8       	movsd  xmm2,QWORD PTR [rbp-0x58]
   140006bfd:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006c02:	66 0f 28 c8          	movapd xmm1,xmm0
   140006c06:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006c0a:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006c0f:	66 0f 2f c1          	comisd xmm0,xmm1
   140006c13:	0f 87 c3 02 00 00    	ja     140006edc <__gdtoa+0xb42>
   140006c19:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006c1c:	83 c0 01             	add    eax,0x1
   140006c1f:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006c22:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006c25:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006c28:	0f 8e 46 01 00 00    	jle    140006d74 <__gdtoa+0x9da>
   140006c2e:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006c33:	f2 0f 10 05 5d 47 00 	movsd  xmm0,QWORD PTR [rip+0x475d]        # 14000b398 <.rdata+0x48>
   140006c3a:	00 
   140006c3b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c3f:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006c44:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006c49:	f2 0f 10 05 47 47 00 	movsd  xmm0,QWORD PTR [rip+0x4747]        # 14000b398 <.rdata+0x48>
   140006c50:	00 
   140006c51:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c55:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c5a:	e9 1d ff ff ff       	jmp    140006b7c <__gdtoa+0x7e2>
   140006c5f:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006c64:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006c67:	8d 50 ff             	lea    edx,[rax-0x1]
   140006c6a:	48 8b 05 0f 4a 00 00 	mov    rax,QWORD PTR [rip+0x4a0f]        # 14000b680 <.refptr.__tens_D2A>
   140006c71:	48 63 d2             	movsxd rdx,edx
   140006c74:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006c79:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c7d:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006c82:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006c89:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c8e:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006c93:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006c97:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006c9a:	83 7d d4 00          	cmp    DWORD PTR [rbp-0x2c],0x0
   140006c9e:	74 1c                	je     140006cbc <__gdtoa+0x922>
   140006ca0:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ca5:	66 0f ef c9          	pxor   xmm1,xmm1
   140006ca9:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006cae:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006cb3:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006cb7:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006cbc:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006cbf:	8d 48 30             	lea    ecx,[rax+0x30]
   140006cc2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006cc6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006cca:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006cce:	89 ca                	mov    edx,ecx
   140006cd0:	88 10                	mov    BYTE PTR [rax],dl
   140006cd2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006cd5:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006cd8:	75 73                	jne    140006d4d <__gdtoa+0x9b3>
   140006cda:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006cdf:	f2 0f 10 05 d9 46 00 	movsd  xmm0,QWORD PTR [rip+0x46d9]        # 14000b3c0 <.rdata+0x70>
   140006ce6:	00 
   140006ce7:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006ceb:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006cf0:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006cf5:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006cfa:	f2 0f 58 4d 08       	addsd  xmm1,QWORD PTR [rbp+0x8]
   140006cff:	66 0f 2f c1          	comisd xmm0,xmm1
   140006d03:	0f 87 d6 01 00 00    	ja     140006edf <__gdtoa+0xb45>
   140006d09:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006d0e:	f2 0f 10 55 a0       	movsd  xmm2,QWORD PTR [rbp-0x60]
   140006d13:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006d18:	f2 0f 5c c2          	subsd  xmm0,xmm2
   140006d1c:	66 0f 2f c1          	comisd xmm0,xmm1
   140006d20:	77 02                	ja     140006d24 <__gdtoa+0x98a>
   140006d22:	eb 51                	jmp    140006d75 <__gdtoa+0x9db>
   140006d24:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d29:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d2d:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006d31:	7a 0e                	jp     140006d41 <__gdtoa+0x9a7>
   140006d33:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d37:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006d3b:	0f 84 41 0b 00 00    	je     140007882 <__gdtoa+0x14e8>
   140006d41:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006d48:	e9 35 0b 00 00       	jmp    140007882 <__gdtoa+0x14e8>
   140006d4d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006d50:	83 c0 01             	add    eax,0x1
   140006d53:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006d56:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006d5b:	f2 0f 10 05 35 46 00 	movsd  xmm0,QWORD PTR [rip+0x4635]        # 14000b398 <.rdata+0x48>
   140006d62:	00 
   140006d63:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006d67:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d6c:	e9 18 ff ff ff       	jmp    140006c89 <__gdtoa+0x8ef>
   140006d71:	90                   	nop
   140006d72:	eb 01                	jmp    140006d75 <__gdtoa+0x9db>
   140006d74:	90                   	nop
   140006d75:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006d79:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006d7d:	f2 0f 10 45 e0       	movsd  xmm0,QWORD PTR [rbp-0x20]
   140006d82:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d87:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140006d8a:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006d8d:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140006d90:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006d93:	83 bd 98 00 00 00 00 	cmp    DWORD PTR [rbp+0x98],0x0
   140006d9a:	0f 88 bf 01 00 00    	js     140006f5f <__gdtoa+0xbc5>
   140006da0:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006da7:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006daa:	39 45 58             	cmp    DWORD PTR [rbp+0x58],eax
   140006dad:	0f 8f ac 01 00 00    	jg     140006f5f <__gdtoa+0xbc5>
   140006db3:	48 8b 05 c6 48 00 00 	mov    rax,QWORD PTR [rip+0x48c6]        # 14000b680 <.refptr.__tens_D2A>
   140006dba:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   140006dbd:	48 63 d2             	movsxd rdx,edx
   140006dc0:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006dc5:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006dca:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006dd1:	79 45                	jns    140006e18 <__gdtoa+0xa7e>
   140006dd3:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006dd7:	7f 3f                	jg     140006e18 <__gdtoa+0xa7e>
   140006dd9:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006de0:	00 
   140006de1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006de5:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006de9:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006ded:	0f 88 ac 04 00 00    	js     14000729f <__gdtoa+0xf05>
   140006df3:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006df8:	f2 0f 10 55 08       	movsd  xmm2,QWORD PTR [rbp+0x8]
   140006dfd:	f2 0f 10 05 a3 45 00 	movsd  xmm0,QWORD PTR [rip+0x45a3]        # 14000b3a8 <.rdata+0x58>
   140006e04:	00 
   140006e05:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006e09:	66 0f 2f c1          	comisd xmm0,xmm1
   140006e0d:	0f 83 8c 04 00 00    	jae    14000729f <__gdtoa+0xf05>
   140006e13:	e9 a6 04 00 00       	jmp    1400072be <__gdtoa+0xf24>
   140006e18:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006e1f:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e24:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006e29:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006e2d:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006e30:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e35:	66 0f ef c9          	pxor   xmm1,xmm1
   140006e39:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006e3e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006e43:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006e47:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006e4c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006e4f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006e52:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e56:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006e5a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006e5e:	89 ca                	mov    edx,ecx
   140006e60:	88 10                	mov    BYTE PTR [rax],dl
   140006e62:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e67:	66 0f ef c9          	pxor   xmm1,xmm1
   140006e6b:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006e6f:	7a 0e                	jp     140006e7f <__gdtoa+0xae5>
   140006e71:	66 0f ef c9          	pxor   xmm1,xmm1
   140006e75:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006e79:	0f 84 da 00 00 00    	je     140006f59 <__gdtoa+0xbbf>
   140006e7f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006e82:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006e85:	0f 85 aa 00 00 00    	jne    140006f35 <__gdtoa+0xb9b>
   140006e8b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006e8f:	74 12                	je     140006ea3 <__gdtoa+0xb09>
   140006e91:	83 7d 44 01          	cmp    DWORD PTR [rbp+0x44],0x1
   140006e95:	74 4b                	je     140006ee2 <__gdtoa+0xb48>
   140006e97:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006e9e:	e9 e3 09 00 00       	jmp    140007886 <__gdtoa+0x14ec>
   140006ea3:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ea8:	f2 0f 58 c0          	addsd  xmm0,xmm0
   140006eac:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006eb1:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006eb6:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006ebb:	77 28                	ja     140006ee5 <__gdtoa+0xb4b>
   140006ebd:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ec2:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006ec7:	7a 63                	jp     140006f2c <__gdtoa+0xb92>
   140006ec9:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006ece:	75 5c                	jne    140006f2c <__gdtoa+0xb92>
   140006ed0:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006ed3:	83 e0 01             	and    eax,0x1
   140006ed6:	85 c0                	test   eax,eax
   140006ed8:	74 52                	je     140006f2c <__gdtoa+0xb92>
   140006eda:	eb 0a                	jmp    140006ee6 <__gdtoa+0xb4c>
   140006edc:	90                   	nop
   140006edd:	eb 07                	jmp    140006ee6 <__gdtoa+0xb4c>
   140006edf:	90                   	nop
   140006ee0:	eb 04                	jmp    140006ee6 <__gdtoa+0xb4c>
   140006ee2:	90                   	nop
   140006ee3:	eb 01                	jmp    140006ee6 <__gdtoa+0xb4c>
   140006ee5:	90                   	nop
   140006ee6:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140006eed:	eb 17                	jmp    140006f06 <__gdtoa+0xb6c>
   140006eef:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006ef3:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140006ef7:	75 0d                	jne    140006f06 <__gdtoa+0xb6c>
   140006ef9:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140006efd:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006f01:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140006f04:	eb 10                	jmp    140006f16 <__gdtoa+0xb7c>
   140006f06:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140006f0b:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006f0f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140006f12:	3c 39                	cmp    al,0x39
   140006f14:	74 d9                	je     140006eef <__gdtoa+0xb55>
   140006f16:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006f1a:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006f1e:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006f22:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140006f25:	83 c2 01             	add    edx,0x1
   140006f28:	88 10                	mov    BYTE PTR [rax],dl
   140006f2a:	eb 2e                	jmp    140006f5a <__gdtoa+0xbc0>
   140006f2c:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006f33:	eb 25                	jmp    140006f5a <__gdtoa+0xbc0>
   140006f35:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f38:	83 c0 01             	add    eax,0x1
   140006f3b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f3e:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006f43:	f2 0f 10 05 4d 44 00 	movsd  xmm0,QWORD PTR [rip+0x444d]        # 14000b398 <.rdata+0x48>
   140006f4a:	00 
   140006f4b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006f4f:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006f54:	e9 c6 fe ff ff       	jmp    140006e1f <__gdtoa+0xa85>
   140006f59:	90                   	nop
   140006f5a:	e9 27 09 00 00       	jmp    140007886 <__gdtoa+0x14ec>
   140006f5f:	8b 45 7c             	mov    eax,DWORD PTR [rbp+0x7c]
   140006f62:	89 45 4c             	mov    DWORD PTR [rbp+0x4c],eax
   140006f65:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006f68:	89 45 48             	mov    DWORD PTR [rbp+0x48],eax
   140006f6b:	48 c7 45 20 00 00 00 	mov    QWORD PTR [rbp+0x20],0x0
   140006f72:	00 
   140006f73:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006f77:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006f7b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006f7f:	0f 84 e0 00 00 00    	je     140007065 <__gdtoa+0xccb>
   140006f85:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   140006f88:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006f8b:	29 c2                	sub    edx,eax
   140006f8d:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006f90:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f93:	8d 50 01             	lea    edx,[rax+0x1]
   140006f96:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006f99:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006f9f:	29 c2                	sub    edx,eax
   140006fa1:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006fa8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006fab:	39 c2                	cmp    edx,eax
   140006fad:	7d 43                	jge    140006ff2 <__gdtoa+0xc58>
   140006faf:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006fb6:	74 3a                	je     140006ff2 <__gdtoa+0xc58>
   140006fb8:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006fbf:	74 31                	je     140006ff2 <__gdtoa+0xc58>
   140006fc1:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006fc8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006fcb:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006fd1:	29 c2                	sub    edx,eax
   140006fd3:	8d 42 01             	lea    eax,[rdx+0x1]
   140006fd6:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006fd9:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006fe0:	7e 68                	jle    14000704a <__gdtoa+0xcb0>
   140006fe2:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006fe6:	7e 62                	jle    14000704a <__gdtoa+0xcb0>
   140006fe8:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006feb:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006fee:	7d 5a                	jge    14000704a <__gdtoa+0xcb0>
   140006ff0:	eb 0a                	jmp    140006ffc <__gdtoa+0xc62>
   140006ff2:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006ff9:	7e 50                	jle    14000704b <__gdtoa+0xcb1>
   140006ffb:	90                   	nop
   140006ffc:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006fff:	83 e8 01             	sub    eax,0x1
   140007002:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140007005:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140007008:	3b 45 60             	cmp    eax,DWORD PTR [rbp+0x60]
   14000700b:	7c 08                	jl     140007015 <__gdtoa+0xc7b>
   14000700d:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140007010:	29 45 48             	sub    DWORD PTR [rbp+0x48],eax
   140007013:	eb 19                	jmp    14000702e <__gdtoa+0xc94>
   140007015:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140007018:	29 45 60             	sub    DWORD PTR [rbp+0x60],eax
   14000701b:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   14000701e:	01 45 3c             	add    DWORD PTR [rbp+0x3c],eax
   140007021:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140007024:	01 45 78             	add    DWORD PTR [rbp+0x78],eax
   140007027:	c7 45 48 00 00 00 00 	mov    DWORD PTR [rbp+0x48],0x0
   14000702e:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140007031:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007034:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007037:	85 c0                	test   eax,eax
   140007039:	79 10                	jns    14000704b <__gdtoa+0xcb1>
   14000703b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000703e:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140007041:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140007048:	eb 01                	jmp    14000704b <__gdtoa+0xcb1>
   14000704a:	90                   	nop
   14000704b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000704e:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   140007051:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007054:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140007057:	b9 01 00 00 00       	mov    ecx,0x1
   14000705c:	e8 f6 0f 00 00       	call   140008057 <__i2b_D2A>
   140007061:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007065:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   140007069:	7e 26                	jle    140007091 <__gdtoa+0xcf7>
   14000706b:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   14000706f:	7e 20                	jle    140007091 <__gdtoa+0xcf7>
   140007071:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140007074:	8b 45 4c             	mov    eax,DWORD PTR [rbp+0x4c]
   140007077:	39 c2                	cmp    edx,eax
   140007079:	0f 4e c2             	cmovle eax,edx
   14000707c:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000707f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007082:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140007085:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007088:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   14000708b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000708e:	29 45 40             	sub    DWORD PTR [rbp+0x40],eax
   140007091:	83 7d 78 00          	cmp    DWORD PTR [rbp+0x78],0x0
   140007095:	7e 7e                	jle    140007115 <__gdtoa+0xd7b>
   140007097:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   14000709b:	74 65                	je     140007102 <__gdtoa+0xd68>
   14000709d:	83 7d 48 00          	cmp    DWORD PTR [rbp+0x48],0x0
   1400070a1:	7e 3b                	jle    1400070de <__gdtoa+0xd44>
   1400070a3:	8b 55 48             	mov    edx,DWORD PTR [rbp+0x48]
   1400070a6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400070aa:	48 89 c1             	mov    rcx,rax
   1400070ad:	e8 11 12 00 00       	call   1400082c3 <__pow5mult_D2A>
   1400070b2:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400070b6:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400070ba:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400070be:	48 89 c1             	mov    rcx,rax
   1400070c1:	e8 d7 0f 00 00       	call   14000809d <__mult_D2A>
   1400070c6:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400070ca:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070ce:	48 89 c1             	mov    rcx,rax
   1400070d1:	e8 c8 0d 00 00       	call   140007e9e <__Bfree_D2A>
   1400070d6:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400070da:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400070de:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   1400070e1:	2b 45 48             	sub    eax,DWORD PTR [rbp+0x48]
   1400070e4:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400070e7:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400070eb:	74 28                	je     140007115 <__gdtoa+0xd7b>
   1400070ed:	8b 55 60             	mov    edx,DWORD PTR [rbp+0x60]
   1400070f0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070f4:	48 89 c1             	mov    rcx,rax
   1400070f7:	e8 c7 11 00 00       	call   1400082c3 <__pow5mult_D2A>
   1400070fc:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007100:	eb 13                	jmp    140007115 <__gdtoa+0xd7b>
   140007102:	8b 55 78             	mov    edx,DWORD PTR [rbp+0x78]
   140007105:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007109:	48 89 c1             	mov    rcx,rax
   14000710c:	e8 b2 11 00 00       	call   1400082c3 <__pow5mult_D2A>
   140007111:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007115:	b9 01 00 00 00       	mov    ecx,0x1
   14000711a:	e8 38 0f 00 00       	call   140008057 <__i2b_D2A>
   14000711f:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007123:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007127:	7e 13                	jle    14000713c <__gdtoa+0xda2>
   140007129:	8b 55 3c             	mov    edx,DWORD PTR [rbp+0x3c]
   14000712c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007130:	48 89 c1             	mov    rcx,rax
   140007133:	e8 8b 11 00 00       	call   1400082c3 <__pow5mult_D2A>
   140007138:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000713c:	c7 45 38 00 00 00 00 	mov    DWORD PTR [rbp+0x38],0x0
   140007143:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000714a:	7f 29                	jg     140007175 <__gdtoa+0xddb>
   14000714c:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   14000714f:	83 f8 01             	cmp    eax,0x1
   140007152:	75 21                	jne    140007175 <__gdtoa+0xddb>
   140007154:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000715b:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000715e:	83 c0 01             	add    eax,0x1
   140007161:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140007164:	7e 0f                	jle    140007175 <__gdtoa+0xddb>
   140007166:	83 45 7c 01          	add    DWORD PTR [rbp+0x7c],0x1
   14000716a:	83 45 40 01          	add    DWORD PTR [rbp+0x40],0x1
   14000716e:	c7 45 38 01 00 00 00 	mov    DWORD PTR [rbp+0x38],0x1
   140007175:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007179:	74 22                	je     14000719d <__gdtoa+0xe03>
   14000717b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000717f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007182:	8d 50 ff             	lea    edx,[rax-0x1]
   140007185:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007189:	48 63 d2             	movsxd rdx,edx
   14000718c:	48 83 c2 04          	add    rdx,0x4
   140007190:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   140007194:	89 c1                	mov    ecx,eax
   140007196:	e8 c5 f0 ff ff       	call   140006260 <__hi0bits_D2A>
   14000719b:	eb 05                	jmp    1400071a2 <__gdtoa+0xe08>
   14000719d:	b8 1f 00 00 00       	mov    eax,0x1f
   1400071a2:	2b 45 40             	sub    eax,DWORD PTR [rbp+0x40]
   1400071a5:	83 e8 04             	sub    eax,0x4
   1400071a8:	83 e0 1f             	and    eax,0x1f
   1400071ab:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400071ae:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400071b1:	01 45 4c             	add    DWORD PTR [rbp+0x4c],eax
   1400071b4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400071b7:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   1400071ba:	83 7d 7c 00          	cmp    DWORD PTR [rbp+0x7c],0x0
   1400071be:	7e 13                	jle    1400071d3 <__gdtoa+0xe39>
   1400071c0:	8b 55 7c             	mov    edx,DWORD PTR [rbp+0x7c]
   1400071c3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400071c7:	48 89 c1             	mov    rcx,rax
   1400071ca:	e8 b1 12 00 00       	call   140008480 <__lshift_D2A>
   1400071cf:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400071d3:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400071d6:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   1400071d9:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   1400071dd:	7e 13                	jle    1400071f2 <__gdtoa+0xe58>
   1400071df:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   1400071e2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400071e6:	48 89 c1             	mov    rcx,rax
   1400071e9:	e8 92 12 00 00       	call   140008480 <__lshift_D2A>
   1400071ee:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400071f2:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   1400071f6:	74 5a                	je     140007252 <__gdtoa+0xeb8>
   1400071f8:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400071fc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007200:	48 89 c1             	mov    rcx,rax
   140007203:	e8 05 14 00 00       	call   14000860d <__cmp_D2A>
   140007208:	85 c0                	test   eax,eax
   14000720a:	79 46                	jns    140007252 <__gdtoa+0xeb8>
   14000720c:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140007210:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007214:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000721a:	ba 0a 00 00 00       	mov    edx,0xa
   14000721f:	48 89 c1             	mov    rcx,rax
   140007222:	e8 02 0d 00 00       	call   140007f29 <__multadd_D2A>
   140007227:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000722b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   14000722f:	74 1b                	je     14000724c <__gdtoa+0xeb2>
   140007231:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007235:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000723b:	ba 0a 00 00 00       	mov    edx,0xa
   140007240:	48 89 c1             	mov    rcx,rax
   140007243:	e8 e1 0c 00 00       	call   140007f29 <__multadd_D2A>
   140007248:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000724c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000724f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140007252:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007256:	0f 8f 81 00 00 00    	jg     1400072dd <__gdtoa+0xf43>
   14000725c:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   140007263:	7e 78                	jle    1400072dd <__gdtoa+0xf43>
   140007265:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007269:	78 37                	js     1400072a2 <__gdtoa+0xf08>
   14000726b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000726f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007275:	ba 05 00 00 00       	mov    edx,0x5
   14000727a:	48 89 c1             	mov    rcx,rax
   14000727d:	e8 a7 0c 00 00       	call   140007f29 <__multadd_D2A>
   140007282:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007286:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000728a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000728e:	48 89 c1             	mov    rcx,rax
   140007291:	e8 77 13 00 00       	call   14000860d <__cmp_D2A>
   140007296:	85 c0                	test   eax,eax
   140007298:	7f 23                	jg     1400072bd <__gdtoa+0xf23>
   14000729a:	eb 07                	jmp    1400072a3 <__gdtoa+0xf09>
   14000729c:	90                   	nop
   14000729d:	eb 04                	jmp    1400072a3 <__gdtoa+0xf09>
   14000729f:	90                   	nop
   1400072a0:	eb 01                	jmp    1400072a3 <__gdtoa+0xf09>
   1400072a2:	90                   	nop
   1400072a3:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   1400072a9:	f7 d0                	not    eax
   1400072ab:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   1400072ae:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400072b5:	e9 87 05 00 00       	jmp    140007841 <__gdtoa+0x14a7>
   1400072ba:	90                   	nop
   1400072bb:	eb 01                	jmp    1400072be <__gdtoa+0xf24>
   1400072bd:	90                   	nop
   1400072be:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400072c5:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400072c9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400072cd:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400072d1:	c6 00 31             	mov    BYTE PTR [rax],0x31
   1400072d4:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   1400072d8:	e9 64 05 00 00       	jmp    140007841 <__gdtoa+0x14a7>
   1400072dd:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   1400072e1:	0f 84 14 04 00 00    	je     1400076fb <__gdtoa+0x1361>
   1400072e7:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   1400072eb:	7e 13                	jle    140007300 <__gdtoa+0xf66>
   1400072ed:	8b 55 4c             	mov    edx,DWORD PTR [rbp+0x4c]
   1400072f0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072f4:	48 89 c1             	mov    rcx,rax
   1400072f7:	e8 84 11 00 00       	call   140008480 <__lshift_D2A>
   1400072fc:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007300:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007304:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007308:	83 7d 38 00          	cmp    DWORD PTR [rbp+0x38],0x0
   14000730c:	74 57                	je     140007365 <__gdtoa+0xfcb>
   14000730e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007312:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007315:	89 c1                	mov    ecx,eax
   140007317:	e8 41 0a 00 00       	call   140007d5d <__Balloc_D2A>
   14000731c:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007320:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007324:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007327:	48 98                	cdqe
   140007329:	48 83 c0 02          	add    rax,0x2
   14000732d:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007334:	00 
   140007335:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007339:	48 8d 50 10          	lea    rdx,[rax+0x10]
   14000733d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007341:	48 83 c0 10          	add    rax,0x10
   140007345:	49 89 c8             	mov    r8,rcx
   140007348:	48 89 c1             	mov    rcx,rax
   14000734b:	e8 e8 23 00 00       	call   140009738 <memcpy>
   140007350:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007354:	ba 01 00 00 00       	mov    edx,0x1
   140007359:	48 89 c1             	mov    rcx,rax
   14000735c:	e8 1f 11 00 00       	call   140008480 <__lshift_D2A>
   140007361:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007365:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   14000736c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007370:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007374:	48 89 c1             	mov    rcx,rax
   140007377:	e8 62 ec ff ff       	call   140005fde <__quorem_D2A>
   14000737c:	83 c0 30             	add    eax,0x30
   14000737f:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007382:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140007386:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000738a:	48 89 c1             	mov    rcx,rax
   14000738d:	e8 7b 12 00 00       	call   14000860d <__cmp_D2A>
   140007392:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140007395:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007399:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000739d:	48 89 c1             	mov    rcx,rax
   1400073a0:	e8 38 13 00 00       	call   1400086dd <__diff_D2A>
   1400073a5:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400073a9:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   1400073ad:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400073b0:	85 c0                	test   eax,eax
   1400073b2:	75 15                	jne    1400073c9 <__gdtoa+0x102f>
   1400073b4:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   1400073b8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073bc:	48 89 c1             	mov    rcx,rax
   1400073bf:	e8 49 12 00 00       	call   14000860d <__cmp_D2A>
   1400073c4:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   1400073c7:	eb 07                	jmp    1400073d0 <__gdtoa+0x1036>
   1400073c9:	c7 45 5c 01 00 00 00 	mov    DWORD PTR [rbp+0x5c],0x1
   1400073d0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   1400073d4:	48 89 c1             	mov    rcx,rax
   1400073d7:	e8 c2 0a 00 00       	call   140007e9e <__Bfree_D2A>
   1400073dc:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400073e0:	75 70                	jne    140007452 <__gdtoa+0x10b8>
   1400073e2:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400073e9:	75 67                	jne    140007452 <__gdtoa+0x10b8>
   1400073eb:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   1400073f2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400073f4:	83 e0 01             	and    eax,0x1
   1400073f7:	85 c0                	test   eax,eax
   1400073f9:	75 57                	jne    140007452 <__gdtoa+0x10b8>
   1400073fb:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400073ff:	75 51                	jne    140007452 <__gdtoa+0x10b8>
   140007401:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   140007405:	0f 84 01 02 00 00    	je     14000760c <__gdtoa+0x1272>
   14000740b:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000740f:	7f 20                	jg     140007431 <__gdtoa+0x1097>
   140007411:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007415:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007418:	83 f8 01             	cmp    eax,0x1
   14000741b:	7f 0b                	jg     140007428 <__gdtoa+0x108e>
   14000741d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007421:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007424:	85 c0                	test   eax,eax
   140007426:	74 14                	je     14000743c <__gdtoa+0x10a2>
   140007428:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000742f:	eb 0b                	jmp    14000743c <__gdtoa+0x10a2>
   140007431:	83 45 74 01          	add    DWORD PTR [rbp+0x74],0x1
   140007435:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   14000743c:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007440:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007444:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007448:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000744b:	88 10                	mov    BYTE PTR [rax],dl
   14000744d:	e9 ef 03 00 00       	jmp    140007841 <__gdtoa+0x14a7>
   140007452:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007456:	78 2b                	js     140007483 <__gdtoa+0x10e9>
   140007458:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000745c:	0f 85 96 01 00 00    	jne    1400075f8 <__gdtoa+0x125e>
   140007462:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   140007469:	0f 85 89 01 00 00    	jne    1400075f8 <__gdtoa+0x125e>
   14000746f:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   140007476:	8b 00                	mov    eax,DWORD PTR [rax]
   140007478:	83 e0 01             	and    eax,0x1
   14000747b:	85 c0                	test   eax,eax
   14000747d:	0f 85 75 01 00 00    	jne    1400075f8 <__gdtoa+0x125e>
   140007483:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140007487:	0f 84 db 00 00 00    	je     140007568 <__gdtoa+0x11ce>
   14000748d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007491:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007494:	83 f8 01             	cmp    eax,0x1
   140007497:	7f 0f                	jg     1400074a8 <__gdtoa+0x110e>
   140007499:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000749d:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400074a0:	85 c0                	test   eax,eax
   1400074a2:	0f 84 c0 00 00 00    	je     140007568 <__gdtoa+0x11ce>
   1400074a8:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   1400074ac:	0f 85 83 00 00 00    	jne    140007535 <__gdtoa+0x119b>
   1400074b2:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400074b9:	e9 24 01 00 00       	jmp    1400075e2 <__gdtoa+0x1248>
   1400074be:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400074c2:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400074c6:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400074ca:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400074cd:	88 10                	mov    BYTE PTR [rax],dl
   1400074cf:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400074d3:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400074d9:	ba 0a 00 00 00       	mov    edx,0xa
   1400074de:	48 89 c1             	mov    rcx,rax
   1400074e1:	e8 43 0a 00 00       	call   140007f29 <__multadd_D2A>
   1400074e6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400074ea:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400074ee:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400074f2:	75 08                	jne    1400074fc <__gdtoa+0x1162>
   1400074f4:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400074f8:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400074fc:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140007500:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007504:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007508:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000750e:	ba 0a 00 00 00       	mov    edx,0xa
   140007513:	48 89 c1             	mov    rcx,rax
   140007516:	e8 0e 0a 00 00       	call   140007f29 <__multadd_D2A>
   14000751b:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000751f:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007523:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007527:	48 89 c1             	mov    rcx,rax
   14000752a:	e8 af ea ff ff       	call   140005fde <__quorem_D2A>
   14000752f:	83 c0 30             	add    eax,0x30
   140007532:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007535:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007539:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000753d:	48 89 c1             	mov    rcx,rax
   140007540:	e8 c8 10 00 00       	call   14000860d <__cmp_D2A>
   140007545:	85 c0                	test   eax,eax
   140007547:	0f 8f 71 ff ff ff    	jg     1400074be <__gdtoa+0x1124>
   14000754d:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007550:	8d 50 01             	lea    edx,[rax+0x1]
   140007553:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007556:	83 f8 39             	cmp    eax,0x39
   140007559:	0f 84 b0 00 00 00    	je     14000760f <__gdtoa+0x1275>
   14000755f:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007566:	eb 7a                	jmp    1400075e2 <__gdtoa+0x1248>
   140007568:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000756c:	7e 53                	jle    1400075c1 <__gdtoa+0x1227>
   14000756e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007572:	ba 01 00 00 00       	mov    edx,0x1
   140007577:	48 89 c1             	mov    rcx,rax
   14000757a:	e8 01 0f 00 00       	call   140008480 <__lshift_D2A>
   14000757f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007583:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007587:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000758b:	48 89 c1             	mov    rcx,rax
   14000758e:	e8 7a 10 00 00       	call   14000860d <__cmp_D2A>
   140007593:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007596:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000759a:	7f 10                	jg     1400075ac <__gdtoa+0x1212>
   14000759c:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400075a0:	75 18                	jne    1400075ba <__gdtoa+0x1220>
   1400075a2:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400075a5:	83 e0 01             	and    eax,0x1
   1400075a8:	85 c0                	test   eax,eax
   1400075aa:	74 0e                	je     1400075ba <__gdtoa+0x1220>
   1400075ac:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400075af:	8d 50 01             	lea    edx,[rax+0x1]
   1400075b2:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   1400075b5:	83 f8 39             	cmp    eax,0x39
   1400075b8:	74 58                	je     140007612 <__gdtoa+0x1278>
   1400075ba:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400075c1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400075c5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400075c8:	83 f8 01             	cmp    eax,0x1
   1400075cb:	7f 0b                	jg     1400075d8 <__gdtoa+0x123e>
   1400075cd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400075d1:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400075d4:	85 c0                	test   eax,eax
   1400075d6:	74 09                	je     1400075e1 <__gdtoa+0x1247>
   1400075d8:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400075df:	eb 01                	jmp    1400075e2 <__gdtoa+0x1248>
   1400075e1:	90                   	nop
   1400075e2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075e6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075ea:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075ee:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400075f1:	88 10                	mov    BYTE PTR [rax],dl
   1400075f3:	e9 49 02 00 00       	jmp    140007841 <__gdtoa+0x14a7>
   1400075f8:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400075fc:	7e 52                	jle    140007650 <__gdtoa+0x12b6>
   1400075fe:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   140007602:	74 4c                	je     140007650 <__gdtoa+0x12b6>
   140007604:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   140007608:	75 24                	jne    14000762e <__gdtoa+0x1294>
   14000760a:	eb 07                	jmp    140007613 <__gdtoa+0x1279>
   14000760c:	90                   	nop
   14000760d:	eb 04                	jmp    140007613 <__gdtoa+0x1279>
   14000760f:	90                   	nop
   140007610:	eb 01                	jmp    140007613 <__gdtoa+0x1279>
   140007612:	90                   	nop
   140007613:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007617:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000761b:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000761f:	c6 00 39             	mov    BYTE PTR [rax],0x39
   140007622:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007629:	e9 9d 01 00 00       	jmp    1400077cb <__gdtoa+0x1431>
   14000762e:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007635:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007638:	8d 48 01             	lea    ecx,[rax+0x1]
   14000763b:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000763f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007643:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007647:	89 ca                	mov    edx,ecx
   140007649:	88 10                	mov    BYTE PTR [rax],dl
   14000764b:	e9 f1 01 00 00       	jmp    140007841 <__gdtoa+0x14a7>
   140007650:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007654:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007658:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000765c:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000765f:	88 10                	mov    BYTE PTR [rax],dl
   140007661:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007664:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140007667:	0f 84 ea 00 00 00    	je     140007757 <__gdtoa+0x13bd>
   14000766d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007671:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007677:	ba 0a 00 00 00       	mov    edx,0xa
   14000767c:	48 89 c1             	mov    rcx,rax
   14000767f:	e8 a5 08 00 00       	call   140007f29 <__multadd_D2A>
   140007684:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007688:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000768c:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007690:	75 25                	jne    1400076b7 <__gdtoa+0x131d>
   140007692:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007696:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000769c:	ba 0a 00 00 00       	mov    edx,0xa
   1400076a1:	48 89 c1             	mov    rcx,rax
   1400076a4:	e8 80 08 00 00       	call   140007f29 <__multadd_D2A>
   1400076a9:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400076ad:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400076b1:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400076b5:	eb 36                	jmp    1400076ed <__gdtoa+0x1353>
   1400076b7:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400076bb:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400076c1:	ba 0a 00 00 00       	mov    edx,0xa
   1400076c6:	48 89 c1             	mov    rcx,rax
   1400076c9:	e8 5b 08 00 00       	call   140007f29 <__multadd_D2A>
   1400076ce:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400076d2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400076d6:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400076dc:	ba 0a 00 00 00       	mov    edx,0xa
   1400076e1:	48 89 c1             	mov    rcx,rax
   1400076e4:	e8 40 08 00 00       	call   140007f29 <__multadd_D2A>
   1400076e9:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400076ed:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400076f0:	83 c0 01             	add    eax,0x1
   1400076f3:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400076f6:	e9 71 fc ff ff       	jmp    14000736c <__gdtoa+0xfd2>
   1400076fb:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140007702:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007706:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000770a:	48 89 c1             	mov    rcx,rax
   14000770d:	e8 cc e8 ff ff       	call   140005fde <__quorem_D2A>
   140007712:	83 c0 30             	add    eax,0x30
   140007715:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007718:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000771c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007720:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007724:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   140007727:	88 10                	mov    BYTE PTR [rax],dl
   140007729:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000772c:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   14000772f:	7e 29                	jle    14000775a <__gdtoa+0x13c0>
   140007731:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007735:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000773b:	ba 0a 00 00 00       	mov    edx,0xa
   140007740:	48 89 c1             	mov    rcx,rax
   140007743:	e8 e1 07 00 00       	call   140007f29 <__multadd_D2A>
   140007748:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000774c:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000774f:	83 c0 01             	add    eax,0x1
   140007752:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007755:	eb ab                	jmp    140007702 <__gdtoa+0x1368>
   140007757:	90                   	nop
   140007758:	eb 01                	jmp    14000775b <__gdtoa+0x13c1>
   14000775a:	90                   	nop
   14000775b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000775f:	74 26                	je     140007787 <__gdtoa+0x13ed>
   140007761:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   140007765:	0f 84 ae 00 00 00    	je     140007819 <__gdtoa+0x147f>
   14000776b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000776f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007772:	83 f8 01             	cmp    eax,0x1
   140007775:	7f 50                	jg     1400077c7 <__gdtoa+0x142d>
   140007777:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000777b:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   14000777e:	85 c0                	test   eax,eax
   140007780:	75 45                	jne    1400077c7 <__gdtoa+0x142d>
   140007782:	e9 92 00 00 00       	jmp    140007819 <__gdtoa+0x147f>
   140007787:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000778b:	ba 01 00 00 00       	mov    edx,0x1
   140007790:	48 89 c1             	mov    rcx,rax
   140007793:	e8 e8 0c 00 00       	call   140008480 <__lshift_D2A>
   140007798:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000779c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400077a0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400077a4:	48 89 c1             	mov    rcx,rax
   1400077a7:	e8 61 0e 00 00       	call   14000860d <__cmp_D2A>
   1400077ac:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400077af:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400077b3:	7f 15                	jg     1400077ca <__gdtoa+0x1430>
   1400077b5:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400077b9:	75 61                	jne    14000781c <__gdtoa+0x1482>
   1400077bb:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400077be:	83 e0 01             	and    eax,0x1
   1400077c1:	85 c0                	test   eax,eax
   1400077c3:	74 5a                	je     14000781f <__gdtoa+0x1485>
   1400077c5:	eb 04                	jmp    1400077cb <__gdtoa+0x1431>
   1400077c7:	90                   	nop
   1400077c8:	eb 01                	jmp    1400077cb <__gdtoa+0x1431>
   1400077ca:	90                   	nop
   1400077cb:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400077d2:	eb 1f                	jmp    1400077f3 <__gdtoa+0x1459>
   1400077d4:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077d8:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400077dc:	75 15                	jne    1400077f3 <__gdtoa+0x1459>
   1400077de:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   1400077e2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077e6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400077ea:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400077ee:	c6 00 31             	mov    BYTE PTR [rax],0x31
   1400077f1:	eb 4e                	jmp    140007841 <__gdtoa+0x14a7>
   1400077f3:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   1400077f8:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077fc:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400077ff:	3c 39                	cmp    al,0x39
   140007801:	74 d1                	je     1400077d4 <__gdtoa+0x143a>
   140007803:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007807:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000780b:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000780f:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140007812:	83 c2 01             	add    edx,0x1
   140007815:	88 10                	mov    BYTE PTR [rax],dl
   140007817:	eb 28                	jmp    140007841 <__gdtoa+0x14a7>
   140007819:	90                   	nop
   14000781a:	eb 04                	jmp    140007820 <__gdtoa+0x1486>
   14000781c:	90                   	nop
   14000781d:	eb 01                	jmp    140007820 <__gdtoa+0x1486>
   14000781f:	90                   	nop
   140007820:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007824:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007827:	83 f8 01             	cmp    eax,0x1
   14000782a:	7f 0b                	jg     140007837 <__gdtoa+0x149d>
   14000782c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007830:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007833:	85 c0                	test   eax,eax
   140007835:	74 09                	je     140007840 <__gdtoa+0x14a6>
   140007837:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000783e:	eb 01                	jmp    140007841 <__gdtoa+0x14a7>
   140007840:	90                   	nop
   140007841:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007845:	48 89 c1             	mov    rcx,rax
   140007848:	e8 51 06 00 00       	call   140007e9e <__Bfree_D2A>
   14000784d:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140007852:	74 31                	je     140007885 <__gdtoa+0x14eb>
   140007854:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140007859:	74 16                	je     140007871 <__gdtoa+0x14d7>
   14000785b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000785f:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007863:	74 0c                	je     140007871 <__gdtoa+0x14d7>
   140007865:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007869:	48 89 c1             	mov    rcx,rax
   14000786c:	e8 2d 06 00 00       	call   140007e9e <__Bfree_D2A>
   140007871:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007875:	48 89 c1             	mov    rcx,rax
   140007878:	e8 21 06 00 00       	call   140007e9e <__Bfree_D2A>
   14000787d:	eb 0e                	jmp    14000788d <__gdtoa+0x14f3>
   14000787f:	90                   	nop
   140007880:	eb 0b                	jmp    14000788d <__gdtoa+0x14f3>
   140007882:	90                   	nop
   140007883:	eb 08                	jmp    14000788d <__gdtoa+0x14f3>
   140007885:	90                   	nop
   140007886:	eb 05                	jmp    14000788d <__gdtoa+0x14f3>
   140007888:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   14000788d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007891:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   140007895:	73 0f                	jae    1400078a6 <__gdtoa+0x150c>
   140007897:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000789b:	48 83 e8 01          	sub    rax,0x1
   14000789f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400078a2:	3c 30                	cmp    al,0x30
   1400078a4:	74 e2                	je     140007888 <__gdtoa+0x14ee>
   1400078a6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400078aa:	48 89 c1             	mov    rcx,rax
   1400078ad:	e8 ec 05 00 00       	call   140007e9e <__Bfree_D2A>
   1400078b2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400078b6:	c6 00 00             	mov    BYTE PTR [rax],0x0
   1400078b9:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400078bc:	8d 50 01             	lea    edx,[rax+0x1]
   1400078bf:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400078c6:	89 10                	mov    DWORD PTR [rax],edx
   1400078c8:	48 83 bd c8 00 00 00 	cmp    QWORD PTR [rbp+0xc8],0x0
   1400078cf:	00 
   1400078d0:	74 0e                	je     1400078e0 <__gdtoa+0x1546>
   1400078d2:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400078d9:	48 8b 55 00          	mov    rdx,QWORD PTR [rbp+0x0]
   1400078dd:	48 89 10             	mov    QWORD PTR [rax],rdx
   1400078e0:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400078e7:	8b 00                	mov    eax,DWORD PTR [rax]
   1400078e9:	0b 45 64             	or     eax,DWORD PTR [rbp+0x64]
   1400078ec:	89 c2                	mov    edx,eax
   1400078ee:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400078f5:	89 10                	mov    DWORD PTR [rax],edx
   1400078f7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400078fb:	48 81 c4 00 01 00 00 	add    rsp,0x100
   140007902:	5d                   	pop    rbp
   140007903:	c3                   	ret
   140007904:	90                   	nop
   140007905:	90                   	nop
   140007906:	90                   	nop
   140007907:	90                   	nop
   140007908:	90                   	nop
   140007909:	90                   	nop
   14000790a:	90                   	nop
   14000790b:	90                   	nop
   14000790c:	90                   	nop
   14000790d:	90                   	nop
   14000790e:	90                   	nop
   14000790f:	90                   	nop

0000000140007910 <__lo0bits_D2A>:
   140007910:	55                   	push   rbp
   140007911:	48 89 e5             	mov    rbp,rsp
   140007914:	48 83 ec 10          	sub    rsp,0x10
   140007918:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000791c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007920:	8b 00                	mov    eax,DWORD PTR [rax]
   140007922:	f3 0f bc c0          	tzcnt  eax,eax
   140007926:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007929:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000792d:	8b 10                	mov    edx,DWORD PTR [rax]
   14000792f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007932:	89 c1                	mov    ecx,eax
   140007934:	d3 ea                	shr    edx,cl
   140007936:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000793a:	89 10                	mov    DWORD PTR [rax],edx
   14000793c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000793f:	48 83 c4 10          	add    rsp,0x10
   140007943:	5d                   	pop    rbp
   140007944:	c3                   	ret

0000000140007945 <__rshift_D2A>:
   140007945:	55                   	push   rbp
   140007946:	48 89 e5             	mov    rbp,rsp
   140007949:	48 83 ec 20          	sub    rsp,0x20
   14000794d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007951:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007954:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007958:	48 83 c0 18          	add    rax,0x18
   14000795c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007960:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007964:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007968:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000796b:	c1 f8 05             	sar    eax,0x5
   14000796e:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007971:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007975:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007978:	39 45 e8             	cmp    DWORD PTR [rbp-0x18],eax
   14000797b:	0f 8d e4 00 00 00    	jge    140007a65 <__rshift_D2A+0x120>
   140007981:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007985:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007988:	48 98                	cdqe
   14000798a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007991:	00 
   140007992:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007996:	48 01 d0             	add    rax,rdx
   140007999:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000799d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400079a0:	48 98                	cdqe
   1400079a2:	48 c1 e0 02          	shl    rax,0x2
   1400079a6:	48 01 45 f8          	add    QWORD PTR [rbp-0x8],rax
   1400079aa:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   1400079ae:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400079b2:	0f 84 a3 00 00 00    	je     140007a5b <__rshift_D2A+0x116>
   1400079b8:	b8 20 00 00 00       	mov    eax,0x20
   1400079bd:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400079c0:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400079c3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079c7:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400079cb:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400079cf:	8b 10                	mov    edx,DWORD PTR [rax]
   1400079d1:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400079d4:	89 c1                	mov    ecx,eax
   1400079d6:	d3 ea                	shr    edx,cl
   1400079d8:	89 d0                	mov    eax,edx
   1400079da:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400079dd:	eb 3c                	jmp    140007a1b <__rshift_D2A+0xd6>
   1400079df:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079e3:	8b 10                	mov    edx,DWORD PTR [rax]
   1400079e5:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400079e8:	89 c1                	mov    ecx,eax
   1400079ea:	d3 e2                	shl    edx,cl
   1400079ec:	89 d1                	mov    ecx,edx
   1400079ee:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079f2:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400079f6:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400079fa:	0b 4d ec             	or     ecx,DWORD PTR [rbp-0x14]
   1400079fd:	89 ca                	mov    edx,ecx
   1400079ff:	89 10                	mov    DWORD PTR [rax],edx
   140007a01:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a05:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007a09:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140007a0d:	8b 10                	mov    edx,DWORD PTR [rax]
   140007a0f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007a12:	89 c1                	mov    ecx,eax
   140007a14:	d3 ea                	shr    edx,cl
   140007a16:	89 d0                	mov    eax,edx
   140007a18:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140007a1b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a1f:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140007a23:	72 ba                	jb     1400079df <__rshift_D2A+0x9a>
   140007a25:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007a29:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007a2c:	89 10                	mov    DWORD PTR [rax],edx
   140007a2e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007a32:	8b 00                	mov    eax,DWORD PTR [rax]
   140007a34:	85 c0                	test   eax,eax
   140007a36:	74 2d                	je     140007a65 <__rshift_D2A+0x120>
   140007a38:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   140007a3d:	eb 26                	jmp    140007a65 <__rshift_D2A+0x120>
   140007a3f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140007a43:	48 8d 42 04          	lea    rax,[rdx+0x4]
   140007a47:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007a4b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007a4f:	48 8d 48 04          	lea    rcx,[rax+0x4]
   140007a53:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
   140007a57:	8b 12                	mov    edx,DWORD PTR [rdx]
   140007a59:	89 10                	mov    DWORD PTR [rax],edx
   140007a5b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a5f:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140007a63:	72 da                	jb     140007a3f <__rshift_D2A+0xfa>
   140007a65:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a69:	48 83 c0 18          	add    rax,0x18
   140007a6d:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140007a71:	48 29 c2             	sub    rdx,rax
   140007a74:	48 89 d0             	mov    rax,rdx
   140007a77:	48 c1 f8 02          	sar    rax,0x2
   140007a7b:	89 c2                	mov    edx,eax
   140007a7d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a81:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007a84:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a88:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007a8b:	85 c0                	test   eax,eax
   140007a8d:	75 0b                	jne    140007a9a <__rshift_D2A+0x155>
   140007a8f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a93:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   140007a9a:	90                   	nop
   140007a9b:	48 83 c4 20          	add    rsp,0x20
   140007a9f:	5d                   	pop    rbp
   140007aa0:	c3                   	ret

0000000140007aa1 <__trailz_D2A>:
   140007aa1:	55                   	push   rbp
   140007aa2:	48 89 e5             	mov    rbp,rsp
   140007aa5:	48 83 ec 40          	sub    rsp,0x40
   140007aa9:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007aad:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007ab4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ab8:	48 83 c0 18          	add    rax,0x18
   140007abc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007ac0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ac4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007ac7:	48 98                	cdqe
   140007ac9:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007ad0:	00 
   140007ad1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007ad5:	48 01 d0             	add    rax,rdx
   140007ad8:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007adc:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007ae3:	eb 09                	jmp    140007aee <__trailz_D2A+0x4d>
   140007ae5:	83 45 f4 20          	add    DWORD PTR [rbp-0xc],0x20
   140007ae9:	48 83 45 f8 04       	add    QWORD PTR [rbp-0x8],0x4
   140007aee:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007af2:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007af6:	73 0a                	jae    140007b02 <__trailz_D2A+0x61>
   140007af8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007afc:	8b 00                	mov    eax,DWORD PTR [rax]
   140007afe:	85 c0                	test   eax,eax
   140007b00:	74 e3                	je     140007ae5 <__trailz_D2A+0x44>
   140007b02:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007b06:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007b0a:	73 18                	jae    140007b24 <__trailz_D2A+0x83>
   140007b0c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007b10:	8b 00                	mov    eax,DWORD PTR [rax]
   140007b12:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007b15:	48 8d 45 e4          	lea    rax,[rbp-0x1c]
   140007b19:	48 89 c1             	mov    rcx,rax
   140007b1c:	e8 ef fd ff ff       	call   140007910 <__lo0bits_D2A>
   140007b21:	01 45 f4             	add    DWORD PTR [rbp-0xc],eax
   140007b24:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007b27:	48 83 c4 40          	add    rsp,0x40
   140007b2b:	5d                   	pop    rbp
   140007b2c:	c3                   	ret
   140007b2d:	90                   	nop
   140007b2e:	90                   	nop
   140007b2f:	90                   	nop

0000000140007b30 <dtoa_lock_cleanup>:
   140007b30:	55                   	push   rbp
   140007b31:	48 89 e5             	mov    rbp,rsp
   140007b34:	48 83 ec 40          	sub    rsp,0x40
   140007b38:	48 8d 05 b1 76 00 00 	lea    rax,[rip+0x76b1]        # 14000f1f0 <dtoa_CS_init>
   140007b3f:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007b43:	c7 45 ec 03 00 00 00 	mov    DWORD PTR [rbp-0x14],0x3
   140007b4a:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007b4d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007b51:	87 10                	xchg   DWORD PTR [rax],edx
   140007b53:	89 d0                	mov    eax,edx
   140007b55:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007b58:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007b5c:	75 3d                	jne    140007b9b <dtoa_lock_cleanup+0x6b>
   140007b5e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007b65:	eb 2e                	jmp    140007b95 <dtoa_lock_cleanup+0x65>
   140007b67:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007b6a:	48 63 d0             	movsxd rdx,eax
   140007b6d:	48 89 d0             	mov    rax,rdx
   140007b70:	48 c1 e0 02          	shl    rax,0x2
   140007b74:	48 01 d0             	add    rax,rdx
   140007b77:	48 c1 e0 03          	shl    rax,0x3
   140007b7b:	48 8d 15 1e 76 00 00 	lea    rdx,[rip+0x761e]        # 14000f1a0 <dtoa_CritSec>
   140007b82:	48 01 d0             	add    rax,rdx
   140007b85:	48 89 c1             	mov    rcx,rax
   140007b88:	48 8b 05 59 86 00 00 	mov    rax,QWORD PTR [rip+0x8659]        # 1400101e8 <__IAT_start__>
   140007b8f:	ff d0                	call   rax
   140007b91:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007b95:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007b99:	7e cc                	jle    140007b67 <dtoa_lock_cleanup+0x37>
   140007b9b:	90                   	nop
   140007b9c:	48 83 c4 40          	add    rsp,0x40
   140007ba0:	5d                   	pop    rbp
   140007ba1:	c3                   	ret

0000000140007ba2 <dtoa_lock>:
   140007ba2:	55                   	push   rbp
   140007ba3:	48 89 e5             	mov    rbp,rsp
   140007ba6:	48 83 ec 40          	sub    rsp,0x40
   140007baa:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007bad:	8b 05 3d 76 00 00    	mov    eax,DWORD PTR [rip+0x763d]        # 14000f1f0 <dtoa_CS_init>
   140007bb3:	83 f8 02             	cmp    eax,0x2
   140007bb6:	75 2c                	jne    140007be4 <dtoa_lock+0x42>
   140007bb8:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007bbb:	48 89 d0             	mov    rax,rdx
   140007bbe:	48 c1 e0 02          	shl    rax,0x2
   140007bc2:	48 01 d0             	add    rax,rdx
   140007bc5:	48 c1 e0 03          	shl    rax,0x3
   140007bc9:	48 8d 15 d0 75 00 00 	lea    rdx,[rip+0x75d0]        # 14000f1a0 <dtoa_CritSec>
   140007bd0:	48 01 d0             	add    rax,rdx
   140007bd3:	48 89 c1             	mov    rcx,rax
   140007bd6:	48 8b 05 13 86 00 00 	mov    rax,QWORD PTR [rip+0x8613]        # 1400101f0 <__imp_EnterCriticalSection>
   140007bdd:	ff d0                	call   rax
   140007bdf:	e9 ea 00 00 00       	jmp    140007cce <dtoa_lock+0x12c>
   140007be4:	8b 05 06 76 00 00    	mov    eax,DWORD PTR [rip+0x7606]        # 14000f1f0 <dtoa_CS_init>
   140007bea:	85 c0                	test   eax,eax
   140007bec:	0f 85 9e 00 00 00    	jne    140007c90 <dtoa_lock+0xee>
   140007bf2:	48 8d 05 f7 75 00 00 	lea    rax,[rip+0x75f7]        # 14000f1f0 <dtoa_CS_init>
   140007bf9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007bfd:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140007c04:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007c07:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007c0b:	87 10                	xchg   DWORD PTR [rax],edx
   140007c0d:	89 d0                	mov    eax,edx
   140007c0f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007c12:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140007c16:	75 58                	jne    140007c70 <dtoa_lock+0xce>
   140007c18:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007c1f:	eb 2e                	jmp    140007c4f <dtoa_lock+0xad>
   140007c21:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007c24:	48 63 d0             	movsxd rdx,eax
   140007c27:	48 89 d0             	mov    rax,rdx
   140007c2a:	48 c1 e0 02          	shl    rax,0x2
   140007c2e:	48 01 d0             	add    rax,rdx
   140007c31:	48 c1 e0 03          	shl    rax,0x3
   140007c35:	48 8d 15 64 75 00 00 	lea    rdx,[rip+0x7564]        # 14000f1a0 <dtoa_CritSec>
   140007c3c:	48 01 d0             	add    rax,rdx
   140007c3f:	48 89 c1             	mov    rcx,rax
   140007c42:	48 8b 05 d7 85 00 00 	mov    rax,QWORD PTR [rip+0x85d7]        # 140010220 <__imp_InitializeCriticalSection>
   140007c49:	ff d0                	call   rax
   140007c4b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007c4f:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007c53:	7e cc                	jle    140007c21 <dtoa_lock+0x7f>
   140007c55:	48 8d 05 d4 fe ff ff 	lea    rax,[rip+0xfffffffffffffed4]        # 140007b30 <dtoa_lock_cleanup>
   140007c5c:	48 89 c1             	mov    rcx,rax
   140007c5f:	e8 cb 99 ff ff       	call   14000162f <atexit>
   140007c64:	c7 05 82 75 00 00 02 	mov    DWORD PTR [rip+0x7582],0x2        # 14000f1f0 <dtoa_CS_init>
   140007c6b:	00 00 00 
   140007c6e:	eb 20                	jmp    140007c90 <dtoa_lock+0xee>
   140007c70:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007c74:	75 1a                	jne    140007c90 <dtoa_lock+0xee>
   140007c76:	c7 05 70 75 00 00 02 	mov    DWORD PTR [rip+0x7570],0x2        # 14000f1f0 <dtoa_CS_init>
   140007c7d:	00 00 00 
   140007c80:	eb 0e                	jmp    140007c90 <dtoa_lock+0xee>
   140007c82:	b9 01 00 00 00       	mov    ecx,0x1
   140007c87:	48 8b 05 ba 85 00 00 	mov    rax,QWORD PTR [rip+0x85ba]        # 140010248 <__imp_Sleep>
   140007c8e:	ff d0                	call   rax
   140007c90:	8b 05 5a 75 00 00    	mov    eax,DWORD PTR [rip+0x755a]        # 14000f1f0 <dtoa_CS_init>
   140007c96:	83 f8 01             	cmp    eax,0x1
   140007c99:	74 e7                	je     140007c82 <dtoa_lock+0xe0>
   140007c9b:	8b 05 4f 75 00 00    	mov    eax,DWORD PTR [rip+0x754f]        # 14000f1f0 <dtoa_CS_init>
   140007ca1:	83 f8 02             	cmp    eax,0x2
   140007ca4:	75 28                	jne    140007cce <dtoa_lock+0x12c>
   140007ca6:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007ca9:	48 89 d0             	mov    rax,rdx
   140007cac:	48 c1 e0 02          	shl    rax,0x2
   140007cb0:	48 01 d0             	add    rax,rdx
   140007cb3:	48 c1 e0 03          	shl    rax,0x3
   140007cb7:	48 8d 15 e2 74 00 00 	lea    rdx,[rip+0x74e2]        # 14000f1a0 <dtoa_CritSec>
   140007cbe:	48 01 d0             	add    rax,rdx
   140007cc1:	48 89 c1             	mov    rcx,rax
   140007cc4:	48 8b 05 25 85 00 00 	mov    rax,QWORD PTR [rip+0x8525]        # 1400101f0 <__imp_EnterCriticalSection>
   140007ccb:	ff d0                	call   rax
   140007ccd:	90                   	nop
   140007cce:	48 83 c4 40          	add    rsp,0x40
   140007cd2:	5d                   	pop    rbp
   140007cd3:	c3                   	ret

0000000140007cd4 <dtoa_unlock>:
   140007cd4:	55                   	push   rbp
   140007cd5:	48 89 e5             	mov    rbp,rsp
   140007cd8:	48 83 ec 20          	sub    rsp,0x20
   140007cdc:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007cdf:	8b 05 0b 75 00 00    	mov    eax,DWORD PTR [rip+0x750b]        # 14000f1f0 <dtoa_CS_init>
   140007ce5:	83 f8 02             	cmp    eax,0x2
   140007ce8:	75 27                	jne    140007d11 <dtoa_unlock+0x3d>
   140007cea:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007ced:	48 89 d0             	mov    rax,rdx
   140007cf0:	48 c1 e0 02          	shl    rax,0x2
   140007cf4:	48 01 d0             	add    rax,rdx
   140007cf7:	48 c1 e0 03          	shl    rax,0x3
   140007cfb:	48 8d 15 9e 74 00 00 	lea    rdx,[rip+0x749e]        # 14000f1a0 <dtoa_CritSec>
   140007d02:	48 01 d0             	add    rax,rdx
   140007d05:	48 89 c1             	mov    rcx,rax
   140007d08:	48 8b 05 19 85 00 00 	mov    rax,QWORD PTR [rip+0x8519]        # 140010228 <__imp_LeaveCriticalSection>
   140007d0f:	ff d0                	call   rax
   140007d11:	90                   	nop
   140007d12:	48 83 c4 20          	add    rsp,0x20
   140007d16:	5d                   	pop    rbp
   140007d17:	c3                   	ret

0000000140007d18 <__lo0bits_D2A>:
   140007d18:	55                   	push   rbp
   140007d19:	48 89 e5             	mov    rbp,rsp
   140007d1c:	48 83 ec 10          	sub    rsp,0x10
   140007d20:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007d24:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007d28:	8b 00                	mov    eax,DWORD PTR [rax]
   140007d2a:	f3 0f bc c0          	tzcnt  eax,eax
   140007d2e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007d31:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007d35:	8b 10                	mov    edx,DWORD PTR [rax]
   140007d37:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007d3a:	89 c1                	mov    ecx,eax
   140007d3c:	d3 ea                	shr    edx,cl
   140007d3e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007d42:	89 10                	mov    DWORD PTR [rax],edx
   140007d44:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007d47:	48 83 c4 10          	add    rsp,0x10
   140007d4b:	5d                   	pop    rbp
   140007d4c:	c3                   	ret

0000000140007d4d <__hi0bits_D2A>:
   140007d4d:	55                   	push   rbp
   140007d4e:	48 89 e5             	mov    rbp,rsp
   140007d51:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007d54:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   140007d58:	83 f0 1f             	xor    eax,0x1f
   140007d5b:	5d                   	pop    rbp
   140007d5c:	c3                   	ret

0000000140007d5d <__Balloc_D2A>:
   140007d5d:	55                   	push   rbp
   140007d5e:	48 89 e5             	mov    rbp,rsp
   140007d61:	48 83 ec 30          	sub    rsp,0x30
   140007d65:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007d68:	b9 00 00 00 00       	mov    ecx,0x0
   140007d6d:	e8 30 fe ff ff       	call   140007ba2 <dtoa_lock>
   140007d72:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007d76:	7f 48                	jg     140007dc0 <__Balloc_D2A+0x63>
   140007d78:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007d7b:	48 98                	cdqe
   140007d7d:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007d84:	00 
   140007d85:	48 8d 05 74 74 00 00 	lea    rax,[rip+0x7474]        # 14000f200 <freelist>
   140007d8c:	48 8b 04 02          	mov    rax,QWORD PTR [rdx+rax*1]
   140007d90:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d94:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007d99:	74 25                	je     140007dc0 <__Balloc_D2A+0x63>
   140007d9b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d9f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140007da2:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007da5:	48 63 d2             	movsxd rdx,edx
   140007da8:	48 8d 0c d5 00 00 00 	lea    rcx,[rdx*8+0x0]
   140007daf:	00 
   140007db0:	48 8d 15 49 74 00 00 	lea    rdx,[rip+0x7449]        # 14000f200 <freelist>
   140007db7:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007dbb:	e9 b1 00 00 00       	jmp    140007e71 <__Balloc_D2A+0x114>
   140007dc0:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007dc3:	ba 01 00 00 00       	mov    edx,0x1
   140007dc8:	89 c1                	mov    ecx,eax
   140007dca:	d3 e2                	shl    edx,cl
   140007dcc:	89 d0                	mov    eax,edx
   140007dce:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140007dd1:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007dd4:	83 e8 01             	sub    eax,0x1
   140007dd7:	48 98                	cdqe
   140007dd9:	48 c1 e0 02          	shl    rax,0x2
   140007ddd:	48 83 c0 27          	add    rax,0x27
   140007de1:	48 c1 e8 03          	shr    rax,0x3
   140007de5:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140007de8:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007dec:	7f 4e                	jg     140007e3c <__Balloc_D2A+0xdf>
   140007dee:	48 8b 15 9b 22 00 00 	mov    rdx,QWORD PTR [rip+0x229b]        # 14000a090 <pmem_next>
   140007df5:	48 8d 05 64 74 00 00 	lea    rax,[rip+0x7464]        # 14000f260 <private_mem>
   140007dfc:	48 29 c2             	sub    rdx,rax
   140007dff:	48 89 d0             	mov    rax,rdx
   140007e02:	48 c1 f8 03          	sar    rax,0x3
   140007e06:	48 89 c2             	mov    rdx,rax
   140007e09:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007e0c:	48 01 d0             	add    rax,rdx
   140007e0f:	48 3d 20 01 00 00    	cmp    rax,0x120
   140007e15:	77 25                	ja     140007e3c <__Balloc_D2A+0xdf>
   140007e17:	48 8b 05 72 22 00 00 	mov    rax,QWORD PTR [rip+0x2272]        # 14000a090 <pmem_next>
   140007e1e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007e22:	48 8b 05 67 22 00 00 	mov    rax,QWORD PTR [rip+0x2267]        # 14000a090 <pmem_next>
   140007e29:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140007e2c:	48 c1 e2 03          	shl    rdx,0x3
   140007e30:	48 01 d0             	add    rax,rdx
   140007e33:	48 89 05 56 22 00 00 	mov    QWORD PTR [rip+0x2256],rax        # 14000a090 <pmem_next>
   140007e3a:	eb 21                	jmp    140007e5d <__Balloc_D2A+0x100>
   140007e3c:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007e3f:	48 c1 e0 03          	shl    rax,0x3
   140007e43:	48 89 c1             	mov    rcx,rax
   140007e46:	e8 e5 18 00 00       	call   140009730 <malloc>
   140007e4b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007e4f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007e54:	75 07                	jne    140007e5d <__Balloc_D2A+0x100>
   140007e56:	b8 00 00 00 00       	mov    eax,0x0
   140007e5b:	eb 3b                	jmp    140007e98 <__Balloc_D2A+0x13b>
   140007e5d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e61:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007e64:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140007e67:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e6b:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140007e6e:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140007e71:	b9 00 00 00 00       	mov    ecx,0x0
   140007e76:	e8 59 fe ff ff       	call   140007cd4 <dtoa_unlock>
   140007e7b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e7f:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   140007e86:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e8a:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007e8d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e91:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140007e94:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e98:	48 83 c4 30          	add    rsp,0x30
   140007e9c:	5d                   	pop    rbp
   140007e9d:	c3                   	ret

0000000140007e9e <__Bfree_D2A>:
   140007e9e:	55                   	push   rbp
   140007e9f:	48 89 e5             	mov    rbp,rsp
   140007ea2:	48 83 ec 20          	sub    rsp,0x20
   140007ea6:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007eaa:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140007eaf:	74 71                	je     140007f22 <__Bfree_D2A+0x84>
   140007eb1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007eb5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007eb8:	83 f8 09             	cmp    eax,0x9
   140007ebb:	7e 0e                	jle    140007ecb <__Bfree_D2A+0x2d>
   140007ebd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ec1:	48 89 c1             	mov    rcx,rax
   140007ec4:	e8 57 18 00 00       	call   140009720 <free>
   140007ec9:	eb 57                	jmp    140007f22 <__Bfree_D2A+0x84>
   140007ecb:	b9 00 00 00 00       	mov    ecx,0x0
   140007ed0:	e8 cd fc ff ff       	call   140007ba2 <dtoa_lock>
   140007ed5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ed9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007edc:	48 98                	cdqe
   140007ede:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007ee5:	00 
   140007ee6:	48 8d 05 13 73 00 00 	lea    rax,[rip+0x7313]        # 14000f200 <freelist>
   140007eed:	48 8b 14 02          	mov    rdx,QWORD PTR [rdx+rax*1]
   140007ef1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ef5:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007ef8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007efc:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007eff:	48 98                	cdqe
   140007f01:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
   140007f08:	00 
   140007f09:	48 8d 15 f0 72 00 00 	lea    rdx,[rip+0x72f0]        # 14000f200 <freelist>
   140007f10:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f14:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007f18:	b9 00 00 00 00       	mov    ecx,0x0
   140007f1d:	e8 b2 fd ff ff       	call   140007cd4 <dtoa_unlock>
   140007f22:	90                   	nop
   140007f23:	48 83 c4 20          	add    rsp,0x20
   140007f27:	5d                   	pop    rbp
   140007f28:	c3                   	ret

0000000140007f29 <__multadd_D2A>:
   140007f29:	55                   	push   rbp
   140007f2a:	48 89 e5             	mov    rbp,rsp
   140007f2d:	48 83 ec 50          	sub    rsp,0x50
   140007f31:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007f35:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007f38:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140007f3c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f40:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007f43:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007f46:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f4a:	48 83 c0 18          	add    rax,0x18
   140007f4e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007f52:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007f59:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140007f5c:	48 98                	cdqe
   140007f5e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007f62:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007f66:	8b 00                	mov    eax,DWORD PTR [rax]
   140007f68:	89 c2                	mov    edx,eax
   140007f6a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007f6d:	48 98                	cdqe
   140007f6f:	48 0f af d0          	imul   rdx,rax
   140007f73:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140007f77:	48 01 d0             	add    rax,rdx
   140007f7a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140007f7e:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140007f82:	48 c1 e8 20          	shr    rax,0x20
   140007f86:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007f8a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007f8e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007f92:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140007f96:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140007f9a:	89 10                	mov    DWORD PTR [rax],edx
   140007f9c:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007fa0:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007fa3:	3b 45 e4             	cmp    eax,DWORD PTR [rbp-0x1c]
   140007fa6:	7c ba                	jl     140007f62 <__multadd_D2A+0x39>
   140007fa8:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140007fad:	0f 84 9a 00 00 00    	je     14000804d <__multadd_D2A+0x124>
   140007fb3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fb7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140007fba:	39 45 e4             	cmp    DWORD PTR [rbp-0x1c],eax
   140007fbd:	7c 67                	jl     140008026 <__multadd_D2A+0xfd>
   140007fbf:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fc3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007fc6:	83 c0 01             	add    eax,0x1
   140007fc9:	89 c1                	mov    ecx,eax
   140007fcb:	e8 8d fd ff ff       	call   140007d5d <__Balloc_D2A>
   140007fd0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140007fd4:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140007fd9:	75 07                	jne    140007fe2 <__multadd_D2A+0xb9>
   140007fdb:	b8 00 00 00 00       	mov    eax,0x0
   140007fe0:	eb 6f                	jmp    140008051 <__multadd_D2A+0x128>
   140007fe2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fe6:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007fe9:	48 98                	cdqe
   140007feb:	48 83 c0 02          	add    rax,0x2
   140007fef:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007ff6:	00 
   140007ff7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ffb:	48 8d 50 10          	lea    rdx,[rax+0x10]
   140007fff:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008003:	48 83 c0 10          	add    rax,0x10
   140008007:	49 89 c8             	mov    r8,rcx
   14000800a:	48 89 c1             	mov    rcx,rax
   14000800d:	e8 26 17 00 00       	call   140009738 <memcpy>
   140008012:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008016:	48 89 c1             	mov    rcx,rax
   140008019:	e8 80 fe ff ff       	call   140007e9e <__Bfree_D2A>
   14000801e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008022:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008026:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008029:	8d 50 01             	lea    edx,[rax+0x1]
   14000802c:	89 55 e4             	mov    DWORD PTR [rbp-0x1c],edx
   14000802f:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140008033:	89 d1                	mov    ecx,edx
   140008035:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008039:	48 98                	cdqe
   14000803b:	48 83 c0 04          	add    rax,0x4
   14000803f:	89 4c 82 08          	mov    DWORD PTR [rdx+rax*4+0x8],ecx
   140008043:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008047:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000804a:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000804d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008051:	48 83 c4 50          	add    rsp,0x50
   140008055:	5d                   	pop    rbp
   140008056:	c3                   	ret

0000000140008057 <__i2b_D2A>:
   140008057:	55                   	push   rbp
   140008058:	48 89 e5             	mov    rbp,rsp
   14000805b:	48 83 ec 30          	sub    rsp,0x30
   14000805f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140008062:	b9 01 00 00 00       	mov    ecx,0x1
   140008067:	e8 f1 fc ff ff       	call   140007d5d <__Balloc_D2A>
   14000806c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008070:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008075:	75 07                	jne    14000807e <__i2b_D2A+0x27>
   140008077:	b8 00 00 00 00       	mov    eax,0x0
   14000807c:	eb 19                	jmp    140008097 <__i2b_D2A+0x40>
   14000807e:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140008081:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008085:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008088:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000808c:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008093:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008097:	48 83 c4 30          	add    rsp,0x30
   14000809b:	5d                   	pop    rbp
   14000809c:	c3                   	ret

000000014000809d <__mult_D2A>:
   14000809d:	55                   	push   rbp
   14000809e:	48 89 e5             	mov    rbp,rsp
   1400080a1:	48 81 ec 90 00 00 00 	sub    rsp,0x90
   1400080a8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400080ac:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400080b0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080b4:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   1400080b7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400080bb:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400080be:	39 c2                	cmp    edx,eax
   1400080c0:	7d 18                	jge    1400080da <__mult_D2A+0x3d>
   1400080c2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080c6:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400080ca:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400080ce:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400080d2:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400080d6:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400080da:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080de:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400080e1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400080e4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080e8:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400080eb:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   1400080ee:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400080f2:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400080f5:	89 45 c0             	mov    DWORD PTR [rbp-0x40],eax
   1400080f8:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   1400080fb:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   1400080fe:	01 d0                	add    eax,edx
   140008100:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008103:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008107:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000810a:	39 45 f8             	cmp    DWORD PTR [rbp-0x8],eax
   14000810d:	7e 04                	jle    140008113 <__mult_D2A+0x76>
   14000810f:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140008113:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008116:	89 c1                	mov    ecx,eax
   140008118:	e8 40 fc ff ff       	call   140007d5d <__Balloc_D2A>
   14000811d:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140008121:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
   140008126:	75 0a                	jne    140008132 <__mult_D2A+0x95>
   140008128:	b8 00 00 00 00       	mov    eax,0x0
   14000812d:	e9 88 01 00 00       	jmp    1400082ba <__mult_D2A+0x21d>
   140008132:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008136:	48 83 c0 18          	add    rax,0x18
   14000813a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000813e:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008141:	48 98                	cdqe
   140008143:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000814a:	00 
   14000814b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000814f:	48 01 d0             	add    rax,rdx
   140008152:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140008156:	eb 0f                	jmp    140008167 <__mult_D2A+0xca>
   140008158:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000815c:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008162:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   140008167:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000816b:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   14000816f:	72 e7                	jb     140008158 <__mult_D2A+0xbb>
   140008171:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008175:	48 83 c0 18          	add    rax,0x18
   140008179:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000817d:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140008180:	48 98                	cdqe
   140008182:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008189:	00 
   14000818a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000818e:	48 01 d0             	add    rax,rdx
   140008191:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008195:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008199:	48 83 c0 18          	add    rax,0x18
   14000819d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400081a1:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   1400081a4:	48 98                	cdqe
   1400081a6:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400081ad:	00 
   1400081ae:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400081b2:	48 01 d0             	add    rax,rdx
   1400081b5:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   1400081b9:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400081bd:	48 83 c0 18          	add    rax,0x18
   1400081c1:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400081c5:	e9 95 00 00 00       	jmp    14000825f <__mult_D2A+0x1c2>
   1400081ca:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400081ce:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400081d2:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   1400081d6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400081d8:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   1400081db:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
   1400081df:	74 79                	je     14000825a <__mult_D2A+0x1bd>
   1400081e1:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400081e5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400081e9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400081ed:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400081f1:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   1400081f8:	00 
   1400081f9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400081fd:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008201:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140008205:	8b 00                	mov    eax,DWORD PTR [rax]
   140008207:	89 c2                	mov    edx,eax
   140008209:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   14000820c:	48 0f af d0          	imul   rdx,rax
   140008210:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008214:	8b 00                	mov    eax,DWORD PTR [rax]
   140008216:	89 c0                	mov    eax,eax
   140008218:	48 01 c2             	add    rdx,rax
   14000821b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000821f:	48 01 d0             	add    rax,rdx
   140008222:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   140008226:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
   14000822a:	48 c1 e8 20          	shr    rax,0x20
   14000822e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008232:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008236:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000823a:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000823e:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140008242:	89 10                	mov    DWORD PTR [rax],edx
   140008244:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008248:	48 3b 45 b0          	cmp    rax,QWORD PTR [rbp-0x50]
   14000824c:	72 ab                	jb     1400081f9 <__mult_D2A+0x15c>
   14000824e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008252:	89 c2                	mov    edx,eax
   140008254:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008258:	89 10                	mov    DWORD PTR [rax],edx
   14000825a:	48 83 45 d8 04       	add    QWORD PTR [rbp-0x28],0x4
   14000825f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008263:	48 3b 45 a8          	cmp    rax,QWORD PTR [rbp-0x58]
   140008267:	0f 82 5d ff ff ff    	jb     1400081ca <__mult_D2A+0x12d>
   14000826d:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008271:	48 83 c0 18          	add    rax,0x18
   140008275:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008279:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000827c:	48 98                	cdqe
   14000827e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008285:	00 
   140008286:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000828a:	48 01 d0             	add    rax,rdx
   14000828d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008291:	eb 04                	jmp    140008297 <__mult_D2A+0x1fa>
   140008293:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008297:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000829b:	7e 0f                	jle    1400082ac <__mult_D2A+0x20f>
   14000829d:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   1400082a2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400082a6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400082a8:	85 c0                	test   eax,eax
   1400082aa:	74 e7                	je     140008293 <__mult_D2A+0x1f6>
   1400082ac:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400082b0:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400082b3:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400082b6:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400082ba:	48 81 c4 90 00 00 00 	add    rsp,0x90
   1400082c1:	5d                   	pop    rbp
   1400082c2:	c3                   	ret

00000001400082c3 <__pow5mult_D2A>:
   1400082c3:	55                   	push   rbp
   1400082c4:	48 89 e5             	mov    rbp,rsp
   1400082c7:	48 83 ec 40          	sub    rsp,0x40
   1400082cb:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400082cf:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400082d2:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400082d5:	83 e0 03             	and    eax,0x3
   1400082d8:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400082db:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   1400082df:	74 41                	je     140008322 <__pow5mult_D2A+0x5f>
   1400082e1:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400082e4:	83 e8 01             	sub    eax,0x1
   1400082e7:	48 98                	cdqe
   1400082e9:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400082f0:	00 
   1400082f1:	48 8d 05 a0 1d 00 00 	lea    rax,[rip+0x1da0]        # 14000a098 <p05.0>
   1400082f8:	8b 14 02             	mov    edx,DWORD PTR [rdx+rax*1]
   1400082fb:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400082ff:	41 b8 00 00 00 00    	mov    r8d,0x0
   140008305:	48 89 c1             	mov    rcx,rax
   140008308:	e8 1c fc ff ff       	call   140007f29 <__multadd_D2A>
   14000830d:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008311:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140008316:	75 0a                	jne    140008322 <__pow5mult_D2A+0x5f>
   140008318:	b8 00 00 00 00       	mov    eax,0x0
   14000831d:	e9 58 01 00 00       	jmp    14000847a <__pow5mult_D2A+0x1b7>
   140008322:	c1 7d 18 02          	sar    DWORD PTR [rbp+0x18],0x2
   140008326:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   14000832a:	75 09                	jne    140008335 <__pow5mult_D2A+0x72>
   14000832c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008330:	e9 45 01 00 00       	jmp    14000847a <__pow5mult_D2A+0x1b7>
   140008335:	48 8b 05 24 78 00 00 	mov    rax,QWORD PTR [rip+0x7824]        # 14000fb60 <p5s>
   14000833c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008340:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008345:	75 5e                	jne    1400083a5 <__pow5mult_D2A+0xe2>
   140008347:	b9 01 00 00 00       	mov    ecx,0x1
   14000834c:	e8 51 f8 ff ff       	call   140007ba2 <dtoa_lock>
   140008351:	48 8b 05 08 78 00 00 	mov    rax,QWORD PTR [rip+0x7808]        # 14000fb60 <p5s>
   140008358:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000835c:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008361:	75 38                	jne    14000839b <__pow5mult_D2A+0xd8>
   140008363:	b9 71 02 00 00       	mov    ecx,0x271
   140008368:	e8 ea fc ff ff       	call   140008057 <__i2b_D2A>
   14000836d:	48 89 05 ec 77 00 00 	mov    QWORD PTR [rip+0x77ec],rax        # 14000fb60 <p5s>
   140008374:	48 8b 05 e5 77 00 00 	mov    rax,QWORD PTR [rip+0x77e5]        # 14000fb60 <p5s>
   14000837b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000837f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008384:	75 0a                	jne    140008390 <__pow5mult_D2A+0xcd>
   140008386:	b8 00 00 00 00       	mov    eax,0x0
   14000838b:	e9 ea 00 00 00       	jmp    14000847a <__pow5mult_D2A+0x1b7>
   140008390:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008394:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000839b:	b9 01 00 00 00       	mov    ecx,0x1
   1400083a0:	e8 2f f9 ff ff       	call   140007cd4 <dtoa_unlock>
   1400083a5:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400083a8:	83 e0 01             	and    eax,0x1
   1400083ab:	85 c0                	test   eax,eax
   1400083ad:	74 39                	je     1400083e8 <__pow5mult_D2A+0x125>
   1400083af:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400083b3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083b7:	48 89 c1             	mov    rcx,rax
   1400083ba:	e8 de fc ff ff       	call   14000809d <__mult_D2A>
   1400083bf:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400083c3:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
   1400083c8:	75 0a                	jne    1400083d4 <__pow5mult_D2A+0x111>
   1400083ca:	b8 00 00 00 00       	mov    eax,0x0
   1400083cf:	e9 a6 00 00 00       	jmp    14000847a <__pow5mult_D2A+0x1b7>
   1400083d4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083d8:	48 89 c1             	mov    rcx,rax
   1400083db:	e8 be fa ff ff       	call   140007e9e <__Bfree_D2A>
   1400083e0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400083e4:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400083e8:	d1 7d 18             	sar    DWORD PTR [rbp+0x18],1
   1400083eb:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400083ef:	0f 84 80 00 00 00    	je     140008475 <__pow5mult_D2A+0x1b2>
   1400083f5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083f9:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400083fc:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008400:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008405:	75 61                	jne    140008468 <__pow5mult_D2A+0x1a5>
   140008407:	b9 01 00 00 00       	mov    ecx,0x1
   14000840c:	e8 91 f7 ff ff       	call   140007ba2 <dtoa_lock>
   140008411:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008415:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008418:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000841c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008421:	75 3b                	jne    14000845e <__pow5mult_D2A+0x19b>
   140008423:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008427:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000842b:	48 89 c1             	mov    rcx,rax
   14000842e:	e8 6a fc ff ff       	call   14000809d <__mult_D2A>
   140008433:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008437:	48 89 02             	mov    QWORD PTR [rdx],rax
   14000843a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000843e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008441:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008445:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000844a:	75 07                	jne    140008453 <__pow5mult_D2A+0x190>
   14000844c:	b8 00 00 00 00       	mov    eax,0x0
   140008451:	eb 27                	jmp    14000847a <__pow5mult_D2A+0x1b7>
   140008453:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008457:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000845e:	b9 01 00 00 00       	mov    ecx,0x1
   140008463:	e8 6c f8 ff ff       	call   140007cd4 <dtoa_unlock>
   140008468:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000846c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008470:	e9 30 ff ff ff       	jmp    1400083a5 <__pow5mult_D2A+0xe2>
   140008475:	90                   	nop
   140008476:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000847a:	48 83 c4 40          	add    rsp,0x40
   14000847e:	5d                   	pop    rbp
   14000847f:	c3                   	ret

0000000140008480 <__lshift_D2A>:
   140008480:	55                   	push   rbp
   140008481:	48 89 e5             	mov    rbp,rsp
   140008484:	48 83 ec 60          	sub    rsp,0x60
   140008488:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000848c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000848f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008492:	c1 f8 05             	sar    eax,0x5
   140008495:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   140008498:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000849c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000849f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400084a2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400084a6:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   1400084a9:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   1400084ac:	01 d0                	add    eax,edx
   1400084ae:	83 c0 01             	add    eax,0x1
   1400084b1:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400084b4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400084b8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400084bb:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400084be:	eb 07                	jmp    1400084c7 <__lshift_D2A+0x47>
   1400084c0:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   1400084c4:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   1400084c7:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400084ca:	3b 45 fc             	cmp    eax,DWORD PTR [rbp-0x4]
   1400084cd:	7f f1                	jg     1400084c0 <__lshift_D2A+0x40>
   1400084cf:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400084d2:	89 c1                	mov    ecx,eax
   1400084d4:	e8 84 f8 ff ff       	call   140007d5d <__Balloc_D2A>
   1400084d9:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400084dd:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   1400084e2:	75 0a                	jne    1400084ee <__lshift_D2A+0x6e>
   1400084e4:	b8 00 00 00 00       	mov    eax,0x0
   1400084e9:	e9 19 01 00 00       	jmp    140008607 <__lshift_D2A+0x187>
   1400084ee:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400084f2:	48 83 c0 18          	add    rax,0x18
   1400084f6:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400084fa:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140008501:	eb 16                	jmp    140008519 <__lshift_D2A+0x99>
   140008503:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008507:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000850b:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000850f:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008515:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140008519:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000851c:	3b 45 d8             	cmp    eax,DWORD PTR [rbp-0x28]
   14000851f:	7c e2                	jl     140008503 <__lshift_D2A+0x83>
   140008521:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008525:	48 83 c0 18          	add    rax,0x18
   140008529:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000852d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008531:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008534:	48 98                	cdqe
   140008536:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000853d:	00 
   14000853e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008542:	48 01 d0             	add    rax,rdx
   140008545:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140008549:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000854d:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140008551:	74 71                	je     1400085c4 <__lshift_D2A+0x144>
   140008553:	b8 20 00 00 00       	mov    eax,0x20
   140008558:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000855b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000855e:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
   140008565:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008569:	8b 10                	mov    edx,DWORD PTR [rax]
   14000856b:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000856e:	89 c1                	mov    ecx,eax
   140008570:	d3 e2                	shl    edx,cl
   140008572:	89 d1                	mov    ecx,edx
   140008574:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008578:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000857c:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008580:	0b 4d dc             	or     ecx,DWORD PTR [rbp-0x24]
   140008583:	89 ca                	mov    edx,ecx
   140008585:	89 10                	mov    DWORD PTR [rax],edx
   140008587:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000858b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000858f:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   140008593:	8b 10                	mov    edx,DWORD PTR [rax]
   140008595:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008598:	89 c1                	mov    ecx,eax
   14000859a:	d3 ea                	shr    edx,cl
   14000859c:	89 d0                	mov    eax,edx
   14000859e:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400085a1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400085a5:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   1400085a9:	72 ba                	jb     140008565 <__lshift_D2A+0xe5>
   1400085ab:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400085af:	8b 55 dc             	mov    edx,DWORD PTR [rbp-0x24]
   1400085b2:	89 10                	mov    DWORD PTR [rax],edx
   1400085b4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400085b8:	8b 00                	mov    eax,DWORD PTR [rax]
   1400085ba:	85 c0                	test   eax,eax
   1400085bc:	74 2c                	je     1400085ea <__lshift_D2A+0x16a>
   1400085be:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   1400085c2:	eb 26                	jmp    1400085ea <__lshift_D2A+0x16a>
   1400085c4:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400085c8:	48 8d 42 04          	lea    rax,[rdx+0x4]
   1400085cc:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400085d0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400085d4:	48 8d 48 04          	lea    rcx,[rax+0x4]
   1400085d8:	48 89 4d e0          	mov    QWORD PTR [rbp-0x20],rcx
   1400085dc:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400085de:	89 10                	mov    DWORD PTR [rax],edx
   1400085e0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400085e4:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   1400085e8:	72 da                	jb     1400085c4 <__lshift_D2A+0x144>
   1400085ea:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400085ed:	8d 50 ff             	lea    edx,[rax-0x1]
   1400085f0:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400085f4:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400085f7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400085fb:	48 89 c1             	mov    rcx,rax
   1400085fe:	e8 9b f8 ff ff       	call   140007e9e <__Bfree_D2A>
   140008603:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008607:	48 83 c4 60          	add    rsp,0x60
   14000860b:	5d                   	pop    rbp
   14000860c:	c3                   	ret

000000014000860d <__cmp_D2A>:
   14000860d:	55                   	push   rbp
   14000860e:	48 89 e5             	mov    rbp,rsp
   140008611:	48 83 ec 30          	sub    rsp,0x30
   140008615:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008619:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000861d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008621:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008624:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140008627:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000862b:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000862e:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140008631:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008634:	29 45 ec             	sub    DWORD PTR [rbp-0x14],eax
   140008637:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   14000863b:	74 08                	je     140008645 <__cmp_D2A+0x38>
   14000863d:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008640:	e9 92 00 00 00       	jmp    1400086d7 <__cmp_D2A+0xca>
   140008645:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008649:	48 83 c0 18          	add    rax,0x18
   14000864d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008651:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008654:	48 98                	cdqe
   140008656:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000865d:	00 
   14000865e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008662:	48 01 d0             	add    rax,rdx
   140008665:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008669:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000866d:	48 83 c0 18          	add    rax,0x18
   140008671:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008675:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008678:	48 98                	cdqe
   14000867a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008681:	00 
   140008682:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140008686:	48 01 d0             	add    rax,rdx
   140008689:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000868d:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008692:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008696:	8b 10                	mov    edx,DWORD PTR [rax]
   140008698:	48 83 6d f0 04       	sub    QWORD PTR [rbp-0x10],0x4
   14000869d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400086a1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400086a3:	39 c2                	cmp    edx,eax
   1400086a5:	74 1e                	je     1400086c5 <__cmp_D2A+0xb8>
   1400086a7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400086ab:	8b 10                	mov    edx,DWORD PTR [rax]
   1400086ad:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400086b1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400086b3:	39 c2                	cmp    edx,eax
   1400086b5:	73 07                	jae    1400086be <__cmp_D2A+0xb1>
   1400086b7:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400086bc:	eb 19                	jmp    1400086d7 <__cmp_D2A+0xca>
   1400086be:	b8 01 00 00 00       	mov    eax,0x1
   1400086c3:	eb 12                	jmp    1400086d7 <__cmp_D2A+0xca>
   1400086c5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400086c9:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400086cd:	73 02                	jae    1400086d1 <__cmp_D2A+0xc4>
   1400086cf:	eb bc                	jmp    14000868d <__cmp_D2A+0x80>
   1400086d1:	90                   	nop
   1400086d2:	b8 00 00 00 00       	mov    eax,0x0
   1400086d7:	48 83 c4 30          	add    rsp,0x30
   1400086db:	5d                   	pop    rbp
   1400086dc:	c3                   	ret

00000001400086dd <__diff_D2A>:
   1400086dd:	55                   	push   rbp
   1400086de:	48 89 e5             	mov    rbp,rsp
   1400086e1:	48 83 ec 70          	sub    rsp,0x70
   1400086e5:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400086e9:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400086ed:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400086f1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400086f5:	48 89 c1             	mov    rcx,rax
   1400086f8:	e8 10 ff ff ff       	call   14000860d <__cmp_D2A>
   1400086fd:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008700:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008704:	75 3e                	jne    140008744 <__diff_D2A+0x67>
   140008706:	b9 00 00 00 00       	mov    ecx,0x0
   14000870b:	e8 4d f6 ff ff       	call   140007d5d <__Balloc_D2A>
   140008710:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008714:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008719:	75 0a                	jne    140008725 <__diff_D2A+0x48>
   14000871b:	b8 00 00 00 00       	mov    eax,0x0
   140008720:	e9 ab 01 00 00       	jmp    1400088d0 <__diff_D2A+0x1f3>
   140008725:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008729:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008730:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008734:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   14000873b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000873f:	e9 8c 01 00 00       	jmp    1400088d0 <__diff_D2A+0x1f3>
   140008744:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008748:	79 21                	jns    14000876b <__diff_D2A+0x8e>
   14000874a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000874e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008752:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008756:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000875a:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000875e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140008762:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140008769:	eb 07                	jmp    140008772 <__diff_D2A+0x95>
   14000876b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140008772:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008776:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140008779:	89 c1                	mov    ecx,eax
   14000877b:	e8 dd f5 ff ff       	call   140007d5d <__Balloc_D2A>
   140008780:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008784:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008789:	75 0a                	jne    140008795 <__diff_D2A+0xb8>
   14000878b:	b8 00 00 00 00       	mov    eax,0x0
   140008790:	e9 3b 01 00 00       	jmp    1400088d0 <__diff_D2A+0x1f3>
   140008795:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008799:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000879c:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000879f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400087a3:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400087a6:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400087a9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400087ad:	48 83 c0 18          	add    rax,0x18
   1400087b1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400087b5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400087b8:	48 98                	cdqe
   1400087ba:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400087c1:	00 
   1400087c2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400087c6:	48 01 d0             	add    rax,rdx
   1400087c9:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400087cd:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400087d1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400087d4:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   1400087d7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400087db:	48 83 c0 18          	add    rax,0x18
   1400087df:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400087e3:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   1400087e6:	48 98                	cdqe
   1400087e8:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400087ef:	00 
   1400087f0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400087f4:	48 01 d0             	add    rax,rdx
   1400087f7:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400087fb:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400087ff:	48 83 c0 18          	add    rax,0x18
   140008803:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008807:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   14000880e:	00 
   14000880f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008813:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008817:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000881b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000881d:	89 c1                	mov    ecx,eax
   14000881f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008823:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008827:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   14000882b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000882d:	89 c2                	mov    edx,eax
   14000882f:	48 89 c8             	mov    rax,rcx
   140008832:	48 29 d0             	sub    rax,rdx
   140008835:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   140008839:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   14000883d:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008841:	48 c1 e8 20          	shr    rax,0x20
   140008845:	83 e0 01             	and    eax,0x1
   140008848:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000884c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008850:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008854:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008858:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   14000885c:	89 10                	mov    DWORD PTR [rax],edx
   14000885e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008862:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   140008866:	72 a7                	jb     14000880f <__diff_D2A+0x132>
   140008868:	eb 39                	jmp    1400088a3 <__diff_D2A+0x1c6>
   14000886a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000886e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008872:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140008876:	8b 00                	mov    eax,DWORD PTR [rax]
   140008878:	89 c0                	mov    eax,eax
   14000887a:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   14000887e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008882:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008886:	48 c1 e8 20          	shr    rax,0x20
   14000888a:	83 e0 01             	and    eax,0x1
   14000888d:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008891:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008895:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008899:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000889d:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400088a1:	89 10                	mov    DWORD PTR [rax],edx
   1400088a3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400088a7:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   1400088ab:	72 bd                	jb     14000886a <__diff_D2A+0x18d>
   1400088ad:	eb 04                	jmp    1400088b3 <__diff_D2A+0x1d6>
   1400088af:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   1400088b3:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   1400088b8:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400088bc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400088be:	85 c0                	test   eax,eax
   1400088c0:	74 ed                	je     1400088af <__diff_D2A+0x1d2>
   1400088c2:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400088c6:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400088c9:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400088cc:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400088d0:	48 83 c4 70          	add    rsp,0x70
   1400088d4:	5d                   	pop    rbp
   1400088d5:	c3                   	ret

00000001400088d6 <__b2d_D2A>:
   1400088d6:	55                   	push   rbp
   1400088d7:	48 89 e5             	mov    rbp,rsp
   1400088da:	48 83 ec 50          	sub    rsp,0x50
   1400088de:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400088e2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400088e6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400088ea:	48 83 c0 18          	add    rax,0x18
   1400088ee:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400088f2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400088f6:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400088f9:	48 98                	cdqe
   1400088fb:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008902:	00 
   140008903:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008907:	48 01 d0             	add    rax,rdx
   14000890a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000890e:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008913:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008917:	8b 00                	mov    eax,DWORD PTR [rax]
   140008919:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   14000891c:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000891f:	89 c1                	mov    ecx,eax
   140008921:	e8 27 f4 ff ff       	call   140007d4d <__hi0bits_D2A>
   140008926:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008929:	b8 20 00 00 00       	mov    eax,0x20
   14000892e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008931:	89 c2                	mov    edx,eax
   140008933:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008937:	89 10                	mov    DWORD PTR [rax],edx
   140008939:	83 7d dc 0a          	cmp    DWORD PTR [rbp-0x24],0xa
   14000893d:	7f 66                	jg     1400089a5 <__b2d_D2A+0xcf>
   14000893f:	b8 0b 00 00 00       	mov    eax,0xb
   140008944:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008947:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000894a:	89 c1                	mov    ecx,eax
   14000894c:	d3 ea                	shr    edx,cl
   14000894e:	89 d0                	mov    eax,edx
   140008950:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008955:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008958:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000895c:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140008960:	73 10                	jae    140008972 <__b2d_D2A+0x9c>
   140008962:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008967:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000896b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000896d:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008970:	eb 07                	jmp    140008979 <__b2d_D2A+0xa3>
   140008972:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140008979:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000897c:	83 c0 15             	add    eax,0x15
   14000897f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008982:	89 c1                	mov    ecx,eax
   140008984:	d3 e2                	shl    edx,cl
   140008986:	41 89 d0             	mov    r8d,edx
   140008989:	b8 0b 00 00 00       	mov    eax,0xb
   14000898e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008991:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140008994:	89 c1                	mov    ecx,eax
   140008996:	d3 ea                	shr    edx,cl
   140008998:	89 d0                	mov    eax,edx
   14000899a:	44 09 c0             	or     eax,r8d
   14000899d:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089a0:	e9 ac 00 00 00       	jmp    140008a51 <__b2d_D2A+0x17b>
   1400089a5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400089a9:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400089ad:	73 10                	jae    1400089bf <__b2d_D2A+0xe9>
   1400089af:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400089b4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400089b8:	8b 00                	mov    eax,DWORD PTR [rax]
   1400089ba:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400089bd:	eb 07                	jmp    1400089c6 <__b2d_D2A+0xf0>
   1400089bf:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
   1400089c6:	83 6d dc 0b          	sub    DWORD PTR [rbp-0x24],0xb
   1400089ca:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   1400089ce:	74 70                	je     140008a40 <__b2d_D2A+0x16a>
   1400089d0:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400089d3:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400089d6:	89 c1                	mov    ecx,eax
   1400089d8:	d3 e2                	shl    edx,cl
   1400089da:	41 89 d0             	mov    r8d,edx
   1400089dd:	b8 20 00 00 00       	mov    eax,0x20
   1400089e2:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400089e5:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400089e8:	89 c1                	mov    ecx,eax
   1400089ea:	d3 ea                	shr    edx,cl
   1400089ec:	89 d0                	mov    eax,edx
   1400089ee:	44 09 c0             	or     eax,r8d
   1400089f1:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400089f6:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400089f9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400089fd:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140008a01:	73 10                	jae    140008a13 <__b2d_D2A+0x13d>
   140008a03:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008a08:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008a0c:	8b 00                	mov    eax,DWORD PTR [rax]
   140008a0e:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140008a11:	eb 07                	jmp    140008a1a <__b2d_D2A+0x144>
   140008a13:	c7 45 f0 00 00 00 00 	mov    DWORD PTR [rbp-0x10],0x0
   140008a1a:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a1d:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140008a20:	89 c1                	mov    ecx,eax
   140008a22:	d3 e2                	shl    edx,cl
   140008a24:	41 89 d0             	mov    r8d,edx
   140008a27:	b8 20 00 00 00       	mov    eax,0x20
   140008a2c:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008a2f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008a32:	89 c1                	mov    ecx,eax
   140008a34:	d3 ea                	shr    edx,cl
   140008a36:	89 d0                	mov    eax,edx
   140008a38:	44 09 c0             	or     eax,r8d
   140008a3b:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a3e:	eb 11                	jmp    140008a51 <__b2d_D2A+0x17b>
   140008a40:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008a43:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008a48:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008a4b:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008a4e:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a51:	f2 0f 10 45 d0       	movsd  xmm0,QWORD PTR [rbp-0x30]
   140008a56:	48 83 c4 50          	add    rsp,0x50
   140008a5a:	5d                   	pop    rbp
   140008a5b:	c3                   	ret

0000000140008a5c <__d2b_D2A>:
   140008a5c:	55                   	push   rbp
   140008a5d:	53                   	push   rbx
   140008a5e:	48 83 ec 58          	sub    rsp,0x58
   140008a62:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140008a67:	f2 0f 11 45 20       	movsd  QWORD PTR [rbp+0x20],xmm0
   140008a6c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140008a70:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140008a74:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140008a79:	f2 0f 11 45 d8       	movsd  QWORD PTR [rbp-0x28],xmm0
   140008a7e:	b9 01 00 00 00       	mov    ecx,0x1
   140008a83:	e8 d5 f2 ff ff       	call   140007d5d <__Balloc_D2A>
   140008a88:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008a8c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008a91:	75 0a                	jne    140008a9d <__d2b_D2A+0x41>
   140008a93:	b8 00 00 00 00       	mov    eax,0x0
   140008a98:	e9 68 01 00 00       	jmp    140008c05 <__d2b_D2A+0x1a9>
   140008a9d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008aa1:	48 83 c0 18          	add    rax,0x18
   140008aa5:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008aa9:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008aac:	25 ff ff 0f 00       	and    eax,0xfffff
   140008ab1:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008ab4:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008ab7:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008abc:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008abf:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008ac2:	c1 e8 14             	shr    eax,0x14
   140008ac5:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140008ac8:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008acc:	74 0b                	je     140008ad9 <__d2b_D2A+0x7d>
   140008ace:	8b 45 d0             	mov    eax,DWORD PTR [rbp-0x30]
   140008ad1:	0d 00 00 10 00       	or     eax,0x100000
   140008ad6:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008ad9:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140008adc:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008adf:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008ae2:	85 c0                	test   eax,eax
   140008ae4:	74 7b                	je     140008b61 <__d2b_D2A+0x105>
   140008ae6:	48 8d 45 d4          	lea    rax,[rbp-0x2c]
   140008aea:	48 89 c1             	mov    rcx,rax
   140008aed:	e8 26 f2 ff ff       	call   140007d18 <__lo0bits_D2A>
   140008af2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008af5:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008af9:	74 2b                	je     140008b26 <__d2b_D2A+0xca>
   140008afb:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008afe:	b8 20 00 00 00       	mov    eax,0x20
   140008b03:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008b06:	89 c1                	mov    ecx,eax
   140008b08:	d3 e2                	shl    edx,cl
   140008b0a:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008b0d:	09 c2                	or     edx,eax
   140008b0f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b13:	89 10                	mov    DWORD PTR [rax],edx
   140008b15:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008b18:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008b1b:	89 c1                	mov    ecx,eax
   140008b1d:	d3 ea                	shr    edx,cl
   140008b1f:	89 d0                	mov    eax,edx
   140008b21:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008b24:	eb 09                	jmp    140008b2f <__d2b_D2A+0xd3>
   140008b26:	8b 55 d4             	mov    edx,DWORD PTR [rbp-0x2c]
   140008b29:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b2d:	89 10                	mov    DWORD PTR [rax],edx
   140008b2f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b33:	48 83 c0 04          	add    rax,0x4
   140008b37:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008b3a:	89 10                	mov    DWORD PTR [rax],edx
   140008b3c:	8b 00                	mov    eax,DWORD PTR [rax]
   140008b3e:	85 c0                	test   eax,eax
   140008b40:	74 07                	je     140008b49 <__d2b_D2A+0xed>
   140008b42:	ba 02 00 00 00       	mov    edx,0x2
   140008b47:	eb 05                	jmp    140008b4e <__d2b_D2A+0xf2>
   140008b49:	ba 01 00 00 00       	mov    edx,0x1
   140008b4e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b52:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008b55:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b59:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008b5c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008b5f:	eb 31                	jmp    140008b92 <__d2b_D2A+0x136>
   140008b61:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140008b65:	48 89 c1             	mov    rcx,rax
   140008b68:	e8 ab f1 ff ff       	call   140007d18 <__lo0bits_D2A>
   140008b6d:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008b70:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008b73:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b77:	89 10                	mov    DWORD PTR [rax],edx
   140008b79:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b7d:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008b84:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b88:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008b8b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008b8e:	83 45 f8 20          	add    DWORD PTR [rbp-0x8],0x20
   140008b92:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008b96:	74 26                	je     140008bbe <__d2b_D2A+0x162>
   140008b98:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008b9b:	8d 90 cd fb ff ff    	lea    edx,[rax-0x433]
   140008ba1:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008ba4:	01 c2                	add    edx,eax
   140008ba6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008baa:	89 10                	mov    DWORD PTR [rax],edx
   140008bac:	b8 35 00 00 00       	mov    eax,0x35
   140008bb1:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008bb4:	89 c2                	mov    edx,eax
   140008bb6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008bba:	89 10                	mov    DWORD PTR [rax],edx
   140008bbc:	eb 43                	jmp    140008c01 <__d2b_D2A+0x1a5>
   140008bbe:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008bc1:	8d 90 ce fb ff ff    	lea    edx,[rax-0x432]
   140008bc7:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008bca:	01 c2                	add    edx,eax
   140008bcc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008bd0:	89 10                	mov    DWORD PTR [rax],edx
   140008bd2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008bd5:	c1 e0 05             	shl    eax,0x5
   140008bd8:	89 c3                	mov    ebx,eax
   140008bda:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008bdd:	48 98                	cdqe
   140008bdf:	48 c1 e0 02          	shl    rax,0x2
   140008be3:	48 8d 50 fc          	lea    rdx,[rax-0x4]
   140008be7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008beb:	48 01 d0             	add    rax,rdx
   140008bee:	8b 00                	mov    eax,DWORD PTR [rax]
   140008bf0:	89 c1                	mov    ecx,eax
   140008bf2:	e8 56 f1 ff ff       	call   140007d4d <__hi0bits_D2A>
   140008bf7:	29 c3                	sub    ebx,eax
   140008bf9:	89 da                	mov    edx,ebx
   140008bfb:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008bff:	89 10                	mov    DWORD PTR [rax],edx
   140008c01:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008c05:	48 83 c4 58          	add    rsp,0x58
   140008c09:	5b                   	pop    rbx
   140008c0a:	5d                   	pop    rbp
   140008c0b:	c3                   	ret

0000000140008c0c <__strcp_D2A>:
   140008c0c:	55                   	push   rbp
   140008c0d:	48 89 e5             	mov    rbp,rsp
   140008c10:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008c14:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008c18:	eb 05                	jmp    140008c1f <__strcp_D2A+0x13>
   140008c1a:	48 83 45 10 01       	add    QWORD PTR [rbp+0x10],0x1
   140008c1f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008c23:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140008c27:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008c2b:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140008c2e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008c32:	88 10                	mov    BYTE PTR [rax],dl
   140008c34:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008c38:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008c3b:	84 c0                	test   al,al
   140008c3d:	75 db                	jne    140008c1a <__strcp_D2A+0xe>
   140008c3f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008c43:	5d                   	pop    rbp
   140008c44:	c3                   	ret
   140008c45:	90                   	nop
   140008c46:	90                   	nop
   140008c47:	90                   	nop
   140008c48:	90                   	nop
   140008c49:	90                   	nop
   140008c4a:	90                   	nop
   140008c4b:	90                   	nop
   140008c4c:	90                   	nop
   140008c4d:	90                   	nop
   140008c4e:	90                   	nop
   140008c4f:	90                   	nop

0000000140008c50 <__fpclassify>:
   140008c50:	55                   	push   rbp
   140008c51:	48 89 e5             	mov    rbp,rsp
   140008c54:	48 83 ec 10          	sub    rsp,0x10
   140008c58:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008c5d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008c62:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008c67:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008c6a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008c6d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008c70:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140008c73:	81 e2 ff ff 0f 00    	and    edx,0xfffff
   140008c79:	09 d0                	or     eax,edx
   140008c7b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c7e:	81 65 fc 00 00 f0 7f 	and    DWORD PTR [rbp-0x4],0x7ff00000
   140008c85:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008c88:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008c8b:	85 c0                	test   eax,eax
   140008c8d:	75 07                	jne    140008c96 <__fpclassify+0x46>
   140008c8f:	b8 00 40 00 00       	mov    eax,0x4000
   140008c94:	eb 2f                	jmp    140008cc5 <__fpclassify+0x75>
   140008c96:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008c9a:	75 07                	jne    140008ca3 <__fpclassify+0x53>
   140008c9c:	b8 00 44 00 00       	mov    eax,0x4400
   140008ca1:	eb 22                	jmp    140008cc5 <__fpclassify+0x75>
   140008ca3:	81 7d fc 00 00 f0 7f 	cmp    DWORD PTR [rbp-0x4],0x7ff00000
   140008caa:	75 14                	jne    140008cc0 <__fpclassify+0x70>
   140008cac:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008cb0:	74 07                	je     140008cb9 <__fpclassify+0x69>
   140008cb2:	b8 00 01 00 00       	mov    eax,0x100
   140008cb7:	eb 0c                	jmp    140008cc5 <__fpclassify+0x75>
   140008cb9:	b8 00 05 00 00       	mov    eax,0x500
   140008cbe:	eb 05                	jmp    140008cc5 <__fpclassify+0x75>
   140008cc0:	b8 00 04 00 00       	mov    eax,0x400
   140008cc5:	48 83 c4 10          	add    rsp,0x10
   140008cc9:	5d                   	pop    rbp
   140008cca:	c3                   	ret
   140008ccb:	90                   	nop
   140008ccc:	90                   	nop
   140008ccd:	90                   	nop
   140008cce:	90                   	nop
   140008ccf:	90                   	nop

0000000140008cd0 <__fpclassifyl>:
   140008cd0:	55                   	push   rbp
   140008cd1:	53                   	push   rbx
   140008cd2:	48 83 ec 38          	sub    rsp,0x38
   140008cd6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008cdb:	48 89 cb             	mov    rbx,rcx
   140008cde:	db 2b                	fld    TBYTE PTR [rbx]
   140008ce0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008ce3:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008ce6:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008ce9:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008ced:	98                   	cwde
   140008cee:	25 ff 7f 00 00       	and    eax,0x7fff
   140008cf3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008cf6:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008cfa:	75 25                	jne    140008d21 <__fpclassifyl+0x51>
   140008cfc:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008cff:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d02:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008d05:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008d08:	85 c0                	test   eax,eax
   140008d0a:	75 07                	jne    140008d13 <__fpclassifyl+0x43>
   140008d0c:	b8 00 40 00 00       	mov    eax,0x4000
   140008d11:	eb 3d                	jmp    140008d50 <__fpclassifyl+0x80>
   140008d13:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d16:	85 c0                	test   eax,eax
   140008d18:	78 31                	js     140008d4b <__fpclassifyl+0x7b>
   140008d1a:	b8 00 44 00 00       	mov    eax,0x4400
   140008d1f:	eb 2f                	jmp    140008d50 <__fpclassifyl+0x80>
   140008d21:	81 7d fc ff 7f 00 00 	cmp    DWORD PTR [rbp-0x4],0x7fff
   140008d28:	75 21                	jne    140008d4b <__fpclassifyl+0x7b>
   140008d2a:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008d2d:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008d32:	89 c2                	mov    edx,eax
   140008d34:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008d37:	09 d0                	or     eax,edx
   140008d39:	85 c0                	test   eax,eax
   140008d3b:	75 07                	jne    140008d44 <__fpclassifyl+0x74>
   140008d3d:	b8 00 05 00 00       	mov    eax,0x500
   140008d42:	eb 0c                	jmp    140008d50 <__fpclassifyl+0x80>
   140008d44:	b8 00 01 00 00       	mov    eax,0x100
   140008d49:	eb 05                	jmp    140008d50 <__fpclassifyl+0x80>
   140008d4b:	b8 00 04 00 00       	mov    eax,0x400
   140008d50:	48 83 c4 38          	add    rsp,0x38
   140008d54:	5b                   	pop    rbx
   140008d55:	5d                   	pop    rbp
   140008d56:	c3                   	ret
   140008d57:	90                   	nop
   140008d58:	90                   	nop
   140008d59:	90                   	nop
   140008d5a:	90                   	nop
   140008d5b:	90                   	nop
   140008d5c:	90                   	nop
   140008d5d:	90                   	nop
   140008d5e:	90                   	nop
   140008d5f:	90                   	nop

0000000140008d60 <__isnan>:
   140008d60:	55                   	push   rbp
   140008d61:	48 89 e5             	mov    rbp,rsp
   140008d64:	48 83 ec 10          	sub    rsp,0x10
   140008d68:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008d6d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008d72:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008d77:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008d7a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d7d:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008d80:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008d85:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d88:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d8b:	f7 d8                	neg    eax
   140008d8d:	0b 45 fc             	or     eax,DWORD PTR [rbp-0x4]
   140008d90:	c1 e8 1f             	shr    eax,0x1f
   140008d93:	89 c2                	mov    edx,eax
   140008d95:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d98:	09 d0                	or     eax,edx
   140008d9a:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d9d:	b8 00 00 f0 7f       	mov    eax,0x7ff00000
   140008da2:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008da5:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008da8:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008dab:	c1 f8 1f             	sar    eax,0x1f
   140008dae:	48 83 c4 10          	add    rsp,0x10
   140008db2:	5d                   	pop    rbp
   140008db3:	c3                   	ret
   140008db4:	90                   	nop
   140008db5:	90                   	nop
   140008db6:	90                   	nop
   140008db7:	90                   	nop
   140008db8:	90                   	nop
   140008db9:	90                   	nop
   140008dba:	90                   	nop
   140008dbb:	90                   	nop
   140008dbc:	90                   	nop
   140008dbd:	90                   	nop
   140008dbe:	90                   	nop
   140008dbf:	90                   	nop

0000000140008dc0 <__isnanl>:
   140008dc0:	55                   	push   rbp
   140008dc1:	53                   	push   rbx
   140008dc2:	48 83 ec 38          	sub    rsp,0x38
   140008dc6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008dcb:	48 89 cb             	mov    rbx,rcx
   140008dce:	db 2b                	fld    TBYTE PTR [rbx]
   140008dd0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008dd3:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008dd6:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008dd9:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008ddd:	98                   	cwde
   140008dde:	01 c0                	add    eax,eax
   140008de0:	25 ff ff 00 00       	and    eax,0xffff
   140008de5:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008de8:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008deb:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140008dee:	81 e2 ff ff ff 7f    	and    edx,0x7fffffff
   140008df4:	09 d0                	or     eax,edx
   140008df6:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008df9:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008dfc:	f7 d8                	neg    eax
   140008dfe:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008e01:	c1 e8 1f             	shr    eax,0x1f
   140008e04:	89 c2                	mov    edx,eax
   140008e06:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008e09:	09 d0                	or     eax,edx
   140008e0b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008e0e:	b8 fe ff 00 00       	mov    eax,0xfffe
   140008e13:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140008e16:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008e19:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008e1c:	c1 f8 10             	sar    eax,0x10
   140008e1f:	48 83 c4 38          	add    rsp,0x38
   140008e23:	5b                   	pop    rbx
   140008e24:	5d                   	pop    rbp
   140008e25:	c3                   	ret
   140008e26:	90                   	nop
   140008e27:	90                   	nop
   140008e28:	90                   	nop
   140008e29:	90                   	nop
   140008e2a:	90                   	nop
   140008e2b:	90                   	nop
   140008e2c:	90                   	nop
   140008e2d:	90                   	nop
   140008e2e:	90                   	nop
   140008e2f:	90                   	nop

0000000140008e30 <wcsnlen>:
   140008e30:	55                   	push   rbp
   140008e31:	48 89 e5             	mov    rbp,rsp
   140008e34:	48 83 ec 10          	sub    rsp,0x10
   140008e38:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e3c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008e40:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140008e47:	00 
   140008e48:	eb 0a                	jmp    140008e54 <wcsnlen+0x24>
   140008e4a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008e4f:	48 83 45 10 02       	add    QWORD PTR [rbp+0x10],0x2
   140008e54:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e58:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008e5c:	73 0c                	jae    140008e6a <wcsnlen+0x3a>
   140008e5e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e62:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140008e65:	66 85 c0             	test   ax,ax
   140008e68:	75 e0                	jne    140008e4a <wcsnlen+0x1a>
   140008e6a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e6e:	48 83 c4 10          	add    rsp,0x10
   140008e72:	5d                   	pop    rbp
   140008e73:	c3                   	ret
   140008e74:	90                   	nop
   140008e75:	90                   	nop
   140008e76:	90                   	nop
   140008e77:	90                   	nop
   140008e78:	90                   	nop
   140008e79:	90                   	nop
   140008e7a:	90                   	nop
   140008e7b:	90                   	nop
   140008e7c:	90                   	nop
   140008e7d:	90                   	nop
   140008e7e:	90                   	nop
   140008e7f:	90                   	nop

0000000140008e80 <strnlen>:
   140008e80:	55                   	push   rbp
   140008e81:	48 89 e5             	mov    rbp,rsp
   140008e84:	48 83 ec 10          	sub    rsp,0x10
   140008e88:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e8c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008e90:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e94:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008e98:	eb 05                	jmp    140008e9f <strnlen+0x1f>
   140008e9a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008e9f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008ea3:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008ea7:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008eab:	73 0b                	jae    140008eb8 <strnlen+0x38>
   140008ead:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008eb1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008eb4:	84 c0                	test   al,al
   140008eb6:	75 e2                	jne    140008e9a <strnlen+0x1a>
   140008eb8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008ebc:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008ec0:	48 83 c4 10          	add    rsp,0x10
   140008ec4:	5d                   	pop    rbp
   140008ec5:	c3                   	ret
   140008ec6:	90                   	nop
   140008ec7:	90                   	nop
   140008ec8:	90                   	nop
   140008ec9:	90                   	nop
   140008eca:	90                   	nop
   140008ecb:	90                   	nop
   140008ecc:	90                   	nop
   140008ecd:	90                   	nop
   140008ece:	90                   	nop
   140008ecf:	90                   	nop

0000000140008ed0 <_initterm_e>:
   140008ed0:	55                   	push   rbp
   140008ed1:	48 89 e5             	mov    rbp,rsp
   140008ed4:	48 83 ec 30          	sub    rsp,0x30
   140008ed8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008edc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008ee0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008ee4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008ee8:	eb 29                	jmp    140008f13 <_initterm_e+0x43>
   140008eea:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008eee:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008ef1:	48 85 c0             	test   rax,rax
   140008ef4:	74 17                	je     140008f0d <_initterm_e+0x3d>
   140008ef6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008efa:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008efd:	ff d0                	call   rax
   140008eff:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008f02:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140008f06:	74 06                	je     140008f0e <_initterm_e+0x3e>
   140008f08:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008f0b:	eb 15                	jmp    140008f22 <_initterm_e+0x52>
   140008f0d:	90                   	nop
   140008f0e:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140008f13:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008f17:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008f1b:	72 cd                	jb     140008eea <_initterm_e+0x1a>
   140008f1d:	b8 00 00 00 00       	mov    eax,0x0
   140008f22:	48 83 c4 30          	add    rsp,0x30
   140008f26:	5d                   	pop    rbp
   140008f27:	c3                   	ret
   140008f28:	90                   	nop
   140008f29:	90                   	nop
   140008f2a:	90                   	nop
   140008f2b:	90                   	nop
   140008f2c:	90                   	nop
   140008f2d:	90                   	nop
   140008f2e:	90                   	nop
   140008f2f:	90                   	nop

0000000140008f30 <__p__fmode>:
   140008f30:	55                   	push   rbp
   140008f31:	48 89 e5             	mov    rbp,rsp
   140008f34:	48 8b 05 c5 26 00 00 	mov    rax,QWORD PTR [rip+0x26c5]        # 14000b600 <.refptr.__imp__fmode>
   140008f3b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008f3e:	5d                   	pop    rbp
   140008f3f:	c3                   	ret

0000000140008f40 <__p__commode>:
   140008f40:	55                   	push   rbp
   140008f41:	48 89 e5             	mov    rbp,rsp
   140008f44:	48 8b 05 a5 26 00 00 	mov    rax,QWORD PTR [rip+0x26a5]        # 14000b5f0 <.refptr.__imp__commode>
   140008f4b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008f4e:	5d                   	pop    rbp
   140008f4f:	c3                   	ret

0000000140008f50 <__p___initenv>:
   140008f50:	55                   	push   rbp
   140008f51:	48 89 e5             	mov    rbp,rsp
   140008f54:	48 8b 05 85 26 00 00 	mov    rax,QWORD PTR [rip+0x2685]        # 14000b5e0 <.refptr.__imp___initenv>
   140008f5b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008f5e:	5d                   	pop    rbp
   140008f5f:	c3                   	ret

0000000140008f60 <_lock_file>:
   140008f60:	55                   	push   rbp
   140008f61:	48 89 e5             	mov    rbp,rsp
   140008f64:	48 83 ec 20          	sub    rsp,0x20
   140008f68:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008f6c:	b9 00 00 00 00       	mov    ecx,0x0
   140008f71:	e8 6a 01 00 00       	call   1400090e0 <__acrt_iob_func>
   140008f76:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008f7a:	72 52                	jb     140008fce <_lock_file+0x6e>
   140008f7c:	b9 13 00 00 00       	mov    ecx,0x13
   140008f81:	e8 5a 01 00 00       	call   1400090e0 <__acrt_iob_func>
   140008f86:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008f8a:	72 42                	jb     140008fce <_lock_file+0x6e>
   140008f8c:	b9 00 00 00 00       	mov    ecx,0x0
   140008f91:	e8 4a 01 00 00       	call   1400090e0 <__acrt_iob_func>
   140008f96:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008f9a:	48 29 c2             	sub    rdx,rax
   140008f9d:	48 c1 fa 04          	sar    rdx,0x4
   140008fa1:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008fa8:	aa aa aa 
   140008fab:	48 0f af c2          	imul   rax,rdx
   140008faf:	83 c0 10             	add    eax,0x10
   140008fb2:	89 c1                	mov    ecx,eax
   140008fb4:	e8 1f 07 00 00       	call   1400096d8 <_lock>
   140008fb9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fbd:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008fc0:	80 cc 80             	or     ah,0x80
   140008fc3:	89 c2                	mov    edx,eax
   140008fc5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fc9:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008fcc:	eb 15                	jmp    140008fe3 <_lock_file+0x83>
   140008fce:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fd2:	48 83 c0 30          	add    rax,0x30
   140008fd6:	48 89 c1             	mov    rcx,rax
   140008fd9:	48 8b 05 10 72 00 00 	mov    rax,QWORD PTR [rip+0x7210]        # 1400101f0 <__imp_EnterCriticalSection>
   140008fe0:	ff d0                	call   rax
   140008fe2:	90                   	nop
   140008fe3:	90                   	nop
   140008fe4:	48 83 c4 20          	add    rsp,0x20
   140008fe8:	5d                   	pop    rbp
   140008fe9:	c3                   	ret

0000000140008fea <_unlock_file>:
   140008fea:	55                   	push   rbp
   140008feb:	48 89 e5             	mov    rbp,rsp
   140008fee:	48 83 ec 20          	sub    rsp,0x20
   140008ff2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008ff6:	b9 00 00 00 00       	mov    ecx,0x0
   140008ffb:	e8 e0 00 00 00       	call   1400090e0 <__acrt_iob_func>
   140009000:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140009004:	72 52                	jb     140009058 <_unlock_file+0x6e>
   140009006:	b9 13 00 00 00       	mov    ecx,0x13
   14000900b:	e8 d0 00 00 00       	call   1400090e0 <__acrt_iob_func>
   140009010:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140009014:	72 42                	jb     140009058 <_unlock_file+0x6e>
   140009016:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000901a:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   14000901d:	80 e4 7f             	and    ah,0x7f
   140009020:	89 c2                	mov    edx,eax
   140009022:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009026:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140009029:	b9 00 00 00 00       	mov    ecx,0x0
   14000902e:	e8 ad 00 00 00       	call   1400090e0 <__acrt_iob_func>
   140009033:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140009037:	48 29 c2             	sub    rdx,rax
   14000903a:	48 c1 fa 04          	sar    rdx,0x4
   14000903e:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140009045:	aa aa aa 
   140009048:	48 0f af c2          	imul   rax,rdx
   14000904c:	83 c0 10             	add    eax,0x10
   14000904f:	89 c1                	mov    ecx,eax
   140009051:	e8 8a 06 00 00       	call   1400096e0 <_unlock>
   140009056:	eb 15                	jmp    14000906d <_unlock_file+0x83>
   140009058:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000905c:	48 83 c0 30          	add    rax,0x30
   140009060:	48 89 c1             	mov    rcx,rax
   140009063:	48 8b 05 be 71 00 00 	mov    rax,QWORD PTR [rip+0x71be]        # 140010228 <__imp_LeaveCriticalSection>
   14000906a:	ff d0                	call   rax
   14000906c:	90                   	nop
   14000906d:	90                   	nop
   14000906e:	48 83 c4 20          	add    rsp,0x20
   140009072:	5d                   	pop    rbp
   140009073:	c3                   	ret
   140009074:	90                   	nop
   140009075:	90                   	nop
   140009076:	90                   	nop
   140009077:	90                   	nop
   140009078:	90                   	nop
   140009079:	90                   	nop
   14000907a:	90                   	nop
   14000907b:	90                   	nop
   14000907c:	90                   	nop
   14000907d:	90                   	nop
   14000907e:	90                   	nop
   14000907f:	90                   	nop

0000000140009080 <_set_invalid_parameter_handler>:
   140009080:	55                   	push   rbp
   140009081:	48 89 e5             	mov    rbp,rsp
   140009084:	48 83 ec 10          	sub    rsp,0x10
   140009088:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000908c:	48 8d 05 ed 6a 00 00 	lea    rax,[rip+0x6aed]        # 14000fb80 <handler>
   140009093:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140009097:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000909b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000909f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400090a3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400090a7:	48 87 10             	xchg   QWORD PTR [rax],rdx
   1400090aa:	48 89 d0             	mov    rax,rdx
   1400090ad:	48 83 c4 10          	add    rsp,0x10
   1400090b1:	5d                   	pop    rbp
   1400090b2:	c3                   	ret

00000001400090b3 <_get_invalid_parameter_handler>:
   1400090b3:	55                   	push   rbp
   1400090b4:	48 89 e5             	mov    rbp,rsp
   1400090b7:	48 8b 05 c2 6a 00 00 	mov    rax,QWORD PTR [rip+0x6ac2]        # 14000fb80 <handler>
   1400090be:	5d                   	pop    rbp
   1400090bf:	c3                   	ret

00000001400090c0 <_configthreadlocale>:
   1400090c0:	55                   	push   rbp
   1400090c1:	48 89 e5             	mov    rbp,rsp
   1400090c4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400090c7:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   1400090cb:	75 07                	jne    1400090d4 <_configthreadlocale+0x14>
   1400090cd:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400090d2:	eb 05                	jmp    1400090d9 <_configthreadlocale+0x19>
   1400090d4:	b8 02 00 00 00       	mov    eax,0x2
   1400090d9:	5d                   	pop    rbp
   1400090da:	c3                   	ret
   1400090db:	90                   	nop
   1400090dc:	90                   	nop
   1400090dd:	90                   	nop
   1400090de:	90                   	nop
   1400090df:	90                   	nop

00000001400090e0 <__acrt_iob_func>:
   1400090e0:	55                   	push   rbp
   1400090e1:	48 89 e5             	mov    rbp,rsp
   1400090e4:	48 83 ec 20          	sub    rsp,0x20
   1400090e8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400090eb:	e8 b0 05 00 00       	call   1400096a0 <__iob_func>
   1400090f0:	48 89 c1             	mov    rcx,rax
   1400090f3:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400090f6:	48 89 d0             	mov    rax,rdx
   1400090f9:	48 01 c0             	add    rax,rax
   1400090fc:	48 01 d0             	add    rax,rdx
   1400090ff:	48 c1 e0 04          	shl    rax,0x4
   140009103:	48 01 c8             	add    rax,rcx
   140009106:	48 83 c4 20          	add    rsp,0x20
   14000910a:	5d                   	pop    rbp
   14000910b:	c3                   	ret
   14000910c:	90                   	nop
   14000910d:	90                   	nop
   14000910e:	90                   	nop
   14000910f:	90                   	nop

0000000140009110 <wcrtomb>:
   140009110:	55                   	push   rbp
   140009111:	48 89 e5             	mov    rbp,rsp
   140009114:	48 83 ec 40          	sub    rsp,0x40
   140009118:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000911c:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   140009120:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009124:	e8 5f 05 00 00       	call   140009688 <___lc_codepage_func>
   140009129:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000912c:	e8 5f 05 00 00       	call   140009690 <___mb_cur_max_func>
   140009131:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140009134:	44 8b 4d fc          	mov    r9d,DWORD PTR [rbp-0x4]
   140009138:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   14000913c:	0f b7 55 18          	movzx  edx,WORD PTR [rbp+0x18]
   140009140:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009144:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140009147:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   14000914b:	48 89 c1             	mov    rcx,rax
   14000914e:	e8 7d 00 00 00       	call   1400091d0 <__mingw_wcrtomb_cp>
   140009153:	48 83 c4 40          	add    rsp,0x40
   140009157:	5d                   	pop    rbp
   140009158:	c3                   	ret
   140009159:	90                   	nop
   14000915a:	90                   	nop
   14000915b:	90                   	nop
   14000915c:	90                   	nop
   14000915d:	90                   	nop
   14000915e:	90                   	nop
   14000915f:	90                   	nop

0000000140009160 <mbrtowc>:
   140009160:	55                   	push   rbp
   140009161:	48 89 e5             	mov    rbp,rsp
   140009164:	48 83 ec 40          	sub    rsp,0x40
   140009168:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000916c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009170:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009174:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009178:	48 83 7d 28 00       	cmp    QWORD PTR [rbp+0x28],0x0
   14000917d:	75 0b                	jne    14000918a <mbrtowc+0x2a>
   14000917f:	48 8d 05 0a 6a 00 00 	lea    rax,[rip+0x6a0a]        # 14000fb90 <state_mbrtowc.0>
   140009186:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000918a:	e8 f9 04 00 00       	call   140009688 <___lc_codepage_func>
   14000918f:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140009192:	e8 f9 04 00 00       	call   140009690 <___mb_cur_max_func>
   140009197:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000919a:	4c 8b 4d 28          	mov    r9,QWORD PTR [rbp+0x28]
   14000919e:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   1400091a2:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400091a6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400091aa:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   1400091ad:	89 4c 24 28          	mov    DWORD PTR [rsp+0x28],ecx
   1400091b1:	8b 4d fc             	mov    ecx,DWORD PTR [rbp-0x4]
   1400091b4:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   1400091b8:	48 89 c1             	mov    rcx,rax
   1400091bb:	e8 70 01 00 00       	call   140009330 <__mingw_mbrtowc_cp>
   1400091c0:	48 83 c4 40          	add    rsp,0x40
   1400091c4:	5d                   	pop    rbp
   1400091c5:	c3                   	ret
   1400091c6:	90                   	nop
   1400091c7:	90                   	nop
   1400091c8:	90                   	nop
   1400091c9:	90                   	nop
   1400091ca:	90                   	nop
   1400091cb:	90                   	nop
   1400091cc:	90                   	nop
   1400091cd:	90                   	nop
   1400091ce:	90                   	nop
   1400091cf:	90                   	nop

00000001400091d0 <__mingw_wcrtomb_cp>:
   1400091d0:	55                   	push   rbp
   1400091d1:	48 89 e5             	mov    rbp,rsp
   1400091d4:	48 83 ec 50          	sub    rsp,0x50
   1400091d8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400091dc:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   1400091e0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400091e4:	44 89 4d 28          	mov    DWORD PTR [rbp+0x28],r9d
   1400091e8:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400091ed:	75 1b                	jne    14000920a <__mingw_wcrtomb_cp+0x3a>
   1400091ef:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400091f4:	74 0a                	je     140009200 <__mingw_wcrtomb_cp+0x30>
   1400091f6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400091fa:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009200:	b8 01 00 00 00       	mov    eax,0x1
   140009205:	e9 17 01 00 00       	jmp    140009321 <__mingw_wcrtomb_cp+0x151>
   14000920a:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   14000920f:	74 21                	je     140009232 <__mingw_wcrtomb_cp+0x62>
   140009211:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140009215:	8b 00                	mov    eax,DWORD PTR [rax]
   140009217:	85 c0                	test   eax,eax
   140009219:	74 17                	je     140009232 <__mingw_wcrtomb_cp+0x62>
   14000921b:	e8 a8 04 00 00       	call   1400096c8 <_errno>
   140009220:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140009226:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000922d:	e9 ef 00 00 00       	jmp    140009321 <__mingw_wcrtomb_cp+0x151>
   140009232:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009236:	66 85 c0             	test   ax,ax
   140009239:	75 18                	jne    140009253 <__mingw_wcrtomb_cp+0x83>
   14000923b:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140009240:	74 07                	je     140009249 <__mingw_wcrtomb_cp+0x79>
   140009242:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009246:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140009249:	b8 01 00 00 00       	mov    eax,0x1
   14000924e:	e9 ce 00 00 00       	jmp    140009321 <__mingw_wcrtomb_cp+0x151>
   140009253:	83 7d 28 00          	cmp    DWORD PTR [rbp+0x28],0x0
   140009257:	75 2b                	jne    140009284 <__mingw_wcrtomb_cp+0xb4>
   140009259:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   14000925d:	66 3d ff 00          	cmp    ax,0xff
   140009261:	0f 87 a4 00 00 00    	ja     14000930b <__mingw_wcrtomb_cp+0x13b>
   140009267:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000926c:	74 0c                	je     14000927a <__mingw_wcrtomb_cp+0xaa>
   14000926e:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009272:	89 c2                	mov    edx,eax
   140009274:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009278:	88 10                	mov    BYTE PTR [rax],dl
   14000927a:	b8 01 00 00 00       	mov    eax,0x1
   14000927f:	e9 9d 00 00 00       	jmp    140009321 <__mingw_wcrtomb_cp+0x151>
   140009284:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   14000928b:	66 c7 45 f6 00 00    	mov    WORD PTR [rbp-0xa],0x0
   140009291:	48 8d 4d 18          	lea    rcx,[rbp+0x18]
   140009295:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140009298:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   14000929c:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   1400092a1:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
   1400092a8:	00 00 
   1400092aa:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   1400092ad:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   1400092b1:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   1400092b5:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400092ba:	41 b9 01 00 00 00    	mov    r9d,0x1
   1400092c0:	49 89 c8             	mov    r8,rcx
   1400092c3:	ba 00 00 00 00       	mov    edx,0x0
   1400092c8:	89 c1                	mov    ecx,eax
   1400092ca:	48 8b 05 97 6f 00 00 	mov    rax,QWORD PTR [rip+0x6f97]        # 140010268 <__imp_WideCharToMultiByte>
   1400092d1:	ff d0                	call   rax
   1400092d3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400092d6:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400092da:	74 32                	je     14000930e <__mingw_wcrtomb_cp+0x13e>
   1400092dc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400092df:	3b 45 30             	cmp    eax,DWORD PTR [rbp+0x30]
   1400092e2:	7f 2a                	jg     14000930e <__mingw_wcrtomb_cp+0x13e>
   1400092e4:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400092e7:	85 c0                	test   eax,eax
   1400092e9:	75 23                	jne    14000930e <__mingw_wcrtomb_cp+0x13e>
   1400092eb:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400092ee:	48 63 c8             	movsxd rcx,eax
   1400092f1:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   1400092f5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400092f9:	49 89 c8             	mov    r8,rcx
   1400092fc:	48 89 c1             	mov    rcx,rax
   1400092ff:	e8 34 04 00 00       	call   140009738 <memcpy>
   140009304:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009307:	48 98                	cdqe
   140009309:	eb 16                	jmp    140009321 <__mingw_wcrtomb_cp+0x151>
   14000930b:	90                   	nop
   14000930c:	eb 01                	jmp    14000930f <__mingw_wcrtomb_cp+0x13f>
   14000930e:	90                   	nop
   14000930f:	e8 b4 03 00 00       	call   1400096c8 <_errno>
   140009314:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   14000931a:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140009321:	48 83 c4 50          	add    rsp,0x50
   140009325:	5d                   	pop    rbp
   140009326:	c3                   	ret
   140009327:	90                   	nop
   140009328:	90                   	nop
   140009329:	90                   	nop
   14000932a:	90                   	nop
   14000932b:	90                   	nop
   14000932c:	90                   	nop
   14000932d:	90                   	nop
   14000932e:	90                   	nop
   14000932f:	90                   	nop

0000000140009330 <__mingw_mbrtowc_cp>:
   140009330:	55                   	push   rbp
   140009331:	48 89 e5             	mov    rbp,rsp
   140009334:	48 83 ec 50          	sub    rsp,0x50
   140009338:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000933c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009340:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009344:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009348:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   14000934d:	75 1b                	jne    14000936a <__mingw_mbrtowc_cp+0x3a>
   14000934f:	48 c7 45 10 00 00 00 	mov    QWORD PTR [rbp+0x10],0x0
   140009356:	00 
   140009357:	48 8d 05 c2 21 00 00 	lea    rax,[rip+0x21c2]        # 14000b520 <.rdata>
   14000935e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140009362:	48 c7 45 20 01 00 00 	mov    QWORD PTR [rbp+0x20],0x1
   140009369:	00 
   14000936a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000936e:	8b 00                	mov    eax,DWORD PTR [rax]
   140009370:	3d ff 00 00 00       	cmp    eax,0xff
   140009375:	0f 87 b9 01 00 00    	ja     140009534 <__mingw_mbrtowc_cp+0x204>
   14000937b:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009380:	75 0c                	jne    14000938e <__mingw_mbrtowc_cp+0x5e>
   140009382:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   140009389:	e9 bc 01 00 00       	jmp    14000954a <__mingw_mbrtowc_cp+0x21a>
   14000938e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009392:	8b 00                	mov    eax,DWORD PTR [rax]
   140009394:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140009397:	83 7d 38 01          	cmp    DWORD PTR [rbp+0x38],0x1
   14000939b:	75 0c                	jne    1400093a9 <__mingw_mbrtowc_cp+0x79>
   14000939d:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   1400093a1:	84 c0                	test   al,al
   1400093a3:	0f 85 8e 01 00 00    	jne    140009537 <__mingw_mbrtowc_cp+0x207>
   1400093a9:	83 7d 30 00          	cmp    DWORD PTR [rbp+0x30],0x0
   1400093ad:	75 2c                	jne    1400093db <__mingw_mbrtowc_cp+0xab>
   1400093af:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400093b4:	74 11                	je     1400093c7 <__mingw_mbrtowc_cp+0x97>
   1400093b6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093ba:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093bd:	0f b6 d0             	movzx  edx,al
   1400093c0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400093c4:	66 89 10             	mov    WORD PTR [rax],dx
   1400093c7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093cb:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093ce:	84 c0                	test   al,al
   1400093d0:	0f 95 c0             	setne  al
   1400093d3:	0f b6 c0             	movzx  eax,al
   1400093d6:	e9 6f 01 00 00       	jmp    14000954a <__mingw_mbrtowc_cp+0x21a>
   1400093db:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400093e2:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400093e9:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   1400093ed:	84 c0                	test   al,al
   1400093ef:	74 1a                	je     14000940b <__mingw_mbrtowc_cp+0xdb>
   1400093f1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093f5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093f8:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   1400093fb:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140009402:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140009409:	eb 73                	jmp    14000947e <__mingw_mbrtowc_cp+0x14e>
   14000940b:	83 7d 38 02          	cmp    DWORD PTR [rbp+0x38],0x2
   14000940f:	75 5c                	jne    14000946d <__mingw_mbrtowc_cp+0x13d>
   140009411:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009415:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009418:	0f b6 c0             	movzx  eax,al
   14000941b:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   14000941e:	89 c1                	mov    ecx,eax
   140009420:	e8 ab 01 00 00       	call   1400095d0 <__mingw_isleadbyte_cp>
   140009425:	85 c0                	test   eax,eax
   140009427:	74 44                	je     14000946d <__mingw_mbrtowc_cp+0x13d>
   140009429:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000942d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009430:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009433:	48 83 7d 20 01       	cmp    QWORD PTR [rbp+0x20],0x1
   140009438:	77 15                	ja     14000944f <__mingw_mbrtowc_cp+0x11f>
   14000943a:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000943d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009441:	89 10                	mov    DWORD PTR [rax],edx
   140009443:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   14000944a:	e9 fb 00 00 00       	jmp    14000954a <__mingw_mbrtowc_cp+0x21a>
   14000944f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009453:	48 83 c0 01          	add    rax,0x1
   140009457:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000945a:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   14000945d:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140009464:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   14000946b:	eb 11                	jmp    14000947e <__mingw_mbrtowc_cp+0x14e>
   14000946d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009471:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009474:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009477:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   14000947e:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009482:	84 c0                	test   al,al
   140009484:	75 24                	jne    1400094aa <__mingw_mbrtowc_cp+0x17a>
   140009486:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000948b:	74 09                	je     140009496 <__mingw_mbrtowc_cp+0x166>
   14000948d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009491:	66 c7 00 00 00       	mov    WORD PTR [rax],0x0
   140009496:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000949a:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400094a0:	b8 00 00 00 00       	mov    eax,0x0
   1400094a5:	e9 a0 00 00 00       	jmp    14000954a <__mingw_mbrtowc_cp+0x21a>
   1400094aa:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   1400094ae:	75 08                	jne    1400094b8 <__mingw_mbrtowc_cp+0x188>
   1400094b0:	0f b6 45 f1          	movzx  eax,BYTE PTR [rbp-0xf]
   1400094b4:	84 c0                	test   al,al
   1400094b6:	74 64                	je     14000951c <__mingw_mbrtowc_cp+0x1ec>
   1400094b8:	66 c7 45 ee ff ff    	mov    WORD PTR [rbp-0x12],0xffff
   1400094be:	44 8b 45 fc          	mov    r8d,DWORD PTR [rbp-0x4]
   1400094c2:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   1400094c6:	8b 45 30             	mov    eax,DWORD PTR [rbp+0x30]
   1400094c9:	c7 44 24 28 01 00 00 	mov    DWORD PTR [rsp+0x28],0x1
   1400094d0:	00 
   1400094d1:	48 8d 55 ee          	lea    rdx,[rbp-0x12]
   1400094d5:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400094da:	45 89 c1             	mov    r9d,r8d
   1400094dd:	49 89 c8             	mov    r8,rcx
   1400094e0:	ba 08 00 00 00       	mov    edx,0x8
   1400094e5:	89 c1                	mov    ecx,eax
   1400094e7:	48 8b 05 4a 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d4a]        # 140010238 <__imp_MultiByteToWideChar>
   1400094ee:	ff d0                	call   rax
   1400094f0:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400094f3:	83 7d f4 01          	cmp    DWORD PTR [rbp-0xc],0x1
   1400094f7:	75 26                	jne    14000951f <__mingw_mbrtowc_cp+0x1ef>
   1400094f9:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400094fe:	74 0b                	je     14000950b <__mingw_mbrtowc_cp+0x1db>
   140009500:	0f b7 55 ee          	movzx  edx,WORD PTR [rbp-0x12]
   140009504:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009508:	66 89 10             	mov    WORD PTR [rax],dx
   14000950b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000950f:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009515:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140009518:	48 98                	cdqe
   14000951a:	eb 2e                	jmp    14000954a <__mingw_mbrtowc_cp+0x21a>
   14000951c:	90                   	nop
   14000951d:	eb 01                	jmp    140009520 <__mingw_mbrtowc_cp+0x1f0>
   14000951f:	90                   	nop
   140009520:	e8 a3 01 00 00       	call   1400096c8 <_errno>
   140009525:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   14000952b:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140009532:	eb 16                	jmp    14000954a <__mingw_mbrtowc_cp+0x21a>
   140009534:	90                   	nop
   140009535:	eb 01                	jmp    140009538 <__mingw_mbrtowc_cp+0x208>
   140009537:	90                   	nop
   140009538:	e8 8b 01 00 00       	call   1400096c8 <_errno>
   14000953d:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140009543:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000954a:	48 83 c4 50          	add    rsp,0x50
   14000954e:	5d                   	pop    rbp
   14000954f:	c3                   	ret

0000000140009550 <fallback_IsDBCSLeadByteEx>:
   140009550:	55                   	push   rbp
   140009551:	48 89 e5             	mov    rbp,rsp
   140009554:	48 83 ec 40          	sub    rsp,0x40
   140009558:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000955b:	88 55 18             	mov    BYTE PTR [rbp+0x18],dl
   14000955e:	48 8d 55 e0          	lea    rdx,[rbp-0x20]
   140009562:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009565:	89 c1                	mov    ecx,eax
   140009567:	48 8b 05 92 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c92]        # 140010200 <__imp_GetCPInfo>
   14000956e:	ff d0                	call   rax
   140009570:	85 c0                	test   eax,eax
   140009572:	74 51                	je     1400095c5 <fallback_IsDBCSLeadByteEx+0x75>
   140009574:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140009577:	83 f8 02             	cmp    eax,0x2
   14000957a:	75 49                	jne    1400095c5 <fallback_IsDBCSLeadByteEx+0x75>
   14000957c:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140009583:	eb 2c                	jmp    1400095b1 <fallback_IsDBCSLeadByteEx+0x61>
   140009585:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009588:	48 98                	cdqe
   14000958a:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   14000958f:	38 45 18             	cmp    BYTE PTR [rbp+0x18],al
   140009592:	72 19                	jb     1400095ad <fallback_IsDBCSLeadByteEx+0x5d>
   140009594:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009597:	83 c0 01             	add    eax,0x1
   14000959a:	48 98                	cdqe
   14000959c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   1400095a1:	3a 45 18             	cmp    al,BYTE PTR [rbp+0x18]
   1400095a4:	72 07                	jb     1400095ad <fallback_IsDBCSLeadByteEx+0x5d>
   1400095a6:	b8 01 00 00 00       	mov    eax,0x1
   1400095ab:	eb 1d                	jmp    1400095ca <fallback_IsDBCSLeadByteEx+0x7a>
   1400095ad:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   1400095b1:	83 7d fc 0b          	cmp    DWORD PTR [rbp-0x4],0xb
   1400095b5:	7f 0e                	jg     1400095c5 <fallback_IsDBCSLeadByteEx+0x75>
   1400095b7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400095ba:	48 98                	cdqe
   1400095bc:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   1400095c1:	84 c0                	test   al,al
   1400095c3:	75 c0                	jne    140009585 <fallback_IsDBCSLeadByteEx+0x35>
   1400095c5:	b8 00 00 00 00       	mov    eax,0x0
   1400095ca:	48 83 c4 40          	add    rsp,0x40
   1400095ce:	5d                   	pop    rbp
   1400095cf:	c3                   	ret

00000001400095d0 <__mingw_isleadbyte_cp>:
   1400095d0:	55                   	push   rbp
   1400095d1:	48 89 e5             	mov    rbp,rsp
   1400095d4:	48 83 ec 40          	sub    rsp,0x40
   1400095d8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400095db:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400095de:	48 8b 05 bb 65 00 00 	mov    rax,QWORD PTR [rip+0x65bb]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   1400095e5:	48 85 c0             	test   rax,rax
   1400095e8:	75 71                	jne    14000965b <__mingw_isleadbyte_cp+0x8b>
   1400095ea:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   1400095f1:	00 
   1400095f2:	48 8d 05 37 1f 00 00 	lea    rax,[rip+0x1f37]        # 14000b530 <.rdata>
   1400095f9:	48 89 c1             	mov    rcx,rax
   1400095fc:	48 8b 05 0d 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c0d]        # 140010210 <__imp_GetModuleHandleA>
   140009603:	ff d0                	call   rax
   140009605:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140009609:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000960e:	74 1b                	je     14000962b <__mingw_isleadbyte_cp+0x5b>
   140009610:	48 8d 15 26 1f 00 00 	lea    rdx,[rip+0x1f26]        # 14000b53d <.rdata+0xd>
   140009617:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000961b:	48 89 c1             	mov    rcx,rax
   14000961e:	48 8b 05 f3 6b 00 00 	mov    rax,QWORD PTR [rip+0x6bf3]        # 140010218 <__imp_GetProcAddress>
   140009625:	ff d0                	call   rax
   140009627:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000962b:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140009630:	75 0b                	jne    14000963d <__mingw_isleadbyte_cp+0x6d>
   140009632:	48 8d 05 17 ff ff ff 	lea    rax,[rip+0xffffffffffffff17]        # 140009550 <fallback_IsDBCSLeadByteEx>
   140009639:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000963d:	48 8d 05 5c 65 00 00 	lea    rax,[rip+0x655c]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009644:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140009648:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000964c:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140009650:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   140009654:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140009658:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000965b:	4c 8b 05 3e 65 00 00 	mov    r8,QWORD PTR [rip+0x653e]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009662:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009665:	0f b6 d0             	movzx  edx,al
   140009668:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000966b:	89 c1                	mov    ecx,eax
   14000966d:	41 ff d0             	call   r8
   140009670:	48 83 c4 40          	add    rsp,0x40
   140009674:	5d                   	pop    rbp
   140009675:	c3                   	ret
   140009676:	90                   	nop
   140009677:	90                   	nop
   140009678:	90                   	nop
   140009679:	90                   	nop
   14000967a:	90                   	nop
   14000967b:	90                   	nop
   14000967c:	90                   	nop
   14000967d:	90                   	nop
   14000967e:	90                   	nop
   14000967f:	90                   	nop

0000000140009680 <__C_specific_handler>:
   140009680:	ff 25 f2 6b 00 00    	jmp    QWORD PTR [rip+0x6bf2]        # 140010278 <__imp___C_specific_handler>
   140009686:	90                   	nop
   140009687:	90                   	nop

0000000140009688 <___lc_codepage_func>:
   140009688:	ff 25 f2 6b 00 00    	jmp    QWORD PTR [rip+0x6bf2]        # 140010280 <__imp____lc_codepage_func>
   14000968e:	90                   	nop
   14000968f:	90                   	nop

0000000140009690 <___mb_cur_max_func>:
   140009690:	ff 25 f2 6b 00 00    	jmp    QWORD PTR [rip+0x6bf2]        # 140010288 <__imp____mb_cur_max_func>
   140009696:	90                   	nop
   140009697:	90                   	nop

0000000140009698 <__getmainargs>:
   140009698:	ff 25 f2 6b 00 00    	jmp    QWORD PTR [rip+0x6bf2]        # 140010290 <__imp___getmainargs>
   14000969e:	90                   	nop
   14000969f:	90                   	nop

00000001400096a0 <__iob_func>:
   1400096a0:	ff 25 fa 6b 00 00    	jmp    QWORD PTR [rip+0x6bfa]        # 1400102a0 <__imp___iob_func>
   1400096a6:	90                   	nop
   1400096a7:	90                   	nop

00000001400096a8 <__set_app_type>:
   1400096a8:	ff 25 fa 6b 00 00    	jmp    QWORD PTR [rip+0x6bfa]        # 1400102a8 <__imp___set_app_type>
   1400096ae:	90                   	nop
   1400096af:	90                   	nop

00000001400096b0 <__setusermatherr>:
   1400096b0:	ff 25 fa 6b 00 00    	jmp    QWORD PTR [rip+0x6bfa]        # 1400102b0 <__imp___setusermatherr>
   1400096b6:	90                   	nop
   1400096b7:	90                   	nop

00000001400096b8 <_amsg_exit>:
   1400096b8:	ff 25 fa 6b 00 00    	jmp    QWORD PTR [rip+0x6bfa]        # 1400102b8 <__imp__amsg_exit>
   1400096be:	90                   	nop
   1400096bf:	90                   	nop

00000001400096c0 <_cexit>:
   1400096c0:	ff 25 fa 6b 00 00    	jmp    QWORD PTR [rip+0x6bfa]        # 1400102c0 <__imp__cexit>
   1400096c6:	90                   	nop
   1400096c7:	90                   	nop

00000001400096c8 <_errno>:
   1400096c8:	ff 25 02 6c 00 00    	jmp    QWORD PTR [rip+0x6c02]        # 1400102d0 <__imp__errno>
   1400096ce:	90                   	nop
   1400096cf:	90                   	nop

00000001400096d0 <_initterm>:
   1400096d0:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 1400102e0 <__imp__initterm>
   1400096d6:	90                   	nop
   1400096d7:	90                   	nop

00000001400096d8 <_lock>:
   1400096d8:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 1400102e8 <__imp__lock>
   1400096de:	90                   	nop
   1400096df:	90                   	nop

00000001400096e0 <_unlock>:
   1400096e0:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 1400102f0 <__imp__unlock>
   1400096e6:	90                   	nop
   1400096e7:	90                   	nop

00000001400096e8 <_crt_atexit>:
   1400096e8:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 1400102f8 <__imp__crt_atexit>
   1400096ee:	90                   	nop
   1400096ef:	90                   	nop

00000001400096f0 <abort>:
   1400096f0:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010300 <__imp_abort>
   1400096f6:	90                   	nop
   1400096f7:	90                   	nop

00000001400096f8 <calloc>:
   1400096f8:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010308 <__imp_calloc>
   1400096fe:	90                   	nop
   1400096ff:	90                   	nop

0000000140009700 <exit>:
   140009700:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010310 <__imp_exit>
   140009706:	90                   	nop
   140009707:	90                   	nop

0000000140009708 <fflush>:
   140009708:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010318 <__imp_fflush>
   14000970e:	90                   	nop
   14000970f:	90                   	nop

0000000140009710 <fprintf>:
   140009710:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010320 <__imp_fprintf>
   140009716:	90                   	nop
   140009717:	90                   	nop

0000000140009718 <fputc>:
   140009718:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010328 <__imp_fputc>
   14000971e:	90                   	nop
   14000971f:	90                   	nop

0000000140009720 <free>:
   140009720:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010330 <__imp_free>
   140009726:	90                   	nop
   140009727:	90                   	nop

0000000140009728 <localeconv>:
   140009728:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010338 <__imp_localeconv>
   14000972e:	90                   	nop
   14000972f:	90                   	nop

0000000140009730 <malloc>:
   140009730:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010340 <__imp_malloc>
   140009736:	90                   	nop
   140009737:	90                   	nop

0000000140009738 <memcpy>:
   140009738:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010348 <__imp_memcpy>
   14000973e:	90                   	nop
   14000973f:	90                   	nop

0000000140009740 <setvbuf>:
   140009740:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010350 <__imp_setvbuf>
   140009746:	90                   	nop
   140009747:	90                   	nop

0000000140009748 <signal>:
   140009748:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010358 <__imp_signal>
   14000974e:	90                   	nop
   14000974f:	90                   	nop

0000000140009750 <strerror>:
   140009750:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010360 <__imp_strerror>
   140009756:	90                   	nop
   140009757:	90                   	nop

0000000140009758 <strlen>:
   140009758:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010368 <__imp_strlen>
   14000975e:	90                   	nop
   14000975f:	90                   	nop

0000000140009760 <strncmp>:
   140009760:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010370 <__imp_strncmp>
   140009766:	90                   	nop
   140009767:	90                   	nop

0000000140009768 <vfprintf>:
   140009768:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010378 <__imp_vfprintf>
   14000976e:	90                   	nop
   14000976f:	90                   	nop

0000000140009770 <wcslen>:
   140009770:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010380 <__imp_wcslen>
   140009776:	90                   	nop
   140009777:	90                   	nop
   140009778:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000977f:	00 

0000000140009780 <WideCharToMultiByte>:
   140009780:	ff 25 e2 6a 00 00    	jmp    QWORD PTR [rip+0x6ae2]        # 140010268 <__imp_WideCharToMultiByte>
   140009786:	90                   	nop
   140009787:	90                   	nop

0000000140009788 <VirtualQuery>:
   140009788:	ff 25 d2 6a 00 00    	jmp    QWORD PTR [rip+0x6ad2]        # 140010260 <__imp_VirtualQuery>
   14000978e:	90                   	nop
   14000978f:	90                   	nop

0000000140009790 <VirtualProtect>:
   140009790:	ff 25 c2 6a 00 00    	jmp    QWORD PTR [rip+0x6ac2]        # 140010258 <__imp_VirtualProtect>
   140009796:	90                   	nop
   140009797:	90                   	nop

0000000140009798 <TlsGetValue>:
   140009798:	ff 25 b2 6a 00 00    	jmp    QWORD PTR [rip+0x6ab2]        # 140010250 <__imp_TlsGetValue>
   14000979e:	90                   	nop
   14000979f:	90                   	nop

00000001400097a0 <Sleep>:
   1400097a0:	ff 25 a2 6a 00 00    	jmp    QWORD PTR [rip+0x6aa2]        # 140010248 <__imp_Sleep>
   1400097a6:	90                   	nop
   1400097a7:	90                   	nop

00000001400097a8 <SetUnhandledExceptionFilter>:
   1400097a8:	ff 25 92 6a 00 00    	jmp    QWORD PTR [rip+0x6a92]        # 140010240 <__imp_SetUnhandledExceptionFilter>
   1400097ae:	90                   	nop
   1400097af:	90                   	nop

00000001400097b0 <MultiByteToWideChar>:
   1400097b0:	ff 25 82 6a 00 00    	jmp    QWORD PTR [rip+0x6a82]        # 140010238 <__imp_MultiByteToWideChar>
   1400097b6:	90                   	nop
   1400097b7:	90                   	nop

00000001400097b8 <LoadLibraryA>:
   1400097b8:	ff 25 72 6a 00 00    	jmp    QWORD PTR [rip+0x6a72]        # 140010230 <__imp_LoadLibraryA>
   1400097be:	90                   	nop
   1400097bf:	90                   	nop

00000001400097c0 <LeaveCriticalSection>:
   1400097c0:	ff 25 62 6a 00 00    	jmp    QWORD PTR [rip+0x6a62]        # 140010228 <__imp_LeaveCriticalSection>
   1400097c6:	90                   	nop
   1400097c7:	90                   	nop

00000001400097c8 <InitializeCriticalSection>:
   1400097c8:	ff 25 52 6a 00 00    	jmp    QWORD PTR [rip+0x6a52]        # 140010220 <__imp_InitializeCriticalSection>
   1400097ce:	90                   	nop
   1400097cf:	90                   	nop

00000001400097d0 <GetProcAddress>:
   1400097d0:	ff 25 42 6a 00 00    	jmp    QWORD PTR [rip+0x6a42]        # 140010218 <__imp_GetProcAddress>
   1400097d6:	90                   	nop
   1400097d7:	90                   	nop

00000001400097d8 <GetModuleHandleA>:
   1400097d8:	ff 25 32 6a 00 00    	jmp    QWORD PTR [rip+0x6a32]        # 140010210 <__imp_GetModuleHandleA>
   1400097de:	90                   	nop
   1400097df:	90                   	nop

00000001400097e0 <GetLastError>:
   1400097e0:	ff 25 22 6a 00 00    	jmp    QWORD PTR [rip+0x6a22]        # 140010208 <__imp_GetLastError>
   1400097e6:	90                   	nop
   1400097e7:	90                   	nop

00000001400097e8 <GetCPInfo>:
   1400097e8:	ff 25 12 6a 00 00    	jmp    QWORD PTR [rip+0x6a12]        # 140010200 <__imp_GetCPInfo>
   1400097ee:	90                   	nop
   1400097ef:	90                   	nop

00000001400097f0 <FreeLibrary>:
   1400097f0:	ff 25 02 6a 00 00    	jmp    QWORD PTR [rip+0x6a02]        # 1400101f8 <__imp_FreeLibrary>
   1400097f6:	90                   	nop
   1400097f7:	90                   	nop

00000001400097f8 <EnterCriticalSection>:
   1400097f8:	ff 25 f2 69 00 00    	jmp    QWORD PTR [rip+0x69f2]        # 1400101f0 <__imp_EnterCriticalSection>
   1400097fe:	90                   	nop
   1400097ff:	90                   	nop

0000000140009800 <DeleteCriticalSection>:
   140009800:	ff 25 e2 69 00 00    	jmp    QWORD PTR [rip+0x69e2]        # 1400101e8 <__IAT_start__>
   140009806:	90                   	nop
   140009807:	90                   	nop
   140009808:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000980f:	00 

0000000140009810 <register_frame_ctor>:
   140009810:	e9 5b 7e ff ff       	jmp    140001670 <__gcc_register_frame>
   140009815:	90                   	nop
   140009816:	90                   	nop
   140009817:	90                   	nop
   140009818:	90                   	nop
   140009819:	90                   	nop
   14000981a:	90                   	nop
   14000981b:	90                   	nop
   14000981c:	90                   	nop
   14000981d:	90                   	nop
   14000981e:	90                   	nop
   14000981f:	90                   	nop
