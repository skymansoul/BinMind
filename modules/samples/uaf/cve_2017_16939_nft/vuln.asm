
C:\Users\Administrator\Desktop\BinMind\round2\samples\uaf\cve_2017_16939_nft\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 7f 86 00 00       	call   1400096a8 <fflush>
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
   1400010e8:	48 8b 05 61 f1 00 00 	mov    rax,QWORD PTR [rip+0xf161]        # 140010250 <__imp_Sleep>
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
   14000113b:	e8 18 85 00 00       	call   140009658 <_amsg_exit>
   140001140:	48 8b 05 29 a5 00 00 	mov    rax,QWORD PTR [rip+0xa529]        # 14000b670 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 18 a5 00 00 	mov    rax,QWORD PTR [rip+0xa518]        # 14000b670 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 18 7f 00 00       	call   140009080 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 67 85 00 00       	call   1400096e8 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 f7 84 00 00       	call   140009690 <abort>
   140001199:	e8 e2 11 00 00       	call   140002380 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 5b a5 00 00 	mov    rax,QWORD PTR [rip+0xa55b]        # 14000b700 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 99 f0 00 00 	mov    rax,QWORD PTR [rip+0xf099]        # 140010248 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 98 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa498]        # 14000b650 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 56 7e 00 00       	call   140009020 <_set_invalid_parameter_handler>
   1400011ca:	e8 c1 1a 00 00       	call   140002c90 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e de 00 00    	mov    DWORD PTR [rip+0xde3e],eax        # 14000f018 <managedapp>
   1400011da:	48 8b 05 2f a4 00 00 	mov    rax,QWORD PTR [rip+0xa42f]        # 14000b610 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 57 84 00 00       	call   140009648 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 4b 84 00 00       	call   140009648 <__set_app_type>
   1400011fd:	e8 ce 7c 00 00       	call   140008ed0 <__p__fmode>
   140001202:	48 8b 15 e7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4e7]        # 14000b6f0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 ce 7c 00 00       	call   140008ee0 <__p__commode>
   140001212:	48 8b 15 b7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4b7]        # 14000b6d0 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 3e 07 00 00       	call   140001960 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 23 84 00 00       	call   140009658 <_amsg_exit>
   140001235:	48 8b 05 24 a3 00 00 	mov    rax,QWORD PTR [rip+0xa324]        # 14000b560 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 c6 a4 00 00 	mov    rax,QWORD PTR [rip+0xa4c6]        # 14000b710 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 48 12 00 00       	call   14000249a <__mingw_setusermatherr>
   140001252:	48 8b 05 77 a3 00 00 	mov    rax,QWORD PTR [rip+0xa377]        # 14000b5d0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 f6 7d 00 00       	call   140009060 <_configthreadlocale>
   14000126a:	48 8b 15 4f a4 00 00 	mov    rdx,QWORD PTR [rip+0xa44f]        # 14000b6c0 <.refptr.__xi_z>
   140001271:	48 8b 05 38 a4 00 00 	mov    rax,QWORD PTR [rip+0xa438]        # 14000b6b0 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 f0 7b 00 00       	call   140008e70 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 ca 83 00 00       	call   140009658 <_amsg_exit>
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
   1400012cb:	e8 68 83 00 00       	call   140009638 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 75 83 00 00       	call   140009658 <_amsg_exit>
   1400012e3:	8b 05 1b dd 00 00    	mov    eax,DWORD PTR [rip+0xdd1b]        # 14000f004 <argc>
   1400012e9:	48 8d 15 18 dd 00 00 	lea    rdx,[rip+0xdd18]        # 14000f008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 4e 83 00 00       	call   140009658 <_amsg_exit>
   14000130a:	48 8b 15 8f a3 00 00 	mov    rdx,QWORD PTR [rip+0xa38f]        # 14000b6a0 <.refptr.__xc_z>
   140001311:	48 8b 05 78 a3 00 00 	mov    rax,QWORD PTR [rip+0xa378]        # 14000b690 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 50 83 00 00       	call   140009670 <_initterm>
   140001320:	e8 12 06 00 00       	call   140001937 <__main>
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
   14000138d:	e8 5e 7b 00 00       	call   140008ef0 <__p___initenv>
   140001392:	48 8b 15 77 dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc77]        # 14000f010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d dc 00 00 	mov    rcx,QWORD PTR [rip+0xdc6d]        # 14000f010 <envp>
   1400013a3:	48 8b 15 5e dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc5e]        # 14000f008 <argv>
   1400013aa:	8b 05 54 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc54]        # 14000f004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 d5 03 00 00       	call   14000178f <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc55]        # 14000f018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 cf 82 00 00       	call   1400096a0 <exit>
   1400013d1:	8b 05 45 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc45]        # 14000f01c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 80 82 00 00       	call   140009660 <_cexit>
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
   140001511:	e8 ba 81 00 00       	call   1400096d0 <malloc>
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
   14000155c:	e8 9f 81 00 00       	call   140009700 <strlen>
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
   140001585:	e8 46 81 00 00       	call   1400096d0 <malloc>
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
   1400015e8:	e8 eb 80 00 00       	call   1400096d8 <memcpy>
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
   140001642:	e8 41 80 00 00       	call   140009688 <_crt_atexit>
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
   140001682:	ff 15 90 eb 00 00    	call   QWORD PTR [rip+0xeb90]        # 140010218 <__imp_GetModuleHandleA>
   140001688:	48 89 c3             	mov    rbx,rax
   14000168b:	48 85 c0             	test   rax,rax
   14000168e:	74 70                	je     140001700 <__gcc_register_frame+0x90>
   140001690:	48 8d 0d 69 99 00 00 	lea    rcx,[rip+0x9969]        # 14000b000 <.rdata>
   140001697:	ff 15 9b eb 00 00    	call   QWORD PTR [rip+0xeb9b]        # 140010238 <__imp_LoadLibraryA>
   14000169d:	4c 8b 0d 7c eb 00 00 	mov    r9,QWORD PTR [rip+0xeb7c]        # 140010220 <__imp_GetProcAddress>
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
   14000174e:	48 ff 25 ab ea 00 00 	rex.W jmp QWORD PTR [rip+0xeaab]        # 140010200 <__imp_FreeLibrary>
   140001755:	0f 1f 00             	nop    DWORD PTR [rax]
   140001758:	48 83 c4 20          	add    rsp,0x20
   14000175c:	5d                   	pop    rbp
   14000175d:	c3                   	ret
   14000175e:	90                   	nop
   14000175f:	90                   	nop

0000000140001760 <nft_set_destroy>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 20          	sub    rsp,0x20
   140001768:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000176c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001770:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001774:	48 89 c1             	mov    rcx,rax
   140001777:	e8 44 7f 00 00       	call   1400096c0 <free>
   14000177c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001780:	48 89 c1             	mov    rcx,rax
   140001783:	e8 38 7f 00 00       	call   1400096c0 <free>
   140001788:	90                   	nop
   140001789:	48 83 c4 20          	add    rsp,0x20
   14000178d:	5d                   	pop    rbp
   14000178e:	c3                   	ret

000000014000178f <main>:
   14000178f:	55                   	push   rbp
   140001790:	48 89 e5             	mov    rbp,rsp
   140001793:	48 83 ec 30          	sub    rsp,0x30
   140001797:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000179a:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000179e:	e8 94 01 00 00       	call   140001937 <__main>
   1400017a3:	b9 20 00 00 00       	mov    ecx,0x20
   1400017a8:	e8 23 7f 00 00       	call   1400096d0 <malloc>
   1400017ad:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400017b1:	b9 40 00 00 00       	mov    ecx,0x40
   1400017b6:	e8 15 7f 00 00       	call   1400096d0 <malloc>
   1400017bb:	48 89 c2             	mov    rdx,rax
   1400017be:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017c2:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   1400017c6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017ca:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   1400017ce:	41 b8 40 00 00 00    	mov    r8d,0x40
   1400017d4:	ba 00 00 00 00       	mov    edx,0x0
   1400017d9:	48 89 c1             	mov    rcx,rax
   1400017dc:	e8 ff 7e 00 00       	call   1400096e0 <memset>
   1400017e1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017e5:	48 b9 62 6c 61 63 6b 	movabs rcx,0x73696c6b63616c62
   1400017ec:	6c 69 73 
   1400017ef:	48 89 08             	mov    QWORD PTR [rax],rcx
   1400017f2:	66 c7 40 08 74 00    	mov    WORD PTR [rax+0x8],0x74
   1400017f8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017fc:	c7 40 10 00 00 00 00 	mov    DWORD PTR [rax+0x10],0x0
   140001803:	b9 10 00 00 00       	mov    ecx,0x10
   140001808:	e8 c3 7e 00 00       	call   1400096d0 <malloc>
   14000180d:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001811:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001815:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001819:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000181c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001820:	c7 40 08 01 00 00 00 	mov    DWORD PTR [rax+0x8],0x1
   140001827:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000182b:	48 89 c1             	mov    rcx,rax
   14000182e:	e8 2d ff ff ff       	call   140001760 <nft_set_destroy>
   140001833:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001837:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000183a:	48 85 c0             	test   rax,rax
   14000183d:	74 27                	je     140001866 <main+0xd7>
   14000183f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001843:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001846:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140001849:	85 c0                	test   eax,eax
   14000184b:	75 19                	jne    140001866 <main+0xd7>
   14000184d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001851:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001854:	48 89 c2             	mov    rdx,rax
   140001857:	48 8d 05 f2 97 00 00 	lea    rax,[rip+0x97f2]        # 14000b050 <.rdata>
   14000185e:	48 89 c1             	mov    rcx,rax
   140001861:	e8 2a 19 00 00       	call   140003190 <__mingw_printf>
   140001866:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000186a:	48 89 c1             	mov    rcx,rax
   14000186d:	e8 4e 7e 00 00       	call   1400096c0 <free>
   140001872:	b8 00 00 00 00       	mov    eax,0x0
   140001877:	48 83 c4 30          	add    rsp,0x30
   14000187b:	5d                   	pop    rbp
   14000187c:	c3                   	ret
   14000187d:	90                   	nop
   14000187e:	90                   	nop
   14000187f:	90                   	nop

0000000140001880 <__do_global_dtors>:
   140001880:	55                   	push   rbp
   140001881:	48 89 e5             	mov    rbp,rsp
   140001884:	48 83 ec 20          	sub    rsp,0x20
   140001888:	eb 1e                	jmp    1400018a8 <__do_global_dtors+0x28>
   14000188a:	48 8b 05 7f 87 00 00 	mov    rax,QWORD PTR [rip+0x877f]        # 14000a010 <p.0>
   140001891:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001894:	ff d0                	call   rax
   140001896:	48 8b 05 73 87 00 00 	mov    rax,QWORD PTR [rip+0x8773]        # 14000a010 <p.0>
   14000189d:	48 83 c0 08          	add    rax,0x8
   1400018a1:	48 89 05 68 87 00 00 	mov    QWORD PTR [rip+0x8768],rax        # 14000a010 <p.0>
   1400018a8:	48 8b 05 61 87 00 00 	mov    rax,QWORD PTR [rip+0x8761]        # 14000a010 <p.0>
   1400018af:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018b2:	48 85 c0             	test   rax,rax
   1400018b5:	75 d3                	jne    14000188a <__do_global_dtors+0xa>
   1400018b7:	90                   	nop
   1400018b8:	90                   	nop
   1400018b9:	48 83 c4 20          	add    rsp,0x20
   1400018bd:	5d                   	pop    rbp
   1400018be:	c3                   	ret

00000001400018bf <__do_global_ctors>:
   1400018bf:	55                   	push   rbp
   1400018c0:	48 89 e5             	mov    rbp,rsp
   1400018c3:	48 83 ec 30          	sub    rsp,0x30
   1400018c7:	48 8b 05 a2 9c 00 00 	mov    rax,QWORD PTR [rip+0x9ca2]        # 14000b570 <.refptr.__CTOR_LIST__>
   1400018ce:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018d1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400018d4:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   1400018d8:	75 25                	jne    1400018ff <__do_global_ctors+0x40>
   1400018da:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400018e1:	eb 04                	jmp    1400018e7 <__do_global_ctors+0x28>
   1400018e3:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400018e7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400018ea:	8d 50 01             	lea    edx,[rax+0x1]
   1400018ed:	48 8b 05 7c 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c7c]        # 14000b570 <.refptr.__CTOR_LIST__>
   1400018f4:	89 d2                	mov    edx,edx
   1400018f6:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   1400018fa:	48 85 c0             	test   rax,rax
   1400018fd:	75 e4                	jne    1400018e3 <__do_global_ctors+0x24>
   1400018ff:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001902:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001905:	eb 14                	jmp    14000191b <__do_global_ctors+0x5c>
   140001907:	48 8b 05 62 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c62]        # 14000b570 <.refptr.__CTOR_LIST__>
   14000190e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001911:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001915:	ff d0                	call   rax
   140001917:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000191b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000191f:	75 e6                	jne    140001907 <__do_global_ctors+0x48>
   140001921:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 140001880 <__do_global_dtors>
   140001928:	48 89 c1             	mov    rcx,rax
   14000192b:	e8 ff fc ff ff       	call   14000162f <atexit>
   140001930:	90                   	nop
   140001931:	48 83 c4 30          	add    rsp,0x30
   140001935:	5d                   	pop    rbp
   140001936:	c3                   	ret

0000000140001937 <__main>:
   140001937:	55                   	push   rbp
   140001938:	48 89 e5             	mov    rbp,rsp
   14000193b:	48 83 ec 20          	sub    rsp,0x20
   14000193f:	8b 05 3b d7 00 00    	mov    eax,DWORD PTR [rip+0xd73b]        # 14000f080 <initialized>
   140001945:	85 c0                	test   eax,eax
   140001947:	75 0f                	jne    140001958 <__main+0x21>
   140001949:	c7 05 2d d7 00 00 01 	mov    DWORD PTR [rip+0xd72d],0x1        # 14000f080 <initialized>
   140001950:	00 00 00 
   140001953:	e8 67 ff ff ff       	call   1400018bf <__do_global_ctors>
   140001958:	90                   	nop
   140001959:	48 83 c4 20          	add    rsp,0x20
   14000195d:	5d                   	pop    rbp
   14000195e:	c3                   	ret
   14000195f:	90                   	nop

0000000140001960 <_setargv>:
   140001960:	55                   	push   rbp
   140001961:	48 89 e5             	mov    rbp,rsp
   140001964:	b8 00 00 00 00       	mov    eax,0x0
   140001969:	5d                   	pop    rbp
   14000196a:	c3                   	ret
   14000196b:	90                   	nop
   14000196c:	90                   	nop
   14000196d:	90                   	nop
   14000196e:	90                   	nop
   14000196f:	90                   	nop

0000000140001970 <__dyn_tls_init>:
   140001970:	55                   	push   rbp
   140001971:	48 89 e5             	mov    rbp,rsp
   140001974:	48 83 ec 30          	sub    rsp,0x30
   140001978:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000197c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000197f:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001983:	48 8b 05 c6 9b 00 00 	mov    rax,QWORD PTR [rip+0x9bc6]        # 14000b550 <.refptr._CRT_MT>
   14000198a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000198c:	83 f8 02             	cmp    eax,0x2
   14000198f:	74 0d                	je     14000199e <__dyn_tls_init+0x2e>
   140001991:	48 8b 05 b8 9b 00 00 	mov    rax,QWORD PTR [rip+0x9bb8]        # 14000b550 <.refptr._CRT_MT>
   140001998:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   14000199e:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   1400019a2:	74 1e                	je     1400019c2 <__dyn_tls_init+0x52>
   1400019a4:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   1400019a8:	75 5b                	jne    140001a05 <__dyn_tls_init+0x95>
   1400019aa:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400019ae:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   1400019b1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400019b5:	49 89 c8             	mov    r8,rcx
   1400019b8:	48 89 c1             	mov    rcx,rax
   1400019bb:	e8 d1 11 00 00       	call   140002b91 <__mingw_TLScallback>
   1400019c0:	eb 43                	jmp    140001a05 <__dyn_tls_init+0x95>
   1400019c2:	48 8d 05 0f 9f 00 00 	lea    rax,[rip+0x9f0f]        # 14000b8d8 <___crt_xd_start__>
   1400019c9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400019cd:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400019d2:	eb 22                	jmp    1400019f6 <__dyn_tls_init+0x86>
   1400019d4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400019d8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400019dc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400019e0:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019e3:	48 85 c0             	test   rax,rax
   1400019e6:	74 09                	je     1400019f1 <__dyn_tls_init+0x81>
   1400019e8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400019ec:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400019ef:	ff d0                	call   rax
   1400019f1:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   1400019f6:	48 8d 05 e3 9e 00 00 	lea    rax,[rip+0x9ee3]        # 14000b8e0 <__xd_z>
   1400019fd:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001a01:	75 d1                	jne    1400019d4 <__dyn_tls_init+0x64>
   140001a03:	eb 01                	jmp    140001a06 <__dyn_tls_init+0x96>
   140001a05:	90                   	nop
   140001a06:	48 83 c4 30          	add    rsp,0x30
   140001a0a:	5d                   	pop    rbp
   140001a0b:	c3                   	ret

0000000140001a0c <__tlregdtor>:
   140001a0c:	55                   	push   rbp
   140001a0d:	48 89 e5             	mov    rbp,rsp
   140001a10:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a14:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001a19:	75 07                	jne    140001a22 <__tlregdtor+0x16>
   140001a1b:	b8 00 00 00 00       	mov    eax,0x0
   140001a20:	eb 05                	jmp    140001a27 <__tlregdtor+0x1b>
   140001a22:	b8 00 00 00 00       	mov    eax,0x0
   140001a27:	5d                   	pop    rbp
   140001a28:	c3                   	ret

0000000140001a29 <__dyn_tls_dtor>:
   140001a29:	55                   	push   rbp
   140001a2a:	48 89 e5             	mov    rbp,rsp
   140001a2d:	48 83 ec 20          	sub    rsp,0x20
   140001a31:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a35:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001a38:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001a3c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001a40:	74 06                	je     140001a48 <__dyn_tls_dtor+0x1f>
   140001a42:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001a46:	75 18                	jne    140001a60 <__dyn_tls_dtor+0x37>
   140001a48:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001a4c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001a4f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001a53:	49 89 c8             	mov    r8,rcx
   140001a56:	48 89 c1             	mov    rcx,rax
   140001a59:	e8 33 11 00 00       	call   140002b91 <__mingw_TLScallback>
   140001a5e:	eb 01                	jmp    140001a61 <__dyn_tls_dtor+0x38>
   140001a60:	90                   	nop
   140001a61:	48 83 c4 20          	add    rsp,0x20
   140001a65:	5d                   	pop    rbp
   140001a66:	c3                   	ret
   140001a67:	90                   	nop
   140001a68:	90                   	nop
   140001a69:	90                   	nop
   140001a6a:	90                   	nop
   140001a6b:	90                   	nop
   140001a6c:	90                   	nop
   140001a6d:	90                   	nop
   140001a6e:	90                   	nop
   140001a6f:	90                   	nop

0000000140001a70 <_matherr>:
   140001a70:	55                   	push   rbp
   140001a71:	53                   	push   rbx
   140001a72:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001a79:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001a7e:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001a82:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001a86:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001a8b:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001a8f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001a93:	8b 00                	mov    eax,DWORD PTR [rax]
   140001a95:	83 f8 06             	cmp    eax,0x6
   140001a98:	74 56                	je     140001af0 <_matherr+0x80>
   140001a9a:	83 f8 06             	cmp    eax,0x6
   140001a9d:	7f 78                	jg     140001b17 <_matherr+0xa7>
   140001a9f:	83 f8 05             	cmp    eax,0x5
   140001aa2:	74 59                	je     140001afd <_matherr+0x8d>
   140001aa4:	83 f8 05             	cmp    eax,0x5
   140001aa7:	7f 6e                	jg     140001b17 <_matherr+0xa7>
   140001aa9:	83 f8 04             	cmp    eax,0x4
   140001aac:	74 5c                	je     140001b0a <_matherr+0x9a>
   140001aae:	83 f8 04             	cmp    eax,0x4
   140001ab1:	7f 64                	jg     140001b17 <_matherr+0xa7>
   140001ab3:	83 f8 03             	cmp    eax,0x3
   140001ab6:	74 2b                	je     140001ae3 <_matherr+0x73>
   140001ab8:	83 f8 03             	cmp    eax,0x3
   140001abb:	7f 5a                	jg     140001b17 <_matherr+0xa7>
   140001abd:	83 f8 01             	cmp    eax,0x1
   140001ac0:	74 07                	je     140001ac9 <_matherr+0x59>
   140001ac2:	83 f8 02             	cmp    eax,0x2
   140001ac5:	74 0f                	je     140001ad6 <_matherr+0x66>
   140001ac7:	eb 4e                	jmp    140001b17 <_matherr+0xa7>
   140001ac9:	48 8d 05 d0 95 00 00 	lea    rax,[rip+0x95d0]        # 14000b0a0 <.rdata>
   140001ad0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ad4:	eb 4d                	jmp    140001b23 <_matherr+0xb3>
   140001ad6:	48 8d 05 e2 95 00 00 	lea    rax,[rip+0x95e2]        # 14000b0bf <.rdata+0x1f>
   140001add:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001ae1:	eb 40                	jmp    140001b23 <_matherr+0xb3>
   140001ae3:	48 8d 05 f6 95 00 00 	lea    rax,[rip+0x95f6]        # 14000b0e0 <.rdata+0x40>
   140001aea:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001aee:	eb 33                	jmp    140001b23 <_matherr+0xb3>
   140001af0:	48 8d 05 09 96 00 00 	lea    rax,[rip+0x9609]        # 14000b100 <.rdata+0x60>
   140001af7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001afb:	eb 26                	jmp    140001b23 <_matherr+0xb3>
   140001afd:	48 8d 05 24 96 00 00 	lea    rax,[rip+0x9624]        # 14000b128 <.rdata+0x88>
   140001b04:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b08:	eb 19                	jmp    140001b23 <_matherr+0xb3>
   140001b0a:	48 8d 05 3f 96 00 00 	lea    rax,[rip+0x963f]        # 14000b150 <.rdata+0xb0>
   140001b11:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b15:	eb 0c                	jmp    140001b23 <_matherr+0xb3>
   140001b17:	48 8d 05 68 96 00 00 	lea    rax,[rip+0x9668]        # 14000b186 <.rdata+0xe6>
   140001b1e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b22:	90                   	nop
   140001b23:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b27:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001b2d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b31:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001b36:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b3a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001b3f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b43:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001b47:	b9 02 00 00 00       	mov    ecx,0x2
   140001b4c:	e8 2f 75 00 00       	call   140009080 <__acrt_iob_func>
   140001b51:	48 89 c1             	mov    rcx,rax
   140001b54:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001b58:	48 8d 05 39 96 00 00 	lea    rax,[rip+0x9639]        # 14000b198 <.rdata+0xf8>
   140001b5f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001b66:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001b6c:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001b72:	49 89 d9             	mov    r9,rbx
   140001b75:	49 89 d0             	mov    r8,rdx
   140001b78:	48 89 c2             	mov    rdx,rax
   140001b7b:	e8 30 7b 00 00       	call   1400096b0 <fprintf>
   140001b80:	b8 00 00 00 00       	mov    eax,0x0
   140001b85:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001b89:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001b8d:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001b92:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001b99:	5b                   	pop    rbx
   140001b9a:	5d                   	pop    rbp
   140001b9b:	c3                   	ret
   140001b9c:	90                   	nop
   140001b9d:	90                   	nop
   140001b9e:	90                   	nop
   140001b9f:	90                   	nop

0000000140001ba0 <__report_error>:
   140001ba0:	55                   	push   rbp
   140001ba1:	53                   	push   rbx
   140001ba2:	48 83 ec 38          	sub    rsp,0x38
   140001ba6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001bab:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001baf:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001bb3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001bb7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001bbb:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001bbf:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001bc3:	b9 02 00 00 00       	mov    ecx,0x2
   140001bc8:	e8 b3 74 00 00       	call   140009080 <__acrt_iob_func>
   140001bcd:	48 89 c1             	mov    rcx,rax
   140001bd0:	48 8d 05 f9 95 00 00 	lea    rax,[rip+0x95f9]        # 14000b1d0 <.rdata>
   140001bd7:	48 89 c2             	mov    rdx,rax
   140001bda:	e8 d1 7a 00 00       	call   1400096b0 <fprintf>
   140001bdf:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001be3:	b9 02 00 00 00       	mov    ecx,0x2
   140001be8:	e8 93 74 00 00       	call   140009080 <__acrt_iob_func>
   140001bed:	48 89 c1             	mov    rcx,rax
   140001bf0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001bf4:	49 89 d8             	mov    r8,rbx
   140001bf7:	48 89 c2             	mov    rdx,rax
   140001bfa:	e8 11 7b 00 00       	call   140009710 <vfprintf>
   140001bff:	e8 8c 7a 00 00       	call   140009690 <abort>
   140001c04:	90                   	nop

0000000140001c05 <mark_section_writable>:
   140001c05:	55                   	push   rbp
   140001c06:	48 89 e5             	mov    rbp,rsp
   140001c09:	48 83 ec 60          	sub    rsp,0x60
   140001c0d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001c11:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001c18:	e9 82 00 00 00       	jmp    140001c9f <mark_section_writable+0x9a>
   140001c1d:	48 8b 0d bc d4 00 00 	mov    rcx,QWORD PTR [rip+0xd4bc]        # 14000f0e0 <the_secs>
   140001c24:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c27:	48 63 d0             	movsxd rdx,eax
   140001c2a:	48 89 d0             	mov    rax,rdx
   140001c2d:	48 c1 e0 02          	shl    rax,0x2
   140001c31:	48 01 d0             	add    rax,rdx
   140001c34:	48 c1 e0 03          	shl    rax,0x3
   140001c38:	48 01 c8             	add    rax,rcx
   140001c3b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001c3f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c43:	72 56                	jb     140001c9b <mark_section_writable+0x96>
   140001c45:	48 8b 0d 94 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd494]        # 14000f0e0 <the_secs>
   140001c4c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c4f:	48 63 d0             	movsxd rdx,eax
   140001c52:	48 89 d0             	mov    rax,rdx
   140001c55:	48 c1 e0 02          	shl    rax,0x2
   140001c59:	48 01 d0             	add    rax,rdx
   140001c5c:	48 c1 e0 03          	shl    rax,0x3
   140001c60:	48 01 c8             	add    rax,rcx
   140001c63:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001c67:	4c 8b 05 72 d4 00 00 	mov    r8,QWORD PTR [rip+0xd472]        # 14000f0e0 <the_secs>
   140001c6e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c71:	48 63 d0             	movsxd rdx,eax
   140001c74:	48 89 d0             	mov    rax,rdx
   140001c77:	48 c1 e0 02          	shl    rax,0x2
   140001c7b:	48 01 d0             	add    rax,rdx
   140001c7e:	48 c1 e0 03          	shl    rax,0x3
   140001c82:	4c 01 c0             	add    rax,r8
   140001c85:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001c89:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001c8c:	89 c0                	mov    eax,eax
   140001c8e:	48 01 c8             	add    rax,rcx
   140001c91:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c95:	0f 82 41 02 00 00    	jb     140001edc <mark_section_writable+0x2d7>
   140001c9b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001c9f:	8b 05 43 d4 00 00    	mov    eax,DWORD PTR [rip+0xd443]        # 14000f0e8 <maxSections>
   140001ca5:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001ca8:	0f 8c 6f ff ff ff    	jl     140001c1d <mark_section_writable+0x18>
   140001cae:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001cb2:	48 89 c1             	mov    rcx,rax
   140001cb5:	e8 c1 11 00 00       	call   140002e7b <__mingw_GetSectionForAddress>
   140001cba:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001cbe:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001cc3:	75 13                	jne    140001cd8 <mark_section_writable+0xd3>
   140001cc5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001cc9:	48 8d 0d 20 95 00 00 	lea    rcx,[rip+0x9520]        # 14000b1f0 <.rdata+0x20>
   140001cd0:	48 89 c2             	mov    rdx,rax
   140001cd3:	e8 c8 fe ff ff       	call   140001ba0 <__report_error>
   140001cd8:	48 8b 0d 01 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd401]        # 14000f0e0 <the_secs>
   140001cdf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ce2:	48 63 d0             	movsxd rdx,eax
   140001ce5:	48 89 d0             	mov    rax,rdx
   140001ce8:	48 c1 e0 02          	shl    rax,0x2
   140001cec:	48 01 d0             	add    rax,rdx
   140001cef:	48 c1 e0 03          	shl    rax,0x3
   140001cf3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001cf7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001cfb:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001cff:	48 8b 0d da d3 00 00 	mov    rcx,QWORD PTR [rip+0xd3da]        # 14000f0e0 <the_secs>
   140001d06:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d09:	48 63 d0             	movsxd rdx,eax
   140001d0c:	48 89 d0             	mov    rax,rdx
   140001d0f:	48 c1 e0 02          	shl    rax,0x2
   140001d13:	48 01 d0             	add    rax,rdx
   140001d16:	48 c1 e0 03          	shl    rax,0x3
   140001d1a:	48 01 c8             	add    rax,rcx
   140001d1d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001d23:	e8 9f 12 00 00       	call   140002fc7 <_GetPEImageBase>
   140001d28:	48 89 c1             	mov    rcx,rax
   140001d2b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d2f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001d32:	41 89 c1             	mov    r9d,eax
   140001d35:	4c 8b 05 a4 d3 00 00 	mov    r8,QWORD PTR [rip+0xd3a4]        # 14000f0e0 <the_secs>
   140001d3c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d3f:	48 63 d0             	movsxd rdx,eax
   140001d42:	48 89 d0             	mov    rax,rdx
   140001d45:	48 c1 e0 02          	shl    rax,0x2
   140001d49:	48 01 d0             	add    rax,rdx
   140001d4c:	48 c1 e0 03          	shl    rax,0x3
   140001d50:	4c 01 c0             	add    rax,r8
   140001d53:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001d57:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001d5b:	48 8b 0d 7e d3 00 00 	mov    rcx,QWORD PTR [rip+0xd37e]        # 14000f0e0 <the_secs>
   140001d62:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d65:	48 63 d0             	movsxd rdx,eax
   140001d68:	48 89 d0             	mov    rax,rdx
   140001d6b:	48 c1 e0 02          	shl    rax,0x2
   140001d6f:	48 01 d0             	add    rax,rdx
   140001d72:	48 c1 e0 03          	shl    rax,0x3
   140001d76:	48 01 c8             	add    rax,rcx
   140001d79:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001d7d:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001d81:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001d87:	48 89 c1             	mov    rcx,rax
   140001d8a:	48 8b 05 d7 e4 00 00 	mov    rax,QWORD PTR [rip+0xe4d7]        # 140010268 <__imp_VirtualQuery>
   140001d91:	ff d0                	call   rax
   140001d93:	48 85 c0             	test   rax,rax
   140001d96:	75 3f                	jne    140001dd7 <mark_section_writable+0x1d2>
   140001d98:	48 8b 0d 41 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd341]        # 14000f0e0 <the_secs>
   140001d9f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001da2:	48 63 d0             	movsxd rdx,eax
   140001da5:	48 89 d0             	mov    rax,rdx
   140001da8:	48 c1 e0 02          	shl    rax,0x2
   140001dac:	48 01 d0             	add    rax,rdx
   140001daf:	48 c1 e0 03          	shl    rax,0x3
   140001db3:	48 01 c8             	add    rax,rcx
   140001db6:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001dba:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001dbe:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001dc1:	89 c1                	mov    ecx,eax
   140001dc3:	48 8d 05 46 94 00 00 	lea    rax,[rip+0x9446]        # 14000b210 <.rdata+0x40>
   140001dca:	49 89 d0             	mov    r8,rdx
   140001dcd:	89 ca                	mov    edx,ecx
   140001dcf:	48 89 c1             	mov    rcx,rax
   140001dd2:	e8 c9 fd ff ff       	call   140001ba0 <__report_error>
   140001dd7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001dda:	83 f8 40             	cmp    eax,0x40
   140001ddd:	0f 84 e8 00 00 00    	je     140001ecb <mark_section_writable+0x2c6>
   140001de3:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001de6:	83 f8 04             	cmp    eax,0x4
   140001de9:	0f 84 dc 00 00 00    	je     140001ecb <mark_section_writable+0x2c6>
   140001def:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001df2:	3d 80 00 00 00       	cmp    eax,0x80
   140001df7:	0f 84 ce 00 00 00    	je     140001ecb <mark_section_writable+0x2c6>
   140001dfd:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e00:	83 f8 08             	cmp    eax,0x8
   140001e03:	0f 84 c2 00 00 00    	je     140001ecb <mark_section_writable+0x2c6>
   140001e09:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e0c:	83 f8 02             	cmp    eax,0x2
   140001e0f:	75 09                	jne    140001e1a <mark_section_writable+0x215>
   140001e11:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001e18:	eb 07                	jmp    140001e21 <mark_section_writable+0x21c>
   140001e1a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001e21:	48 8b 0d b8 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd2b8]        # 14000f0e0 <the_secs>
   140001e28:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e2b:	48 63 d0             	movsxd rdx,eax
   140001e2e:	48 89 d0             	mov    rax,rdx
   140001e31:	48 c1 e0 02          	shl    rax,0x2
   140001e35:	48 01 d0             	add    rax,rdx
   140001e38:	48 c1 e0 03          	shl    rax,0x3
   140001e3c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e40:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e44:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001e48:	48 8b 0d 91 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd291]        # 14000f0e0 <the_secs>
   140001e4f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e52:	48 63 d0             	movsxd rdx,eax
   140001e55:	48 89 d0             	mov    rax,rdx
   140001e58:	48 c1 e0 02          	shl    rax,0x2
   140001e5c:	48 01 d0             	add    rax,rdx
   140001e5f:	48 c1 e0 03          	shl    rax,0x3
   140001e63:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e67:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001e6b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001e6f:	48 8b 0d 6a d2 00 00 	mov    rcx,QWORD PTR [rip+0xd26a]        # 14000f0e0 <the_secs>
   140001e76:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e79:	48 63 d0             	movsxd rdx,eax
   140001e7c:	48 89 d0             	mov    rax,rdx
   140001e7f:	48 c1 e0 02          	shl    rax,0x2
   140001e83:	48 01 d0             	add    rax,rdx
   140001e86:	48 c1 e0 03          	shl    rax,0x3
   140001e8a:	48 01 c8             	add    rax,rcx
   140001e8d:	49 89 c0             	mov    r8,rax
   140001e90:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001e94:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e98:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001e9b:	4d 89 c1             	mov    r9,r8
   140001e9e:	41 89 c8             	mov    r8d,ecx
   140001ea1:	48 89 c1             	mov    rcx,rax
   140001ea4:	48 8b 05 b5 e3 00 00 	mov    rax,QWORD PTR [rip+0xe3b5]        # 140010260 <__imp_VirtualProtect>
   140001eab:	ff d0                	call   rax
   140001ead:	85 c0                	test   eax,eax
   140001eaf:	75 1a                	jne    140001ecb <mark_section_writable+0x2c6>
   140001eb1:	48 8b 05 58 e3 00 00 	mov    rax,QWORD PTR [rip+0xe358]        # 140010210 <__imp_GetLastError>
   140001eb8:	ff d0                	call   rax
   140001eba:	89 c2                	mov    edx,eax
   140001ebc:	48 8d 05 85 93 00 00 	lea    rax,[rip+0x9385]        # 14000b248 <.rdata+0x78>
   140001ec3:	48 89 c1             	mov    rcx,rax
   140001ec6:	e8 d5 fc ff ff       	call   140001ba0 <__report_error>
   140001ecb:	8b 05 17 d2 00 00    	mov    eax,DWORD PTR [rip+0xd217]        # 14000f0e8 <maxSections>
   140001ed1:	83 c0 01             	add    eax,0x1
   140001ed4:	89 05 0e d2 00 00    	mov    DWORD PTR [rip+0xd20e],eax        # 14000f0e8 <maxSections>
   140001eda:	eb 01                	jmp    140001edd <mark_section_writable+0x2d8>
   140001edc:	90                   	nop
   140001edd:	48 83 c4 60          	add    rsp,0x60
   140001ee1:	5d                   	pop    rbp
   140001ee2:	c3                   	ret

0000000140001ee3 <restore_modified_sections>:
   140001ee3:	55                   	push   rbp
   140001ee4:	48 89 e5             	mov    rbp,rsp
   140001ee7:	48 83 ec 30          	sub    rsp,0x30
   140001eeb:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001ef2:	e9 ad 00 00 00       	jmp    140001fa4 <restore_modified_sections+0xc1>
   140001ef7:	48 8b 0d e2 d1 00 00 	mov    rcx,QWORD PTR [rip+0xd1e2]        # 14000f0e0 <the_secs>
   140001efe:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f01:	48 63 d0             	movsxd rdx,eax
   140001f04:	48 89 d0             	mov    rax,rdx
   140001f07:	48 c1 e0 02          	shl    rax,0x2
   140001f0b:	48 01 d0             	add    rax,rdx
   140001f0e:	48 c1 e0 03          	shl    rax,0x3
   140001f12:	48 01 c8             	add    rax,rcx
   140001f15:	8b 00                	mov    eax,DWORD PTR [rax]
   140001f17:	85 c0                	test   eax,eax
   140001f19:	0f 84 80 00 00 00    	je     140001f9f <restore_modified_sections+0xbc>
   140001f1f:	48 8b 0d ba d1 00 00 	mov    rcx,QWORD PTR [rip+0xd1ba]        # 14000f0e0 <the_secs>
   140001f26:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f29:	48 63 d0             	movsxd rdx,eax
   140001f2c:	48 89 d0             	mov    rax,rdx
   140001f2f:	48 c1 e0 02          	shl    rax,0x2
   140001f33:	48 01 d0             	add    rax,rdx
   140001f36:	48 c1 e0 03          	shl    rax,0x3
   140001f3a:	48 01 c8             	add    rax,rcx
   140001f3d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001f40:	48 8b 0d 99 d1 00 00 	mov    rcx,QWORD PTR [rip+0xd199]        # 14000f0e0 <the_secs>
   140001f47:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f4a:	48 63 d0             	movsxd rdx,eax
   140001f4d:	48 89 d0             	mov    rax,rdx
   140001f50:	48 c1 e0 02          	shl    rax,0x2
   140001f54:	48 01 d0             	add    rax,rdx
   140001f57:	48 c1 e0 03          	shl    rax,0x3
   140001f5b:	48 01 c8             	add    rax,rcx
   140001f5e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001f62:	4c 8b 05 77 d1 00 00 	mov    r8,QWORD PTR [rip+0xd177]        # 14000f0e0 <the_secs>
   140001f69:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f6c:	48 63 d0             	movsxd rdx,eax
   140001f6f:	48 89 d0             	mov    rax,rdx
   140001f72:	48 c1 e0 02          	shl    rax,0x2
   140001f76:	48 01 d0             	add    rax,rdx
   140001f79:	48 c1 e0 03          	shl    rax,0x3
   140001f7d:	4c 01 c0             	add    rax,r8
   140001f80:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001f84:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001f88:	49 89 d1             	mov    r9,rdx
   140001f8b:	45 89 d0             	mov    r8d,r10d
   140001f8e:	48 89 ca             	mov    rdx,rcx
   140001f91:	48 89 c1             	mov    rcx,rax
   140001f94:	48 8b 05 c5 e2 00 00 	mov    rax,QWORD PTR [rip+0xe2c5]        # 140010260 <__imp_VirtualProtect>
   140001f9b:	ff d0                	call   rax
   140001f9d:	eb 01                	jmp    140001fa0 <restore_modified_sections+0xbd>
   140001f9f:	90                   	nop
   140001fa0:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001fa4:	8b 05 3e d1 00 00    	mov    eax,DWORD PTR [rip+0xd13e]        # 14000f0e8 <maxSections>
   140001faa:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001fad:	0f 8c 44 ff ff ff    	jl     140001ef7 <restore_modified_sections+0x14>
   140001fb3:	90                   	nop
   140001fb4:	90                   	nop
   140001fb5:	48 83 c4 30          	add    rsp,0x30
   140001fb9:	5d                   	pop    rbp
   140001fba:	c3                   	ret

0000000140001fbb <__write_memory>:
   140001fbb:	55                   	push   rbp
   140001fbc:	48 89 e5             	mov    rbp,rsp
   140001fbf:	48 83 ec 20          	sub    rsp,0x20
   140001fc3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001fc7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001fcb:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001fcf:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140001fd4:	74 25                	je     140001ffb <__write_memory+0x40>
   140001fd6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fda:	48 89 c1             	mov    rcx,rax
   140001fdd:	e8 23 fc ff ff       	call   140001c05 <mark_section_writable>
   140001fe2:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001fe6:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140001fea:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001fee:	49 89 c8             	mov    r8,rcx
   140001ff1:	48 89 c1             	mov    rcx,rax
   140001ff4:	e8 df 76 00 00       	call   1400096d8 <memcpy>
   140001ff9:	eb 01                	jmp    140001ffc <__write_memory+0x41>
   140001ffb:	90                   	nop
   140001ffc:	48 83 c4 20          	add    rsp,0x20
   140002000:	5d                   	pop    rbp
   140002001:	c3                   	ret

0000000140002002 <do_pseudo_reloc>:
   140002002:	55                   	push   rbp
   140002003:	48 89 e5             	mov    rbp,rsp
   140002006:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   14000200a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000200e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002012:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002016:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000201a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   14000201e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002022:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002026:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000202a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   14000202f:	0f 8e 44 03 00 00    	jle    140002379 <do_pseudo_reloc+0x377>
   140002035:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   14000203a:	7e 25                	jle    140002061 <do_pseudo_reloc+0x5f>
   14000203c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002040:	8b 00                	mov    eax,DWORD PTR [rax]
   140002042:	85 c0                	test   eax,eax
   140002044:	75 1b                	jne    140002061 <do_pseudo_reloc+0x5f>
   140002046:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000204a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000204d:	85 c0                	test   eax,eax
   14000204f:	75 10                	jne    140002061 <do_pseudo_reloc+0x5f>
   140002051:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002055:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002058:	85 c0                	test   eax,eax
   14000205a:	75 05                	jne    140002061 <do_pseudo_reloc+0x5f>
   14000205c:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   140002061:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002065:	8b 00                	mov    eax,DWORD PTR [rax]
   140002067:	85 c0                	test   eax,eax
   140002069:	75 0b                	jne    140002076 <do_pseudo_reloc+0x74>
   14000206b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000206f:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002072:	85 c0                	test   eax,eax
   140002074:	74 59                	je     1400020cf <do_pseudo_reloc+0xcd>
   140002076:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000207a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000207e:	eb 40                	jmp    1400020c0 <do_pseudo_reloc+0xbe>
   140002080:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002084:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002087:	89 c2                	mov    edx,eax
   140002089:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000208d:	48 01 d0             	add    rax,rdx
   140002090:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002094:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002098:	8b 10                	mov    edx,DWORD PTR [rax]
   14000209a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000209e:	8b 00                	mov    eax,DWORD PTR [rax]
   1400020a0:	01 d0                	add    eax,edx
   1400020a2:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   1400020a5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020a9:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   1400020ad:	41 b8 04 00 00 00    	mov    r8d,0x4
   1400020b3:	48 89 c1             	mov    rcx,rax
   1400020b6:	e8 00 ff ff ff       	call   140001fbb <__write_memory>
   1400020bb:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   1400020c0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020c4:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400020c8:	72 b6                	jb     140002080 <do_pseudo_reloc+0x7e>
   1400020ca:	e9 ab 02 00 00       	jmp    14000237a <do_pseudo_reloc+0x378>
   1400020cf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020d3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020d6:	83 f8 01             	cmp    eax,0x1
   1400020d9:	74 18                	je     1400020f3 <do_pseudo_reloc+0xf1>
   1400020db:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020df:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020e2:	89 c2                	mov    edx,eax
   1400020e4:	48 8d 05 85 91 00 00 	lea    rax,[rip+0x9185]        # 14000b270 <.rdata+0xa0>
   1400020eb:	48 89 c1             	mov    rcx,rax
   1400020ee:	e8 ad fa ff ff       	call   140001ba0 <__report_error>
   1400020f3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020f7:	48 83 c0 0c          	add    rax,0xc
   1400020fb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400020ff:	e9 65 02 00 00       	jmp    140002369 <do_pseudo_reloc+0x367>
   140002104:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002108:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000210b:	89 c2                	mov    edx,eax
   14000210d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002111:	48 01 d0             	add    rax,rdx
   140002114:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002118:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000211c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000211e:	89 c2                	mov    edx,eax
   140002120:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002124:	48 01 d0             	add    rax,rdx
   140002127:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000212b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000212f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002132:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002136:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000213a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000213d:	0f b6 c0             	movzx  eax,al
   140002140:	83 f8 40             	cmp    eax,0x40
   140002143:	0f 84 b6 00 00 00    	je     1400021ff <do_pseudo_reloc+0x1fd>
   140002149:	83 f8 40             	cmp    eax,0x40
   14000214c:	0f 87 ba 00 00 00    	ja     14000220c <do_pseudo_reloc+0x20a>
   140002152:	83 f8 20             	cmp    eax,0x20
   140002155:	74 77                	je     1400021ce <do_pseudo_reloc+0x1cc>
   140002157:	83 f8 20             	cmp    eax,0x20
   14000215a:	0f 87 ac 00 00 00    	ja     14000220c <do_pseudo_reloc+0x20a>
   140002160:	83 f8 08             	cmp    eax,0x8
   140002163:	74 0a                	je     14000216f <do_pseudo_reloc+0x16d>
   140002165:	83 f8 10             	cmp    eax,0x10
   140002168:	74 38                	je     1400021a2 <do_pseudo_reloc+0x1a0>
   14000216a:	e9 9d 00 00 00       	jmp    14000220c <do_pseudo_reloc+0x20a>
   14000216f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002173:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140002176:	0f b6 c0             	movzx  eax,al
   140002179:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000217d:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002181:	25 80 00 00 00       	and    eax,0x80
   140002186:	48 85 c0             	test   rax,rax
   140002189:	0f 84 9d 00 00 00    	je     14000222c <do_pseudo_reloc+0x22a>
   14000218f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002193:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   140002199:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000219d:	e9 8a 00 00 00       	jmp    14000222c <do_pseudo_reloc+0x22a>
   1400021a2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021a6:	0f b7 00             	movzx  eax,WORD PTR [rax]
   1400021a9:	0f b7 c0             	movzx  eax,ax
   1400021ac:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021b0:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021b4:	25 00 80 00 00       	and    eax,0x8000
   1400021b9:	48 85 c0             	test   rax,rax
   1400021bc:	74 71                	je     14000222f <do_pseudo_reloc+0x22d>
   1400021be:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021c2:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   1400021c8:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021cc:	eb 61                	jmp    14000222f <do_pseudo_reloc+0x22d>
   1400021ce:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021d2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400021d4:	89 c0                	mov    eax,eax
   1400021d6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021da:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021de:	25 00 00 00 80       	and    eax,0x80000000
   1400021e3:	48 85 c0             	test   rax,rax
   1400021e6:	74 4a                	je     140002232 <do_pseudo_reloc+0x230>
   1400021e8:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021ec:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   1400021f3:	ff ff ff 
   1400021f6:	48 09 d0             	or     rax,rdx
   1400021f9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021fd:	eb 33                	jmp    140002232 <do_pseudo_reloc+0x230>
   1400021ff:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002203:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002206:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000220a:	eb 27                	jmp    140002233 <do_pseudo_reloc+0x231>
   14000220c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002213:	00 
   140002214:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002218:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000221b:	0f b6 c0             	movzx  eax,al
   14000221e:	48 8d 0d 83 90 00 00 	lea    rcx,[rip+0x9083]        # 14000b2a8 <.rdata+0xd8>
   140002225:	89 c2                	mov    edx,eax
   140002227:	e8 74 f9 ff ff       	call   140001ba0 <__report_error>
   14000222c:	90                   	nop
   14000222d:	eb 04                	jmp    140002233 <do_pseudo_reloc+0x231>
   14000222f:	90                   	nop
   140002230:	eb 01                	jmp    140002233 <do_pseudo_reloc+0x231>
   140002232:	90                   	nop
   140002233:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002237:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000223b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000223d:	89 c2                	mov    edx,eax
   14000223f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002243:	48 01 c2             	add    rdx,rax
   140002246:	48 89 c8             	mov    rax,rcx
   140002249:	48 29 d0             	sub    rax,rdx
   14000224c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002250:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140002254:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140002258:	48 01 d0             	add    rax,rdx
   14000225b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000225f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002263:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002266:	25 ff 00 00 00       	and    eax,0xff
   14000226b:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000226e:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   140002272:	77 67                	ja     1400022db <do_pseudo_reloc+0x2d9>
   140002274:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002277:	ba 01 00 00 00       	mov    edx,0x1
   14000227c:	89 c1                	mov    ecx,eax
   14000227e:	48 d3 e2             	shl    rdx,cl
   140002281:	48 89 d0             	mov    rax,rdx
   140002284:	48 83 e8 01          	sub    rax,0x1
   140002288:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000228c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   14000228f:	83 e8 01             	sub    eax,0x1
   140002292:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   140002299:	89 c1                	mov    ecx,eax
   14000229b:	48 d3 e2             	shl    rdx,cl
   14000229e:	48 89 d0             	mov    rax,rdx
   1400022a1:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400022a5:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022a9:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   1400022ad:	7c 0a                	jl     1400022b9 <do_pseudo_reloc+0x2b7>
   1400022af:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022b3:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400022b7:	7e 22                	jle    1400022db <do_pseudo_reloc+0x2d9>
   1400022b9:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400022bd:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   1400022c1:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   1400022c5:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022c8:	48 8d 0d 09 90 00 00 	lea    rcx,[rip+0x9009]        # 14000b2d8 <.rdata+0x108>
   1400022cf:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400022d4:	89 c2                	mov    edx,eax
   1400022d6:	e8 c5 f8 ff ff       	call   140001ba0 <__report_error>
   1400022db:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022df:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400022e2:	0f b6 c0             	movzx  eax,al
   1400022e5:	83 f8 40             	cmp    eax,0x40
   1400022e8:	74 63                	je     14000234d <do_pseudo_reloc+0x34b>
   1400022ea:	83 f8 40             	cmp    eax,0x40
   1400022ed:	77 75                	ja     140002364 <do_pseudo_reloc+0x362>
   1400022ef:	83 f8 20             	cmp    eax,0x20
   1400022f2:	74 41                	je     140002335 <do_pseudo_reloc+0x333>
   1400022f4:	83 f8 20             	cmp    eax,0x20
   1400022f7:	77 6b                	ja     140002364 <do_pseudo_reloc+0x362>
   1400022f9:	83 f8 08             	cmp    eax,0x8
   1400022fc:	74 07                	je     140002305 <do_pseudo_reloc+0x303>
   1400022fe:	83 f8 10             	cmp    eax,0x10
   140002301:	74 1a                	je     14000231d <do_pseudo_reloc+0x31b>
   140002303:	eb 5f                	jmp    140002364 <do_pseudo_reloc+0x362>
   140002305:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002309:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000230d:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002313:	48 89 c1             	mov    rcx,rax
   140002316:	e8 a0 fc ff ff       	call   140001fbb <__write_memory>
   14000231b:	eb 47                	jmp    140002364 <do_pseudo_reloc+0x362>
   14000231d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002321:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002325:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000232b:	48 89 c1             	mov    rcx,rax
   14000232e:	e8 88 fc ff ff       	call   140001fbb <__write_memory>
   140002333:	eb 2f                	jmp    140002364 <do_pseudo_reloc+0x362>
   140002335:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002339:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000233d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002343:	48 89 c1             	mov    rcx,rax
   140002346:	e8 70 fc ff ff       	call   140001fbb <__write_memory>
   14000234b:	eb 17                	jmp    140002364 <do_pseudo_reloc+0x362>
   14000234d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002351:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002355:	41 b8 08 00 00 00    	mov    r8d,0x8
   14000235b:	48 89 c1             	mov    rcx,rax
   14000235e:	e8 58 fc ff ff       	call   140001fbb <__write_memory>
   140002363:	90                   	nop
   140002364:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   140002369:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000236d:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002371:	0f 82 8d fd ff ff    	jb     140002104 <do_pseudo_reloc+0x102>
   140002377:	eb 01                	jmp    14000237a <do_pseudo_reloc+0x378>
   140002379:	90                   	nop
   14000237a:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   14000237e:	5d                   	pop    rbp
   14000237f:	c3                   	ret

0000000140002380 <_pei386_runtime_relocator>:
   140002380:	55                   	push   rbp
   140002381:	48 89 e5             	mov    rbp,rsp
   140002384:	48 83 ec 30          	sub    rsp,0x30
   140002388:	8b 05 5e cd 00 00    	mov    eax,DWORD PTR [rip+0xcd5e]        # 14000f0ec <was_init.0>
   14000238e:	85 c0                	test   eax,eax
   140002390:	0f 85 88 00 00 00    	jne    14000241e <_pei386_runtime_relocator+0x9e>
   140002396:	8b 05 50 cd 00 00    	mov    eax,DWORD PTR [rip+0xcd50]        # 14000f0ec <was_init.0>
   14000239c:	83 c0 01             	add    eax,0x1
   14000239f:	89 05 47 cd 00 00    	mov    DWORD PTR [rip+0xcd47],eax        # 14000f0ec <was_init.0>
   1400023a5:	e8 21 0b 00 00       	call   140002ecb <__mingw_GetSectionCount>
   1400023aa:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400023ad:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400023b0:	48 63 d0             	movsxd rdx,eax
   1400023b3:	48 89 d0             	mov    rax,rdx
   1400023b6:	48 c1 e0 02          	shl    rax,0x2
   1400023ba:	48 01 d0             	add    rax,rdx
   1400023bd:	48 c1 e0 03          	shl    rax,0x3
   1400023c1:	48 83 c0 0f          	add    rax,0xf
   1400023c5:	48 c1 e8 04          	shr    rax,0x4
   1400023c9:	48 c1 e0 04          	shl    rax,0x4
   1400023cd:	e8 7e 0d 00 00       	call   140003150 <___chkstk_ms>
   1400023d2:	48 29 c4             	sub    rsp,rax
   1400023d5:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400023da:	48 83 c0 0f          	add    rax,0xf
   1400023de:	48 c1 e8 04          	shr    rax,0x4
   1400023e2:	48 c1 e0 04          	shl    rax,0x4
   1400023e6:	48 89 05 f3 cc 00 00 	mov    QWORD PTR [rip+0xccf3],rax        # 14000f0e0 <the_secs>
   1400023ed:	c7 05 f1 cc 00 00 00 	mov    DWORD PTR [rip+0xccf1],0x0        # 14000f0e8 <maxSections>
   1400023f4:	00 00 00 
   1400023f7:	48 8b 0d 82 91 00 00 	mov    rcx,QWORD PTR [rip+0x9182]        # 14000b580 <.refptr.__ImageBase>
   1400023fe:	48 8b 15 8b 91 00 00 	mov    rdx,QWORD PTR [rip+0x918b]        # 14000b590 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002405:	48 8b 05 94 91 00 00 	mov    rax,QWORD PTR [rip+0x9194]        # 14000b5a0 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000240c:	49 89 c8             	mov    r8,rcx
   14000240f:	48 89 c1             	mov    rcx,rax
   140002412:	e8 eb fb ff ff       	call   140002002 <do_pseudo_reloc>
   140002417:	e8 c7 fa ff ff       	call   140001ee3 <restore_modified_sections>
   14000241c:	eb 01                	jmp    14000241f <_pei386_runtime_relocator+0x9f>
   14000241e:	90                   	nop
   14000241f:	48 89 ec             	mov    rsp,rbp
   140002422:	5d                   	pop    rbp
   140002423:	c3                   	ret
   140002424:	90                   	nop
   140002425:	90                   	nop
   140002426:	90                   	nop
   140002427:	90                   	nop
   140002428:	90                   	nop
   140002429:	90                   	nop
   14000242a:	90                   	nop
   14000242b:	90                   	nop
   14000242c:	90                   	nop
   14000242d:	90                   	nop
   14000242e:	90                   	nop
   14000242f:	90                   	nop

0000000140002430 <__mingw_raise_matherr>:
   140002430:	55                   	push   rbp
   140002431:	48 89 e5             	mov    rbp,rsp
   140002434:	48 83 ec 50          	sub    rsp,0x50
   140002438:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000243b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000243f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002444:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002449:	48 8b 05 a0 cc 00 00 	mov    rax,QWORD PTR [rip+0xcca0]        # 14000f0f0 <stUserMathErr>
   140002450:	48 85 c0             	test   rax,rax
   140002453:	74 3e                	je     140002493 <__mingw_raise_matherr+0x63>
   140002455:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140002458:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000245b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000245f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002463:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140002468:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   14000246d:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   140002472:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   140002477:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   14000247c:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140002481:	48 8b 15 68 cc 00 00 	mov    rdx,QWORD PTR [rip+0xcc68]        # 14000f0f0 <stUserMathErr>
   140002488:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000248c:	48 89 c1             	mov    rcx,rax
   14000248f:	ff d2                	call   rdx
   140002491:	eb 01                	jmp    140002494 <__mingw_raise_matherr+0x64>
   140002493:	90                   	nop
   140002494:	48 83 c4 50          	add    rsp,0x50
   140002498:	5d                   	pop    rbp
   140002499:	c3                   	ret

000000014000249a <__mingw_setusermatherr>:
   14000249a:	55                   	push   rbp
   14000249b:	48 89 e5             	mov    rbp,rsp
   14000249e:	48 83 ec 20          	sub    rsp,0x20
   1400024a2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400024a6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024aa:	48 89 05 3f cc 00 00 	mov    QWORD PTR [rip+0xcc3f],rax        # 14000f0f0 <stUserMathErr>
   1400024b1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024b5:	48 89 c1             	mov    rcx,rax
   1400024b8:	e8 93 71 00 00       	call   140009650 <__setusermatherr>
   1400024bd:	90                   	nop
   1400024be:	48 83 c4 20          	add    rsp,0x20
   1400024c2:	5d                   	pop    rbp
   1400024c3:	c3                   	ret
   1400024c4:	90                   	nop
   1400024c5:	90                   	nop
   1400024c6:	90                   	nop
   1400024c7:	90                   	nop
   1400024c8:	90                   	nop
   1400024c9:	90                   	nop
   1400024ca:	90                   	nop
   1400024cb:	90                   	nop
   1400024cc:	90                   	nop
   1400024cd:	90                   	nop
   1400024ce:	90                   	nop
   1400024cf:	90                   	nop

00000001400024d0 <__mingw_SEH_error_handler>:
   1400024d0:	55                   	push   rbp
   1400024d1:	48 89 e5             	mov    rbp,rsp
   1400024d4:	48 83 ec 30          	sub    rsp,0x30
   1400024d8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400024dc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400024e0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400024e4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400024e8:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400024ef:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400024f6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024fa:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400024fd:	83 e0 02             	and    eax,0x2
   140002500:	85 c0                	test   eax,eax
   140002502:	74 0a                	je     14000250e <__mingw_SEH_error_handler+0x3e>
   140002504:	b8 01 00 00 00       	mov    eax,0x1
   140002509:	e9 16 02 00 00       	jmp    140002724 <__mingw_SEH_error_handler+0x254>
   14000250e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002512:	8b 00                	mov    eax,DWORD PTR [rax]
   140002514:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002519:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000251e:	75 18                	jne    140002538 <__mingw_SEH_error_handler+0x68>
   140002520:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002524:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002527:	83 e0 01             	and    eax,0x1
   14000252a:	85 c0                	test   eax,eax
   14000252c:	75 0a                	jne    140002538 <__mingw_SEH_error_handler+0x68>
   14000252e:	b8 00 00 00 00       	mov    eax,0x0
   140002533:	e9 ec 01 00 00       	jmp    140002724 <__mingw_SEH_error_handler+0x254>
   140002538:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000253c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000253e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002543:	0f 84 12 01 00 00    	je     14000265b <__mingw_SEH_error_handler+0x18b>
   140002549:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000254e:	0f 87 c3 01 00 00    	ja     140002717 <__mingw_SEH_error_handler+0x247>
   140002554:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002559:	0f 87 b8 01 00 00    	ja     140002717 <__mingw_SEH_error_handler+0x247>
   14000255f:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   140002564:	0f 83 4c 01 00 00    	jae    1400026b6 <__mingw_SEH_error_handler+0x1e6>
   14000256a:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000256f:	0f 84 3a 01 00 00    	je     1400026af <__mingw_SEH_error_handler+0x1df>
   140002575:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   14000257a:	0f 87 97 01 00 00    	ja     140002717 <__mingw_SEH_error_handler+0x247>
   140002580:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002585:	0f 84 83 01 00 00    	je     14000270e <__mingw_SEH_error_handler+0x23e>
   14000258b:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002590:	0f 87 81 01 00 00    	ja     140002717 <__mingw_SEH_error_handler+0x247>
   140002596:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000259b:	0f 87 76 01 00 00    	ja     140002717 <__mingw_SEH_error_handler+0x247>
   1400025a1:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400025a6:	0f 83 03 01 00 00    	jae    1400026af <__mingw_SEH_error_handler+0x1df>
   1400025ac:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400025b1:	0f 84 57 01 00 00    	je     14000270e <__mingw_SEH_error_handler+0x23e>
   1400025b7:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400025bc:	0f 87 55 01 00 00    	ja     140002717 <__mingw_SEH_error_handler+0x247>
   1400025c2:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400025c7:	0f 84 8e 00 00 00    	je     14000265b <__mingw_SEH_error_handler+0x18b>
   1400025cd:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   1400025d2:	0f 87 3f 01 00 00    	ja     140002717 <__mingw_SEH_error_handler+0x247>
   1400025d8:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400025dd:	0f 84 2b 01 00 00    	je     14000270e <__mingw_SEH_error_handler+0x23e>
   1400025e3:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   1400025e8:	0f 87 29 01 00 00    	ja     140002717 <__mingw_SEH_error_handler+0x247>
   1400025ee:	3d 02 00 00 80       	cmp    eax,0x80000002
   1400025f3:	0f 84 15 01 00 00    	je     14000270e <__mingw_SEH_error_handler+0x23e>
   1400025f9:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   1400025fe:	0f 85 13 01 00 00    	jne    140002717 <__mingw_SEH_error_handler+0x247>
   140002604:	ba 00 00 00 00       	mov    edx,0x0
   140002609:	b9 0b 00 00 00       	mov    ecx,0xb
   14000260e:	e8 dd 70 00 00       	call   1400096f0 <signal>
   140002613:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002617:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000261c:	75 1b                	jne    140002639 <__mingw_SEH_error_handler+0x169>
   14000261e:	ba 01 00 00 00       	mov    edx,0x1
   140002623:	b9 0b 00 00 00       	mov    ecx,0xb
   140002628:	e8 c3 70 00 00       	call   1400096f0 <signal>
   14000262d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002634:	e9 e1 00 00 00       	jmp    14000271a <__mingw_SEH_error_handler+0x24a>
   140002639:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000263e:	0f 84 d6 00 00 00    	je     14000271a <__mingw_SEH_error_handler+0x24a>
   140002644:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002648:	b9 0b 00 00 00       	mov    ecx,0xb
   14000264d:	ff d0                	call   rax
   14000264f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002656:	e9 bf 00 00 00       	jmp    14000271a <__mingw_SEH_error_handler+0x24a>
   14000265b:	ba 00 00 00 00       	mov    edx,0x0
   140002660:	b9 04 00 00 00       	mov    ecx,0x4
   140002665:	e8 86 70 00 00       	call   1400096f0 <signal>
   14000266a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000266e:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002673:	75 1b                	jne    140002690 <__mingw_SEH_error_handler+0x1c0>
   140002675:	ba 01 00 00 00       	mov    edx,0x1
   14000267a:	b9 04 00 00 00       	mov    ecx,0x4
   14000267f:	e8 6c 70 00 00       	call   1400096f0 <signal>
   140002684:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000268b:	e9 8d 00 00 00       	jmp    14000271d <__mingw_SEH_error_handler+0x24d>
   140002690:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002695:	0f 84 82 00 00 00    	je     14000271d <__mingw_SEH_error_handler+0x24d>
   14000269b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000269f:	b9 04 00 00 00       	mov    ecx,0x4
   1400026a4:	ff d0                	call   rax
   1400026a6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026ad:	eb 6e                	jmp    14000271d <__mingw_SEH_error_handler+0x24d>
   1400026af:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400026b6:	ba 00 00 00 00       	mov    edx,0x0
   1400026bb:	b9 08 00 00 00       	mov    ecx,0x8
   1400026c0:	e8 2b 70 00 00       	call   1400096f0 <signal>
   1400026c5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400026c9:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400026ce:	75 23                	jne    1400026f3 <__mingw_SEH_error_handler+0x223>
   1400026d0:	ba 01 00 00 00       	mov    edx,0x1
   1400026d5:	b9 08 00 00 00       	mov    ecx,0x8
   1400026da:	e8 11 70 00 00       	call   1400096f0 <signal>
   1400026df:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400026e3:	74 05                	je     1400026ea <__mingw_SEH_error_handler+0x21a>
   1400026e5:	e8 a6 05 00 00       	call   140002c90 <_fpreset>
   1400026ea:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026f1:	eb 2d                	jmp    140002720 <__mingw_SEH_error_handler+0x250>
   1400026f3:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400026f8:	74 26                	je     140002720 <__mingw_SEH_error_handler+0x250>
   1400026fa:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400026fe:	b9 08 00 00 00       	mov    ecx,0x8
   140002703:	ff d0                	call   rax
   140002705:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000270c:	eb 12                	jmp    140002720 <__mingw_SEH_error_handler+0x250>
   14000270e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002715:	eb 0a                	jmp    140002721 <__mingw_SEH_error_handler+0x251>
   140002717:	90                   	nop
   140002718:	eb 07                	jmp    140002721 <__mingw_SEH_error_handler+0x251>
   14000271a:	90                   	nop
   14000271b:	eb 04                	jmp    140002721 <__mingw_SEH_error_handler+0x251>
   14000271d:	90                   	nop
   14000271e:	eb 01                	jmp    140002721 <__mingw_SEH_error_handler+0x251>
   140002720:	90                   	nop
   140002721:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002724:	48 83 c4 30          	add    rsp,0x30
   140002728:	5d                   	pop    rbp
   140002729:	c3                   	ret

000000014000272a <_gnu_exception_handler>:
   14000272a:	55                   	push   rbp
   14000272b:	48 89 e5             	mov    rbp,rsp
   14000272e:	48 83 ec 30          	sub    rsp,0x30
   140002732:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002736:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000273d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002744:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002748:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000274b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000274d:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002752:	3d 43 43 47 20       	cmp    eax,0x20474343
   140002757:	75 1b                	jne    140002774 <_gnu_exception_handler+0x4a>
   140002759:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000275d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002760:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002763:	83 e0 01             	and    eax,0x1
   140002766:	85 c0                	test   eax,eax
   140002768:	75 0a                	jne    140002774 <_gnu_exception_handler+0x4a>
   14000276a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000276f:	e9 14 02 00 00       	jmp    140002988 <_gnu_exception_handler+0x25e>
   140002774:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002778:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000277b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000277d:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002782:	0f 84 12 01 00 00    	je     14000289a <_gnu_exception_handler+0x170>
   140002788:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000278d:	0f 87 c3 01 00 00    	ja     140002956 <_gnu_exception_handler+0x22c>
   140002793:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   140002798:	0f 87 b8 01 00 00    	ja     140002956 <_gnu_exception_handler+0x22c>
   14000279e:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400027a3:	0f 83 4c 01 00 00    	jae    1400028f5 <_gnu_exception_handler+0x1cb>
   1400027a9:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400027ae:	0f 84 3a 01 00 00    	je     1400028ee <_gnu_exception_handler+0x1c4>
   1400027b4:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400027b9:	0f 87 97 01 00 00    	ja     140002956 <_gnu_exception_handler+0x22c>
   1400027bf:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400027c4:	0f 84 83 01 00 00    	je     14000294d <_gnu_exception_handler+0x223>
   1400027ca:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400027cf:	0f 87 81 01 00 00    	ja     140002956 <_gnu_exception_handler+0x22c>
   1400027d5:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400027da:	0f 87 76 01 00 00    	ja     140002956 <_gnu_exception_handler+0x22c>
   1400027e0:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400027e5:	0f 83 03 01 00 00    	jae    1400028ee <_gnu_exception_handler+0x1c4>
   1400027eb:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400027f0:	0f 84 57 01 00 00    	je     14000294d <_gnu_exception_handler+0x223>
   1400027f6:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   1400027fb:	0f 87 55 01 00 00    	ja     140002956 <_gnu_exception_handler+0x22c>
   140002801:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002806:	0f 84 8e 00 00 00    	je     14000289a <_gnu_exception_handler+0x170>
   14000280c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002811:	0f 87 3f 01 00 00    	ja     140002956 <_gnu_exception_handler+0x22c>
   140002817:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000281c:	0f 84 2b 01 00 00    	je     14000294d <_gnu_exception_handler+0x223>
   140002822:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002827:	0f 87 29 01 00 00    	ja     140002956 <_gnu_exception_handler+0x22c>
   14000282d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002832:	0f 84 15 01 00 00    	je     14000294d <_gnu_exception_handler+0x223>
   140002838:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000283d:	0f 85 13 01 00 00    	jne    140002956 <_gnu_exception_handler+0x22c>
   140002843:	ba 00 00 00 00       	mov    edx,0x0
   140002848:	b9 0b 00 00 00       	mov    ecx,0xb
   14000284d:	e8 9e 6e 00 00       	call   1400096f0 <signal>
   140002852:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002856:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000285b:	75 1b                	jne    140002878 <_gnu_exception_handler+0x14e>
   14000285d:	ba 01 00 00 00       	mov    edx,0x1
   140002862:	b9 0b 00 00 00       	mov    ecx,0xb
   140002867:	e8 84 6e 00 00       	call   1400096f0 <signal>
   14000286c:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002873:	e9 e1 00 00 00       	jmp    140002959 <_gnu_exception_handler+0x22f>
   140002878:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000287d:	0f 84 d6 00 00 00    	je     140002959 <_gnu_exception_handler+0x22f>
   140002883:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002887:	b9 0b 00 00 00       	mov    ecx,0xb
   14000288c:	ff d0                	call   rax
   14000288e:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002895:	e9 bf 00 00 00       	jmp    140002959 <_gnu_exception_handler+0x22f>
   14000289a:	ba 00 00 00 00       	mov    edx,0x0
   14000289f:	b9 04 00 00 00       	mov    ecx,0x4
   1400028a4:	e8 47 6e 00 00       	call   1400096f0 <signal>
   1400028a9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400028ad:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028b2:	75 1b                	jne    1400028cf <_gnu_exception_handler+0x1a5>
   1400028b4:	ba 01 00 00 00       	mov    edx,0x1
   1400028b9:	b9 04 00 00 00       	mov    ecx,0x4
   1400028be:	e8 2d 6e 00 00       	call   1400096f0 <signal>
   1400028c3:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028ca:	e9 8d 00 00 00       	jmp    14000295c <_gnu_exception_handler+0x232>
   1400028cf:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028d4:	0f 84 82 00 00 00    	je     14000295c <_gnu_exception_handler+0x232>
   1400028da:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028de:	b9 04 00 00 00       	mov    ecx,0x4
   1400028e3:	ff d0                	call   rax
   1400028e5:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028ec:	eb 6e                	jmp    14000295c <_gnu_exception_handler+0x232>
   1400028ee:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400028f5:	ba 00 00 00 00       	mov    edx,0x0
   1400028fa:	b9 08 00 00 00       	mov    ecx,0x8
   1400028ff:	e8 ec 6d 00 00       	call   1400096f0 <signal>
   140002904:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002908:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000290d:	75 23                	jne    140002932 <_gnu_exception_handler+0x208>
   14000290f:	ba 01 00 00 00       	mov    edx,0x1
   140002914:	b9 08 00 00 00       	mov    ecx,0x8
   140002919:	e8 d2 6d 00 00       	call   1400096f0 <signal>
   14000291e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002922:	74 05                	je     140002929 <_gnu_exception_handler+0x1ff>
   140002924:	e8 67 03 00 00       	call   140002c90 <_fpreset>
   140002929:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002930:	eb 2d                	jmp    14000295f <_gnu_exception_handler+0x235>
   140002932:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002937:	74 26                	je     14000295f <_gnu_exception_handler+0x235>
   140002939:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000293d:	b9 08 00 00 00       	mov    ecx,0x8
   140002942:	ff d0                	call   rax
   140002944:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000294b:	eb 12                	jmp    14000295f <_gnu_exception_handler+0x235>
   14000294d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002954:	eb 0a                	jmp    140002960 <_gnu_exception_handler+0x236>
   140002956:	90                   	nop
   140002957:	eb 07                	jmp    140002960 <_gnu_exception_handler+0x236>
   140002959:	90                   	nop
   14000295a:	eb 04                	jmp    140002960 <_gnu_exception_handler+0x236>
   14000295c:	90                   	nop
   14000295d:	eb 01                	jmp    140002960 <_gnu_exception_handler+0x236>
   14000295f:	90                   	nop
   140002960:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140002964:	75 1f                	jne    140002985 <_gnu_exception_handler+0x25b>
   140002966:	48 8b 05 a3 c7 00 00 	mov    rax,QWORD PTR [rip+0xc7a3]        # 14000f110 <__mingw_oldexcpt_handler>
   14000296d:	48 85 c0             	test   rax,rax
   140002970:	74 13                	je     140002985 <_gnu_exception_handler+0x25b>
   140002972:	48 8b 15 97 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc797]        # 14000f110 <__mingw_oldexcpt_handler>
   140002979:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000297d:	48 89 c1             	mov    rcx,rax
   140002980:	ff d2                	call   rdx
   140002982:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140002985:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002988:	48 83 c4 30          	add    rsp,0x30
   14000298c:	5d                   	pop    rbp
   14000298d:	c3                   	ret
   14000298e:	90                   	nop
   14000298f:	90                   	nop

0000000140002990 <___w64_mingwthr_add_key_dtor>:
   140002990:	55                   	push   rbp
   140002991:	48 89 e5             	mov    rbp,rsp
   140002994:	48 83 ec 30          	sub    rsp,0x30
   140002998:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000299b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000299f:	8b 05 a3 c7 00 00    	mov    eax,DWORD PTR [rip+0xc7a3]        # 14000f148 <__mingwthr_cs_init>
   1400029a5:	85 c0                	test   eax,eax
   1400029a7:	75 07                	jne    1400029b0 <___w64_mingwthr_add_key_dtor+0x20>
   1400029a9:	b8 00 00 00 00       	mov    eax,0x0
   1400029ae:	eb 7b                	jmp    140002a2b <___w64_mingwthr_add_key_dtor+0x9b>
   1400029b0:	ba 18 00 00 00       	mov    edx,0x18
   1400029b5:	b9 01 00 00 00       	mov    ecx,0x1
   1400029ba:	e8 d9 6c 00 00       	call   140009698 <calloc>
   1400029bf:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400029c3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400029c8:	75 07                	jne    1400029d1 <___w64_mingwthr_add_key_dtor+0x41>
   1400029ca:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400029cf:	eb 5a                	jmp    140002a2b <___w64_mingwthr_add_key_dtor+0x9b>
   1400029d1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029d5:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400029d8:	89 10                	mov    DWORD PTR [rax],edx
   1400029da:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400029de:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400029e2:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   1400029e6:	48 8d 05 33 c7 00 00 	lea    rax,[rip+0xc733]        # 14000f120 <__mingwthr_cs>
   1400029ed:	48 89 c1             	mov    rcx,rax
   1400029f0:	48 8b 05 01 d8 00 00 	mov    rax,QWORD PTR [rip+0xd801]        # 1400101f8 <__imp_EnterCriticalSection>
   1400029f7:	ff d0                	call   rax
   1400029f9:	48 8b 15 50 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc750]        # 14000f150 <key_dtor_list>
   140002a00:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a04:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a08:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a0c:	48 89 05 3d c7 00 00 	mov    QWORD PTR [rip+0xc73d],rax        # 14000f150 <key_dtor_list>
   140002a13:	48 8d 05 06 c7 00 00 	lea    rax,[rip+0xc706]        # 14000f120 <__mingwthr_cs>
   140002a1a:	48 89 c1             	mov    rcx,rax
   140002a1d:	48 8b 05 0c d8 00 00 	mov    rax,QWORD PTR [rip+0xd80c]        # 140010230 <__imp_LeaveCriticalSection>
   140002a24:	ff d0                	call   rax
   140002a26:	b8 00 00 00 00       	mov    eax,0x0
   140002a2b:	48 83 c4 30          	add    rsp,0x30
   140002a2f:	5d                   	pop    rbp
   140002a30:	c3                   	ret

0000000140002a31 <___w64_mingwthr_remove_key_dtor>:
   140002a31:	55                   	push   rbp
   140002a32:	48 89 e5             	mov    rbp,rsp
   140002a35:	48 83 ec 30          	sub    rsp,0x30
   140002a39:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002a3c:	8b 05 06 c7 00 00    	mov    eax,DWORD PTR [rip+0xc706]        # 14000f148 <__mingwthr_cs_init>
   140002a42:	85 c0                	test   eax,eax
   140002a44:	75 0a                	jne    140002a50 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002a46:	b8 00 00 00 00       	mov    eax,0x0
   140002a4b:	e9 9c 00 00 00       	jmp    140002aec <___w64_mingwthr_remove_key_dtor+0xbb>
   140002a50:	48 8d 05 c9 c6 00 00 	lea    rax,[rip+0xc6c9]        # 14000f120 <__mingwthr_cs>
   140002a57:	48 89 c1             	mov    rcx,rax
   140002a5a:	48 8b 05 97 d7 00 00 	mov    rax,QWORD PTR [rip+0xd797]        # 1400101f8 <__imp_EnterCriticalSection>
   140002a61:	ff d0                	call   rax
   140002a63:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002a6a:	00 
   140002a6b:	48 8b 05 de c6 00 00 	mov    rax,QWORD PTR [rip+0xc6de]        # 14000f150 <key_dtor_list>
   140002a72:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a76:	eb 55                	jmp    140002acd <___w64_mingwthr_remove_key_dtor+0x9c>
   140002a78:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a7c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a7e:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002a81:	75 36                	jne    140002ab9 <___w64_mingwthr_remove_key_dtor+0x88>
   140002a83:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002a88:	75 11                	jne    140002a9b <___w64_mingwthr_remove_key_dtor+0x6a>
   140002a8a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a8e:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002a92:	48 89 05 b7 c6 00 00 	mov    QWORD PTR [rip+0xc6b7],rax        # 14000f150 <key_dtor_list>
   140002a99:	eb 10                	jmp    140002aab <___w64_mingwthr_remove_key_dtor+0x7a>
   140002a9b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002a9f:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002aa3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002aa7:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002aab:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aaf:	48 89 c1             	mov    rcx,rax
   140002ab2:	e8 09 6c 00 00       	call   1400096c0 <free>
   140002ab7:	eb 1b                	jmp    140002ad4 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002ab9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002abd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ac1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ac5:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002ac9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002acd:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002ad2:	75 a4                	jne    140002a78 <___w64_mingwthr_remove_key_dtor+0x47>
   140002ad4:	48 8d 05 45 c6 00 00 	lea    rax,[rip+0xc645]        # 14000f120 <__mingwthr_cs>
   140002adb:	48 89 c1             	mov    rcx,rax
   140002ade:	48 8b 05 4b d7 00 00 	mov    rax,QWORD PTR [rip+0xd74b]        # 140010230 <__imp_LeaveCriticalSection>
   140002ae5:	ff d0                	call   rax
   140002ae7:	b8 00 00 00 00       	mov    eax,0x0
   140002aec:	48 83 c4 30          	add    rsp,0x30
   140002af0:	5d                   	pop    rbp
   140002af1:	c3                   	ret

0000000140002af2 <__mingwthr_run_key_dtors>:
   140002af2:	55                   	push   rbp
   140002af3:	48 89 e5             	mov    rbp,rsp
   140002af6:	48 83 ec 30          	sub    rsp,0x30
   140002afa:	8b 05 48 c6 00 00    	mov    eax,DWORD PTR [rip+0xc648]        # 14000f148 <__mingwthr_cs_init>
   140002b00:	85 c0                	test   eax,eax
   140002b02:	0f 84 82 00 00 00    	je     140002b8a <__mingwthr_run_key_dtors+0x98>
   140002b08:	48 8d 05 11 c6 00 00 	lea    rax,[rip+0xc611]        # 14000f120 <__mingwthr_cs>
   140002b0f:	48 89 c1             	mov    rcx,rax
   140002b12:	48 8b 05 df d6 00 00 	mov    rax,QWORD PTR [rip+0xd6df]        # 1400101f8 <__imp_EnterCriticalSection>
   140002b19:	ff d0                	call   rax
   140002b1b:	48 8b 05 2e c6 00 00 	mov    rax,QWORD PTR [rip+0xc62e]        # 14000f150 <key_dtor_list>
   140002b22:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b26:	eb 46                	jmp    140002b6e <__mingwthr_run_key_dtors+0x7c>
   140002b28:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b2c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002b2e:	89 c1                	mov    ecx,eax
   140002b30:	48 8b 05 21 d7 00 00 	mov    rax,QWORD PTR [rip+0xd721]        # 140010258 <__imp_TlsGetValue>
   140002b37:	ff d0                	call   rax
   140002b39:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b3d:	48 8b 05 cc d6 00 00 	mov    rax,QWORD PTR [rip+0xd6cc]        # 140010210 <__imp_GetLastError>
   140002b44:	ff d0                	call   rax
   140002b46:	85 c0                	test   eax,eax
   140002b48:	75 18                	jne    140002b62 <__mingwthr_run_key_dtors+0x70>
   140002b4a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002b4f:	74 11                	je     140002b62 <__mingwthr_run_key_dtors+0x70>
   140002b51:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b55:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002b59:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b5d:	48 89 c1             	mov    rcx,rax
   140002b60:	ff d2                	call   rdx
   140002b62:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b66:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b6a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b6e:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002b73:	75 b3                	jne    140002b28 <__mingwthr_run_key_dtors+0x36>
   140002b75:	48 8d 05 a4 c5 00 00 	lea    rax,[rip+0xc5a4]        # 14000f120 <__mingwthr_cs>
   140002b7c:	48 89 c1             	mov    rcx,rax
   140002b7f:	48 8b 05 aa d6 00 00 	mov    rax,QWORD PTR [rip+0xd6aa]        # 140010230 <__imp_LeaveCriticalSection>
   140002b86:	ff d0                	call   rax
   140002b88:	eb 01                	jmp    140002b8b <__mingwthr_run_key_dtors+0x99>
   140002b8a:	90                   	nop
   140002b8b:	48 83 c4 30          	add    rsp,0x30
   140002b8f:	5d                   	pop    rbp
   140002b90:	c3                   	ret

0000000140002b91 <__mingw_TLScallback>:
   140002b91:	55                   	push   rbp
   140002b92:	48 89 e5             	mov    rbp,rsp
   140002b95:	48 83 ec 30          	sub    rsp,0x30
   140002b99:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002b9d:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002ba0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002ba4:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002ba8:	0f 84 cc 00 00 00    	je     140002c7a <__mingw_TLScallback+0xe9>
   140002bae:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002bb2:	0f 87 ca 00 00 00    	ja     140002c82 <__mingw_TLScallback+0xf1>
   140002bb8:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002bbc:	0f 84 b1 00 00 00    	je     140002c73 <__mingw_TLScallback+0xe2>
   140002bc2:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002bc6:	0f 87 b6 00 00 00    	ja     140002c82 <__mingw_TLScallback+0xf1>
   140002bcc:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002bd0:	74 33                	je     140002c05 <__mingw_TLScallback+0x74>
   140002bd2:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002bd6:	0f 85 a6 00 00 00    	jne    140002c82 <__mingw_TLScallback+0xf1>
   140002bdc:	8b 05 66 c5 00 00    	mov    eax,DWORD PTR [rip+0xc566]        # 14000f148 <__mingwthr_cs_init>
   140002be2:	85 c0                	test   eax,eax
   140002be4:	75 13                	jne    140002bf9 <__mingw_TLScallback+0x68>
   140002be6:	48 8d 05 33 c5 00 00 	lea    rax,[rip+0xc533]        # 14000f120 <__mingwthr_cs>
   140002bed:	48 89 c1             	mov    rcx,rax
   140002bf0:	48 8b 05 31 d6 00 00 	mov    rax,QWORD PTR [rip+0xd631]        # 140010228 <__imp_InitializeCriticalSection>
   140002bf7:	ff d0                	call   rax
   140002bf9:	c7 05 45 c5 00 00 01 	mov    DWORD PTR [rip+0xc545],0x1        # 14000f148 <__mingwthr_cs_init>
   140002c00:	00 00 00 
   140002c03:	eb 7d                	jmp    140002c82 <__mingw_TLScallback+0xf1>
   140002c05:	e8 e8 fe ff ff       	call   140002af2 <__mingwthr_run_key_dtors>
   140002c0a:	8b 05 38 c5 00 00    	mov    eax,DWORD PTR [rip+0xc538]        # 14000f148 <__mingwthr_cs_init>
   140002c10:	83 f8 01             	cmp    eax,0x1
   140002c13:	75 6c                	jne    140002c81 <__mingw_TLScallback+0xf0>
   140002c15:	48 8b 05 34 c5 00 00 	mov    rax,QWORD PTR [rip+0xc534]        # 14000f150 <key_dtor_list>
   140002c1c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c20:	eb 20                	jmp    140002c42 <__mingw_TLScallback+0xb1>
   140002c22:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c26:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c2a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c2e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c32:	48 89 c1             	mov    rcx,rax
   140002c35:	e8 86 6a 00 00       	call   1400096c0 <free>
   140002c3a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c3e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c42:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002c47:	75 d9                	jne    140002c22 <__mingw_TLScallback+0x91>
   140002c49:	48 c7 05 fc c4 00 00 	mov    QWORD PTR [rip+0xc4fc],0x0        # 14000f150 <key_dtor_list>
   140002c50:	00 00 00 00 
   140002c54:	c7 05 ea c4 00 00 00 	mov    DWORD PTR [rip+0xc4ea],0x0        # 14000f148 <__mingwthr_cs_init>
   140002c5b:	00 00 00 
   140002c5e:	48 8d 05 bb c4 00 00 	lea    rax,[rip+0xc4bb]        # 14000f120 <__mingwthr_cs>
   140002c65:	48 89 c1             	mov    rcx,rax
   140002c68:	48 8b 05 81 d5 00 00 	mov    rax,QWORD PTR [rip+0xd581]        # 1400101f0 <__IAT_start__>
   140002c6f:	ff d0                	call   rax
   140002c71:	eb 0e                	jmp    140002c81 <__mingw_TLScallback+0xf0>
   140002c73:	e8 18 00 00 00       	call   140002c90 <_fpreset>
   140002c78:	eb 08                	jmp    140002c82 <__mingw_TLScallback+0xf1>
   140002c7a:	e8 73 fe ff ff       	call   140002af2 <__mingwthr_run_key_dtors>
   140002c7f:	eb 01                	jmp    140002c82 <__mingw_TLScallback+0xf1>
   140002c81:	90                   	nop
   140002c82:	b8 01 00 00 00       	mov    eax,0x1
   140002c87:	48 83 c4 30          	add    rsp,0x30
   140002c8b:	5d                   	pop    rbp
   140002c8c:	c3                   	ret
   140002c8d:	90                   	nop
   140002c8e:	90                   	nop
   140002c8f:	90                   	nop

0000000140002c90 <_fpreset>:
   140002c90:	55                   	push   rbp
   140002c91:	48 89 e5             	mov    rbp,rsp
   140002c94:	db e3                	fninit
   140002c96:	90                   	nop
   140002c97:	5d                   	pop    rbp
   140002c98:	c3                   	ret
   140002c99:	90                   	nop
   140002c9a:	90                   	nop
   140002c9b:	90                   	nop
   140002c9c:	90                   	nop
   140002c9d:	90                   	nop
   140002c9e:	90                   	nop
   140002c9f:	90                   	nop

0000000140002ca0 <_ValidateImageBase>:
   140002ca0:	55                   	push   rbp
   140002ca1:	48 89 e5             	mov    rbp,rsp
   140002ca4:	48 83 ec 20          	sub    rsp,0x20
   140002ca8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002cac:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002cb0:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002cb4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cb8:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002cbb:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002cbf:	74 07                	je     140002cc8 <_ValidateImageBase+0x28>
   140002cc1:	b8 00 00 00 00       	mov    eax,0x0
   140002cc6:	eb 4e                	jmp    140002d16 <_ValidateImageBase+0x76>
   140002cc8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ccc:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002ccf:	48 63 d0             	movsxd rdx,eax
   140002cd2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002cd6:	48 01 d0             	add    rax,rdx
   140002cd9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002cdd:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ce1:	8b 00                	mov    eax,DWORD PTR [rax]
   140002ce3:	3d 50 45 00 00       	cmp    eax,0x4550
   140002ce8:	74 07                	je     140002cf1 <_ValidateImageBase+0x51>
   140002cea:	b8 00 00 00 00       	mov    eax,0x0
   140002cef:	eb 25                	jmp    140002d16 <_ValidateImageBase+0x76>
   140002cf1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002cf5:	48 83 c0 18          	add    rax,0x18
   140002cf9:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002cfd:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d01:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002d04:	66 3d 0b 02          	cmp    ax,0x20b
   140002d08:	74 07                	je     140002d11 <_ValidateImageBase+0x71>
   140002d0a:	b8 00 00 00 00       	mov    eax,0x0
   140002d0f:	eb 05                	jmp    140002d16 <_ValidateImageBase+0x76>
   140002d11:	b8 01 00 00 00       	mov    eax,0x1
   140002d16:	48 83 c4 20          	add    rsp,0x20
   140002d1a:	5d                   	pop    rbp
   140002d1b:	c3                   	ret

0000000140002d1c <_FindPESection>:
   140002d1c:	55                   	push   rbp
   140002d1d:	48 89 e5             	mov    rbp,rsp
   140002d20:	48 83 ec 20          	sub    rsp,0x20
   140002d24:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d28:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002d2c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d30:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d33:	48 63 d0             	movsxd rdx,eax
   140002d36:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d3a:	48 01 d0             	add    rax,rdx
   140002d3d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d41:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d48:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d4c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002d50:	0f b7 d0             	movzx  edx,ax
   140002d53:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d57:	48 01 d0             	add    rax,rdx
   140002d5a:	48 83 c0 18          	add    rax,0x18
   140002d5e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d62:	eb 36                	jmp    140002d9a <_FindPESection+0x7e>
   140002d64:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d68:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002d6b:	89 c0                	mov    eax,eax
   140002d6d:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d71:	72 1e                	jb     140002d91 <_FindPESection+0x75>
   140002d73:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d77:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002d7a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d7e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002d81:	01 d0                	add    eax,edx
   140002d83:	89 c0                	mov    eax,eax
   140002d85:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002d89:	73 06                	jae    140002d91 <_FindPESection+0x75>
   140002d8b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d8f:	eb 1e                	jmp    140002daf <_FindPESection+0x93>
   140002d91:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002d95:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002d9a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d9e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002da2:	0f b7 c0             	movzx  eax,ax
   140002da5:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002da8:	72 ba                	jb     140002d64 <_FindPESection+0x48>
   140002daa:	b8 00 00 00 00       	mov    eax,0x0
   140002daf:	48 83 c4 20          	add    rsp,0x20
   140002db3:	5d                   	pop    rbp
   140002db4:	c3                   	ret

0000000140002db5 <_FindPESectionByName>:
   140002db5:	55                   	push   rbp
   140002db6:	48 89 e5             	mov    rbp,rsp
   140002db9:	48 83 ec 40          	sub    rsp,0x40
   140002dbd:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002dc1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002dc5:	48 89 c1             	mov    rcx,rax
   140002dc8:	e8 33 69 00 00       	call   140009700 <strlen>
   140002dcd:	48 83 f8 08          	cmp    rax,0x8
   140002dd1:	76 0a                	jbe    140002ddd <_FindPESectionByName+0x28>
   140002dd3:	b8 00 00 00 00       	mov    eax,0x0
   140002dd8:	e9 98 00 00 00       	jmp    140002e75 <_FindPESectionByName+0xc0>
   140002ddd:	48 8b 05 9c 87 00 00 	mov    rax,QWORD PTR [rip+0x879c]        # 14000b580 <.refptr.__ImageBase>
   140002de4:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002de8:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dec:	48 89 c1             	mov    rcx,rax
   140002def:	e8 ac fe ff ff       	call   140002ca0 <_ValidateImageBase>
   140002df4:	85 c0                	test   eax,eax
   140002df6:	75 07                	jne    140002dff <_FindPESectionByName+0x4a>
   140002df8:	b8 00 00 00 00       	mov    eax,0x0
   140002dfd:	eb 76                	jmp    140002e75 <_FindPESectionByName+0xc0>
   140002dff:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e03:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e06:	48 63 d0             	movsxd rdx,eax
   140002e09:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e0d:	48 01 d0             	add    rax,rdx
   140002e10:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002e14:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002e1b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e1f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002e23:	0f b7 d0             	movzx  edx,ax
   140002e26:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e2a:	48 01 d0             	add    rax,rdx
   140002e2d:	48 83 c0 18          	add    rax,0x18
   140002e31:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e35:	eb 29                	jmp    140002e60 <_FindPESectionByName+0xab>
   140002e37:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e3b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002e3f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002e45:	48 89 c1             	mov    rcx,rax
   140002e48:	e8 bb 68 00 00       	call   140009708 <strncmp>
   140002e4d:	85 c0                	test   eax,eax
   140002e4f:	75 06                	jne    140002e57 <_FindPESectionByName+0xa2>
   140002e51:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e55:	eb 1e                	jmp    140002e75 <_FindPESectionByName+0xc0>
   140002e57:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002e5b:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002e60:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e64:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002e68:	0f b7 c0             	movzx  eax,ax
   140002e6b:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002e6e:	72 c7                	jb     140002e37 <_FindPESectionByName+0x82>
   140002e70:	b8 00 00 00 00       	mov    eax,0x0
   140002e75:	48 83 c4 40          	add    rsp,0x40
   140002e79:	5d                   	pop    rbp
   140002e7a:	c3                   	ret

0000000140002e7b <__mingw_GetSectionForAddress>:
   140002e7b:	55                   	push   rbp
   140002e7c:	48 89 e5             	mov    rbp,rsp
   140002e7f:	48 83 ec 30          	sub    rsp,0x30
   140002e83:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e87:	48 8b 05 f2 86 00 00 	mov    rax,QWORD PTR [rip+0x86f2]        # 14000b580 <.refptr.__ImageBase>
   140002e8e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e92:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e96:	48 89 c1             	mov    rcx,rax
   140002e99:	e8 02 fe ff ff       	call   140002ca0 <_ValidateImageBase>
   140002e9e:	85 c0                	test   eax,eax
   140002ea0:	75 07                	jne    140002ea9 <__mingw_GetSectionForAddress+0x2e>
   140002ea2:	b8 00 00 00 00       	mov    eax,0x0
   140002ea7:	eb 1c                	jmp    140002ec5 <__mingw_GetSectionForAddress+0x4a>
   140002ea9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002ead:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002eb1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002eb5:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002eb9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ebd:	48 89 c1             	mov    rcx,rax
   140002ec0:	e8 57 fe ff ff       	call   140002d1c <_FindPESection>
   140002ec5:	48 83 c4 30          	add    rsp,0x30
   140002ec9:	5d                   	pop    rbp
   140002eca:	c3                   	ret

0000000140002ecb <__mingw_GetSectionCount>:
   140002ecb:	55                   	push   rbp
   140002ecc:	48 89 e5             	mov    rbp,rsp
   140002ecf:	48 83 ec 30          	sub    rsp,0x30
   140002ed3:	48 8b 05 a6 86 00 00 	mov    rax,QWORD PTR [rip+0x86a6]        # 14000b580 <.refptr.__ImageBase>
   140002eda:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ede:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ee2:	48 89 c1             	mov    rcx,rax
   140002ee5:	e8 b6 fd ff ff       	call   140002ca0 <_ValidateImageBase>
   140002eea:	85 c0                	test   eax,eax
   140002eec:	75 07                	jne    140002ef5 <__mingw_GetSectionCount+0x2a>
   140002eee:	b8 00 00 00 00       	mov    eax,0x0
   140002ef3:	eb 20                	jmp    140002f15 <__mingw_GetSectionCount+0x4a>
   140002ef5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ef9:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002efc:	48 63 d0             	movsxd rdx,eax
   140002eff:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f03:	48 01 d0             	add    rax,rdx
   140002f06:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002f0a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002f0e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f12:	0f b7 c0             	movzx  eax,ax
   140002f15:	48 83 c4 30          	add    rsp,0x30
   140002f19:	5d                   	pop    rbp
   140002f1a:	c3                   	ret

0000000140002f1b <_FindPESectionExec>:
   140002f1b:	55                   	push   rbp
   140002f1c:	48 89 e5             	mov    rbp,rsp
   140002f1f:	48 83 ec 40          	sub    rsp,0x40
   140002f23:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f27:	48 8b 05 52 86 00 00 	mov    rax,QWORD PTR [rip+0x8652]        # 14000b580 <.refptr.__ImageBase>
   140002f2e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002f32:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f36:	48 89 c1             	mov    rcx,rax
   140002f39:	e8 62 fd ff ff       	call   140002ca0 <_ValidateImageBase>
   140002f3e:	85 c0                	test   eax,eax
   140002f40:	75 07                	jne    140002f49 <_FindPESectionExec+0x2e>
   140002f42:	b8 00 00 00 00       	mov    eax,0x0
   140002f47:	eb 78                	jmp    140002fc1 <_FindPESectionExec+0xa6>
   140002f49:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f4d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f50:	48 63 d0             	movsxd rdx,eax
   140002f53:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f57:	48 01 d0             	add    rax,rdx
   140002f5a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002f5e:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002f65:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f69:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002f6d:	0f b7 d0             	movzx  edx,ax
   140002f70:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002f74:	48 01 d0             	add    rax,rdx
   140002f77:	48 83 c0 18          	add    rax,0x18
   140002f7b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f7f:	eb 2b                	jmp    140002fac <_FindPESectionExec+0x91>
   140002f81:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f85:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002f88:	25 00 00 00 20       	and    eax,0x20000000
   140002f8d:	85 c0                	test   eax,eax
   140002f8f:	74 12                	je     140002fa3 <_FindPESectionExec+0x88>
   140002f91:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002f96:	75 06                	jne    140002f9e <_FindPESectionExec+0x83>
   140002f98:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f9c:	eb 23                	jmp    140002fc1 <_FindPESectionExec+0xa6>
   140002f9e:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002fa3:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002fa7:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002fac:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002fb0:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002fb4:	0f b7 c0             	movzx  eax,ax
   140002fb7:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002fba:	72 c5                	jb     140002f81 <_FindPESectionExec+0x66>
   140002fbc:	b8 00 00 00 00       	mov    eax,0x0
   140002fc1:	48 83 c4 40          	add    rsp,0x40
   140002fc5:	5d                   	pop    rbp
   140002fc6:	c3                   	ret

0000000140002fc7 <_GetPEImageBase>:
   140002fc7:	55                   	push   rbp
   140002fc8:	48 89 e5             	mov    rbp,rsp
   140002fcb:	48 83 ec 30          	sub    rsp,0x30
   140002fcf:	48 8b 05 aa 85 00 00 	mov    rax,QWORD PTR [rip+0x85aa]        # 14000b580 <.refptr.__ImageBase>
   140002fd6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fda:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fde:	48 89 c1             	mov    rcx,rax
   140002fe1:	e8 ba fc ff ff       	call   140002ca0 <_ValidateImageBase>
   140002fe6:	85 c0                	test   eax,eax
   140002fe8:	75 07                	jne    140002ff1 <_GetPEImageBase+0x2a>
   140002fea:	b8 00 00 00 00       	mov    eax,0x0
   140002fef:	eb 04                	jmp    140002ff5 <_GetPEImageBase+0x2e>
   140002ff1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ff5:	48 83 c4 30          	add    rsp,0x30
   140002ff9:	5d                   	pop    rbp
   140002ffa:	c3                   	ret

0000000140002ffb <_IsNonwritableInCurrentImage>:
   140002ffb:	55                   	push   rbp
   140002ffc:	48 89 e5             	mov    rbp,rsp
   140002fff:	48 83 ec 40          	sub    rsp,0x40
   140003003:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003007:	48 8b 05 72 85 00 00 	mov    rax,QWORD PTR [rip+0x8572]        # 14000b580 <.refptr.__ImageBase>
   14000300e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003012:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003016:	48 89 c1             	mov    rcx,rax
   140003019:	e8 82 fc ff ff       	call   140002ca0 <_ValidateImageBase>
   14000301e:	85 c0                	test   eax,eax
   140003020:	75 07                	jne    140003029 <_IsNonwritableInCurrentImage+0x2e>
   140003022:	b8 00 00 00 00       	mov    eax,0x0
   140003027:	eb 3d                	jmp    140003066 <_IsNonwritableInCurrentImage+0x6b>
   140003029:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000302d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140003031:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003035:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003039:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000303d:	48 89 c1             	mov    rcx,rax
   140003040:	e8 d7 fc ff ff       	call   140002d1c <_FindPESection>
   140003045:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003049:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   14000304e:	75 07                	jne    140003057 <_IsNonwritableInCurrentImage+0x5c>
   140003050:	b8 00 00 00 00       	mov    eax,0x0
   140003055:	eb 0f                	jmp    140003066 <_IsNonwritableInCurrentImage+0x6b>
   140003057:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000305b:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000305e:	f7 d0                	not    eax
   140003060:	c1 e8 1f             	shr    eax,0x1f
   140003063:	0f b6 c0             	movzx  eax,al
   140003066:	48 83 c4 40          	add    rsp,0x40
   14000306a:	5d                   	pop    rbp
   14000306b:	c3                   	ret

000000014000306c <__mingw_enum_import_library_names>:
   14000306c:	55                   	push   rbp
   14000306d:	48 89 e5             	mov    rbp,rsp
   140003070:	48 83 ec 50          	sub    rsp,0x50
   140003074:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003077:	48 8b 05 02 85 00 00 	mov    rax,QWORD PTR [rip+0x8502]        # 14000b580 <.refptr.__ImageBase>
   14000307e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003082:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003086:	48 89 c1             	mov    rcx,rax
   140003089:	e8 12 fc ff ff       	call   140002ca0 <_ValidateImageBase>
   14000308e:	85 c0                	test   eax,eax
   140003090:	75 0a                	jne    14000309c <__mingw_enum_import_library_names+0x30>
   140003092:	b8 00 00 00 00       	mov    eax,0x0
   140003097:	e9 ab 00 00 00       	jmp    140003147 <__mingw_enum_import_library_names+0xdb>
   14000309c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030a0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   1400030a3:	48 63 d0             	movsxd rdx,eax
   1400030a6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030aa:	48 01 d0             	add    rax,rdx
   1400030ad:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400030b1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400030b5:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   1400030bb:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400030be:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400030c2:	75 07                	jne    1400030cb <__mingw_enum_import_library_names+0x5f>
   1400030c4:	b8 00 00 00 00       	mov    eax,0x0
   1400030c9:	eb 7c                	jmp    140003147 <__mingw_enum_import_library_names+0xdb>
   1400030cb:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400030ce:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030d2:	48 89 c1             	mov    rcx,rax
   1400030d5:	e8 42 fc ff ff       	call   140002d1c <_FindPESection>
   1400030da:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400030de:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   1400030e3:	75 07                	jne    1400030ec <__mingw_enum_import_library_names+0x80>
   1400030e5:	b8 00 00 00 00       	mov    eax,0x0
   1400030ea:	eb 5b                	jmp    140003147 <__mingw_enum_import_library_names+0xdb>
   1400030ec:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   1400030ef:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030f3:	48 01 d0             	add    rax,rdx
   1400030f6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400030fa:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400030ff:	75 07                	jne    140003108 <__mingw_enum_import_library_names+0x9c>
   140003101:	b8 00 00 00 00       	mov    eax,0x0
   140003106:	eb 3f                	jmp    140003147 <__mingw_enum_import_library_names+0xdb>
   140003108:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000310c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000310f:	85 c0                	test   eax,eax
   140003111:	75 0b                	jne    14000311e <__mingw_enum_import_library_names+0xb2>
   140003113:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003117:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000311a:	85 c0                	test   eax,eax
   14000311c:	74 23                	je     140003141 <__mingw_enum_import_library_names+0xd5>
   14000311e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003122:	7f 12                	jg     140003136 <__mingw_enum_import_library_names+0xca>
   140003124:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003128:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000312b:	89 c2                	mov    edx,eax
   14000312d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003131:	48 01 d0             	add    rax,rdx
   140003134:	eb 11                	jmp    140003147 <__mingw_enum_import_library_names+0xdb>
   140003136:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000313a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000313f:	eb c7                	jmp    140003108 <__mingw_enum_import_library_names+0x9c>
   140003141:	90                   	nop
   140003142:	b8 00 00 00 00       	mov    eax,0x0
   140003147:	48 83 c4 50          	add    rsp,0x50
   14000314b:	5d                   	pop    rbp
   14000314c:	c3                   	ret
   14000314d:	90                   	nop
   14000314e:	90                   	nop
   14000314f:	90                   	nop

0000000140003150 <___chkstk_ms>:
   140003150:	51                   	push   rcx
   140003151:	50                   	push   rax
   140003152:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003158:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   14000315d:	72 19                	jb     140003178 <___chkstk_ms+0x28>
   14000315f:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   140003166:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000316a:	48 2d 00 10 00 00    	sub    rax,0x1000
   140003170:	48 3d 00 10 00 00    	cmp    rax,0x1000
   140003176:	77 e7                	ja     14000315f <___chkstk_ms+0xf>
   140003178:	48 29 c1             	sub    rcx,rax
   14000317b:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   14000317f:	58                   	pop    rax
   140003180:	59                   	pop    rcx
   140003181:	c3                   	ret
   140003182:	90                   	nop
   140003183:	90                   	nop
   140003184:	90                   	nop
   140003185:	90                   	nop
   140003186:	90                   	nop
   140003187:	90                   	nop
   140003188:	90                   	nop
   140003189:	90                   	nop
   14000318a:	90                   	nop
   14000318b:	90                   	nop
   14000318c:	90                   	nop
   14000318d:	90                   	nop
   14000318e:	90                   	nop
   14000318f:	90                   	nop

0000000140003190 <__mingw_printf>:
   140003190:	55                   	push   rbp
   140003191:	53                   	push   rbx
   140003192:	48 83 ec 48          	sub    rsp,0x48
   140003196:	48 8d 6c 24 40       	lea    rbp,[rsp+0x40]
   14000319b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   14000319f:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400031a3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   1400031a7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   1400031ab:	48 8d 45 28          	lea    rax,[rbp+0x28]
   1400031af:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400031b3:	b9 01 00 00 00       	mov    ecx,0x1
   1400031b8:	e8 c3 5e 00 00       	call   140009080 <__acrt_iob_func>
   1400031bd:	48 89 c1             	mov    rcx,rax
   1400031c0:	e8 3b 5d 00 00       	call   140008f00 <_lock_file>
   1400031c5:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   1400031c9:	b9 01 00 00 00       	mov    ecx,0x1
   1400031ce:	e8 ad 5e 00 00       	call   140009080 <__acrt_iob_func>
   1400031d3:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400031d7:	48 89 5c 24 20       	mov    QWORD PTR [rsp+0x20],rbx
   1400031dc:	49 89 d1             	mov    r9,rdx
   1400031df:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400031e5:	48 89 c2             	mov    rdx,rax
   1400031e8:	b9 00 60 00 00       	mov    ecx,0x6000
   1400031ed:	e8 b1 1f 00 00       	call   1400051a3 <__mingw_pformat>
   1400031f2:	89 c3                	mov    ebx,eax
   1400031f4:	b9 01 00 00 00       	mov    ecx,0x1
   1400031f9:	e8 82 5e 00 00       	call   140009080 <__acrt_iob_func>
   1400031fe:	48 89 c1             	mov    rcx,rax
   140003201:	e8 84 5d 00 00       	call   140008f8a <_unlock_file>
   140003206:	89 d8                	mov    eax,ebx
   140003208:	48 83 c4 48          	add    rsp,0x48
   14000320c:	5b                   	pop    rbx
   14000320d:	5d                   	pop    rbp
   14000320e:	c3                   	ret
   14000320f:	90                   	nop

0000000140003210 <__pformat_putc>:
   140003210:	55                   	push   rbp
   140003211:	48 89 e5             	mov    rbp,rsp
   140003214:	48 83 ec 20          	sub    rsp,0x20
   140003218:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000321b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000321f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003223:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003226:	25 00 40 00 00       	and    eax,0x4000
   14000322b:	85 c0                	test   eax,eax
   14000322d:	75 12                	jne    140003241 <__pformat_putc+0x31>
   14000322f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003233:	8b 50 28             	mov    edx,DWORD PTR [rax+0x28]
   140003236:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000323a:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000323d:	39 c2                	cmp    edx,eax
   14000323f:	7e 3b                	jle    14000327c <__pformat_putc+0x6c>
   140003241:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003245:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003248:	25 00 20 00 00       	and    eax,0x2000
   14000324d:	85 c0                	test   eax,eax
   14000324f:	74 13                	je     140003264 <__pformat_putc+0x54>
   140003251:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003255:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003258:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000325b:	89 c1                	mov    ecx,eax
   14000325d:	e8 56 64 00 00       	call   1400096b8 <fputc>
   140003262:	eb 18                	jmp    14000327c <__pformat_putc+0x6c>
   140003264:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003268:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   14000326b:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000326f:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140003272:	48 98                	cdqe
   140003274:	48 01 d0             	add    rax,rdx
   140003277:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   14000327a:	88 10                	mov    BYTE PTR [rax],dl
   14000327c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003280:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140003283:	8d 50 01             	lea    edx,[rax+0x1]
   140003286:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000328a:	89 50 24             	mov    DWORD PTR [rax+0x24],edx
   14000328d:	90                   	nop
   14000328e:	48 83 c4 20          	add    rsp,0x20
   140003292:	5d                   	pop    rbp
   140003293:	c3                   	ret

0000000140003294 <__pformat_putchars>:
   140003294:	55                   	push   rbp
   140003295:	48 89 e5             	mov    rbp,rsp
   140003298:	48 83 ec 20          	sub    rsp,0x20
   14000329c:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400032a0:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400032a3:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400032a7:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032ab:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400032ae:	85 c0                	test   eax,eax
   1400032b0:	78 16                	js     1400032c8 <__pformat_putchars+0x34>
   1400032b2:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032b6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400032b9:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400032bc:	7e 0a                	jle    1400032c8 <__pformat_putchars+0x34>
   1400032be:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032c2:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400032c5:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   1400032c8:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032cc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032cf:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400032d2:	7d 15                	jge    1400032e9 <__pformat_putchars+0x55>
   1400032d4:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032d8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032db:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400032de:	89 c2                	mov    edx,eax
   1400032e0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032e4:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400032e7:	eb 0b                	jmp    1400032f4 <__pformat_putchars+0x60>
   1400032e9:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032ed:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400032f4:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032f8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032fb:	85 c0                	test   eax,eax
   1400032fd:	7e 57                	jle    140003356 <__pformat_putchars+0xc2>
   1400032ff:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003303:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003306:	25 00 04 00 00       	and    eax,0x400
   14000330b:	85 c0                	test   eax,eax
   14000330d:	75 47                	jne    140003356 <__pformat_putchars+0xc2>
   14000330f:	eb 11                	jmp    140003322 <__pformat_putchars+0x8e>
   140003311:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003315:	48 89 c2             	mov    rdx,rax
   140003318:	b9 20 00 00 00       	mov    ecx,0x20
   14000331d:	e8 ee fe ff ff       	call   140003210 <__pformat_putc>
   140003322:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003326:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003329:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000332c:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003330:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003333:	85 c0                	test   eax,eax
   140003335:	75 da                	jne    140003311 <__pformat_putchars+0x7d>
   140003337:	eb 1d                	jmp    140003356 <__pformat_putchars+0xc2>
   140003339:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000333d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003341:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003345:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003348:	0f be c0             	movsx  eax,al
   14000334b:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000334f:	89 c1                	mov    ecx,eax
   140003351:	e8 ba fe ff ff       	call   140003210 <__pformat_putc>
   140003356:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003359:	8d 50 ff             	lea    edx,[rax-0x1]
   14000335c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000335f:	85 c0                	test   eax,eax
   140003361:	75 d6                	jne    140003339 <__pformat_putchars+0xa5>
   140003363:	eb 11                	jmp    140003376 <__pformat_putchars+0xe2>
   140003365:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003369:	48 89 c2             	mov    rdx,rax
   14000336c:	b9 20 00 00 00       	mov    ecx,0x20
   140003371:	e8 9a fe ff ff       	call   140003210 <__pformat_putc>
   140003376:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000337a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000337d:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003380:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003384:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003387:	85 c0                	test   eax,eax
   140003389:	7f da                	jg     140003365 <__pformat_putchars+0xd1>
   14000338b:	90                   	nop
   14000338c:	90                   	nop
   14000338d:	48 83 c4 20          	add    rsp,0x20
   140003391:	5d                   	pop    rbp
   140003392:	c3                   	ret

0000000140003393 <__pformat_puts>:
   140003393:	55                   	push   rbp
   140003394:	48 89 e5             	mov    rbp,rsp
   140003397:	48 83 ec 20          	sub    rsp,0x20
   14000339b:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000339f:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400033a3:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400033a8:	75 0b                	jne    1400033b5 <__pformat_puts+0x22>
   1400033aa:	48 8d 05 7f 7f 00 00 	lea    rax,[rip+0x7f7f]        # 14000b330 <.rdata>
   1400033b1:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400033b5:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400033b9:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033bc:	85 c0                	test   eax,eax
   1400033be:	78 2f                	js     1400033ef <__pformat_puts+0x5c>
   1400033c0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400033c4:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400033c7:	48 63 d0             	movsxd rdx,eax
   1400033ca:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033ce:	48 89 c1             	mov    rcx,rax
   1400033d1:	e8 4a 5a 00 00       	call   140008e20 <strnlen>
   1400033d6:	89 c1                	mov    ecx,eax
   1400033d8:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400033dc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033e0:	49 89 d0             	mov    r8,rdx
   1400033e3:	89 ca                	mov    edx,ecx
   1400033e5:	48 89 c1             	mov    rcx,rax
   1400033e8:	e8 a7 fe ff ff       	call   140003294 <__pformat_putchars>
   1400033ed:	eb 23                	jmp    140003412 <__pformat_puts+0x7f>
   1400033ef:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400033f3:	48 89 c1             	mov    rcx,rax
   1400033f6:	e8 05 63 00 00       	call   140009700 <strlen>
   1400033fb:	89 c1                	mov    ecx,eax
   1400033fd:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003401:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003405:	49 89 d0             	mov    r8,rdx
   140003408:	89 ca                	mov    edx,ecx
   14000340a:	48 89 c1             	mov    rcx,rax
   14000340d:	e8 82 fe ff ff       	call   140003294 <__pformat_putchars>
   140003412:	90                   	nop
   140003413:	48 83 c4 20          	add    rsp,0x20
   140003417:	5d                   	pop    rbp
   140003418:	c3                   	ret

0000000140003419 <__pformat_wputchars>:
   140003419:	55                   	push   rbp
   14000341a:	48 89 e5             	mov    rbp,rsp
   14000341d:	48 83 ec 50          	sub    rsp,0x50
   140003421:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003425:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003428:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000342c:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   140003433:	00 
   140003434:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003438:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000343b:	85 c0                	test   eax,eax
   14000343d:	78 16                	js     140003455 <__pformat_wputchars+0x3c>
   14000343f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003443:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003446:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003449:	7e 0a                	jle    140003455 <__pformat_wputchars+0x3c>
   14000344b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000344f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003452:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   140003455:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003459:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000345c:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   14000345f:	7d 15                	jge    140003476 <__pformat_wputchars+0x5d>
   140003461:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003465:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003468:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000346b:	89 c2                	mov    edx,eax
   14000346d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003471:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003474:	eb 0b                	jmp    140003481 <__pformat_wputchars+0x68>
   140003476:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000347a:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003481:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003485:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003488:	85 c0                	test   eax,eax
   14000348a:	7e 6e                	jle    1400034fa <__pformat_wputchars+0xe1>
   14000348c:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003490:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003493:	25 00 04 00 00       	and    eax,0x400
   140003498:	85 c0                	test   eax,eax
   14000349a:	75 5e                	jne    1400034fa <__pformat_wputchars+0xe1>
   14000349c:	eb 11                	jmp    1400034af <__pformat_wputchars+0x96>
   14000349e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034a2:	48 89 c2             	mov    rdx,rax
   1400034a5:	b9 20 00 00 00       	mov    ecx,0x20
   1400034aa:	e8 61 fd ff ff       	call   140003210 <__pformat_putc>
   1400034af:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034b3:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400034b6:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400034b9:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400034bd:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400034c0:	85 c0                	test   eax,eax
   1400034c2:	75 da                	jne    14000349e <__pformat_wputchars+0x85>
   1400034c4:	eb 34                	jmp    1400034fa <__pformat_wputchars+0xe1>
   1400034c6:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   1400034ca:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400034ce:	eb 1d                	jmp    1400034ed <__pformat_wputchars+0xd4>
   1400034d0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400034d4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400034d8:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400034dc:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400034df:	0f be c0             	movsx  eax,al
   1400034e2:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400034e6:	89 c1                	mov    ecx,eax
   1400034e8:	e8 23 fd ff ff       	call   140003210 <__pformat_putc>
   1400034ed:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400034f0:	8d 50 ff             	lea    edx,[rax-0x1]
   1400034f3:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   1400034f6:	85 c0                	test   eax,eax
   1400034f8:	7f d6                	jg     1400034d0 <__pformat_wputchars+0xb7>
   1400034fa:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400034fd:	8d 50 ff             	lea    edx,[rax-0x1]
   140003500:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003503:	85 c0                	test   eax,eax
   140003505:	7e 41                	jle    140003548 <__pformat_wputchars+0x12f>
   140003507:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000350b:	48 8d 50 02          	lea    rdx,[rax+0x2]
   14000350f:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003513:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140003516:	48 8d 4d d8          	lea    rcx,[rbp-0x28]
   14000351a:	0f b7 d0             	movzx  edx,ax
   14000351d:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003521:	49 89 c8             	mov    r8,rcx
   140003524:	48 89 c1             	mov    rcx,rax
   140003527:	e8 84 5b 00 00       	call   1400090b0 <wcrtomb>
   14000352c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000352f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003533:	7f 91                	jg     1400034c6 <__pformat_wputchars+0xad>
   140003535:	eb 11                	jmp    140003548 <__pformat_wputchars+0x12f>
   140003537:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000353b:	48 89 c2             	mov    rdx,rax
   14000353e:	b9 20 00 00 00       	mov    ecx,0x20
   140003543:	e8 c8 fc ff ff       	call   140003210 <__pformat_putc>
   140003548:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000354c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000354f:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003552:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003556:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003559:	85 c0                	test   eax,eax
   14000355b:	7f da                	jg     140003537 <__pformat_wputchars+0x11e>
   14000355d:	90                   	nop
   14000355e:	90                   	nop
   14000355f:	48 83 c4 50          	add    rsp,0x50
   140003563:	5d                   	pop    rbp
   140003564:	c3                   	ret

0000000140003565 <__pformat_wcputs>:
   140003565:	55                   	push   rbp
   140003566:	48 89 e5             	mov    rbp,rsp
   140003569:	48 83 ec 20          	sub    rsp,0x20
   14000356d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003571:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003575:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000357a:	75 0b                	jne    140003587 <__pformat_wcputs+0x22>
   14000357c:	48 8d 05 b5 7d 00 00 	lea    rax,[rip+0x7db5]        # 14000b338 <.rdata+0x8>
   140003583:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140003587:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000358b:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000358e:	85 c0                	test   eax,eax
   140003590:	78 2f                	js     1400035c1 <__pformat_wcputs+0x5c>
   140003592:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003596:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003599:	48 63 d0             	movsxd rdx,eax
   14000359c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035a0:	48 89 c1             	mov    rcx,rax
   1400035a3:	e8 28 58 00 00       	call   140008dd0 <wcsnlen>
   1400035a8:	89 c1                	mov    ecx,eax
   1400035aa:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400035ae:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035b2:	49 89 d0             	mov    r8,rdx
   1400035b5:	89 ca                	mov    edx,ecx
   1400035b7:	48 89 c1             	mov    rcx,rax
   1400035ba:	e8 5a fe ff ff       	call   140003419 <__pformat_wputchars>
   1400035bf:	eb 23                	jmp    1400035e4 <__pformat_wcputs+0x7f>
   1400035c1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035c5:	48 89 c1             	mov    rcx,rax
   1400035c8:	e8 4b 61 00 00       	call   140009718 <wcslen>
   1400035cd:	89 c1                	mov    ecx,eax
   1400035cf:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400035d3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035d7:	49 89 d0             	mov    r8,rdx
   1400035da:	89 ca                	mov    edx,ecx
   1400035dc:	48 89 c1             	mov    rcx,rax
   1400035df:	e8 35 fe ff ff       	call   140003419 <__pformat_wputchars>
   1400035e4:	90                   	nop
   1400035e5:	48 83 c4 20          	add    rsp,0x20
   1400035e9:	5d                   	pop    rbp
   1400035ea:	c3                   	ret

00000001400035eb <__pformat_int_bufsiz>:
   1400035eb:	55                   	push   rbp
   1400035ec:	48 89 e5             	mov    rbp,rsp
   1400035ef:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400035f2:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400035f5:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400035f9:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400035fc:	83 e8 01             	sub    eax,0x1
   1400035ff:	48 98                	cdqe
   140003601:	48 83 c0 40          	add    rax,0x40
   140003605:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140003608:	48 63 ca             	movsxd rcx,edx
   14000360b:	ba 00 00 00 00       	mov    edx,0x0
   140003610:	48 f7 f1             	div    rcx
   140003613:	89 c2                	mov    edx,eax
   140003615:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140003618:	01 d0                	add    eax,edx
   14000361a:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   14000361d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003621:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003624:	ba 00 00 00 00       	mov    edx,0x0
   140003629:	85 c0                	test   eax,eax
   14000362b:	0f 48 c2             	cmovs  eax,edx
   14000362e:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   140003631:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003635:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003638:	25 00 10 00 00       	and    eax,0x1000
   14000363d:	85 c0                	test   eax,eax
   14000363f:	74 29                	je     14000366a <__pformat_int_bufsiz+0x7f>
   140003641:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003645:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003649:	66 85 c0             	test   ax,ax
   14000364c:	74 1c                	je     14000366a <__pformat_int_bufsiz+0x7f>
   14000364e:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003651:	48 63 d0             	movsxd rdx,eax
   140003654:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   14000365b:	48 89 d1             	mov    rcx,rdx
   14000365e:	48 c1 e9 20          	shr    rcx,0x20
   140003662:	99                   	cdq
   140003663:	89 c8                	mov    eax,ecx
   140003665:	29 d0                	sub    eax,edx
   140003667:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   14000366a:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000366e:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140003671:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003674:	39 c2                	cmp    edx,eax
   140003676:	0f 4d c2             	cmovge eax,edx
   140003679:	5d                   	pop    rbp
   14000367a:	c3                   	ret

000000014000367b <__pformat_int>:
   14000367b:	55                   	push   rbp
   14000367c:	53                   	push   rbx
   14000367d:	48 83 ec 58          	sub    rsp,0x58
   140003681:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003686:	48 89 cb             	mov    rbx,rcx
   140003689:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
   14000368c:	48 8b 5b 08          	mov    rbx,QWORD PTR [rbx+0x8]
   140003690:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
   140003694:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
   140003698:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000369c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036a0:	49 89 c0             	mov    r8,rax
   1400036a3:	ba 03 00 00 00       	mov    edx,0x3
   1400036a8:	b9 01 00 00 00       	mov    ecx,0x1
   1400036ad:	e8 39 ff ff ff       	call   1400035eb <__pformat_int_bufsiz>
   1400036b2:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400036b5:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
   1400036bc:	00 
   1400036bd:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400036c0:	48 98                	cdqe
   1400036c2:	48 83 c0 0f          	add    rax,0xf
   1400036c6:	48 c1 e8 04          	shr    rax,0x4
   1400036ca:	48 c1 e0 04          	shl    rax,0x4
   1400036ce:	e8 7d fa ff ff       	call   140003150 <___chkstk_ms>
   1400036d3:	48 29 c4             	sub    rsp,rax
   1400036d6:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400036db:	48 83 c0 0f          	add    rax,0xf
   1400036df:	48 c1 e8 04          	shr    rax,0x4
   1400036e3:	48 c1 e0 04          	shl    rax,0x4
   1400036e7:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400036eb:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400036ef:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400036f3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036f7:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400036fa:	25 80 00 00 00       	and    eax,0x80
   1400036ff:	85 c0                	test   eax,eax
   140003701:	0f 84 ea 00 00 00    	je     1400037f1 <__pformat_int+0x176>
   140003707:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000370b:	48 85 c0             	test   rax,rax
   14000370e:	79 10                	jns    140003720 <__pformat_int+0xa5>
   140003710:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003714:	48 f7 d8             	neg    rax
   140003717:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000371b:	e9 d1 00 00 00       	jmp    1400037f1 <__pformat_int+0x176>
   140003720:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003724:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003727:	24 7f                	and    al,0x7f
   140003729:	89 c2                	mov    edx,eax
   14000372b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000372f:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003732:	e9 ba 00 00 00       	jmp    1400037f1 <__pformat_int+0x176>
   140003737:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000373b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000373f:	74 54                	je     140003795 <__pformat_int+0x11a>
   140003741:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003745:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003748:	25 00 10 00 00       	and    eax,0x1000
   14000374d:	85 c0                	test   eax,eax
   14000374f:	74 44                	je     140003795 <__pformat_int+0x11a>
   140003751:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003755:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003759:	66 85 c0             	test   ax,ax
   14000375c:	74 37                	je     140003795 <__pformat_int+0x11a>
   14000375e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003762:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   140003766:	48 89 c2             	mov    rdx,rax
   140003769:	48 89 d0             	mov    rax,rdx
   14000376c:	48 c1 f8 3f          	sar    rax,0x3f
   140003770:	48 c1 e8 3e          	shr    rax,0x3e
   140003774:	48 01 c2             	add    rdx,rax
   140003777:	83 e2 03             	and    edx,0x3
   14000377a:	48 29 c2             	sub    rdx,rax
   14000377d:	48 89 d0             	mov    rax,rdx
   140003780:	48 83 f8 03          	cmp    rax,0x3
   140003784:	75 0f                	jne    140003795 <__pformat_int+0x11a>
   140003786:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000378a:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000378e:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003792:	c6 00 2c             	mov    BYTE PTR [rax],0x2c
   140003795:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
   140003799:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   1400037a0:	cc cc cc 
   1400037a3:	48 89 c8             	mov    rax,rcx
   1400037a6:	48 f7 e2             	mul    rdx
   1400037a9:	48 c1 ea 03          	shr    rdx,0x3
   1400037ad:	48 89 d0             	mov    rax,rdx
   1400037b0:	48 c1 e0 02          	shl    rax,0x2
   1400037b4:	48 01 d0             	add    rax,rdx
   1400037b7:	48 01 c0             	add    rax,rax
   1400037ba:	48 29 c1             	sub    rcx,rax
   1400037bd:	48 89 ca             	mov    rdx,rcx
   1400037c0:	89 d0                	mov    eax,edx
   1400037c2:	8d 48 30             	lea    ecx,[rax+0x30]
   1400037c5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037c9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400037cd:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400037d1:	89 ca                	mov    edx,ecx
   1400037d3:	88 10                	mov    BYTE PTR [rax],dl
   1400037d5:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400037d9:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   1400037e0:	cc cc cc 
   1400037e3:	48 f7 e2             	mul    rdx
   1400037e6:	48 89 d0             	mov    rax,rdx
   1400037e9:	48 c1 e8 03          	shr    rax,0x3
   1400037ed:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400037f1:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400037f5:	48 85 c0             	test   rax,rax
   1400037f8:	0f 85 39 ff ff ff    	jne    140003737 <__pformat_int+0xbc>
   1400037fe:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003802:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003805:	85 c0                	test   eax,eax
   140003807:	7e 3e                	jle    140003847 <__pformat_int+0x1cc>
   140003809:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000380d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003810:	89 c1                	mov    ecx,eax
   140003812:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003816:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   14000381a:	89 c2                	mov    edx,eax
   14000381c:	89 c8                	mov    eax,ecx
   14000381e:	29 d0                	sub    eax,edx
   140003820:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003823:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003827:	7e 1e                	jle    140003847 <__pformat_int+0x1cc>
   140003829:	eb 0f                	jmp    14000383a <__pformat_int+0x1bf>
   14000382b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000382f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003833:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003837:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000383a:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000383d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003840:	89 55 f4             	mov    DWORD PTR [rbp-0xc],edx
   140003843:	85 c0                	test   eax,eax
   140003845:	7f e4                	jg     14000382b <__pformat_int+0x1b0>
   140003847:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000384b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000384f:	75 1a                	jne    14000386b <__pformat_int+0x1f0>
   140003851:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003855:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003858:	85 c0                	test   eax,eax
   14000385a:	74 0f                	je     14000386b <__pformat_int+0x1f0>
   14000385c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003860:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003864:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003868:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000386b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000386f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003872:	85 c0                	test   eax,eax
   140003874:	0f 8e ce 00 00 00    	jle    140003948 <__pformat_int+0x2cd>
   14000387a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000387e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003881:	89 c1                	mov    ecx,eax
   140003883:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003887:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   14000388b:	89 c2                	mov    edx,eax
   14000388d:	89 c8                	mov    eax,ecx
   14000388f:	29 d0                	sub    eax,edx
   140003891:	89 c2                	mov    edx,eax
   140003893:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003897:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000389a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000389e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038a1:	85 c0                	test   eax,eax
   1400038a3:	0f 8e 9f 00 00 00    	jle    140003948 <__pformat_int+0x2cd>
   1400038a9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038ad:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038b0:	25 c0 01 00 00       	and    eax,0x1c0
   1400038b5:	85 c0                	test   eax,eax
   1400038b7:	74 11                	je     1400038ca <__pformat_int+0x24f>
   1400038b9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038bd:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038c0:	8d 50 ff             	lea    edx,[rax-0x1]
   1400038c3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038c7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400038ca:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038ce:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400038d1:	85 c0                	test   eax,eax
   1400038d3:	79 3b                	jns    140003910 <__pformat_int+0x295>
   1400038d5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038d9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038dc:	25 00 06 00 00       	and    eax,0x600
   1400038e1:	3d 00 02 00 00       	cmp    eax,0x200
   1400038e6:	75 28                	jne    140003910 <__pformat_int+0x295>
   1400038e8:	eb 0f                	jmp    1400038f9 <__pformat_int+0x27e>
   1400038ea:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038ee:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400038f2:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400038f6:	c6 00 30             	mov    BYTE PTR [rax],0x30
   1400038f9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038fd:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003900:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003903:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003907:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000390a:	85 c0                	test   eax,eax
   14000390c:	7f dc                	jg     1400038ea <__pformat_int+0x26f>
   14000390e:	eb 38                	jmp    140003948 <__pformat_int+0x2cd>
   140003910:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003914:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003917:	25 00 04 00 00       	and    eax,0x400
   14000391c:	85 c0                	test   eax,eax
   14000391e:	75 28                	jne    140003948 <__pformat_int+0x2cd>
   140003920:	eb 11                	jmp    140003933 <__pformat_int+0x2b8>
   140003922:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003926:	48 89 c2             	mov    rdx,rax
   140003929:	b9 20 00 00 00       	mov    ecx,0x20
   14000392e:	e8 dd f8 ff ff       	call   140003210 <__pformat_putc>
   140003933:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003937:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000393a:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000393d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003941:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003944:	85 c0                	test   eax,eax
   140003946:	7f da                	jg     140003922 <__pformat_int+0x2a7>
   140003948:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000394c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000394f:	25 80 00 00 00       	and    eax,0x80
   140003954:	85 c0                	test   eax,eax
   140003956:	74 11                	je     140003969 <__pformat_int+0x2ee>
   140003958:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000395c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003960:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003964:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   140003967:	eb 5a                	jmp    1400039c3 <__pformat_int+0x348>
   140003969:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000396d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003970:	25 00 01 00 00       	and    eax,0x100
   140003975:	85 c0                	test   eax,eax
   140003977:	74 11                	je     14000398a <__pformat_int+0x30f>
   140003979:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000397d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003981:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003985:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   140003988:	eb 39                	jmp    1400039c3 <__pformat_int+0x348>
   14000398a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000398e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003991:	83 e0 40             	and    eax,0x40
   140003994:	85 c0                	test   eax,eax
   140003996:	74 2b                	je     1400039c3 <__pformat_int+0x348>
   140003998:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000399c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400039a0:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400039a4:	c6 00 20             	mov    BYTE PTR [rax],0x20
   1400039a7:	eb 1a                	jmp    1400039c3 <__pformat_int+0x348>
   1400039a9:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   1400039ae:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039b2:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400039b5:	0f be c0             	movsx  eax,al
   1400039b8:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400039bc:	89 c1                	mov    ecx,eax
   1400039be:	e8 4d f8 ff ff       	call   140003210 <__pformat_putc>
   1400039c3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039c7:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   1400039cb:	72 dc                	jb     1400039a9 <__pformat_int+0x32e>
   1400039cd:	eb 11                	jmp    1400039e0 <__pformat_int+0x365>
   1400039cf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400039d3:	48 89 c2             	mov    rdx,rax
   1400039d6:	b9 20 00 00 00       	mov    ecx,0x20
   1400039db:	e8 30 f8 ff ff       	call   140003210 <__pformat_putc>
   1400039e0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400039e4:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400039e7:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400039ea:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400039ee:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400039f1:	85 c0                	test   eax,eax
   1400039f3:	7f da                	jg     1400039cf <__pformat_int+0x354>
   1400039f5:	90                   	nop
   1400039f6:	90                   	nop
   1400039f7:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   1400039fb:	5b                   	pop    rbx
   1400039fc:	5d                   	pop    rbp
   1400039fd:	c3                   	ret

00000001400039fe <__pformat_xint>:
   1400039fe:	55                   	push   rbp
   1400039ff:	53                   	push   rbx
   140003a00:	48 83 ec 68          	sub    rsp,0x68
   140003a04:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003a09:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003a0c:	48 89 d3             	mov    rbx,rdx
   140003a0f:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140003a12:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
   140003a16:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003a1a:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   140003a1e:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003a22:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003a26:	74 1e                	je     140003a46 <__pformat_xint+0x48>
   140003a28:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003a2c:	74 06                	je     140003a34 <__pformat_xint+0x36>
   140003a2e:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003a32:	75 09                	jne    140003a3d <__pformat_xint+0x3f>
   140003a34:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003a3b:	eb 10                	jmp    140003a4d <__pformat_xint+0x4f>
   140003a3d:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140003a44:	eb 07                	jmp    140003a4d <__pformat_xint+0x4f>
   140003a46:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140003a4d:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003a51:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003a54:	49 89 d0             	mov    r8,rdx
   140003a57:	89 c2                	mov    edx,eax
   140003a59:	b9 02 00 00 00       	mov    ecx,0x2
   140003a5e:	e8 88 fb ff ff       	call   1400035eb <__pformat_int_bufsiz>
   140003a63:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140003a66:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
   140003a6d:	00 
   140003a6e:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140003a71:	48 98                	cdqe
   140003a73:	48 83 c0 0f          	add    rax,0xf
   140003a77:	48 c1 e8 04          	shr    rax,0x4
   140003a7b:	48 c1 e0 04          	shl    rax,0x4
   140003a7f:	e8 cc f6 ff ff       	call   140003150 <___chkstk_ms>
   140003a84:	48 29 c4             	sub    rsp,rax
   140003a87:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003a8c:	48 83 c0 0f          	add    rax,0xf
   140003a90:	48 c1 e8 04          	shr    rax,0x4
   140003a94:	48 c1 e0 04          	shl    rax,0x4
   140003a98:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140003a9c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003aa0:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003aa4:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003aa8:	74 1e                	je     140003ac8 <__pformat_xint+0xca>
   140003aaa:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003aae:	74 06                	je     140003ab6 <__pformat_xint+0xb8>
   140003ab0:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003ab4:	75 09                	jne    140003abf <__pformat_xint+0xc1>
   140003ab6:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140003abd:	eb 10                	jmp    140003acf <__pformat_xint+0xd1>
   140003abf:	c7 45 ec 0f 00 00 00 	mov    DWORD PTR [rbp-0x14],0xf
   140003ac6:	eb 67                	jmp    140003b2f <__pformat_xint+0x131>
   140003ac8:	c7 45 ec 07 00 00 00 	mov    DWORD PTR [rbp-0x14],0x7
   140003acf:	eb 5e                	jmp    140003b2f <__pformat_xint+0x131>
   140003ad1:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003ad5:	89 c2                	mov    edx,eax
   140003ad7:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140003ada:	21 d0                	and    eax,edx
   140003adc:	8d 48 30             	lea    ecx,[rax+0x30]
   140003adf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ae3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003ae7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003aeb:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003aef:	89 ca                	mov    edx,ecx
   140003af1:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003af5:	88 10                	mov    BYTE PTR [rax],dl
   140003af7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003afb:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003afe:	3c 39                	cmp    al,0x39
   140003b00:	7e 1a                	jle    140003b1c <__pformat_xint+0x11e>
   140003b02:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b06:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003b09:	83 c0 07             	add    eax,0x7
   140003b0c:	89 c2                	mov    edx,eax
   140003b0e:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140003b11:	83 e0 20             	and    eax,0x20
   140003b14:	09 c2                	or     edx,eax
   140003b16:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b1a:	88 10                	mov    BYTE PTR [rax],dl
   140003b1c:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140003b20:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003b23:	89 c1                	mov    ecx,eax
   140003b25:	48 d3 ea             	shr    rdx,cl
   140003b28:	48 89 d0             	mov    rax,rdx
   140003b2b:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003b2f:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003b33:	48 85 c0             	test   rax,rax
   140003b36:	75 99                	jne    140003ad1 <__pformat_xint+0xd3>
   140003b38:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b3c:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003b40:	75 13                	jne    140003b55 <__pformat_xint+0x157>
   140003b42:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b46:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003b49:	80 e4 f7             	and    ah,0xf7
   140003b4c:	89 c2                	mov    edx,eax
   140003b4e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b52:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003b55:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b59:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003b5c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003b5f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b63:	7e 3a                	jle    140003b9f <__pformat_xint+0x1a1>
   140003b65:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140003b68:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b6c:	48 2b 45 e0          	sub    rax,QWORD PTR [rbp-0x20]
   140003b70:	89 c1                	mov    ecx,eax
   140003b72:	89 d0                	mov    eax,edx
   140003b74:	29 c8                	sub    eax,ecx
   140003b76:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003b79:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b7d:	7e 20                	jle    140003b9f <__pformat_xint+0x1a1>
   140003b7f:	eb 0f                	jmp    140003b90 <__pformat_xint+0x192>
   140003b81:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b85:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b89:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b8d:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003b90:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003b93:	8d 50 ff             	lea    edx,[rax-0x1]
   140003b96:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003b99:	85 c0                	test   eax,eax
   140003b9b:	7f e4                	jg     140003b81 <__pformat_xint+0x183>
   140003b9d:	eb 25                	jmp    140003bc4 <__pformat_xint+0x1c6>
   140003b9f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003ba3:	75 1f                	jne    140003bc4 <__pformat_xint+0x1c6>
   140003ba5:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ba9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003bac:	25 00 08 00 00       	and    eax,0x800
   140003bb1:	85 c0                	test   eax,eax
   140003bb3:	74 0f                	je     140003bc4 <__pformat_xint+0x1c6>
   140003bb5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bb9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003bbd:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bc1:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003bc4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bc8:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003bcc:	75 1a                	jne    140003be8 <__pformat_xint+0x1ea>
   140003bce:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bd2:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003bd5:	85 c0                	test   eax,eax
   140003bd7:	74 0f                	je     140003be8 <__pformat_xint+0x1ea>
   140003bd9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bdd:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003be1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003be5:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003be8:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bec:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003bef:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003bf3:	48 2b 55 e0          	sub    rdx,QWORD PTR [rbp-0x20]
   140003bf7:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003bfa:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140003bfd:	7d 15                	jge    140003c14 <__pformat_xint+0x216>
   140003bff:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c03:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003c06:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140003c09:	89 c2                	mov    edx,eax
   140003c0b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c0f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003c12:	eb 0b                	jmp    140003c1f <__pformat_xint+0x221>
   140003c14:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c18:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003c1f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c23:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003c26:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003c29:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c2d:	7e 1a                	jle    140003c49 <__pformat_xint+0x24b>
   140003c2f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003c33:	74 14                	je     140003c49 <__pformat_xint+0x24b>
   140003c35:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c39:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c3c:	25 00 08 00 00       	and    eax,0x800
   140003c41:	85 c0                	test   eax,eax
   140003c43:	74 04                	je     140003c49 <__pformat_xint+0x24b>
   140003c45:	83 6d fc 02          	sub    DWORD PTR [rbp-0x4],0x2
   140003c49:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c4d:	7e 3c                	jle    140003c8b <__pformat_xint+0x28d>
   140003c4f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c53:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003c56:	85 c0                	test   eax,eax
   140003c58:	79 31                	jns    140003c8b <__pformat_xint+0x28d>
   140003c5a:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c5e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c61:	25 00 06 00 00       	and    eax,0x600
   140003c66:	3d 00 02 00 00       	cmp    eax,0x200
   140003c6b:	75 1e                	jne    140003c8b <__pformat_xint+0x28d>
   140003c6d:	eb 0f                	jmp    140003c7e <__pformat_xint+0x280>
   140003c6f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c73:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c77:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c7b:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c7e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003c81:	8d 50 ff             	lea    edx,[rax-0x1]
   140003c84:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c87:	85 c0                	test   eax,eax
   140003c89:	7f e4                	jg     140003c6f <__pformat_xint+0x271>
   140003c8b:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003c8f:	74 30                	je     140003cc1 <__pformat_xint+0x2c3>
   140003c91:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c95:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c98:	25 00 08 00 00       	and    eax,0x800
   140003c9d:	85 c0                	test   eax,eax
   140003c9f:	74 20                	je     140003cc1 <__pformat_xint+0x2c3>
   140003ca1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ca5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003ca9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003cad:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003cb0:	88 10                	mov    BYTE PTR [rax],dl
   140003cb2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003cb6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003cba:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003cbe:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003cc1:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003cc5:	7e 4c                	jle    140003d13 <__pformat_xint+0x315>
   140003cc7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ccb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003cce:	25 00 04 00 00       	and    eax,0x400
   140003cd3:	85 c0                	test   eax,eax
   140003cd5:	75 3c                	jne    140003d13 <__pformat_xint+0x315>
   140003cd7:	eb 11                	jmp    140003cea <__pformat_xint+0x2ec>
   140003cd9:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003cdd:	48 89 c2             	mov    rdx,rax
   140003ce0:	b9 20 00 00 00       	mov    ecx,0x20
   140003ce5:	e8 26 f5 ff ff       	call   140003210 <__pformat_putc>
   140003cea:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003ced:	8d 50 ff             	lea    edx,[rax-0x1]
   140003cf0:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003cf3:	85 c0                	test   eax,eax
   140003cf5:	7f e2                	jg     140003cd9 <__pformat_xint+0x2db>
   140003cf7:	eb 1a                	jmp    140003d13 <__pformat_xint+0x315>
   140003cf9:	48 83 6d f0 01       	sub    QWORD PTR [rbp-0x10],0x1
   140003cfe:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d02:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003d05:	0f be c0             	movsx  eax,al
   140003d08:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003d0c:	89 c1                	mov    ecx,eax
   140003d0e:	e8 fd f4 ff ff       	call   140003210 <__pformat_putc>
   140003d13:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d17:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140003d1b:	72 dc                	jb     140003cf9 <__pformat_xint+0x2fb>
   140003d1d:	eb 11                	jmp    140003d30 <__pformat_xint+0x332>
   140003d1f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003d23:	48 89 c2             	mov    rdx,rax
   140003d26:	b9 20 00 00 00       	mov    ecx,0x20
   140003d2b:	e8 e0 f4 ff ff       	call   140003210 <__pformat_putc>
   140003d30:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003d33:	8d 50 ff             	lea    edx,[rax-0x1]
   140003d36:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003d39:	85 c0                	test   eax,eax
   140003d3b:	7f e2                	jg     140003d1f <__pformat_xint+0x321>
   140003d3d:	90                   	nop
   140003d3e:	90                   	nop
   140003d3f:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003d43:	5b                   	pop    rbx
   140003d44:	5d                   	pop    rbp
   140003d45:	c3                   	ret

0000000140003d46 <init_fpreg_ldouble>:
   140003d46:	55                   	push   rbp
   140003d47:	53                   	push   rbx
   140003d48:	48 83 ec 28          	sub    rsp,0x28
   140003d4c:	48 8d 6c 24 20       	lea    rbp,[rsp+0x20]
   140003d51:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003d55:	48 89 d3             	mov    rbx,rdx
   140003d58:	db 2b                	fld    TBYTE PTR [rbx]
   140003d5a:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003d5d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140003d60:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003d63:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140003d67:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d6b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140003d6f:	48 89 01             	mov    QWORD PTR [rcx],rax
   140003d72:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
   140003d76:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003d7a:	48 83 c4 28          	add    rsp,0x28
   140003d7e:	5b                   	pop    rbx
   140003d7f:	5d                   	pop    rbp
   140003d80:	c3                   	ret

0000000140003d81 <__pformat_cvt>:
   140003d81:	55                   	push   rbp
   140003d82:	53                   	push   rbx
   140003d83:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140003d8a:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140003d91:	00 
   140003d92:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003d95:	48 89 d3             	mov    rbx,rdx
   140003d98:	db 2b                	fld    TBYTE PTR [rbx]
   140003d9a:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140003d9d:	44 89 45 30          	mov    DWORD PTR [rbp+0x30],r8d
   140003da1:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003da5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140003dac:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003db0:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003db3:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003db6:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140003dba:	48 89 c1             	mov    rcx,rax
   140003dbd:	e8 84 ff ff ff       	call   140003d46 <init_fpreg_ldouble>
   140003dc2:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003dc5:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003dc8:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140003dcc:	48 89 c1             	mov    rcx,rax
   140003dcf:	e8 9c 4e 00 00       	call   140008c70 <__fpclassifyl>
   140003dd4:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003dd7:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003dda:	25 00 01 00 00       	and    eax,0x100
   140003ddf:	85 c0                	test   eax,eax
   140003de1:	74 1d                	je     140003e00 <__pformat_cvt+0x7f>
   140003de3:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003de6:	25 00 04 00 00       	and    eax,0x400
   140003deb:	85 c0                	test   eax,eax
   140003ded:	74 07                	je     140003df6 <__pformat_cvt+0x75>
   140003def:	b8 03 00 00 00       	mov    eax,0x3
   140003df4:	eb 05                	jmp    140003dfb <__pformat_cvt+0x7a>
   140003df6:	b8 04 00 00 00       	mov    eax,0x4
   140003dfb:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003dfe:	eb 4a                	jmp    140003e4a <__pformat_cvt+0xc9>
   140003e00:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e03:	25 00 04 00 00       	and    eax,0x400
   140003e08:	85 c0                	test   eax,eax
   140003e0a:	74 37                	je     140003e43 <__pformat_cvt+0xc2>
   140003e0c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e0f:	25 00 40 00 00       	and    eax,0x4000
   140003e14:	85 c0                	test   eax,eax
   140003e16:	74 10                	je     140003e28 <__pformat_cvt+0xa7>
   140003e18:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140003e1f:	c7 45 fc c3 bf ff ff 	mov    DWORD PTR [rbp-0x4],0xffffbfc3
   140003e26:	eb 22                	jmp    140003e4a <__pformat_cvt+0xc9>
   140003e28:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003e2f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003e33:	98                   	cwde
   140003e34:	25 ff 7f 00 00       	and    eax,0x7fff
   140003e39:	2d 3e 40 00 00       	sub    eax,0x403e
   140003e3e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003e41:	eb 07                	jmp    140003e4a <__pformat_cvt+0xc9>
   140003e43:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140003e4a:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e4d:	83 f8 04             	cmp    eax,0x4
   140003e50:	74 0e                	je     140003e60 <__pformat_cvt+0xdf>
   140003e52:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003e56:	98                   	cwde
   140003e57:	25 00 80 00 00       	and    eax,0x8000
   140003e5c:	89 c2                	mov    edx,eax
   140003e5e:	eb 05                	jmp    140003e65 <__pformat_cvt+0xe4>
   140003e60:	ba 00 00 00 00       	mov    edx,0x0
   140003e65:	48 8b 45 40          	mov    rax,QWORD PTR [rbp+0x40]
   140003e69:	89 10                	mov    DWORD PTR [rax],edx
   140003e6b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003e6e:	4c 8d 4d f8          	lea    r9,[rbp-0x8]
   140003e72:	4c 8d 45 e0          	lea    r8,[rbp-0x20]
   140003e76:	48 8d 0d f3 61 00 00 	lea    rcx,[rip+0x61f3]        # 14000a070 <fpi.0>
   140003e7d:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
   140003e81:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140003e86:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003e8a:	48 89 54 24 30       	mov    QWORD PTR [rsp+0x30],rdx
   140003e8f:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   140003e92:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140003e96:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003e99:	89 54 24 20          	mov    DWORD PTR [rsp+0x20],edx
   140003e9d:	89 c2                	mov    edx,eax
   140003e9f:	e8 96 24 00 00       	call   14000633a <__gdtoa>
   140003ea4:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140003eab:	5b                   	pop    rbx
   140003eac:	5d                   	pop    rbp
   140003ead:	c3                   	ret

0000000140003eae <__pformat_ecvt>:
   140003eae:	55                   	push   rbp
   140003eaf:	53                   	push   rbx
   140003eb0:	48 83 ec 58          	sub    rsp,0x58
   140003eb4:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003eb9:	48 89 cb             	mov    rbx,rcx
   140003ebc:	db 2b                	fld    TBYTE PTR [rbx]
   140003ebe:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003ec1:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003ec4:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003ec8:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003ecc:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003ecf:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003ed2:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003ed6:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003ed9:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003edd:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003ee1:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003ee6:	4d 89 c1             	mov    r9,r8
   140003ee9:	41 89 c8             	mov    r8d,ecx
   140003eec:	48 89 c2             	mov    rdx,rax
   140003eef:	b9 02 00 00 00       	mov    ecx,0x2
   140003ef4:	e8 88 fe ff ff       	call   140003d81 <__pformat_cvt>
   140003ef9:	48 83 c4 58          	add    rsp,0x58
   140003efd:	5b                   	pop    rbx
   140003efe:	5d                   	pop    rbp
   140003eff:	c3                   	ret

0000000140003f00 <__pformat_fcvt>:
   140003f00:	55                   	push   rbp
   140003f01:	53                   	push   rbx
   140003f02:	48 83 ec 58          	sub    rsp,0x58
   140003f06:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003f0b:	48 89 cb             	mov    rbx,rcx
   140003f0e:	db 2b                	fld    TBYTE PTR [rbx]
   140003f10:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003f13:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003f16:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003f1a:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003f1e:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003f21:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003f24:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003f28:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003f2b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003f2f:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003f33:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003f38:	4d 89 c1             	mov    r9,r8
   140003f3b:	41 89 c8             	mov    r8d,ecx
   140003f3e:	48 89 c2             	mov    rdx,rax
   140003f41:	b9 03 00 00 00       	mov    ecx,0x3
   140003f46:	e8 36 fe ff ff       	call   140003d81 <__pformat_cvt>
   140003f4b:	48 83 c4 58          	add    rsp,0x58
   140003f4f:	5b                   	pop    rbx
   140003f50:	5d                   	pop    rbp
   140003f51:	c3                   	ret

0000000140003f52 <__pformat_emit_radix_point>:
   140003f52:	55                   	push   rbp
   140003f53:	53                   	push   rbx
   140003f54:	48 83 ec 68          	sub    rsp,0x68
   140003f58:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003f5d:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003f61:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f65:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003f68:	83 f8 fd             	cmp    eax,0xfffffffd
   140003f6b:	75 48                	jne    140003fb5 <__pformat_emit_radix_point+0x63>
   140003f6d:	48 c7 45 cc 00 00 00 	mov    QWORD PTR [rbp-0x34],0x0
   140003f74:	00 
   140003f75:	e8 4e 57 00 00       	call   1400096c8 <localeconv>
   140003f7a:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003f7d:	48 8d 4d cc          	lea    rcx,[rbp-0x34]
   140003f81:	48 8d 45 d6          	lea    rax,[rbp-0x2a]
   140003f85:	49 89 c9             	mov    r9,rcx
   140003f88:	41 b8 10 00 00 00    	mov    r8d,0x10
   140003f8e:	48 89 c1             	mov    rcx,rax
   140003f91:	e8 6a 51 00 00       	call   140009100 <mbrtowc>
   140003f96:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140003f99:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   140003f9d:	7e 0c                	jle    140003fab <__pformat_emit_radix_point+0x59>
   140003f9f:	0f b7 55 d6          	movzx  edx,WORD PTR [rbp-0x2a]
   140003fa3:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fa7:	66 89 50 18          	mov    WORD PTR [rax+0x18],dx
   140003fab:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003faf:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140003fb2:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140003fb5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fb9:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003fbd:	66 85 c0             	test   ax,ax
   140003fc0:	0f 84 b8 00 00 00    	je     14000407e <__pformat_emit_radix_point+0x12c>
   140003fc6:	48 89 e0             	mov    rax,rsp
   140003fc9:	48 89 c3             	mov    rbx,rax
   140003fcc:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fd0:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003fd3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003fd6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003fd9:	48 63 d0             	movsxd rdx,eax
   140003fdc:	48 83 ea 01          	sub    rdx,0x1
   140003fe0:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140003fe4:	48 98                	cdqe
   140003fe6:	48 83 c0 0f          	add    rax,0xf
   140003fea:	48 c1 e8 04          	shr    rax,0x4
   140003fee:	48 c1 e0 04          	shl    rax,0x4
   140003ff2:	e8 59 f1 ff ff       	call   140003150 <___chkstk_ms>
   140003ff7:	48 29 c4             	sub    rsp,rax
   140003ffa:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003fff:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140004003:	48 c7 45 c4 00 00 00 	mov    QWORD PTR [rbp-0x3c],0x0
   14000400a:	00 
   14000400b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000400f:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140004013:	48 8d 4d c4          	lea    rcx,[rbp-0x3c]
   140004017:	0f b7 d0             	movzx  edx,ax
   14000401a:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000401e:	49 89 c8             	mov    r8,rcx
   140004021:	48 89 c1             	mov    rcx,rax
   140004024:	e8 87 50 00 00       	call   1400090b0 <wcrtomb>
   140004029:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000402c:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004030:	7e 36                	jle    140004068 <__pformat_emit_radix_point+0x116>
   140004032:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140004036:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000403a:	eb 1d                	jmp    140004059 <__pformat_emit_radix_point+0x107>
   14000403c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004040:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004044:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140004048:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000404b:	0f be c0             	movsx  eax,al
   14000404e:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140004052:	89 c1                	mov    ecx,eax
   140004054:	e8 b7 f1 ff ff       	call   140003210 <__pformat_putc>
   140004059:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000405c:	8d 50 ff             	lea    edx,[rax-0x1]
   14000405f:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140004062:	85 c0                	test   eax,eax
   140004064:	7f d6                	jg     14000403c <__pformat_emit_radix_point+0xea>
   140004066:	eb 11                	jmp    140004079 <__pformat_emit_radix_point+0x127>
   140004068:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000406c:	48 89 c2             	mov    rdx,rax
   14000406f:	b9 2e 00 00 00       	mov    ecx,0x2e
   140004074:	e8 97 f1 ff ff       	call   140003210 <__pformat_putc>
   140004079:	48 89 dc             	mov    rsp,rbx
   14000407c:	eb 11                	jmp    14000408f <__pformat_emit_radix_point+0x13d>
   14000407e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004082:	48 89 c2             	mov    rdx,rax
   140004085:	b9 2e 00 00 00       	mov    ecx,0x2e
   14000408a:	e8 81 f1 ff ff       	call   140003210 <__pformat_putc>
   14000408f:	90                   	nop
   140004090:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140004094:	5b                   	pop    rbx
   140004095:	5d                   	pop    rbp
   140004096:	c3                   	ret

0000000140004097 <__pformat_emit_numeric_value>:
   140004097:	55                   	push   rbp
   140004098:	48 89 e5             	mov    rbp,rsp
   14000409b:	48 83 ec 30          	sub    rsp,0x30
   14000409f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400040a2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400040a6:	83 7d 10 2e          	cmp    DWORD PTR [rbp+0x10],0x2e
   1400040aa:	75 0e                	jne    1400040ba <__pformat_emit_numeric_value+0x23>
   1400040ac:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400040b0:	48 89 c1             	mov    rcx,rax
   1400040b3:	e8 9a fe ff ff       	call   140003f52 <__pformat_emit_radix_point>
   1400040b8:	eb 43                	jmp    1400040fd <__pformat_emit_numeric_value+0x66>
   1400040ba:	83 7d 10 2c          	cmp    DWORD PTR [rbp+0x10],0x2c
   1400040be:	75 2f                	jne    1400040ef <__pformat_emit_numeric_value+0x58>
   1400040c0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400040c4:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400040c8:	66 89 45 fe          	mov    WORD PTR [rbp-0x2],ax
   1400040cc:	0f b7 45 fe          	movzx  eax,WORD PTR [rbp-0x2]
   1400040d0:	66 85 c0             	test   ax,ax
   1400040d3:	74 28                	je     1400040fd <__pformat_emit_numeric_value+0x66>
   1400040d5:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400040d9:	48 8d 45 fe          	lea    rax,[rbp-0x2]
   1400040dd:	49 89 d0             	mov    r8,rdx
   1400040e0:	ba 01 00 00 00       	mov    edx,0x1
   1400040e5:	48 89 c1             	mov    rcx,rax
   1400040e8:	e8 2c f3 ff ff       	call   140003419 <__pformat_wputchars>
   1400040ed:	eb 0e                	jmp    1400040fd <__pformat_emit_numeric_value+0x66>
   1400040ef:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400040f3:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400040f6:	89 c1                	mov    ecx,eax
   1400040f8:	e8 13 f1 ff ff       	call   140003210 <__pformat_putc>
   1400040fd:	90                   	nop
   1400040fe:	48 83 c4 30          	add    rsp,0x30
   140004102:	5d                   	pop    rbp
   140004103:	c3                   	ret

0000000140004104 <__pformat_emit_inf_or_nan>:
   140004104:	55                   	push   rbp
   140004105:	48 89 e5             	mov    rbp,rsp
   140004108:	48 83 ec 40          	sub    rsp,0x40
   14000410c:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000410f:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004113:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140004117:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000411b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000411f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004123:	c7 40 10 ff ff ff ff 	mov    DWORD PTR [rax+0x10],0xffffffff
   14000412a:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   14000412e:	74 11                	je     140004141 <__pformat_emit_inf_or_nan+0x3d>
   140004130:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004134:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004138:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000413c:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   14000413f:	eb 3e                	jmp    14000417f <__pformat_emit_inf_or_nan+0x7b>
   140004141:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004145:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004148:	25 00 01 00 00       	and    eax,0x100
   14000414d:	85 c0                	test   eax,eax
   14000414f:	74 11                	je     140004162 <__pformat_emit_inf_or_nan+0x5e>
   140004151:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004155:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004159:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000415d:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   140004160:	eb 1d                	jmp    14000417f <__pformat_emit_inf_or_nan+0x7b>
   140004162:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004166:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004169:	83 e0 40             	and    eax,0x40
   14000416c:	85 c0                	test   eax,eax
   14000416e:	74 0f                	je     14000417f <__pformat_emit_inf_or_nan+0x7b>
   140004170:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004174:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004178:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000417c:	c6 00 20             	mov    BYTE PTR [rax],0x20
   14000417f:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140004186:	eb 38                	jmp    1400041c0 <__pformat_emit_inf_or_nan+0xbc>
   140004188:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000418c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004190:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004194:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004197:	83 e0 df             	and    eax,0xffffffdf
   14000419a:	41 89 c0             	mov    r8d,eax
   14000419d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400041a1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400041a4:	83 e0 20             	and    eax,0x20
   1400041a7:	89 c1                	mov    ecx,eax
   1400041a9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400041ad:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400041b1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400041b5:	44 89 c2             	mov    edx,r8d
   1400041b8:	09 ca                	or     edx,ecx
   1400041ba:	88 10                	mov    BYTE PTR [rax],dl
   1400041bc:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400041c0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400041c4:	7f c2                	jg     140004188 <__pformat_emit_inf_or_nan+0x84>
   1400041c6:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   1400041ca:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   1400041ce:	48 29 c2             	sub    rdx,rax
   1400041d1:	89 d1                	mov    ecx,edx
   1400041d3:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400041d7:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   1400041db:	49 89 d0             	mov    r8,rdx
   1400041de:	89 ca                	mov    edx,ecx
   1400041e0:	48 89 c1             	mov    rcx,rax
   1400041e3:	e8 ac f0 ff ff       	call   140003294 <__pformat_putchars>
   1400041e8:	90                   	nop
   1400041e9:	48 83 c4 40          	add    rsp,0x40
   1400041ed:	5d                   	pop    rbp
   1400041ee:	c3                   	ret

00000001400041ef <__pformat_emit_float>:
   1400041ef:	55                   	push   rbp
   1400041f0:	48 89 e5             	mov    rbp,rsp
   1400041f3:	48 83 ec 30          	sub    rsp,0x30
   1400041f7:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400041fa:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400041fe:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140004202:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004206:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000420a:	7e 2e                	jle    14000423a <__pformat_emit_float+0x4b>
   14000420c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004210:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004213:	39 45 20             	cmp    DWORD PTR [rbp+0x20],eax
   140004216:	7f 15                	jg     14000422d <__pformat_emit_float+0x3e>
   140004218:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000421c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000421f:	2b 45 20             	sub    eax,DWORD PTR [rbp+0x20]
   140004222:	89 c2                	mov    edx,eax
   140004224:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004228:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000422b:	eb 29                	jmp    140004256 <__pformat_emit_float+0x67>
   14000422d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004231:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004238:	eb 1c                	jmp    140004256 <__pformat_emit_float+0x67>
   14000423a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000423e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004241:	85 c0                	test   eax,eax
   140004243:	7e 11                	jle    140004256 <__pformat_emit_float+0x67>
   140004245:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004249:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000424c:	8d 50 ff             	lea    edx,[rax-0x1]
   14000424f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004253:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004256:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000425a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000425d:	85 c0                	test   eax,eax
   14000425f:	78 2b                	js     14000428c <__pformat_emit_float+0x9d>
   140004261:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004265:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004268:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000426c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000426f:	39 c2                	cmp    edx,eax
   140004271:	7e 19                	jle    14000428c <__pformat_emit_float+0x9d>
   140004273:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004277:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   14000427a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000427e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004281:	29 c2                	sub    edx,eax
   140004283:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004287:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000428a:	eb 0b                	jmp    140004297 <__pformat_emit_float+0xa8>
   14000428c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004290:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004297:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000429b:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000429e:	85 c0                	test   eax,eax
   1400042a0:	7e 2c                	jle    1400042ce <__pformat_emit_float+0xdf>
   1400042a2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042a6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400042a9:	85 c0                	test   eax,eax
   1400042ab:	7f 10                	jg     1400042bd <__pformat_emit_float+0xce>
   1400042ad:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042b1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400042b4:	25 00 08 00 00       	and    eax,0x800
   1400042b9:	85 c0                	test   eax,eax
   1400042bb:	74 11                	je     1400042ce <__pformat_emit_float+0xdf>
   1400042bd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042c1:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042c4:	8d 50 ff             	lea    edx,[rax-0x1]
   1400042c7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042cb:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400042ce:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400042d2:	7e 64                	jle    140004338 <__pformat_emit_float+0x149>
   1400042d4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042d8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400042db:	25 00 10 00 00       	and    eax,0x1000
   1400042e0:	85 c0                	test   eax,eax
   1400042e2:	74 54                	je     140004338 <__pformat_emit_float+0x149>
   1400042e4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042e8:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400042ec:	66 85 c0             	test   ax,ax
   1400042ef:	74 47                	je     140004338 <__pformat_emit_float+0x149>
   1400042f1:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400042f4:	83 c0 02             	add    eax,0x2
   1400042f7:	48 63 d0             	movsxd rdx,eax
   1400042fa:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   140004301:	48 c1 ea 20          	shr    rdx,0x20
   140004305:	c1 f8 1f             	sar    eax,0x1f
   140004308:	29 c2                	sub    edx,eax
   14000430a:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000430d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004310:	eb 15                	jmp    140004327 <__pformat_emit_float+0x138>
   140004312:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004316:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000431a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000431d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004320:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004324:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004327:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000432b:	7e 0b                	jle    140004338 <__pformat_emit_float+0x149>
   14000432d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004331:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004334:	85 c0                	test   eax,eax
   140004336:	7f da                	jg     140004312 <__pformat_emit_float+0x123>
   140004338:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000433c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000433f:	85 c0                	test   eax,eax
   140004341:	7e 27                	jle    14000436a <__pformat_emit_float+0x17b>
   140004343:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004347:	75 10                	jne    140004359 <__pformat_emit_float+0x16a>
   140004349:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000434d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004350:	25 c0 01 00 00       	and    eax,0x1c0
   140004355:	85 c0                	test   eax,eax
   140004357:	74 11                	je     14000436a <__pformat_emit_float+0x17b>
   140004359:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000435d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004360:	8d 50 ff             	lea    edx,[rax-0x1]
   140004363:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004367:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000436a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000436e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004371:	85 c0                	test   eax,eax
   140004373:	7e 38                	jle    1400043ad <__pformat_emit_float+0x1be>
   140004375:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004379:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000437c:	25 00 06 00 00       	and    eax,0x600
   140004381:	85 c0                	test   eax,eax
   140004383:	75 28                	jne    1400043ad <__pformat_emit_float+0x1be>
   140004385:	eb 11                	jmp    140004398 <__pformat_emit_float+0x1a9>
   140004387:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000438b:	48 89 c2             	mov    rdx,rax
   14000438e:	b9 20 00 00 00       	mov    ecx,0x20
   140004393:	e8 78 ee ff ff       	call   140003210 <__pformat_putc>
   140004398:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000439c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000439f:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400043a2:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400043a6:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400043a9:	85 c0                	test   eax,eax
   1400043ab:	7f da                	jg     140004387 <__pformat_emit_float+0x198>
   1400043ad:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400043b1:	74 13                	je     1400043c6 <__pformat_emit_float+0x1d7>
   1400043b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043b7:	48 89 c2             	mov    rdx,rax
   1400043ba:	b9 2d 00 00 00       	mov    ecx,0x2d
   1400043bf:	e8 4c ee ff ff       	call   140003210 <__pformat_putc>
   1400043c4:	eb 42                	jmp    140004408 <__pformat_emit_float+0x219>
   1400043c6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043ca:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043cd:	25 00 01 00 00       	and    eax,0x100
   1400043d2:	85 c0                	test   eax,eax
   1400043d4:	74 13                	je     1400043e9 <__pformat_emit_float+0x1fa>
   1400043d6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043da:	48 89 c2             	mov    rdx,rax
   1400043dd:	b9 2b 00 00 00       	mov    ecx,0x2b
   1400043e2:	e8 29 ee ff ff       	call   140003210 <__pformat_putc>
   1400043e7:	eb 1f                	jmp    140004408 <__pformat_emit_float+0x219>
   1400043e9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043ed:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043f0:	83 e0 40             	and    eax,0x40
   1400043f3:	85 c0                	test   eax,eax
   1400043f5:	74 11                	je     140004408 <__pformat_emit_float+0x219>
   1400043f7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043fb:	48 89 c2             	mov    rdx,rax
   1400043fe:	b9 20 00 00 00       	mov    ecx,0x20
   140004403:	e8 08 ee ff ff       	call   140003210 <__pformat_putc>
   140004408:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000440c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000440f:	85 c0                	test   eax,eax
   140004411:	7e 3b                	jle    14000444e <__pformat_emit_float+0x25f>
   140004413:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004417:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000441a:	25 00 06 00 00       	and    eax,0x600
   14000441f:	3d 00 02 00 00       	cmp    eax,0x200
   140004424:	75 28                	jne    14000444e <__pformat_emit_float+0x25f>
   140004426:	eb 11                	jmp    140004439 <__pformat_emit_float+0x24a>
   140004428:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000442c:	48 89 c2             	mov    rdx,rax
   14000442f:	b9 30 00 00 00       	mov    ecx,0x30
   140004434:	e8 d7 ed ff ff       	call   140003210 <__pformat_putc>
   140004439:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000443d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004440:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004443:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004447:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000444a:	85 c0                	test   eax,eax
   14000444c:	7f da                	jg     140004428 <__pformat_emit_float+0x239>
   14000444e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004452:	0f 8e a7 00 00 00    	jle    1400044ff <__pformat_emit_float+0x310>
   140004458:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000445c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000445f:	84 c0                	test   al,al
   140004461:	74 14                	je     140004477 <__pformat_emit_float+0x288>
   140004463:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004467:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000446b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000446f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004472:	0f be c0             	movsx  eax,al
   140004475:	eb 05                	jmp    14000447c <__pformat_emit_float+0x28d>
   140004477:	b8 30 00 00 00       	mov    eax,0x30
   14000447c:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004480:	89 c1                	mov    ecx,eax
   140004482:	e8 89 ed ff ff       	call   140003210 <__pformat_putc>
   140004487:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   14000448b:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000448f:	74 62                	je     1400044f3 <__pformat_emit_float+0x304>
   140004491:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004495:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004498:	25 00 10 00 00       	and    eax,0x1000
   14000449d:	85 c0                	test   eax,eax
   14000449f:	74 52                	je     1400044f3 <__pformat_emit_float+0x304>
   1400044a1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044a5:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400044a9:	66 85 c0             	test   ax,ax
   1400044ac:	74 45                	je     1400044f3 <__pformat_emit_float+0x304>
   1400044ae:	8b 4d 20             	mov    ecx,DWORD PTR [rbp+0x20]
   1400044b1:	48 63 c1             	movsxd rax,ecx
   1400044b4:	48 69 c0 56 55 55 55 	imul   rax,rax,0x55555556
   1400044bb:	48 c1 e8 20          	shr    rax,0x20
   1400044bf:	48 89 c2             	mov    rdx,rax
   1400044c2:	89 c8                	mov    eax,ecx
   1400044c4:	c1 f8 1f             	sar    eax,0x1f
   1400044c7:	29 c2                	sub    edx,eax
   1400044c9:	89 d0                	mov    eax,edx
   1400044cb:	01 c0                	add    eax,eax
   1400044cd:	01 d0                	add    eax,edx
   1400044cf:	29 c1                	sub    ecx,eax
   1400044d1:	89 ca                	mov    edx,ecx
   1400044d3:	85 d2                	test   edx,edx
   1400044d5:	75 1c                	jne    1400044f3 <__pformat_emit_float+0x304>
   1400044d7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044db:	48 83 c0 20          	add    rax,0x20
   1400044df:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400044e3:	49 89 d0             	mov    r8,rdx
   1400044e6:	ba 01 00 00 00       	mov    edx,0x1
   1400044eb:	48 89 c1             	mov    rcx,rax
   1400044ee:	e8 26 ef ff ff       	call   140003419 <__pformat_wputchars>
   1400044f3:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400044f7:	0f 8f 5b ff ff ff    	jg     140004458 <__pformat_emit_float+0x269>
   1400044fd:	eb 11                	jmp    140004510 <__pformat_emit_float+0x321>
   1400044ff:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004503:	48 89 c2             	mov    rdx,rax
   140004506:	b9 30 00 00 00       	mov    ecx,0x30
   14000450b:	e8 00 ed ff ff       	call   140003210 <__pformat_putc>
   140004510:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004514:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004517:	85 c0                	test   eax,eax
   140004519:	7f 10                	jg     14000452b <__pformat_emit_float+0x33c>
   14000451b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000451f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004522:	25 00 08 00 00       	and    eax,0x800
   140004527:	85 c0                	test   eax,eax
   140004529:	74 0c                	je     140004537 <__pformat_emit_float+0x348>
   14000452b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000452f:	48 89 c1             	mov    rcx,rax
   140004532:	e8 1b fa ff ff       	call   140003f52 <__pformat_emit_radix_point>
   140004537:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000453b:	79 5f                	jns    14000459c <__pformat_emit_float+0x3ad>
   14000453d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004541:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004544:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004547:	01 c2                	add    edx,eax
   140004549:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000454d:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004550:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004554:	48 89 c2             	mov    rdx,rax
   140004557:	b9 30 00 00 00       	mov    ecx,0x30
   14000455c:	e8 af ec ff ff       	call   140003210 <__pformat_putc>
   140004561:	83 45 20 01          	add    DWORD PTR [rbp+0x20],0x1
   140004565:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004569:	78 e5                	js     140004550 <__pformat_emit_float+0x361>
   14000456b:	eb 2f                	jmp    14000459c <__pformat_emit_float+0x3ad>
   14000456d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004571:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004574:	84 c0                	test   al,al
   140004576:	74 14                	je     14000458c <__pformat_emit_float+0x39d>
   140004578:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000457c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004580:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004584:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004587:	0f be c0             	movsx  eax,al
   14000458a:	eb 05                	jmp    140004591 <__pformat_emit_float+0x3a2>
   14000458c:	b8 30 00 00 00       	mov    eax,0x30
   140004591:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004595:	89 c1                	mov    ecx,eax
   140004597:	e8 74 ec ff ff       	call   140003210 <__pformat_putc>
   14000459c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045a0:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400045a3:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400045a6:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400045aa:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   1400045ad:	85 c0                	test   eax,eax
   1400045af:	7f bc                	jg     14000456d <__pformat_emit_float+0x37e>
   1400045b1:	90                   	nop
   1400045b2:	90                   	nop
   1400045b3:	48 83 c4 30          	add    rsp,0x30
   1400045b7:	5d                   	pop    rbp
   1400045b8:	c3                   	ret

00000001400045b9 <__pformat_emit_efloat>:
   1400045b9:	55                   	push   rbp
   1400045ba:	48 89 e5             	mov    rbp,rsp
   1400045bd:	48 83 ec 50          	sub    rsp,0x50
   1400045c1:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400045c4:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400045c8:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   1400045cc:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400045d0:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400045d7:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   1400045db:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400045df:	79 09                	jns    1400045ea <__pformat_emit_efloat+0x31>
   1400045e1:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400045e8:	eb 05                	jmp    1400045ef <__pformat_emit_efloat+0x36>
   1400045ea:	b8 00 00 00 00       	mov    eax,0x0
   1400045ef:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400045f3:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   1400045f6:	48 98                	cdqe
   1400045f8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400045fc:	eb 04                	jmp    140004602 <__pformat_emit_efloat+0x49>
   1400045fe:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140004602:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004605:	48 63 d0             	movsxd rdx,eax
   140004608:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   14000460f:	48 c1 ea 20          	shr    rdx,0x20
   140004613:	89 d1                	mov    ecx,edx
   140004615:	c1 f9 02             	sar    ecx,0x2
   140004618:	99                   	cdq
   140004619:	89 c8                	mov    eax,ecx
   14000461b:	29 d0                	sub    eax,edx
   14000461d:	89 45 20             	mov    DWORD PTR [rbp+0x20],eax
   140004620:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004624:	75 d8                	jne    1400045fe <__pformat_emit_efloat+0x45>
   140004626:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000462a:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   14000462d:	83 f8 ff             	cmp    eax,0xffffffff
   140004630:	75 0b                	jne    14000463d <__pformat_emit_efloat+0x84>
   140004632:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004636:	c7 40 2c 02 00 00 00 	mov    DWORD PTR [rax+0x2c],0x2
   14000463d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004641:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004644:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004647:	7d 0a                	jge    140004653 <__pformat_emit_efloat+0x9a>
   140004649:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000464d:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004650:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004653:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004657:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000465a:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   14000465e:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004661:	7d 15                	jge    140004678 <__pformat_emit_efloat+0xbf>
   140004663:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004667:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000466a:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   14000466d:	89 c2                	mov    edx,eax
   14000466f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004673:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004676:	eb 0b                	jmp    140004683 <__pformat_emit_efloat+0xca>
   140004678:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000467c:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004683:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004687:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000468b:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000468e:	49 89 c9             	mov    r9,rcx
   140004691:	41 b8 01 00 00 00    	mov    r8d,0x1
   140004697:	89 c1                	mov    ecx,eax
   140004699:	e8 51 fb ff ff       	call   1400041ef <__pformat_emit_float>
   14000469e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046a2:	8b 50 2c             	mov    edx,DWORD PTR [rax+0x2c]
   1400046a5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046a9:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400046ac:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046b0:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400046b3:	0d c0 01 00 00       	or     eax,0x1c0
   1400046b8:	89 c2                	mov    edx,eax
   1400046ba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046be:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   1400046c1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046c5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400046c8:	83 e0 20             	and    eax,0x20
   1400046cb:	83 c8 45             	or     eax,0x45
   1400046ce:	89 c1                	mov    ecx,eax
   1400046d0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046d4:	48 89 c2             	mov    rdx,rax
   1400046d7:	e8 34 eb ff ff       	call   140003210 <__pformat_putc>
   1400046dc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046e0:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400046e3:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400046e6:	83 ea 01             	sub    edx,0x1
   1400046e9:	01 c2                	add    edx,eax
   1400046eb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046ef:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400046f2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400046f6:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400046fa:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400046fe:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140004702:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004706:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000470a:	48 89 c1             	mov    rcx,rax
   14000470d:	e8 69 ef ff ff       	call   14000367b <__pformat_int>
   140004712:	90                   	nop
   140004713:	48 83 c4 50          	add    rsp,0x50
   140004717:	5d                   	pop    rbp
   140004718:	c3                   	ret

0000000140004719 <__pformat_float>:
   140004719:	55                   	push   rbp
   14000471a:	53                   	push   rbx
   14000471b:	48 83 ec 58          	sub    rsp,0x58
   14000471f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004724:	48 89 cb             	mov    rbx,rcx
   140004727:	db 2b                	fld    TBYTE PTR [rbx]
   140004729:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000472c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004730:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004734:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004737:	85 c0                	test   eax,eax
   140004739:	79 0b                	jns    140004746 <__pformat_float+0x2d>
   14000473b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000473f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004746:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000474a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000474d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004750:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004753:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   140004757:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000475b:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000475f:	4d 89 c1             	mov    r9,r8
   140004762:	49 89 c8             	mov    r8,rcx
   140004765:	48 89 c1             	mov    rcx,rax
   140004768:	e8 93 f7 ff ff       	call   140003f00 <__pformat_fcvt>
   14000476d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004771:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004774:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   140004779:	75 17                	jne    140004792 <__pformat_float+0x79>
   14000477b:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000477e:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004782:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004786:	49 89 c8             	mov    r8,rcx
   140004789:	89 c1                	mov    ecx,eax
   14000478b:	e8 74 f9 ff ff       	call   140004104 <__pformat_emit_inf_or_nan>
   140004790:	eb 43                	jmp    1400047d5 <__pformat_float+0xbc>
   140004792:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004795:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004798:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000479c:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400047a0:	4d 89 c1             	mov    r9,r8
   1400047a3:	41 89 c8             	mov    r8d,ecx
   1400047a6:	89 c1                	mov    ecx,eax
   1400047a8:	e8 42 fa ff ff       	call   1400041ef <__pformat_emit_float>
   1400047ad:	eb 11                	jmp    1400047c0 <__pformat_float+0xa7>
   1400047af:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047b3:	48 89 c2             	mov    rdx,rax
   1400047b6:	b9 20 00 00 00       	mov    ecx,0x20
   1400047bb:	e8 50 ea ff ff       	call   140003210 <__pformat_putc>
   1400047c0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047c4:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400047c7:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400047ca:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400047ce:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400047d1:	85 c0                	test   eax,eax
   1400047d3:	7f da                	jg     1400047af <__pformat_float+0x96>
   1400047d5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400047d9:	48 89 c1             	mov    rcx,rax
   1400047dc:	e8 4e 17 00 00       	call   140005f2f <__freedtoa>
   1400047e1:	90                   	nop
   1400047e2:	48 83 c4 58          	add    rsp,0x58
   1400047e6:	5b                   	pop    rbx
   1400047e7:	5d                   	pop    rbp
   1400047e8:	c3                   	ret

00000001400047e9 <__pformat_efloat>:
   1400047e9:	55                   	push   rbp
   1400047ea:	53                   	push   rbx
   1400047eb:	48 83 ec 58          	sub    rsp,0x58
   1400047ef:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400047f4:	48 89 cb             	mov    rbx,rcx
   1400047f7:	db 2b                	fld    TBYTE PTR [rbx]
   1400047f9:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   1400047fc:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004800:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004804:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004807:	85 c0                	test   eax,eax
   140004809:	79 0b                	jns    140004816 <__pformat_efloat+0x2d>
   14000480b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000480f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004816:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000481a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000481d:	8d 50 01             	lea    edx,[rax+0x1]
   140004820:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004823:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004826:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000482a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000482e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004832:	4d 89 c1             	mov    r9,r8
   140004835:	49 89 c8             	mov    r8,rcx
   140004838:	48 89 c1             	mov    rcx,rax
   14000483b:	e8 6e f6 ff ff       	call   140003eae <__pformat_ecvt>
   140004840:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004844:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004847:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000484c:	75 17                	jne    140004865 <__pformat_efloat+0x7c>
   14000484e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004851:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004855:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004859:	49 89 c8             	mov    r8,rcx
   14000485c:	89 c1                	mov    ecx,eax
   14000485e:	e8 a1 f8 ff ff       	call   140004104 <__pformat_emit_inf_or_nan>
   140004863:	eb 1b                	jmp    140004880 <__pformat_efloat+0x97>
   140004865:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004868:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000486b:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000486f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004873:	4d 89 c1             	mov    r9,r8
   140004876:	41 89 c8             	mov    r8d,ecx
   140004879:	89 c1                	mov    ecx,eax
   14000487b:	e8 39 fd ff ff       	call   1400045b9 <__pformat_emit_efloat>
   140004880:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004884:	48 89 c1             	mov    rcx,rax
   140004887:	e8 a3 16 00 00       	call   140005f2f <__freedtoa>
   14000488c:	90                   	nop
   14000488d:	48 83 c4 58          	add    rsp,0x58
   140004891:	5b                   	pop    rbx
   140004892:	5d                   	pop    rbp
   140004893:	c3                   	ret

0000000140004894 <__pformat_gfloat>:
   140004894:	55                   	push   rbp
   140004895:	53                   	push   rbx
   140004896:	48 83 ec 58          	sub    rsp,0x58
   14000489a:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   14000489f:	48 89 cb             	mov    rbx,rcx
   1400048a2:	db 2b                	fld    TBYTE PTR [rbx]
   1400048a4:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   1400048a7:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400048ab:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048af:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400048b2:	85 c0                	test   eax,eax
   1400048b4:	79 0d                	jns    1400048c3 <__pformat_gfloat+0x2f>
   1400048b6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048ba:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   1400048c1:	eb 16                	jmp    1400048d9 <__pformat_gfloat+0x45>
   1400048c3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048c7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400048ca:	85 c0                	test   eax,eax
   1400048cc:	75 0b                	jne    1400048d9 <__pformat_gfloat+0x45>
   1400048ce:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048d2:	c7 40 10 01 00 00 00 	mov    DWORD PTR [rax+0x10],0x1
   1400048d9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048dd:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400048e0:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   1400048e3:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   1400048e6:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   1400048ea:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   1400048ee:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400048f2:	4d 89 c1             	mov    r9,r8
   1400048f5:	49 89 c8             	mov    r8,rcx
   1400048f8:	48 89 c1             	mov    rcx,rax
   1400048fb:	e8 ae f5 ff ff       	call   140003eae <__pformat_ecvt>
   140004900:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004904:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004907:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000490c:	75 1a                	jne    140004928 <__pformat_gfloat+0x94>
   14000490e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004911:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004915:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004919:	49 89 c8             	mov    r8,rcx
   14000491c:	89 c1                	mov    ecx,eax
   14000491e:	e8 e1 f7 ff ff       	call   140004104 <__pformat_emit_inf_or_nan>
   140004923:	e9 14 01 00 00       	jmp    140004a3c <__pformat_gfloat+0x1a8>
   140004928:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000492b:	83 f8 fd             	cmp    eax,0xfffffffd
   14000492e:	0f 8c b2 00 00 00    	jl     1400049e6 <__pformat_gfloat+0x152>
   140004934:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004938:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000493b:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000493e:	39 c2                	cmp    edx,eax
   140004940:	0f 8c a0 00 00 00    	jl     1400049e6 <__pformat_gfloat+0x152>
   140004946:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000494a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000494d:	25 00 08 00 00       	and    eax,0x800
   140004952:	85 c0                	test   eax,eax
   140004954:	74 15                	je     14000496b <__pformat_gfloat+0xd7>
   140004956:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000495a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000495d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004960:	29 c2                	sub    edx,eax
   140004962:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004966:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004969:	eb 20                	jmp    14000498b <__pformat_gfloat+0xf7>
   14000496b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000496f:	48 89 c1             	mov    rcx,rax
   140004972:	e8 89 4d 00 00       	call   140009700 <strlen>
   140004977:	89 c1                	mov    ecx,eax
   140004979:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000497c:	89 c2                	mov    edx,eax
   14000497e:	89 c8                	mov    eax,ecx
   140004980:	29 d0                	sub    eax,edx
   140004982:	89 c2                	mov    edx,eax
   140004984:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004988:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000498b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000498f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004992:	85 c0                	test   eax,eax
   140004994:	79 0b                	jns    1400049a1 <__pformat_gfloat+0x10d>
   140004996:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000499a:	c7 40 10 00 00 00 00 	mov    DWORD PTR [rax+0x10],0x0
   1400049a1:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400049a4:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400049a7:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400049ab:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400049af:	4d 89 c1             	mov    r9,r8
   1400049b2:	41 89 c8             	mov    r8d,ecx
   1400049b5:	89 c1                	mov    ecx,eax
   1400049b7:	e8 33 f8 ff ff       	call   1400041ef <__pformat_emit_float>
   1400049bc:	eb 11                	jmp    1400049cf <__pformat_gfloat+0x13b>
   1400049be:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049c2:	48 89 c2             	mov    rdx,rax
   1400049c5:	b9 20 00 00 00       	mov    ecx,0x20
   1400049ca:	e8 41 e8 ff ff       	call   140003210 <__pformat_putc>
   1400049cf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049d3:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400049d6:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400049d9:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400049dd:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400049e0:	85 c0                	test   eax,eax
   1400049e2:	7f da                	jg     1400049be <__pformat_gfloat+0x12a>
   1400049e4:	eb 56                	jmp    140004a3c <__pformat_gfloat+0x1a8>
   1400049e6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049ea:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400049ed:	25 00 08 00 00       	and    eax,0x800
   1400049f2:	85 c0                	test   eax,eax
   1400049f4:	74 13                	je     140004a09 <__pformat_gfloat+0x175>
   1400049f6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049fa:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400049fd:	8d 50 ff             	lea    edx,[rax-0x1]
   140004a00:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a04:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004a07:	eb 18                	jmp    140004a21 <__pformat_gfloat+0x18d>
   140004a09:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004a0d:	48 89 c1             	mov    rcx,rax
   140004a10:	e8 eb 4c 00 00       	call   140009700 <strlen>
   140004a15:	83 e8 01             	sub    eax,0x1
   140004a18:	89 c2                	mov    edx,eax
   140004a1a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a1e:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004a21:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004a24:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004a27:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   140004a2b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004a2f:	4d 89 c1             	mov    r9,r8
   140004a32:	41 89 c8             	mov    r8d,ecx
   140004a35:	89 c1                	mov    ecx,eax
   140004a37:	e8 7d fb ff ff       	call   1400045b9 <__pformat_emit_efloat>
   140004a3c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004a40:	48 89 c1             	mov    rcx,rax
   140004a43:	e8 e7 14 00 00       	call   140005f2f <__freedtoa>
   140004a48:	90                   	nop
   140004a49:	48 83 c4 58          	add    rsp,0x58
   140004a4d:	5b                   	pop    rbx
   140004a4e:	5d                   	pop    rbp
   140004a4f:	c3                   	ret

0000000140004a50 <__pformat_emit_xfloat>:
   140004a50:	55                   	push   rbp
   140004a51:	53                   	push   rbx
   140004a52:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140004a59:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140004a60:	00 
   140004a61:	48 89 cb             	mov    rbx,rcx
   140004a64:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004a68:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004a6c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004a70:	66 c7 45 f6 02 00    	mov    WORD PTR [rbp-0xa],0x2
   140004a76:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a79:	48 85 c0             	test   rax,rax
   140004a7c:	75 09                	jne    140004a87 <__pformat_emit_xfloat+0x37>
   140004a7e:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004a82:	66 85 c0             	test   ax,ax
   140004a85:	74 0b                	je     140004a92 <__pformat_emit_xfloat+0x42>
   140004a87:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004a8b:	83 e8 03             	sub    eax,0x3
   140004a8e:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004a92:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a96:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a99:	85 c0                	test   eax,eax
   140004a9b:	0f 88 90 00 00 00    	js     140004b31 <__pformat_emit_xfloat+0xe1>
   140004aa1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004aa5:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004aa8:	83 f8 0e             	cmp    eax,0xe
   140004aab:	0f 8f 80 00 00 00    	jg     140004b31 <__pformat_emit_xfloat+0xe1>
   140004ab1:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004ab4:	48 d1 e8             	shr    rax,1
   140004ab7:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004aba:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004abd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ac1:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ac4:	b9 0e 00 00 00       	mov    ecx,0xe
   140004ac9:	29 c1                	sub    ecx,eax
   140004acb:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004ad2:	41 b8 04 00 00 00    	mov    r8d,0x4
   140004ad8:	89 c1                	mov    ecx,eax
   140004ada:	49 d3 e0             	shl    r8,cl
   140004add:	4c 89 c0             	mov    rax,r8
   140004ae0:	48 01 d0             	add    rax,rdx
   140004ae3:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004ae6:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004ae9:	48 85 c0             	test   rax,rax
   140004aec:	78 0b                	js     140004af9 <__pformat_emit_xfloat+0xa9>
   140004aee:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004af1:	48 01 c0             	add    rax,rax
   140004af4:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004af7:	eb 15                	jmp    140004b0e <__pformat_emit_xfloat+0xbe>
   140004af9:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004afd:	83 c0 04             	add    eax,0x4
   140004b00:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004b04:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b07:	48 c1 e8 03          	shr    rax,0x3
   140004b0b:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b0e:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004b11:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b15:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b18:	b9 0f 00 00 00       	mov    ecx,0xf
   140004b1d:	29 c1                	sub    ecx,eax
   140004b1f:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004b26:	89 c1                	mov    ecx,eax
   140004b28:	48 d3 ea             	shr    rdx,cl
   140004b2b:	48 89 d0             	mov    rax,rdx
   140004b2e:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b31:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b34:	48 85 c0             	test   rax,rax
   140004b37:	75 0f                	jne    140004b48 <__pformat_emit_xfloat+0xf8>
   140004b39:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b3d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b40:	85 c0                	test   eax,eax
   140004b42:	0f 8e f8 00 00 00    	jle    140004c40 <__pformat_emit_xfloat+0x1f0>
   140004b48:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b4c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b4f:	83 f8 0e             	cmp    eax,0xe
   140004b52:	7f 1a                	jg     140004b6e <__pformat_emit_xfloat+0x11e>
   140004b54:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b58:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b5b:	85 c0                	test   eax,eax
   140004b5d:	78 0f                	js     140004b6e <__pformat_emit_xfloat+0x11e>
   140004b5f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b63:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b66:	83 c0 01             	add    eax,0x1
   140004b69:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140004b6c:	eb 07                	jmp    140004b75 <__pformat_emit_xfloat+0x125>
   140004b6e:	c7 45 f0 10 00 00 00 	mov    DWORD PTR [rbp-0x10],0x10
   140004b75:	e9 bc 00 00 00       	jmp    140004c36 <__pformat_emit_xfloat+0x1e6>
   140004b7a:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b7d:	83 e0 0f             	and    eax,0xf
   140004b80:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140004b83:	83 7d f0 01          	cmp    DWORD PTR [rbp-0x10],0x1
   140004b87:	75 36                	jne    140004bbf <__pformat_emit_xfloat+0x16f>
   140004b89:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004b8d:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004b91:	72 1b                	jb     140004bae <__pformat_emit_xfloat+0x15e>
   140004b93:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b97:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004b9a:	25 00 08 00 00       	and    eax,0x800
   140004b9f:	85 c0                	test   eax,eax
   140004ba1:	75 0b                	jne    140004bae <__pformat_emit_xfloat+0x15e>
   140004ba3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ba7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004baa:	85 c0                	test   eax,eax
   140004bac:	7e 2d                	jle    140004bdb <__pformat_emit_xfloat+0x18b>
   140004bae:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004bb2:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004bb6:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004bba:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004bbd:	eb 1c                	jmp    140004bdb <__pformat_emit_xfloat+0x18b>
   140004bbf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bc3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bc6:	85 c0                	test   eax,eax
   140004bc8:	7e 11                	jle    140004bdb <__pformat_emit_xfloat+0x18b>
   140004bca:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bce:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bd1:	8d 50 ff             	lea    edx,[rax-0x1]
   140004bd4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bd8:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004bdb:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140004bdf:	75 15                	jne    140004bf6 <__pformat_emit_xfloat+0x1a6>
   140004be1:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004be5:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004be9:	72 0b                	jb     140004bf6 <__pformat_emit_xfloat+0x1a6>
   140004beb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bef:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bf2:	85 c0                	test   eax,eax
   140004bf4:	78 32                	js     140004c28 <__pformat_emit_xfloat+0x1d8>
   140004bf6:	83 7d e4 09          	cmp    DWORD PTR [rbp-0x1c],0x9
   140004bfa:	76 16                	jbe    140004c12 <__pformat_emit_xfloat+0x1c2>
   140004bfc:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004bff:	8d 50 37             	lea    edx,[rax+0x37]
   140004c02:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c06:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c09:	83 e0 20             	and    eax,0x20
   140004c0c:	09 d0                	or     eax,edx
   140004c0e:	89 c1                	mov    ecx,eax
   140004c10:	eb 08                	jmp    140004c1a <__pformat_emit_xfloat+0x1ca>
   140004c12:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004c15:	83 c0 30             	add    eax,0x30
   140004c18:	89 c1                	mov    ecx,eax
   140004c1a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c1e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c22:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c26:	88 08                	mov    BYTE PTR [rax],cl
   140004c28:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004c2b:	48 c1 e8 04          	shr    rax,0x4
   140004c2f:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004c32:	83 6d f0 01          	sub    DWORD PTR [rbp-0x10],0x1
   140004c36:	83 7d f0 00          	cmp    DWORD PTR [rbp-0x10],0x0
   140004c3a:	0f 8f 3a ff ff ff    	jg     140004b7a <__pformat_emit_xfloat+0x12a>
   140004c40:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c44:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140004c48:	75 39                	jne    140004c83 <__pformat_emit_xfloat+0x233>
   140004c4a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c4e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c51:	85 c0                	test   eax,eax
   140004c53:	7f 10                	jg     140004c65 <__pformat_emit_xfloat+0x215>
   140004c55:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c59:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c5c:	25 00 08 00 00       	and    eax,0x800
   140004c61:	85 c0                	test   eax,eax
   140004c63:	74 0f                	je     140004c74 <__pformat_emit_xfloat+0x224>
   140004c65:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c69:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c6d:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c71:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004c74:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c78:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c7c:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c80:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140004c83:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c87:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004c8a:	85 c0                	test   eax,eax
   140004c8c:	0f 8e e3 00 00 00    	jle    140004d75 <__pformat_emit_xfloat+0x325>
   140004c92:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c96:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004c9a:	48 29 c2             	sub    rdx,rax
   140004c9d:	89 55 ec             	mov    DWORD PTR [rbp-0x14],edx
   140004ca0:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004ca4:	98                   	cwde
   140004ca5:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004ca8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cac:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004caf:	85 c0                	test   eax,eax
   140004cb1:	7e 0a                	jle    140004cbd <__pformat_emit_xfloat+0x26d>
   140004cb3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cb7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004cba:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004cbd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cc1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004cc4:	25 c0 01 00 00       	and    eax,0x1c0
   140004cc9:	85 c0                	test   eax,eax
   140004ccb:	74 07                	je     140004cd4 <__pformat_emit_xfloat+0x284>
   140004ccd:	b8 06 00 00 00       	mov    eax,0x6
   140004cd2:	eb 05                	jmp    140004cd9 <__pformat_emit_xfloat+0x289>
   140004cd4:	b8 05 00 00 00       	mov    eax,0x5
   140004cd9:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004cdc:	eb 0f                	jmp    140004ced <__pformat_emit_xfloat+0x29d>
   140004cde:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
   140004ce2:	0f b7 45 f6          	movzx  eax,WORD PTR [rbp-0xa]
   140004ce6:	83 c0 01             	add    eax,0x1
   140004ce9:	66 89 45 f6          	mov    WORD PTR [rbp-0xa],ax
   140004ced:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140004cf0:	48 63 d0             	movsxd rdx,eax
   140004cf3:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   140004cfa:	48 c1 ea 20          	shr    rdx,0x20
   140004cfe:	89 d1                	mov    ecx,edx
   140004d00:	c1 f9 02             	sar    ecx,0x2
   140004d03:	99                   	cdq
   140004d04:	89 c8                	mov    eax,ecx
   140004d06:	29 d0                	sub    eax,edx
   140004d08:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004d0b:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140004d0f:	75 cd                	jne    140004cde <__pformat_emit_xfloat+0x28e>
   140004d11:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d15:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d18:	39 45 ec             	cmp    DWORD PTR [rbp-0x14],eax
   140004d1b:	7d 4d                	jge    140004d6a <__pformat_emit_xfloat+0x31a>
   140004d1d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d21:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d24:	2b 45 ec             	sub    eax,DWORD PTR [rbp-0x14]
   140004d27:	89 c2                	mov    edx,eax
   140004d29:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d2d:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004d30:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d34:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d37:	25 00 06 00 00       	and    eax,0x600
   140004d3c:	85 c0                	test   eax,eax
   140004d3e:	75 35                	jne    140004d75 <__pformat_emit_xfloat+0x325>
   140004d40:	eb 11                	jmp    140004d53 <__pformat_emit_xfloat+0x303>
   140004d42:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d46:	48 89 c2             	mov    rdx,rax
   140004d49:	b9 20 00 00 00       	mov    ecx,0x20
   140004d4e:	e8 bd e4 ff ff       	call   140003210 <__pformat_putc>
   140004d53:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d57:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d5a:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004d5d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004d61:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004d64:	85 c0                	test   eax,eax
   140004d66:	7f da                	jg     140004d42 <__pformat_emit_xfloat+0x2f2>
   140004d68:	eb 0b                	jmp    140004d75 <__pformat_emit_xfloat+0x325>
   140004d6a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d6e:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004d75:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d79:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d7c:	25 80 00 00 00       	and    eax,0x80
   140004d81:	85 c0                	test   eax,eax
   140004d83:	74 13                	je     140004d98 <__pformat_emit_xfloat+0x348>
   140004d85:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d89:	48 89 c2             	mov    rdx,rax
   140004d8c:	b9 2d 00 00 00       	mov    ecx,0x2d
   140004d91:	e8 7a e4 ff ff       	call   140003210 <__pformat_putc>
   140004d96:	eb 42                	jmp    140004dda <__pformat_emit_xfloat+0x38a>
   140004d98:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d9c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d9f:	25 00 01 00 00       	and    eax,0x100
   140004da4:	85 c0                	test   eax,eax
   140004da6:	74 13                	je     140004dbb <__pformat_emit_xfloat+0x36b>
   140004da8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dac:	48 89 c2             	mov    rdx,rax
   140004daf:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004db4:	e8 57 e4 ff ff       	call   140003210 <__pformat_putc>
   140004db9:	eb 1f                	jmp    140004dda <__pformat_emit_xfloat+0x38a>
   140004dbb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dbf:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004dc2:	83 e0 40             	and    eax,0x40
   140004dc5:	85 c0                	test   eax,eax
   140004dc7:	74 11                	je     140004dda <__pformat_emit_xfloat+0x38a>
   140004dc9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dcd:	48 89 c2             	mov    rdx,rax
   140004dd0:	b9 20 00 00 00       	mov    ecx,0x20
   140004dd5:	e8 36 e4 ff ff       	call   140003210 <__pformat_putc>
   140004dda:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dde:	48 89 c2             	mov    rdx,rax
   140004de1:	b9 30 00 00 00       	mov    ecx,0x30
   140004de6:	e8 25 e4 ff ff       	call   140003210 <__pformat_putc>
   140004deb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004def:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004df2:	83 e0 20             	and    eax,0x20
   140004df5:	83 c8 58             	or     eax,0x58
   140004df8:	89 c1                	mov    ecx,eax
   140004dfa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dfe:	48 89 c2             	mov    rdx,rax
   140004e01:	e8 0a e4 ff ff       	call   140003210 <__pformat_putc>
   140004e06:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e0a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004e0d:	85 c0                	test   eax,eax
   140004e0f:	7e 54                	jle    140004e65 <__pformat_emit_xfloat+0x415>
   140004e11:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e15:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e18:	25 00 02 00 00       	and    eax,0x200
   140004e1d:	85 c0                	test   eax,eax
   140004e1f:	74 44                	je     140004e65 <__pformat_emit_xfloat+0x415>
   140004e21:	eb 11                	jmp    140004e34 <__pformat_emit_xfloat+0x3e4>
   140004e23:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e27:	48 89 c2             	mov    rdx,rax
   140004e2a:	b9 30 00 00 00       	mov    ecx,0x30
   140004e2f:	e8 dc e3 ff ff       	call   140003210 <__pformat_putc>
   140004e34:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e38:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004e3b:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004e3e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e42:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004e45:	85 c0                	test   eax,eax
   140004e47:	7f da                	jg     140004e23 <__pformat_emit_xfloat+0x3d3>
   140004e49:	eb 1a                	jmp    140004e65 <__pformat_emit_xfloat+0x415>
   140004e4b:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   140004e50:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004e54:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004e57:	0f be c0             	movsx  eax,al
   140004e5a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e5e:	89 c1                	mov    ecx,eax
   140004e60:	e8 32 f2 ff ff       	call   140004097 <__pformat_emit_numeric_value>
   140004e65:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004e69:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004e6d:	72 dc                	jb     140004e4b <__pformat_emit_xfloat+0x3fb>
   140004e6f:	eb 11                	jmp    140004e82 <__pformat_emit_xfloat+0x432>
   140004e71:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e75:	48 89 c2             	mov    rdx,rax
   140004e78:	b9 30 00 00 00       	mov    ecx,0x30
   140004e7d:	e8 8e e3 ff ff       	call   140003210 <__pformat_putc>
   140004e82:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e86:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004e89:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004e8c:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e90:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   140004e93:	85 c0                	test   eax,eax
   140004e95:	7f da                	jg     140004e71 <__pformat_emit_xfloat+0x421>
   140004e97:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e9b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e9e:	83 e0 20             	and    eax,0x20
   140004ea1:	83 c8 50             	or     eax,0x50
   140004ea4:	89 c1                	mov    ecx,eax
   140004ea6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004eaa:	48 89 c2             	mov    rdx,rax
   140004ead:	e8 5e e3 ff ff       	call   140003210 <__pformat_putc>
   140004eb2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004eb6:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004eb9:	0f bf 45 f6          	movsx  eax,WORD PTR [rbp-0xa]
   140004ebd:	01 c2                	add    edx,eax
   140004ebf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ec3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004ec6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004eca:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004ecd:	0d c0 01 00 00       	or     eax,0x1c0
   140004ed2:	89 c2                	mov    edx,eax
   140004ed4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ed8:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004edb:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004edf:	66 85 c0             	test   ax,ax
   140004ee2:	79 09                	jns    140004eed <__pformat_emit_xfloat+0x49d>
   140004ee4:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004eeb:	eb 05                	jmp    140004ef2 <__pformat_emit_xfloat+0x4a2>
   140004eed:	b8 00 00 00 00       	mov    eax,0x0
   140004ef2:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140004ef6:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004efa:	48 0f bf c0          	movsx  rax,ax
   140004efe:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004f02:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140004f06:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140004f0a:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   140004f0e:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
   140004f12:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004f16:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140004f1a:	48 89 c1             	mov    rcx,rax
   140004f1d:	e8 59 e7 ff ff       	call   14000367b <__pformat_int>
   140004f22:	90                   	nop
   140004f23:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140004f2a:	5b                   	pop    rbx
   140004f2b:	5d                   	pop    rbp
   140004f2c:	c3                   	ret

0000000140004f2d <__pformat_xldouble>:
   140004f2d:	55                   	push   rbp
   140004f2e:	53                   	push   rbx
   140004f2f:	48 83 ec 78          	sub    rsp,0x78
   140004f33:	48 8d 6c 24 70       	lea    rbp,[rsp+0x70]
   140004f38:	48 89 cb             	mov    rbx,rcx
   140004f3b:	db 2b                	fld    TBYTE PTR [rbx]
   140004f3d:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004f40:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004f44:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004f4b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004f4f:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f52:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f55:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140004f59:	48 89 c1             	mov    rcx,rax
   140004f5c:	e8 e5 ed ff ff       	call   140003d46 <init_fpreg_ldouble>
   140004f61:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004f64:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004f67:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004f6b:	48 89 c1             	mov    rcx,rax
   140004f6e:	e8 ed 3d 00 00       	call   140008d60 <__isnanl>
   140004f73:	85 c0                	test   eax,eax
   140004f75:	74 1d                	je     140004f94 <__pformat_xldouble+0x67>
   140004f77:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004f7a:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004f7e:	48 8d 15 c1 63 00 00 	lea    rdx,[rip+0x63c1]        # 14000b346 <.rdata+0x16>
   140004f85:	49 89 c8             	mov    r8,rcx
   140004f88:	89 c1                	mov    ecx,eax
   140004f8a:	e8 75 f1 ff ff       	call   140004104 <__pformat_emit_inf_or_nan>
   140004f8f:	e9 aa 00 00 00       	jmp    14000503e <__pformat_xldouble+0x111>
   140004f94:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f98:	98                   	cwde
   140004f99:	25 00 80 00 00       	and    eax,0x8000
   140004f9e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004fa1:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004fa5:	74 12                	je     140004fb9 <__pformat_xldouble+0x8c>
   140004fa7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004fab:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004fae:	0c 80                	or     al,0x80
   140004fb0:	89 c2                	mov    edx,eax
   140004fb2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004fb6:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004fb9:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004fbc:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004fbf:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004fc3:	48 89 c1             	mov    rcx,rax
   140004fc6:	e8 a5 3c 00 00       	call   140008c70 <__fpclassifyl>
   140004fcb:	3d 00 05 00 00       	cmp    eax,0x500
   140004fd0:	75 1a                	jne    140004fec <__pformat_xldouble+0xbf>
   140004fd2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004fd5:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004fd9:	48 8d 15 6a 63 00 00 	lea    rdx,[rip+0x636a]        # 14000b34a <.rdata+0x1a>
   140004fe0:	49 89 c8             	mov    r8,rcx
   140004fe3:	89 c1                	mov    ecx,eax
   140004fe5:	e8 1a f1 ff ff       	call   140004104 <__pformat_emit_inf_or_nan>
   140004fea:	eb 52                	jmp    14000503e <__pformat_xldouble+0x111>
   140004fec:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004ff0:	66 25 ff 7f          	and    ax,0x7fff
   140004ff4:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140004ff8:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004ffc:	66 85 c0             	test   ax,ax
   140004fff:	75 11                	jne    140005012 <__pformat_xldouble+0xe5>
   140005001:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005005:	48 85 c0             	test   rax,rax
   140005008:	74 14                	je     14000501e <__pformat_xldouble+0xf1>
   14000500a:	66 c7 45 e8 02 c0    	mov    WORD PTR [rbp-0x18],0xc002
   140005010:	eb 0c                	jmp    14000501e <__pformat_xldouble+0xf1>
   140005012:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005016:	66 2d ff 3f          	sub    ax,0x3fff
   14000501a:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   14000501e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005022:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140005026:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   14000502a:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
   14000502e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140005032:	48 8d 45 b0          	lea    rax,[rbp-0x50]
   140005036:	48 89 c1             	mov    rcx,rax
   140005039:	e8 12 fa ff ff       	call   140004a50 <__pformat_emit_xfloat>
   14000503e:	90                   	nop
   14000503f:	48 83 c4 78          	add    rsp,0x78
   140005043:	5b                   	pop    rbx
   140005044:	5d                   	pop    rbp
   140005045:	c3                   	ret

0000000140005046 <__pformat_xdouble>:
   140005046:	55                   	push   rbp
   140005047:	48 89 e5             	mov    rbp,rsp
   14000504a:	48 83 ec 60          	sub    rsp,0x60
   14000504e:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140005053:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005057:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000505e:	dd 45 10             	fld    QWORD PTR [rbp+0x10]
   140005061:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140005065:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140005068:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
   14000506c:	48 89 c1             	mov    rcx,rax
   14000506f:	e8 d2 ec ff ff       	call   140003d46 <init_fpreg_ldouble>
   140005074:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005078:	66 48 0f 6e c0       	movq   xmm0,rax
   14000507d:	e8 7e 3c 00 00       	call   140008d00 <__isnan>
   140005082:	85 c0                	test   eax,eax
   140005084:	74 1d                	je     1400050a3 <__pformat_xdouble+0x5d>
   140005086:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005089:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   14000508d:	48 8d 15 b2 62 00 00 	lea    rdx,[rip+0x62b2]        # 14000b346 <.rdata+0x16>
   140005094:	49 89 c8             	mov    r8,rcx
   140005097:	89 c1                	mov    ecx,eax
   140005099:	e8 66 f0 ff ff       	call   140004104 <__pformat_emit_inf_or_nan>
   14000509e:	e9 f9 00 00 00       	jmp    14000519c <__pformat_xdouble+0x156>
   1400050a3:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050a7:	98                   	cwde
   1400050a8:	25 00 80 00 00       	and    eax,0x8000
   1400050ad:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400050b0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400050b4:	74 12                	je     1400050c8 <__pformat_xdouble+0x82>
   1400050b6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400050ba:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400050bd:	0c 80                	or     al,0x80
   1400050bf:	89 c2                	mov    edx,eax
   1400050c1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400050c5:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   1400050c8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400050cc:	66 48 0f 6e c0       	movq   xmm0,rax
   1400050d1:	e8 1a 3b 00 00       	call   140008bf0 <__fpclassify>
   1400050d6:	3d 00 05 00 00       	cmp    eax,0x500
   1400050db:	75 1d                	jne    1400050fa <__pformat_xdouble+0xb4>
   1400050dd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400050e0:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   1400050e4:	48 8d 15 5f 62 00 00 	lea    rdx,[rip+0x625f]        # 14000b34a <.rdata+0x1a>
   1400050eb:	49 89 c8             	mov    r8,rcx
   1400050ee:	89 c1                	mov    ecx,eax
   1400050f0:	e8 0f f0 ff ff       	call   140004104 <__pformat_emit_inf_or_nan>
   1400050f5:	e9 a2 00 00 00       	jmp    14000519c <__pformat_xdouble+0x156>
   1400050fa:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050fe:	66 25 ff 7f          	and    ax,0x7fff
   140005102:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005106:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000510a:	66 85 c0             	test   ax,ax
   14000510d:	74 3b                	je     14000514a <__pformat_xdouble+0x104>
   14000510f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005113:	66 3d 00 3c          	cmp    ax,0x3c00
   140005117:	7f 31                	jg     14000514a <__pformat_xdouble+0x104>
   140005119:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000511d:	98                   	cwde
   14000511e:	ba 01 3c 00 00       	mov    edx,0x3c01
   140005123:	29 c2                	sub    edx,eax
   140005125:	89 55 f8             	mov    DWORD PTR [rbp-0x8],edx
   140005128:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   14000512c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000512f:	89 c1                	mov    ecx,eax
   140005131:	48 d3 ea             	shr    rdx,cl
   140005134:	48 89 d0             	mov    rax,rdx
   140005137:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000513b:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000513f:	89 c2                	mov    edx,eax
   140005141:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005144:	01 d0                	add    eax,edx
   140005146:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   14000514a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000514e:	66 85 c0             	test   ax,ax
   140005151:	75 11                	jne    140005164 <__pformat_xdouble+0x11e>
   140005153:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005157:	48 85 c0             	test   rax,rax
   14000515a:	74 14                	je     140005170 <__pformat_xdouble+0x12a>
   14000515c:	66 c7 45 e8 05 fc    	mov    WORD PTR [rbp-0x18],0xfc05
   140005162:	eb 0c                	jmp    140005170 <__pformat_xdouble+0x12a>
   140005164:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005168:	66 2d fc 3f          	sub    ax,0x3ffc
   14000516c:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005170:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005174:	48 c1 e8 03          	shr    rax,0x3
   140005178:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000517c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005180:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140005184:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140005188:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   14000518c:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140005190:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140005194:	48 89 c1             	mov    rcx,rax
   140005197:	e8 b4 f8 ff ff       	call   140004a50 <__pformat_emit_xfloat>
   14000519c:	90                   	nop
   14000519d:	48 83 c4 60          	add    rsp,0x60
   1400051a1:	5d                   	pop    rbp
   1400051a2:	c3                   	ret

00000001400051a3 <__mingw_pformat>:
   1400051a3:	55                   	push   rbp
   1400051a4:	48 89 e5             	mov    rbp,rsp
   1400051a7:	48 81 ec d0 00 00 00 	sub    rsp,0xd0
   1400051ae:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400051b1:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400051b5:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   1400051b9:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400051bd:	e8 a6 44 00 00       	call   140009668 <_errno>
   1400051c2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400051c4:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400051c7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400051cb:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   1400051cf:	81 65 10 00 60 00 00 	and    DWORD PTR [rbp+0x10],0x6000
   1400051d6:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400051d9:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400051dc:	c7 45 ac ff ff ff ff 	mov    DWORD PTR [rbp-0x54],0xffffffff
   1400051e3:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   1400051ea:	c7 45 b4 fd ff ff ff 	mov    DWORD PTR [rbp-0x4c],0xfffffffd
   1400051f1:	66 c7 45 b8 00 00    	mov    WORD PTR [rbp-0x48],0x0
   1400051f7:	c7 45 bc 00 00 00 00 	mov    DWORD PTR [rbp-0x44],0x0
   1400051fe:	66 c7 45 c0 00 00    	mov    WORD PTR [rbp-0x40],0x0
   140005204:	c7 45 c4 00 00 00 00 	mov    DWORD PTR [rbp-0x3c],0x0
   14000520b:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   14000520e:	89 45 c8             	mov    DWORD PTR [rbp-0x38],eax
   140005211:	c7 45 cc ff ff ff ff 	mov    DWORD PTR [rbp-0x34],0xffffffff
   140005218:	e9 27 0c 00 00       	jmp    140005e44 <__mingw_pformat+0xca1>
   14000521d:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005221:	0f 85 0f 0c 00 00    	jne    140005e36 <__mingw_pformat+0xc93>
   140005227:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000522e:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005235:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005239:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000523d:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005241:	48 83 c0 0c          	add    rax,0xc
   140005245:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005249:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000524c:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000524f:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005256:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140005259:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000525c:	e9 c4 0b 00 00       	jmp    140005e25 <__mingw_pformat+0xc82>
   140005261:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005265:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005269:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   14000526d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005270:	0f be c0             	movsx  eax,al
   140005273:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005276:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   14000527a:	0f 84 94 09 00 00    	je     140005c14 <__mingw_pformat+0xa71>
   140005280:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   140005284:	0f 8f 02 0b 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   14000528a:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   14000528e:	0f 84 eb 03 00 00    	je     14000567f <__mingw_pformat+0x4dc>
   140005294:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   140005298:	0f 8f ee 0a 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   14000529e:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   1400052a2:	0f 84 31 09 00 00    	je     140005bd9 <__mingw_pformat+0xa36>
   1400052a8:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   1400052ac:	0f 8f da 0a 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   1400052b2:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   1400052b6:	0f 84 c3 03 00 00    	je     14000567f <__mingw_pformat+0x4dc>
   1400052bc:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   1400052c0:	0f 8f c6 0a 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   1400052c6:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   1400052ca:	0f 84 31 09 00 00    	je     140005c01 <__mingw_pformat+0xa5e>
   1400052d0:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   1400052d4:	0f 8f b2 0a 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   1400052da:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   1400052de:	0f 84 31 03 00 00    	je     140005615 <__mingw_pformat+0x472>
   1400052e4:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   1400052e8:	0f 8f 9e 0a 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   1400052ee:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   1400052f2:	0f 84 28 05 00 00    	je     140005820 <__mingw_pformat+0x67d>
   1400052f8:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   1400052fc:	0f 8f 8a 0a 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   140005302:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005306:	0f 84 73 03 00 00    	je     14000567f <__mingw_pformat+0x4dc>
   14000530c:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005310:	0f 8f 76 0a 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   140005316:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   14000531a:	0f 84 4d 07 00 00    	je     140005a6d <__mingw_pformat+0x8ca>
   140005320:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   140005324:	0f 8f 62 0a 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   14000532a:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   14000532e:	0f 84 2d 03 00 00    	je     140005661 <__mingw_pformat+0x4be>
   140005334:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   140005338:	0f 8f 4e 0a 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   14000533e:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   140005342:	0f 84 65 08 00 00    	je     140005bad <__mingw_pformat+0xa0a>
   140005348:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   14000534c:	0f 8f 3a 0a 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   140005352:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   140005356:	0f 84 db 07 00 00    	je     140005b37 <__mingw_pformat+0x994>
   14000535c:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   140005360:	0f 8f 26 0a 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   140005366:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   14000536a:	0f 84 ee 03 00 00    	je     14000575e <__mingw_pformat+0x5bb>
   140005370:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   140005374:	0f 8f 12 0a 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   14000537a:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   14000537e:	0f 84 87 07 00 00    	je     140005b0b <__mingw_pformat+0x968>
   140005384:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   140005388:	0f 8f fe 09 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   14000538e:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   140005392:	0f 84 f3 05 00 00    	je     14000598b <__mingw_pformat+0x7e8>
   140005398:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   14000539c:	0f 8f ea 09 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   1400053a2:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   1400053a6:	0f 84 61 05 00 00    	je     14000590d <__mingw_pformat+0x76a>
   1400053ac:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   1400053b0:	0f 8f d6 09 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   1400053b6:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   1400053ba:	0f 84 cf 04 00 00    	je     14000588f <__mingw_pformat+0x6ec>
   1400053c0:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   1400053c4:	0f 8f c2 09 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   1400053ca:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   1400053ce:	0f 84 8a 03 00 00    	je     14000575e <__mingw_pformat+0x5bb>
   1400053d4:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   1400053d8:	0f 8f ae 09 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   1400053de:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   1400053e2:	0f 84 b5 01 00 00    	je     14000559d <__mingw_pformat+0x3fa>
   1400053e8:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   1400053ec:	0f 8f 9a 09 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   1400053f2:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   1400053f6:	0f 84 83 02 00 00    	je     14000567f <__mingw_pformat+0x4dc>
   1400053fc:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005400:	0f 8f 86 09 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   140005406:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   14000540a:	0f 84 f9 05 00 00    	je     140005a09 <__mingw_pformat+0x866>
   140005410:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   140005414:	0f 8f 72 09 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   14000541a:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   14000541e:	0f 84 5b 02 00 00    	je     14000567f <__mingw_pformat+0x4dc>
   140005424:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   140005428:	0f 8f 5e 09 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   14000542e:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   140005432:	0f 84 d6 01 00 00    	je     14000560e <__mingw_pformat+0x46b>
   140005438:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   14000543c:	0f 8f 4a 09 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   140005442:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005446:	0f 84 a0 07 00 00    	je     140005bec <__mingw_pformat+0xa49>
   14000544c:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005450:	0f 8f 36 09 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   140005456:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   14000545a:	0f 84 ea 06 00 00    	je     140005b4a <__mingw_pformat+0x9a7>
   140005460:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   140005464:	0f 8f 22 09 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   14000546a:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   14000546e:	0f 84 20 05 00 00    	je     140005994 <__mingw_pformat+0x7f1>
   140005474:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   140005478:	0f 8f 0e 09 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   14000547e:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   140005482:	0f 84 8e 04 00 00    	je     140005916 <__mingw_pformat+0x773>
   140005488:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   14000548c:	0f 8f fa 08 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   140005492:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   140005496:	0f 84 fc 03 00 00    	je     140005898 <__mingw_pformat+0x6f5>
   14000549c:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   1400054a0:	0f 8f e6 08 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   1400054a6:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   1400054aa:	0f 84 e6 00 00 00    	je     140005596 <__mingw_pformat+0x3f3>
   1400054b0:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   1400054b4:	0f 8f d2 08 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   1400054ba:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   1400054be:	0f 84 bb 01 00 00    	je     14000567f <__mingw_pformat+0x4dc>
   1400054c4:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   1400054c8:	0f 8f be 08 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   1400054ce:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   1400054d2:	0f 84 3a 05 00 00    	je     140005a12 <__mingw_pformat+0x86f>
   1400054d8:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   1400054dc:	0f 8f aa 08 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   1400054e2:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   1400054e6:	0f 84 8c 08 00 00    	je     140005d78 <__mingw_pformat+0xbd5>
   1400054ec:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   1400054f0:	0f 8f 96 08 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   1400054f6:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   1400054fa:	0f 84 27 07 00 00    	je     140005c27 <__mingw_pformat+0xa84>
   140005500:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   140005504:	0f 8f 82 08 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   14000550a:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   14000550e:	0f 84 db 07 00 00    	je     140005cef <__mingw_pformat+0xb4c>
   140005514:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   140005518:	0f 8f 6e 08 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   14000551e:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   140005522:	0f 84 af 07 00 00    	je     140005cd7 <__mingw_pformat+0xb34>
   140005528:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   14000552c:	0f 8f 5a 08 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   140005532:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005536:	0f 84 1c 07 00 00    	je     140005c58 <__mingw_pformat+0xab5>
   14000553c:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005540:	0f 8f 46 08 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   140005546:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   14000554a:	0f 84 b7 07 00 00    	je     140005d07 <__mingw_pformat+0xb64>
   140005550:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   140005554:	0f 8f 32 08 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   14000555a:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   14000555e:	74 23                	je     140005583 <__mingw_pformat+0x3e0>
   140005560:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005564:	0f 8f 22 08 00 00    	jg     140005d8c <__mingw_pformat+0xbe9>
   14000556a:	83 7d e8 20          	cmp    DWORD PTR [rbp-0x18],0x20
   14000556e:	0f 84 ec 07 00 00    	je     140005d60 <__mingw_pformat+0xbbd>
   140005574:	83 7d e8 23          	cmp    DWORD PTR [rbp-0x18],0x23
   140005578:	0f 84 41 07 00 00    	je     140005cbf <__mingw_pformat+0xb1c>
   14000557e:	e9 09 08 00 00       	jmp    140005d8c <__mingw_pformat+0xbe9>
   140005583:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005587:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   14000558a:	89 c1                	mov    ecx,eax
   14000558c:	e8 7f dc ff ff       	call   140003210 <__pformat_putc>
   140005591:	e9 82 fc ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   140005596:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   14000559d:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   1400055a4:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400055a8:	74 06                	je     1400055b0 <__mingw_pformat+0x40d>
   1400055aa:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400055ae:	75 30                	jne    1400055e0 <__mingw_pformat+0x43d>
   1400055b0:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055b4:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055b8:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055bc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400055be:	66 89 45 8e          	mov    WORD PTR [rbp-0x72],ax
   1400055c2:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055c6:	48 8d 45 8e          	lea    rax,[rbp-0x72]
   1400055ca:	49 89 d0             	mov    r8,rdx
   1400055cd:	ba 01 00 00 00       	mov    edx,0x1
   1400055d2:	48 89 c1             	mov    rcx,rax
   1400055d5:	e8 3f de ff ff       	call   140003419 <__pformat_wputchars>
   1400055da:	90                   	nop
   1400055db:	e9 38 fc ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   1400055e0:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055e4:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055e8:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055ec:	8b 00                	mov    eax,DWORD PTR [rax]
   1400055ee:	88 45 90             	mov    BYTE PTR [rbp-0x70],al
   1400055f1:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055f5:	48 8d 45 90          	lea    rax,[rbp-0x70]
   1400055f9:	49 89 d0             	mov    r8,rdx
   1400055fc:	ba 01 00 00 00       	mov    edx,0x1
   140005601:	48 89 c1             	mov    rcx,rax
   140005604:	e8 8b dc ff ff       	call   140003294 <__pformat_putchars>
   140005609:	e9 0a fc ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   14000560e:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005615:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005619:	74 06                	je     140005621 <__mingw_pformat+0x47e>
   14000561b:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000561f:	75 20                	jne    140005641 <__mingw_pformat+0x49e>
   140005621:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005625:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005629:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000562d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005630:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005634:	48 89 c1             	mov    rcx,rax
   140005637:	e8 29 df ff ff       	call   140003565 <__pformat_wcputs>
   14000563c:	e9 d7 fb ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   140005641:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005645:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005649:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000564d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005650:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005654:	48 89 c1             	mov    rcx,rax
   140005657:	e8 37 dd ff ff       	call   140003393 <__pformat_puts>
   14000565c:	e9 b7 fb ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   140005661:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140005664:	89 c1                	mov    ecx,eax
   140005666:	e8 8d 40 00 00       	call   1400096f8 <strerror>
   14000566b:	48 89 c1             	mov    rcx,rax
   14000566e:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005672:	48 89 c2             	mov    rdx,rax
   140005675:	e8 19 dd ff ff       	call   140003393 <__pformat_puts>
   14000567a:	e9 99 fb ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   14000567f:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005682:	80 e4 fe             	and    ah,0xfe
   140005685:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005688:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000568c:	75 15                	jne    1400056a3 <__mingw_pformat+0x500>
   14000568e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005692:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005696:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000569a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000569d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056a1:	eb 54                	jmp    1400056f7 <__mingw_pformat+0x554>
   1400056a3:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400056a7:	75 16                	jne    1400056bf <__mingw_pformat+0x51c>
   1400056a9:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056ad:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056b1:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056b5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400056b7:	89 c0                	mov    eax,eax
   1400056b9:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056bd:	eb 38                	jmp    1400056f7 <__mingw_pformat+0x554>
   1400056bf:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056c3:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056c7:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056cb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400056cd:	89 c0                	mov    eax,eax
   1400056cf:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056d3:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   1400056d7:	75 0d                	jne    1400056e6 <__mingw_pformat+0x543>
   1400056d9:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   1400056dd:	0f b7 c0             	movzx  eax,ax
   1400056e0:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056e4:	eb 11                	jmp    1400056f7 <__mingw_pformat+0x554>
   1400056e6:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   1400056ea:	75 0b                	jne    1400056f7 <__mingw_pformat+0x554>
   1400056ec:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   1400056f0:	0f b6 c0             	movzx  eax,al
   1400056f3:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056f7:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   1400056fb:	75 2e                	jne    14000572b <__mingw_pformat+0x588>
   1400056fd:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005701:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005705:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000570c:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005713:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005717:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   14000571e:	48 89 c1             	mov    rcx,rax
   140005721:	e8 55 df ff ff       	call   14000367b <__pformat_int>
   140005726:	e9 ed fa ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   14000572b:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000572f:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005733:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000573a:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005741:	48 8d 4d a0          	lea    rcx,[rbp-0x60]
   140005745:	48 8d 95 70 ff ff ff 	lea    rdx,[rbp-0x90]
   14000574c:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   14000574f:	49 89 c8             	mov    r8,rcx
   140005752:	89 c1                	mov    ecx,eax
   140005754:	e8 a5 e2 ff ff       	call   1400039fe <__pformat_xint>
   140005759:	e9 ba fa ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   14000575e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005761:	0c 80                	or     al,0x80
   140005763:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005766:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000576a:	75 15                	jne    140005781 <__mingw_pformat+0x5de>
   14000576c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005770:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005774:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005778:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000577b:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000577f:	eb 56                	jmp    1400057d7 <__mingw_pformat+0x634>
   140005781:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005785:	75 16                	jne    14000579d <__mingw_pformat+0x5fa>
   140005787:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000578b:	48 8d 50 08          	lea    rdx,[rax+0x8]
   14000578f:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005793:	8b 00                	mov    eax,DWORD PTR [rax]
   140005795:	48 98                	cdqe
   140005797:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000579b:	eb 3a                	jmp    1400057d7 <__mingw_pformat+0x634>
   14000579d:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400057a1:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400057a5:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400057a9:	8b 00                	mov    eax,DWORD PTR [rax]
   1400057ab:	48 98                	cdqe
   1400057ad:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057b1:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   1400057b5:	75 0e                	jne    1400057c5 <__mingw_pformat+0x622>
   1400057b7:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   1400057bb:	48 0f bf c0          	movsx  rax,ax
   1400057bf:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057c3:	eb 12                	jmp    1400057d7 <__mingw_pformat+0x634>
   1400057c5:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   1400057c9:	75 0c                	jne    1400057d7 <__mingw_pformat+0x634>
   1400057cb:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   1400057cf:	48 0f be c0          	movsx  rax,al
   1400057d3:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057d7:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400057db:	48 85 c0             	test   rax,rax
   1400057de:	79 09                	jns    1400057e9 <__mingw_pformat+0x646>
   1400057e0:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400057e7:	eb 05                	jmp    1400057ee <__mingw_pformat+0x64b>
   1400057e9:	b8 00 00 00 00       	mov    eax,0x0
   1400057ee:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   1400057f2:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400057f6:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400057fa:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005801:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005808:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000580c:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   140005813:	48 89 c1             	mov    rcx,rax
   140005816:	e8 60 de ff ff       	call   14000367b <__pformat_int>
   14000581b:	e9 f8 f9 ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   140005820:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005824:	75 18                	jne    14000583e <__mingw_pformat+0x69b>
   140005826:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005829:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   14000582c:	75 10                	jne    14000583e <__mingw_pformat+0x69b>
   14000582e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005831:	80 cc 02             	or     ah,0x2
   140005834:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005837:	c7 45 b0 10 00 00 00 	mov    DWORD PTR [rbp-0x50],0x10
   14000583e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005842:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005846:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000584a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000584d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005851:	48 c7 45 98 00 00 00 	mov    QWORD PTR [rbp-0x68],0x0
   140005858:	00 
   140005859:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000585d:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005861:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005868:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   14000586f:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005873:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   14000587a:	49 89 d0             	mov    r8,rdx
   14000587d:	48 89 c2             	mov    rdx,rax
   140005880:	b9 78 00 00 00       	mov    ecx,0x78
   140005885:	e8 74 e1 ff ff       	call   1400039fe <__pformat_xint>
   14000588a:	e9 89 f9 ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   14000588f:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005892:	83 c8 20             	or     eax,0x20
   140005895:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005898:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   14000589b:	83 e0 04             	and    eax,0x4
   14000589e:	85 c0                	test   eax,eax
   1400058a0:	74 2f                	je     1400058d1 <__mingw_pformat+0x72e>
   1400058a2:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058a6:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058aa:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058ae:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400058b1:	db 28                	fld    TBYTE PTR [rax]
   1400058b3:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058b9:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058bd:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400058c4:	48 89 c1             	mov    rcx,rax
   1400058c7:	e8 1d ef ff ff       	call   1400047e9 <__pformat_efloat>
   1400058cc:	e9 47 f9 ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   1400058d1:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058d5:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058d9:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058dd:	f2 0f 10 08          	movsd  xmm1,QWORD PTR [rax]
   1400058e1:	f2 0f 11 8d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm1
   1400058e8:	ff 
   1400058e9:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   1400058ef:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058f5:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058f9:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005900:	48 89 c1             	mov    rcx,rax
   140005903:	e8 e1 ee ff ff       	call   1400047e9 <__pformat_efloat>
   140005908:	e9 0b f9 ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   14000590d:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005910:	83 c8 20             	or     eax,0x20
   140005913:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005916:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005919:	83 e0 04             	and    eax,0x4
   14000591c:	85 c0                	test   eax,eax
   14000591e:	74 2f                	je     14000594f <__mingw_pformat+0x7ac>
   140005920:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005924:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005928:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000592c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000592f:	db 28                	fld    TBYTE PTR [rax]
   140005931:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005937:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000593b:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005942:	48 89 c1             	mov    rcx,rax
   140005945:	e8 cf ed ff ff       	call   140004719 <__pformat_float>
   14000594a:	e9 c9 f8 ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   14000594f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005953:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005957:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000595b:	f2 0f 10 10          	movsd  xmm2,QWORD PTR [rax]
   14000595f:	f2 0f 11 95 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm2
   140005966:	ff 
   140005967:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000596d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005973:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005977:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   14000597e:	48 89 c1             	mov    rcx,rax
   140005981:	e8 93 ed ff ff       	call   140004719 <__pformat_float>
   140005986:	e9 8d f8 ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   14000598b:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   14000598e:	83 c8 20             	or     eax,0x20
   140005991:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005994:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005997:	83 e0 04             	and    eax,0x4
   14000599a:	85 c0                	test   eax,eax
   14000599c:	74 2f                	je     1400059cd <__mingw_pformat+0x82a>
   14000599e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059a2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059a6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059aa:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059ad:	db 28                	fld    TBYTE PTR [rax]
   1400059af:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400059b5:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059b9:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400059c0:	48 89 c1             	mov    rcx,rax
   1400059c3:	e8 cc ee ff ff       	call   140004894 <__pformat_gfloat>
   1400059c8:	e9 4b f8 ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   1400059cd:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059d1:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059d5:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059d9:	f2 0f 10 18          	movsd  xmm3,QWORD PTR [rax]
   1400059dd:	f2 0f 11 9d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm3
   1400059e4:	ff 
   1400059e5:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   1400059eb:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400059f1:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059f5:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400059fc:	48 89 c1             	mov    rcx,rax
   1400059ff:	e8 90 ee ff ff       	call   140004894 <__pformat_gfloat>
   140005a04:	e9 0f f8 ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   140005a09:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005a0c:	83 c8 20             	or     eax,0x20
   140005a0f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005a12:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005a15:	83 e0 04             	and    eax,0x4
   140005a18:	85 c0                	test   eax,eax
   140005a1a:	74 2f                	je     140005a4b <__mingw_pformat+0x8a8>
   140005a1c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a20:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a24:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a28:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a2b:	db 28                	fld    TBYTE PTR [rax]
   140005a2d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005a33:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a37:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005a3e:	48 89 c1             	mov    rcx,rax
   140005a41:	e8 e7 f4 ff ff       	call   140004f2d <__pformat_xldouble>
   140005a46:	e9 cd f7 ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   140005a4b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a4f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a53:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a57:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a5a:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a5e:	66 48 0f 6e c0       	movq   xmm0,rax
   140005a63:	e8 de f5 ff ff       	call   140005046 <__pformat_xdouble>
   140005a68:	e9 ab f7 ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   140005a6d:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   140005a71:	75 1b                	jne    140005a8e <__mingw_pformat+0x8eb>
   140005a73:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a76:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a7a:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a7e:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a82:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a85:	89 ca                	mov    edx,ecx
   140005a87:	88 10                	mov    BYTE PTR [rax],dl
   140005a89:	e9 8a f7 ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   140005a8e:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005a92:	75 1c                	jne    140005ab0 <__mingw_pformat+0x90d>
   140005a94:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a97:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a9b:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a9f:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005aa3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005aa6:	89 ca                	mov    edx,ecx
   140005aa8:	66 89 10             	mov    WORD PTR [rax],dx
   140005aab:	e9 68 f7 ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   140005ab0:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005ab4:	75 19                	jne    140005acf <__mingw_pformat+0x92c>
   140005ab6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005aba:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005abe:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005ac2:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005ac5:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005ac8:	89 10                	mov    DWORD PTR [rax],edx
   140005aca:	e9 49 f7 ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   140005acf:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   140005ad3:	75 1d                	jne    140005af2 <__mingw_pformat+0x94f>
   140005ad5:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005ad8:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005adc:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005ae0:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005ae4:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005ae7:	48 63 d1             	movsxd rdx,ecx
   140005aea:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005aed:	e9 26 f7 ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   140005af2:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005af6:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005afa:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005afe:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005b01:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005b04:	89 10                	mov    DWORD PTR [rax],edx
   140005b06:	e9 0d f7 ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   140005b0b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b0f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b12:	3c 68                	cmp    al,0x68
   140005b14:	75 0e                	jne    140005b24 <__mingw_pformat+0x981>
   140005b16:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005b1b:	c7 45 f8 05 00 00 00 	mov    DWORD PTR [rbp-0x8],0x5
   140005b22:	eb 07                	jmp    140005b2b <__mingw_pformat+0x988>
   140005b24:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140005b2b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b32:	e9 ee 02 00 00       	jmp    140005e25 <__mingw_pformat+0xc82>
   140005b37:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b3e:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b45:	e9 db 02 00 00       	jmp    140005e25 <__mingw_pformat+0xc82>
   140005b4a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b4e:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b51:	3c 36                	cmp    al,0x36
   140005b53:	75 1d                	jne    140005b72 <__mingw_pformat+0x9cf>
   140005b55:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b59:	48 83 c0 01          	add    rax,0x1
   140005b5d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b60:	3c 34                	cmp    al,0x34
   140005b62:	75 0e                	jne    140005b72 <__mingw_pformat+0x9cf>
   140005b64:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b6b:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005b70:	eb 2f                	jmp    140005ba1 <__mingw_pformat+0x9fe>
   140005b72:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b76:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b79:	3c 33                	cmp    al,0x33
   140005b7b:	75 1d                	jne    140005b9a <__mingw_pformat+0x9f7>
   140005b7d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b81:	48 83 c0 01          	add    rax,0x1
   140005b85:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b88:	3c 32                	cmp    al,0x32
   140005b8a:	75 0e                	jne    140005b9a <__mingw_pformat+0x9f7>
   140005b8c:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005b93:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005b98:	eb 07                	jmp    140005ba1 <__mingw_pformat+0x9fe>
   140005b9a:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005ba1:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005ba8:	e9 78 02 00 00       	jmp    140005e25 <__mingw_pformat+0xc82>
   140005bad:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005bb1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005bb4:	3c 6c                	cmp    al,0x6c
   140005bb6:	75 0e                	jne    140005bc6 <__mingw_pformat+0xa23>
   140005bb8:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005bbd:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005bc4:	eb 07                	jmp    140005bcd <__mingw_pformat+0xa2a>
   140005bc6:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005bcd:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bd4:	e9 4c 02 00 00       	jmp    140005e25 <__mingw_pformat+0xc82>
   140005bd9:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005be0:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005be7:	e9 39 02 00 00       	jmp    140005e25 <__mingw_pformat+0xc82>
   140005bec:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005bef:	83 c8 04             	or     eax,0x4
   140005bf2:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005bf5:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bfc:	e9 24 02 00 00       	jmp    140005e25 <__mingw_pformat+0xc82>
   140005c01:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005c08:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c0f:	e9 11 02 00 00       	jmp    140005e25 <__mingw_pformat+0xc82>
   140005c14:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005c1b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c22:	e9 fe 01 00 00       	jmp    140005e25 <__mingw_pformat+0xc82>
   140005c27:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140005c2b:	77 1f                	ja     140005c4c <__mingw_pformat+0xaa9>
   140005c2d:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140005c34:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005c38:	48 83 c0 10          	add    rax,0x10
   140005c3c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005c40:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140005c47:	e9 d9 01 00 00       	jmp    140005e25 <__mingw_pformat+0xc82>
   140005c4c:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c53:	e9 cd 01 00 00       	jmp    140005e25 <__mingw_pformat+0xc82>
   140005c58:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005c5d:	74 4c                	je     140005cab <__mingw_pformat+0xb08>
   140005c5f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c63:	74 06                	je     140005c6b <__mingw_pformat+0xac8>
   140005c65:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005c69:	75 40                	jne    140005cab <__mingw_pformat+0xb08>
   140005c6b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005c6f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005c73:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005c77:	8b 10                	mov    edx,DWORD PTR [rax]
   140005c79:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005c7d:	89 10                	mov    DWORD PTR [rax],edx
   140005c7f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005c83:	8b 00                	mov    eax,DWORD PTR [rax]
   140005c85:	85 c0                	test   eax,eax
   140005c87:	79 29                	jns    140005cb2 <__mingw_pformat+0xb0f>
   140005c89:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c8d:	75 13                	jne    140005ca2 <__mingw_pformat+0xaff>
   140005c8f:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c92:	80 cc 04             	or     ah,0x4
   140005c95:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c98:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140005c9b:	f7 d8                	neg    eax
   140005c9d:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140005ca0:	eb 10                	jmp    140005cb2 <__mingw_pformat+0xb0f>
   140005ca2:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005ca9:	eb 07                	jmp    140005cb2 <__mingw_pformat+0xb0f>
   140005cab:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005cb2:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
   140005cb9:	00 
   140005cba:	e9 66 01 00 00       	jmp    140005e25 <__mingw_pformat+0xc82>
   140005cbf:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cc3:	0f 85 4f 01 00 00    	jne    140005e18 <__mingw_pformat+0xc75>
   140005cc9:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005ccc:	80 cc 08             	or     ah,0x8
   140005ccf:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cd2:	e9 41 01 00 00       	jmp    140005e18 <__mingw_pformat+0xc75>
   140005cd7:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cdb:	0f 85 3a 01 00 00    	jne    140005e1b <__mingw_pformat+0xc78>
   140005ce1:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005ce4:	80 cc 01             	or     ah,0x1
   140005ce7:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cea:	e9 2c 01 00 00       	jmp    140005e1b <__mingw_pformat+0xc78>
   140005cef:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cf3:	0f 85 25 01 00 00    	jne    140005e1e <__mingw_pformat+0xc7b>
   140005cf9:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cfc:	80 cc 04             	or     ah,0x4
   140005cff:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d02:	e9 17 01 00 00       	jmp    140005e1e <__mingw_pformat+0xc7b>
   140005d07:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d0b:	0f 85 10 01 00 00    	jne    140005e21 <__mingw_pformat+0xc7e>
   140005d11:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d14:	80 cc 10             	or     ah,0x10
   140005d17:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d1a:	48 c7 45 84 00 00 00 	mov    QWORD PTR [rbp-0x7c],0x0
   140005d21:	00 
   140005d22:	e8 a1 39 00 00       	call   1400096c8 <localeconv>
   140005d27:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140005d2b:	48 8d 4d 84          	lea    rcx,[rbp-0x7c]
   140005d2f:	48 8d 45 8c          	lea    rax,[rbp-0x74]
   140005d33:	49 89 c9             	mov    r9,rcx
   140005d36:	41 b8 10 00 00 00    	mov    r8d,0x10
   140005d3c:	48 89 c1             	mov    rcx,rax
   140005d3f:	e8 bc 33 00 00       	call   140009100 <mbrtowc>
   140005d44:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140005d47:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   140005d4b:	7e 08                	jle    140005d55 <__mingw_pformat+0xbb2>
   140005d4d:	0f b7 45 8c          	movzx  eax,WORD PTR [rbp-0x74]
   140005d51:	66 89 45 c0          	mov    WORD PTR [rbp-0x40],ax
   140005d55:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140005d58:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
   140005d5b:	e9 c1 00 00 00       	jmp    140005e21 <__mingw_pformat+0xc7e>
   140005d60:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d64:	0f 85 ba 00 00 00    	jne    140005e24 <__mingw_pformat+0xc81>
   140005d6a:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d6d:	83 c8 40             	or     eax,0x40
   140005d70:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d73:	e9 ac 00 00 00       	jmp    140005e24 <__mingw_pformat+0xc81>
   140005d78:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d7c:	75 0e                	jne    140005d8c <__mingw_pformat+0xbe9>
   140005d7e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d81:	80 cc 02             	or     ah,0x2
   140005d84:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d87:	e9 99 00 00 00       	jmp    140005e25 <__mingw_pformat+0xc82>
   140005d8c:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
   140005d90:	77 68                	ja     140005dfa <__mingw_pformat+0xc57>
   140005d92:	83 7d e8 39          	cmp    DWORD PTR [rbp-0x18],0x39
   140005d96:	7f 62                	jg     140005dfa <__mingw_pformat+0xc57>
   140005d98:	83 7d e8 2f          	cmp    DWORD PTR [rbp-0x18],0x2f
   140005d9c:	7e 5c                	jle    140005dfa <__mingw_pformat+0xc57>
   140005d9e:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005da2:	75 09                	jne    140005dad <__mingw_pformat+0xc0a>
   140005da4:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140005dab:	eb 0d                	jmp    140005dba <__mingw_pformat+0xc17>
   140005dad:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005db1:	75 07                	jne    140005dba <__mingw_pformat+0xc17>
   140005db3:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140005dba:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005dbf:	74 64                	je     140005e25 <__mingw_pformat+0xc82>
   140005dc1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005dc5:	8b 00                	mov    eax,DWORD PTR [rax]
   140005dc7:	85 c0                	test   eax,eax
   140005dc9:	79 0e                	jns    140005dd9 <__mingw_pformat+0xc36>
   140005dcb:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005dce:	8d 50 d0             	lea    edx,[rax-0x30]
   140005dd1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005dd5:	89 10                	mov    DWORD PTR [rax],edx
   140005dd7:	eb 4c                	jmp    140005e25 <__mingw_pformat+0xc82>
   140005dd9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ddd:	8b 10                	mov    edx,DWORD PTR [rax]
   140005ddf:	89 d0                	mov    eax,edx
   140005de1:	c1 e0 02             	shl    eax,0x2
   140005de4:	01 d0                	add    eax,edx
   140005de6:	01 c0                	add    eax,eax
   140005de8:	89 c2                	mov    edx,eax
   140005dea:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005ded:	01 d0                	add    eax,edx
   140005def:	8d 50 d0             	lea    edx,[rax-0x30]
   140005df2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005df6:	89 10                	mov    DWORD PTR [rax],edx
   140005df8:	eb 2b                	jmp    140005e25 <__mingw_pformat+0xc82>
   140005dfa:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005dfe:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140005e02:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005e06:	48 89 c2             	mov    rdx,rax
   140005e09:	b9 25 00 00 00       	mov    ecx,0x25
   140005e0e:	e8 fd d3 ff ff       	call   140003210 <__pformat_putc>
   140005e13:	e9 00 f4 ff ff       	jmp    140005218 <__mingw_pformat+0x75>
   140005e18:	90                   	nop
   140005e19:	eb 0a                	jmp    140005e25 <__mingw_pformat+0xc82>
   140005e1b:	90                   	nop
   140005e1c:	eb 07                	jmp    140005e25 <__mingw_pformat+0xc82>
   140005e1e:	90                   	nop
   140005e1f:	eb 04                	jmp    140005e25 <__mingw_pformat+0xc82>
   140005e21:	90                   	nop
   140005e22:	eb 01                	jmp    140005e25 <__mingw_pformat+0xc82>
   140005e24:	90                   	nop
   140005e25:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005e29:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e2c:	84 c0                	test   al,al
   140005e2e:	0f 85 2d f4 ff ff    	jne    140005261 <__mingw_pformat+0xbe>
   140005e34:	eb 0e                	jmp    140005e44 <__mingw_pformat+0xca1>
   140005e36:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005e3a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005e3d:	89 c1                	mov    ecx,eax
   140005e3f:	e8 cc d3 ff ff       	call   140003210 <__pformat_putc>
   140005e44:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005e48:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005e4c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140005e50:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e53:	0f be c0             	movsx  eax,al
   140005e56:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005e59:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140005e5d:	0f 85 ba f3 ff ff    	jne    14000521d <__mingw_pformat+0x7a>
   140005e63:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140005e66:	48 81 c4 d0 00 00 00 	add    rsp,0xd0
   140005e6d:	5d                   	pop    rbp
   140005e6e:	c3                   	ret
   140005e6f:	90                   	nop

0000000140005e70 <__rv_alloc_D2A>:
   140005e70:	55                   	push   rbp
   140005e71:	48 89 e5             	mov    rbp,rsp
   140005e74:	48 83 ec 30          	sub    rsp,0x30
   140005e78:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005e7b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005e82:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005e89:	eb 07                	jmp    140005e92 <__rv_alloc_D2A+0x22>
   140005e8b:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140005e8f:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140005e92:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005e95:	83 c0 17             	add    eax,0x17
   140005e98:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140005e9b:	7f ee                	jg     140005e8b <__rv_alloc_D2A+0x1b>
   140005e9d:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005ea0:	89 c1                	mov    ecx,eax
   140005ea2:	e8 56 1e 00 00       	call   140007cfd <__Balloc_D2A>
   140005ea7:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005eab:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005eaf:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140005eb2:	89 10                	mov    DWORD PTR [rax],edx
   140005eb4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005eb8:	48 83 c0 04          	add    rax,0x4
   140005ebc:	48 83 c4 30          	add    rsp,0x30
   140005ec0:	5d                   	pop    rbp
   140005ec1:	c3                   	ret

0000000140005ec2 <__nrv_alloc_D2A>:
   140005ec2:	55                   	push   rbp
   140005ec3:	48 89 e5             	mov    rbp,rsp
   140005ec6:	48 83 ec 30          	sub    rsp,0x30
   140005eca:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005ece:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005ed2:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005ed6:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140005ed9:	89 c1                	mov    ecx,eax
   140005edb:	e8 90 ff ff ff       	call   140005e70 <__rv_alloc_D2A>
   140005ee0:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005ee4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ee8:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005eec:	eb 05                	jmp    140005ef3 <__nrv_alloc_D2A+0x31>
   140005eee:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140005ef3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005ef7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005efb:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140005eff:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140005f02:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f06:	88 10                	mov    BYTE PTR [rax],dl
   140005f08:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f0c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005f0f:	84 c0                	test   al,al
   140005f11:	75 db                	jne    140005eee <__nrv_alloc_D2A+0x2c>
   140005f13:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140005f18:	74 0b                	je     140005f25 <__nrv_alloc_D2A+0x63>
   140005f1a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f1e:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140005f22:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005f25:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f29:	48 83 c4 30          	add    rsp,0x30
   140005f2d:	5d                   	pop    rbp
   140005f2e:	c3                   	ret

0000000140005f2f <__freedtoa>:
   140005f2f:	55                   	push   rbp
   140005f30:	48 89 e5             	mov    rbp,rsp
   140005f33:	48 83 ec 30          	sub    rsp,0x30
   140005f37:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005f3b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f3f:	48 83 e8 04          	sub    rax,0x4
   140005f43:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005f47:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f4b:	8b 10                	mov    edx,DWORD PTR [rax]
   140005f4d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f51:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005f54:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f58:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140005f5b:	ba 01 00 00 00       	mov    edx,0x1
   140005f60:	89 c1                	mov    ecx,eax
   140005f62:	d3 e2                	shl    edx,cl
   140005f64:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f68:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140005f6b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f6f:	48 89 c1             	mov    rcx,rax
   140005f72:	e8 c7 1e 00 00       	call   140007e3e <__Bfree_D2A>
   140005f77:	90                   	nop
   140005f78:	48 83 c4 30          	add    rsp,0x30
   140005f7c:	5d                   	pop    rbp
   140005f7d:	c3                   	ret

0000000140005f7e <__quorem_D2A>:
   140005f7e:	55                   	push   rbp
   140005f7f:	48 89 e5             	mov    rbp,rsp
   140005f82:	48 83 ec 70          	sub    rsp,0x70
   140005f86:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005f8a:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005f8e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f92:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005f95:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005f98:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f9c:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005f9f:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140005fa2:	7e 0a                	jle    140005fae <__quorem_D2A+0x30>
   140005fa4:	b8 00 00 00 00       	mov    eax,0x0
   140005fa9:	e9 3f 02 00 00       	jmp    1400061ed <__quorem_D2A+0x26f>
   140005fae:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005fb2:	48 83 c0 18          	add    rax,0x18
   140005fb6:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140005fba:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140005fbe:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005fc1:	48 98                	cdqe
   140005fc3:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005fca:	00 
   140005fcb:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005fcf:	48 01 d0             	add    rax,rdx
   140005fd2:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140005fd6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005fda:	48 83 c0 18          	add    rax,0x18
   140005fde:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005fe2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005fe5:	48 98                	cdqe
   140005fe7:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005fee:	00 
   140005fef:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ff3:	48 01 d0             	add    rax,rdx
   140005ff6:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140005ffa:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140005ffe:	8b 00                	mov    eax,DWORD PTR [rax]
   140006000:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140006004:	8b 12                	mov    edx,DWORD PTR [rdx]
   140006006:	8d 4a 01             	lea    ecx,[rdx+0x1]
   140006009:	ba 00 00 00 00       	mov    edx,0x0
   14000600e:	f7 f1                	div    ecx
   140006010:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140006013:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140006017:	0f 84 c4 00 00 00    	je     1400060e1 <__quorem_D2A+0x163>
   14000601d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140006024:	00 
   140006025:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   14000602c:	00 
   14000602d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006031:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140006035:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006039:	8b 00                	mov    eax,DWORD PTR [rax]
   14000603b:	89 c2                	mov    edx,eax
   14000603d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140006040:	48 0f af d0          	imul   rdx,rax
   140006044:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006048:	48 01 d0             	add    rax,rdx
   14000604b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000604f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006053:	48 c1 e8 20          	shr    rax,0x20
   140006057:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000605b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000605f:	8b 00                	mov    eax,DWORD PTR [rax]
   140006061:	89 c1                	mov    ecx,eax
   140006063:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006067:	89 c2                	mov    edx,eax
   140006069:	48 89 c8             	mov    rax,rcx
   14000606c:	48 29 d0             	sub    rax,rdx
   14000606f:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140006073:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140006077:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   14000607b:	48 c1 e8 20          	shr    rax,0x20
   14000607f:	83 e0 01             	and    eax,0x1
   140006082:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140006086:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000608a:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000608e:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006092:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140006096:	89 10                	mov    DWORD PTR [rax],edx
   140006098:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000609c:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400060a0:	73 8b                	jae    14000602d <__quorem_D2A+0xaf>
   1400060a2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400060a6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060a8:	85 c0                	test   eax,eax
   1400060aa:	75 35                	jne    1400060e1 <__quorem_D2A+0x163>
   1400060ac:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060b0:	48 83 c0 18          	add    rax,0x18
   1400060b4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400060b8:	eb 04                	jmp    1400060be <__quorem_D2A+0x140>
   1400060ba:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400060be:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   1400060c3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400060c7:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   1400060cb:	73 0a                	jae    1400060d7 <__quorem_D2A+0x159>
   1400060cd:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400060d1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060d3:	85 c0                	test   eax,eax
   1400060d5:	74 e3                	je     1400060ba <__quorem_D2A+0x13c>
   1400060d7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060db:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400060de:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400060e1:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400060e5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060e9:	48 89 c1             	mov    rcx,rax
   1400060ec:	e8 bc 24 00 00       	call   1400085ad <__cmp_D2A>
   1400060f1:	85 c0                	test   eax,eax
   1400060f3:	0f 88 f1 00 00 00    	js     1400061ea <__quorem_D2A+0x26c>
   1400060f9:	83 45 e4 01          	add    DWORD PTR [rbp-0x1c],0x1
   1400060fd:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140006104:	00 
   140006105:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   14000610c:	00 
   14000610d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006111:	48 83 c0 18          	add    rax,0x18
   140006115:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006119:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000611d:	48 83 c0 18          	add    rax,0x18
   140006121:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140006125:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006129:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000612d:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006131:	8b 00                	mov    eax,DWORD PTR [rax]
   140006133:	89 c2                	mov    edx,eax
   140006135:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006139:	48 01 d0             	add    rax,rdx
   14000613c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140006140:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006144:	48 c1 e8 20          	shr    rax,0x20
   140006148:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000614c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006150:	8b 00                	mov    eax,DWORD PTR [rax]
   140006152:	89 c1                	mov    ecx,eax
   140006154:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006158:	89 c2                	mov    edx,eax
   14000615a:	48 89 c8             	mov    rax,rcx
   14000615d:	48 29 d0             	sub    rax,rdx
   140006160:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140006164:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140006168:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   14000616c:	48 c1 e8 20          	shr    rax,0x20
   140006170:	83 e0 01             	and    eax,0x1
   140006173:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140006177:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000617b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000617f:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006183:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140006187:	89 10                	mov    DWORD PTR [rax],edx
   140006189:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000618d:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140006191:	73 92                	jae    140006125 <__quorem_D2A+0x1a7>
   140006193:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006197:	48 83 c0 18          	add    rax,0x18
   14000619b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000619f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400061a2:	48 98                	cdqe
   1400061a4:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400061ab:	00 
   1400061ac:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400061b0:	48 01 d0             	add    rax,rdx
   1400061b3:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400061b7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061bb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400061bd:	85 c0                	test   eax,eax
   1400061bf:	75 29                	jne    1400061ea <__quorem_D2A+0x26c>
   1400061c1:	eb 04                	jmp    1400061c7 <__quorem_D2A+0x249>
   1400061c3:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400061c7:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   1400061cc:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061d0:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   1400061d4:	73 0a                	jae    1400061e0 <__quorem_D2A+0x262>
   1400061d6:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061da:	8b 00                	mov    eax,DWORD PTR [rax]
   1400061dc:	85 c0                	test   eax,eax
   1400061de:	74 e3                	je     1400061c3 <__quorem_D2A+0x245>
   1400061e0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400061e4:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   1400061e7:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400061ea:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400061ed:	48 83 c4 70          	add    rsp,0x70
   1400061f1:	5d                   	pop    rbp
   1400061f2:	c3                   	ret
   1400061f3:	90                   	nop
   1400061f4:	90                   	nop
   1400061f5:	90                   	nop
   1400061f6:	90                   	nop
   1400061f7:	90                   	nop
   1400061f8:	90                   	nop
   1400061f9:	90                   	nop
   1400061fa:	90                   	nop
   1400061fb:	90                   	nop
   1400061fc:	90                   	nop
   1400061fd:	90                   	nop
   1400061fe:	90                   	nop
   1400061ff:	90                   	nop

0000000140006200 <__hi0bits_D2A>:
   140006200:	55                   	push   rbp
   140006201:	48 89 e5             	mov    rbp,rsp
   140006204:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140006207:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   14000620b:	83 f0 1f             	xor    eax,0x1f
   14000620e:	5d                   	pop    rbp
   14000620f:	c3                   	ret

0000000140006210 <bitstob>:
   140006210:	55                   	push   rbp
   140006211:	53                   	push   rbx
   140006212:	48 83 ec 58          	sub    rsp,0x58
   140006216:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   14000621b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   14000621f:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140006222:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140006226:	c7 45 fc 20 00 00 00 	mov    DWORD PTR [rbp-0x4],0x20
   14000622d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140006234:	eb 07                	jmp    14000623d <bitstob+0x2d>
   140006236:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140006239:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   14000623d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006240:	3b 45 28             	cmp    eax,DWORD PTR [rbp+0x28]
   140006243:	7c f1                	jl     140006236 <bitstob+0x26>
   140006245:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140006248:	89 c1                	mov    ecx,eax
   14000624a:	e8 ae 1a 00 00       	call   140007cfd <__Balloc_D2A>
   14000624f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140006253:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140006256:	83 e8 01             	sub    eax,0x1
   140006259:	c1 f8 05             	sar    eax,0x5
   14000625c:	48 98                	cdqe
   14000625e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006265:	00 
   140006266:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000626a:	48 01 d0             	add    rax,rdx
   14000626d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140006271:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006275:	48 83 c0 18          	add    rax,0x18
   140006279:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000627d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006281:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006285:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006289:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000628d:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140006291:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140006295:	8b 12                	mov    edx,DWORD PTR [rdx]
   140006297:	89 10                	mov    DWORD PTR [rax],edx
   140006299:	48 83 45 20 04       	add    QWORD PTR [rbp+0x20],0x4
   14000629e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400062a2:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400062a6:	73 dd                	jae    140006285 <bitstob+0x75>
   1400062a8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400062ac:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   1400062b0:	48 c1 f8 02          	sar    rax,0x2
   1400062b4:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400062b7:	eb 1d                	jmp    1400062d6 <bitstob+0xc6>
   1400062b9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400062bd:	75 17                	jne    1400062d6 <bitstob+0xc6>
   1400062bf:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062c3:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   1400062ca:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400062ce:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400062d4:	eb 59                	jmp    14000632f <bitstob+0x11f>
   1400062d6:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   1400062da:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400062dd:	48 98                	cdqe
   1400062df:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400062e6:	00 
   1400062e7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400062eb:	48 01 d0             	add    rax,rdx
   1400062ee:	8b 00                	mov    eax,DWORD PTR [rax]
   1400062f0:	85 c0                	test   eax,eax
   1400062f2:	74 c5                	je     1400062b9 <bitstob+0xa9>
   1400062f4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400062f7:	8d 50 01             	lea    edx,[rax+0x1]
   1400062fa:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062fe:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006301:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006304:	83 c0 01             	add    eax,0x1
   140006307:	c1 e0 05             	shl    eax,0x5
   14000630a:	89 c3                	mov    ebx,eax
   14000630c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006310:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006313:	48 63 d2             	movsxd rdx,edx
   140006316:	48 83 c2 04          	add    rdx,0x4
   14000631a:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   14000631e:	89 c1                	mov    ecx,eax
   140006320:	e8 db fe ff ff       	call   140006200 <__hi0bits_D2A>
   140006325:	29 c3                	sub    ebx,eax
   140006327:	89 da                	mov    edx,ebx
   140006329:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000632d:	89 10                	mov    DWORD PTR [rax],edx
   14000632f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006333:	48 83 c4 58          	add    rsp,0x58
   140006337:	5b                   	pop    rbx
   140006338:	5d                   	pop    rbp
   140006339:	c3                   	ret

000000014000633a <__gdtoa>:
   14000633a:	55                   	push   rbp
   14000633b:	48 81 ec 00 01 00 00 	sub    rsp,0x100
   140006342:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140006349:	00 
   14000634a:	48 89 8d 90 00 00 00 	mov    QWORD PTR [rbp+0x90],rcx
   140006351:	89 95 98 00 00 00    	mov    DWORD PTR [rbp+0x98],edx
   140006357:	4c 89 85 a0 00 00 00 	mov    QWORD PTR [rbp+0xa0],r8
   14000635e:	4c 89 8d a8 00 00 00 	mov    QWORD PTR [rbp+0xa8],r9
   140006365:	c7 45 64 00 00 00 00 	mov    DWORD PTR [rbp+0x64],0x0
   14000636c:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140006373:	8b 00                	mov    eax,DWORD PTR [rax]
   140006375:	83 e0 cf             	and    eax,0xffffffcf
   140006378:	89 c2                	mov    edx,eax
   14000637a:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140006381:	89 10                	mov    DWORD PTR [rax],edx
   140006383:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   14000638a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000638c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000638f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006392:	83 e0 07             	and    eax,0x7
   140006395:	83 f8 04             	cmp    eax,0x4
   140006398:	0f 84 b0 00 00 00    	je     14000644e <__gdtoa+0x114>
   14000639e:	83 f8 04             	cmp    eax,0x4
   1400063a1:	0f 8f d5 00 00 00    	jg     14000647c <__gdtoa+0x142>
   1400063a7:	83 f8 03             	cmp    eax,0x3
   1400063aa:	74 74                	je     140006420 <__gdtoa+0xe6>
   1400063ac:	83 f8 03             	cmp    eax,0x3
   1400063af:	0f 8f c7 00 00 00    	jg     14000647c <__gdtoa+0x142>
   1400063b5:	85 c0                	test   eax,eax
   1400063b7:	0f 84 05 01 00 00    	je     1400064c2 <__gdtoa+0x188>
   1400063bd:	85 c0                	test   eax,eax
   1400063bf:	0f 88 b7 00 00 00    	js     14000647c <__gdtoa+0x142>
   1400063c5:	83 e8 01             	sub    eax,0x1
   1400063c8:	83 f8 01             	cmp    eax,0x1
   1400063cb:	0f 87 ab 00 00 00    	ja     14000647c <__gdtoa+0x142>
   1400063d1:	90                   	nop
   1400063d2:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   1400063d9:	8b 00                	mov    eax,DWORD PTR [rax]
   1400063db:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400063de:	48 8d 4d b4          	lea    rcx,[rbp-0x4c]
   1400063e2:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400063e5:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   1400063ec:	49 89 c8             	mov    r8,rcx
   1400063ef:	48 89 c1             	mov    rcx,rax
   1400063f2:	e8 19 fe ff ff       	call   140006210 <bitstob>
   1400063f7:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400063fb:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006401:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140006404:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006408:	48 89 c1             	mov    rcx,rax
   14000640b:	e8 31 16 00 00       	call   140007a41 <__trailz_D2A>
   140006410:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006413:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006416:	85 c0                	test   eax,eax
   140006418:	0f 84 8b 00 00 00    	je     1400064a9 <__gdtoa+0x16f>
   14000641e:	eb 66                	jmp    140006486 <__gdtoa+0x14c>
   140006420:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006427:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000642d:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006434:	48 8d 0d 15 4f 00 00 	lea    rcx,[rip+0x4f15]        # 14000b350 <.rdata>
   14000643b:	41 b8 08 00 00 00    	mov    r8d,0x8
   140006441:	48 89 c2             	mov    rdx,rax
   140006444:	e8 79 fa ff ff       	call   140005ec2 <__nrv_alloc_D2A>
   140006449:	e9 4d 14 00 00       	jmp    14000789b <__gdtoa+0x1561>
   14000644e:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006455:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000645b:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006462:	48 8d 0d f0 4e 00 00 	lea    rcx,[rip+0x4ef0]        # 14000b359 <.rdata+0x9>
   140006469:	41 b8 03 00 00 00    	mov    r8d,0x3
   14000646f:	48 89 c2             	mov    rdx,rax
   140006472:	e8 4b fa ff ff       	call   140005ec2 <__nrv_alloc_D2A>
   140006477:	e9 1f 14 00 00       	jmp    14000789b <__gdtoa+0x1561>
   14000647c:	b8 00 00 00 00       	mov    eax,0x0
   140006481:	e9 15 14 00 00       	jmp    14000789b <__gdtoa+0x1561>
   140006486:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006489:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000648d:	48 89 c1             	mov    rcx,rax
   140006490:	e8 50 14 00 00       	call   1400078e5 <__rshift_D2A>
   140006495:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006498:	01 85 98 00 00 00    	add    DWORD PTR [rbp+0x98],eax
   14000649e:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   1400064a1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400064a4:	29 c2                	sub    edx,eax
   1400064a6:	89 55 b4             	mov    DWORD PTR [rbp-0x4c],edx
   1400064a9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400064ad:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400064b0:	85 c0                	test   eax,eax
   1400064b2:	75 3d                	jne    1400064f1 <__gdtoa+0x1b7>
   1400064b4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400064b8:	48 89 c1             	mov    rcx,rax
   1400064bb:	e8 7e 19 00 00       	call   140007e3e <__Bfree_D2A>
   1400064c0:	eb 01                	jmp    1400064c3 <__gdtoa+0x189>
   1400064c2:	90                   	nop
   1400064c3:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400064ca:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   1400064d0:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400064d7:	48 8d 0d 7f 4e 00 00 	lea    rcx,[rip+0x4e7f]        # 14000b35d <.rdata+0xd>
   1400064de:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400064e4:	48 89 c2             	mov    rdx,rax
   1400064e7:	e8 d6 f9 ff ff       	call   140005ec2 <__nrv_alloc_D2A>
   1400064ec:	e9 aa 13 00 00       	jmp    14000789b <__gdtoa+0x1561>
   1400064f1:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
   1400064f5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400064f9:	48 89 c1             	mov    rcx,rax
   1400064fc:	e8 75 23 00 00       	call   140008876 <__b2d_D2A>
   140006501:	66 48 0f 7e c0       	movq   rax,xmm0
   140006506:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   14000650a:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   14000650d:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006513:	01 d0                	add    eax,edx
   140006515:	83 e8 01             	sub    eax,0x1
   140006518:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000651b:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   14000651e:	25 ff ff 0f 00       	and    eax,0xfffff
   140006523:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006526:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006529:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   14000652e:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006531:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006536:	f2 0f 10 15 22 4e 00 	movsd  xmm2,QWORD PTR [rip+0x4e22]        # 14000b360 <.rdata+0x10>
   14000653d:	00 
   14000653e:	66 0f 28 c8          	movapd xmm1,xmm0
   140006542:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006546:	f2 0f 10 05 1a 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e1a]        # 14000b368 <.rdata+0x18>
   14000654d:	00 
   14000654e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006552:	f2 0f 10 05 16 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e16]        # 14000b370 <.rdata+0x20>
   140006559:	00 
   14000655a:	f2 0f 58 c8          	addsd  xmm1,xmm0
   14000655e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006561:	66 0f ef d2          	pxor   xmm2,xmm2
   140006565:	f2 0f 2a d0          	cvtsi2sd xmm2,eax
   140006569:	f2 0f 10 05 07 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e07]        # 14000b378 <.rdata+0x28>
   140006570:	00 
   140006571:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006575:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006579:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000657e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006581:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006584:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006588:	79 03                	jns    14000658d <__gdtoa+0x253>
   14000658a:	f7 5d 60             	neg    DWORD PTR [rbp+0x60]
   14000658d:	81 6d 60 35 04 00 00 	sub    DWORD PTR [rbp+0x60],0x435
   140006594:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006598:	7e 23                	jle    1400065bd <__gdtoa+0x283>
   14000659a:	66 0f ef c9          	pxor   xmm1,xmm1
   14000659e:	f2 0f 2a 4d 60       	cvtsi2sd xmm1,DWORD PTR [rbp+0x60]
   1400065a3:	f2 0f 10 05 d5 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4dd5]        # 14000b380 <.rdata+0x30>
   1400065aa:	00 
   1400065ab:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400065af:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   1400065b4:	f2 0f 58 c1          	addsd  xmm0,xmm1
   1400065b8:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400065bd:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   1400065c2:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   1400065c6:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   1400065c9:	66 0f ef c0          	pxor   xmm0,xmm0
   1400065cd:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   1400065d2:	76 1b                	jbe    1400065ef <__gdtoa+0x2b5>
   1400065d4:	66 0f ef c0          	pxor   xmm0,xmm0
   1400065d8:	f2 0f 2a 45 58       	cvtsi2sd xmm0,DWORD PTR [rbp+0x58]
   1400065dd:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   1400065e2:	7a 07                	jp     1400065eb <__gdtoa+0x2b1>
   1400065e4:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   1400065e9:	74 04                	je     1400065ef <__gdtoa+0x2b5>
   1400065eb:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   1400065ef:	c7 45 54 01 00 00 00 	mov    DWORD PTR [rbp+0x54],0x1
   1400065f6:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   1400065f9:	8b 4d b4             	mov    ecx,DWORD PTR [rbp-0x4c]
   1400065fc:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006602:	01 ca                	add    edx,ecx
   140006604:	83 ea 01             	sub    edx,0x1
   140006607:	c1 e2 14             	shl    edx,0x14
   14000660a:	01 d0                	add    eax,edx
   14000660c:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000660f:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   140006613:	78 2e                	js     140006643 <__gdtoa+0x309>
   140006615:	83 7d 58 16          	cmp    DWORD PTR [rbp+0x58],0x16
   140006619:	7f 28                	jg     140006643 <__gdtoa+0x309>
   14000661b:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006620:	48 8b 05 59 50 00 00 	mov    rax,QWORD PTR [rip+0x5059]        # 14000b680 <.refptr.__tens_D2A>
   140006627:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   14000662a:	48 63 d2             	movsxd rdx,edx
   14000662d:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006632:	66 0f 2f c1          	comisd xmm0,xmm1
   140006636:	76 04                	jbe    14000663c <__gdtoa+0x302>
   140006638:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000663c:	c7 45 54 00 00 00 00 	mov    DWORD PTR [rbp+0x54],0x0
   140006643:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   140006646:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006649:	29 c2                	sub    edx,eax
   14000664b:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000664e:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006651:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006655:	78 0f                	js     140006666 <__gdtoa+0x32c>
   140006657:	c7 45 7c 00 00 00 00 	mov    DWORD PTR [rbp+0x7c],0x0
   14000665e:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006661:	89 45 40             	mov    DWORD PTR [rbp+0x40],eax
   140006664:	eb 0f                	jmp    140006675 <__gdtoa+0x33b>
   140006666:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006669:	f7 d8                	neg    eax
   14000666b:	89 45 7c             	mov    DWORD PTR [rbp+0x7c],eax
   14000666e:	c7 45 40 00 00 00 00 	mov    DWORD PTR [rbp+0x40],0x0
   140006675:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   140006679:	78 15                	js     140006690 <__gdtoa+0x356>
   14000667b:	c7 45 78 00 00 00 00 	mov    DWORD PTR [rbp+0x78],0x0
   140006682:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006685:	89 45 3c             	mov    DWORD PTR [rbp+0x3c],eax
   140006688:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000668b:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   14000668e:	eb 15                	jmp    1400066a5 <__gdtoa+0x36b>
   140006690:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006693:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140006696:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006699:	f7 d8                	neg    eax
   14000669b:	89 45 78             	mov    DWORD PTR [rbp+0x78],eax
   14000669e:	c7 45 3c 00 00 00 00 	mov    DWORD PTR [rbp+0x3c],0x0
   1400066a5:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400066ac:	78 09                	js     1400066b7 <__gdtoa+0x37d>
   1400066ae:	83 bd b0 00 00 00 09 	cmp    DWORD PTR [rbp+0xb0],0x9
   1400066b5:	7e 0a                	jle    1400066c1 <__gdtoa+0x387>
   1400066b7:	c7 85 b0 00 00 00 00 	mov    DWORD PTR [rbp+0xb0],0x0
   1400066be:	00 00 00 
   1400066c1:	c7 45 34 01 00 00 00 	mov    DWORD PTR [rbp+0x34],0x1
   1400066c8:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   1400066cf:	7e 10                	jle    1400066e1 <__gdtoa+0x3a7>
   1400066d1:	83 ad b0 00 00 00 04 	sub    DWORD PTR [rbp+0xb0],0x4
   1400066d8:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   1400066df:	eb 1b                	jmp    1400066fc <__gdtoa+0x3c2>
   1400066e1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400066e4:	3d f9 03 00 00       	cmp    eax,0x3f9
   1400066e9:	7f 0a                	jg     1400066f5 <__gdtoa+0x3bb>
   1400066eb:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400066ee:	3d 02 fc ff ff       	cmp    eax,0xfffffc02
   1400066f3:	7d 07                	jge    1400066fc <__gdtoa+0x3c2>
   1400066f5:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   1400066fc:	c7 45 50 01 00 00 00 	mov    DWORD PTR [rbp+0x50],0x1
   140006703:	c7 45 68 ff ff ff ff 	mov    DWORD PTR [rbp+0x68],0xffffffff
   14000670a:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000670d:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006710:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006717:	0f 84 c5 00 00 00    	je     1400067e2 <__gdtoa+0x4a8>
   14000671d:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006724:	0f 8f e6 00 00 00    	jg     140006810 <__gdtoa+0x4d6>
   14000672a:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   140006731:	74 7e                	je     1400067b1 <__gdtoa+0x477>
   140006733:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   14000673a:	0f 8f d0 00 00 00    	jg     140006810 <__gdtoa+0x4d6>
   140006740:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006747:	0f 84 8e 00 00 00    	je     1400067db <__gdtoa+0x4a1>
   14000674d:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006754:	0f 8f b6 00 00 00    	jg     140006810 <__gdtoa+0x4d6>
   14000675a:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006761:	7f 0e                	jg     140006771 <__gdtoa+0x437>
   140006763:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   14000676a:	79 13                	jns    14000677f <__gdtoa+0x445>
   14000676c:	e9 9f 00 00 00       	jmp    140006810 <__gdtoa+0x4d6>
   140006771:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   140006778:	74 30                	je     1400067aa <__gdtoa+0x470>
   14000677a:	e9 91 00 00 00       	jmp    140006810 <__gdtoa+0x4d6>
   14000677f:	66 0f ef c9          	pxor   xmm1,xmm1
   140006783:	f2 0f 2a 4d f8       	cvtsi2sd xmm1,DWORD PTR [rbp-0x8]
   140006788:	f2 0f 10 05 f8 4b 00 	movsd  xmm0,QWORD PTR [rip+0x4bf8]        # 14000b388 <.rdata+0x38>
   14000678f:	00 
   140006790:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006794:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006798:	83 c0 03             	add    eax,0x3
   14000679b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000679e:	c7 85 b8 00 00 00 00 	mov    DWORD PTR [rbp+0xb8],0x0
   1400067a5:	00 00 00 
   1400067a8:	eb 66                	jmp    140006810 <__gdtoa+0x4d6>
   1400067aa:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   1400067b1:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   1400067b8:	7f 0a                	jg     1400067c4 <__gdtoa+0x48a>
   1400067ba:	c7 85 b8 00 00 00 01 	mov    DWORD PTR [rbp+0xb8],0x1
   1400067c1:	00 00 00 
   1400067c4:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   1400067ca:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400067cd:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067d0:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   1400067d3:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   1400067d6:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400067d9:	eb 35                	jmp    140006810 <__gdtoa+0x4d6>
   1400067db:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   1400067e2:	8b 95 b8 00 00 00    	mov    edx,DWORD PTR [rbp+0xb8]
   1400067e8:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400067eb:	01 d0                	add    eax,edx
   1400067ed:	83 c0 01             	add    eax,0x1
   1400067f0:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400067f3:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067f6:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400067f9:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400067fc:	83 e8 01             	sub    eax,0x1
   1400067ff:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006802:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006805:	85 c0                	test   eax,eax
   140006807:	7f 07                	jg     140006810 <__gdtoa+0x4d6>
   140006809:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006810:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006813:	89 c1                	mov    ecx,eax
   140006815:	e8 56 f6 ff ff       	call   140005e70 <__rv_alloc_D2A>
   14000681a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000681e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006822:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006826:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000682d:	7f 09                	jg     140006838 <__gdtoa+0x4fe>
   14000682f:	c7 45 44 00 00 00 00 	mov    DWORD PTR [rbp+0x44],0x0
   140006836:	eb 38                	jmp    140006870 <__gdtoa+0x536>
   140006838:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000683f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140006842:	83 e8 01             	sub    eax,0x1
   140006845:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   140006848:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000684c:	74 22                	je     140006870 <__gdtoa+0x536>
   14000684e:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006852:	79 07                	jns    14000685b <__gdtoa+0x521>
   140006854:	c7 45 44 02 00 00 00 	mov    DWORD PTR [rbp+0x44],0x2
   14000685b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000685e:	83 e0 08             	and    eax,0x8
   140006861:	85 c0                	test   eax,eax
   140006863:	74 0b                	je     140006870 <__gdtoa+0x536>
   140006865:	b8 03 00 00 00       	mov    eax,0x3
   14000686a:	2b 45 44             	sub    eax,DWORD PTR [rbp+0x44]
   14000686d:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   140006870:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006874:	0f 88 b9 04 00 00    	js     140006d33 <__gdtoa+0x9f9>
   14000687a:	83 7d 6c 0e          	cmp    DWORD PTR [rbp+0x6c],0xe
   14000687e:	0f 8f af 04 00 00    	jg     140006d33 <__gdtoa+0x9f9>
   140006884:	83 7d 34 00          	cmp    DWORD PTR [rbp+0x34],0x0
   140006888:	0f 84 a5 04 00 00    	je     140006d33 <__gdtoa+0x9f9>
   14000688e:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006892:	0f 85 9b 04 00 00    	jne    140006d33 <__gdtoa+0x9f9>
   140006898:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   14000689c:	0f 85 91 04 00 00    	jne    140006d33 <__gdtoa+0x9f9>
   1400068a2:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   1400068a9:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400068ae:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400068b3:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400068b6:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400068b9:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   1400068bc:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   1400068bf:	c7 45 70 02 00 00 00 	mov    DWORD PTR [rbp+0x70],0x2
   1400068c6:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400068ca:	0f 8e 98 00 00 00    	jle    140006968 <__gdtoa+0x62e>
   1400068d0:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400068d3:	83 e0 0f             	and    eax,0xf
   1400068d6:	89 c2                	mov    edx,eax
   1400068d8:	48 8b 05 a1 4d 00 00 	mov    rax,QWORD PTR [rip+0x4da1]        # 14000b680 <.refptr.__tens_D2A>
   1400068df:	48 63 d2             	movsxd rdx,edx
   1400068e2:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400068e7:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400068ec:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400068ef:	c1 f8 04             	sar    eax,0x4
   1400068f2:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400068f5:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400068f8:	83 e0 10             	and    eax,0x10
   1400068fb:	85 c0                	test   eax,eax
   1400068fd:	74 5e                	je     14000695d <__gdtoa+0x623>
   1400068ff:	83 65 60 0f          	and    DWORD PTR [rbp+0x60],0xf
   140006903:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006908:	48 8b 05 a1 4c 00 00 	mov    rax,QWORD PTR [rip+0x4ca1]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000690f:	f2 0f 10 48 20       	movsd  xmm1,QWORD PTR [rax+0x20]
   140006914:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006918:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   14000691d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006921:	eb 3a                	jmp    14000695d <__gdtoa+0x623>
   140006923:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006926:	83 e0 01             	and    eax,0x1
   140006929:	85 c0                	test   eax,eax
   14000692b:	74 24                	je     140006951 <__gdtoa+0x617>
   14000692d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006931:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006934:	48 8b 05 75 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c75]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000693b:	48 63 d2             	movsxd rdx,edx
   14000693e:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006943:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006948:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000694c:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006951:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006954:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006957:	83 c0 01             	add    eax,0x1
   14000695a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000695d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006961:	75 c0                	jne    140006923 <__gdtoa+0x5e9>
   140006963:	e9 8b 00 00 00       	jmp    1400069f3 <__gdtoa+0x6b9>
   140006968:	f2 0f 10 05 20 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4a20]        # 14000b390 <.rdata+0x40>
   14000696f:	00 
   140006970:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006975:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006978:	f7 d8                	neg    eax
   14000697a:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   14000697d:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140006981:	74 70                	je     1400069f3 <__gdtoa+0x6b9>
   140006983:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006988:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   14000698b:	83 e0 0f             	and    eax,0xf
   14000698e:	89 c2                	mov    edx,eax
   140006990:	48 8b 05 e9 4c 00 00 	mov    rax,QWORD PTR [rip+0x4ce9]        # 14000b680 <.refptr.__tens_D2A>
   140006997:	48 63 d2             	movsxd rdx,edx
   14000699a:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   14000699f:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400069a3:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400069a8:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   1400069ab:	c1 f8 04             	sar    eax,0x4
   1400069ae:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400069b1:	eb 3a                	jmp    1400069ed <__gdtoa+0x6b3>
   1400069b3:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400069b6:	83 e0 01             	and    eax,0x1
   1400069b9:	85 c0                	test   eax,eax
   1400069bb:	74 24                	je     1400069e1 <__gdtoa+0x6a7>
   1400069bd:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   1400069c1:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069c6:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400069c9:	48 8b 05 e0 4b 00 00 	mov    rax,QWORD PTR [rip+0x4be0]        # 14000b5b0 <.refptr.__bigtens_D2A>
   1400069d0:	48 63 d2             	movsxd rdx,edx
   1400069d3:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400069d8:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400069dc:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400069e1:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   1400069e4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400069e7:	83 c0 01             	add    eax,0x1
   1400069ea:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400069ed:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400069f1:	75 c0                	jne    1400069b3 <__gdtoa+0x679>
   1400069f3:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   1400069f7:	74 47                	je     140006a40 <__gdtoa+0x706>
   1400069f9:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069fe:	f2 0f 10 05 8a 49 00 	movsd  xmm0,QWORD PTR [rip+0x498a]        # 14000b390 <.rdata+0x40>
   140006a05:	00 
   140006a06:	66 0f 2f c1          	comisd xmm0,xmm1
   140006a0a:	76 34                	jbe    140006a40 <__gdtoa+0x706>
   140006a0c:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006a10:	7e 2e                	jle    140006a40 <__gdtoa+0x706>
   140006a12:	83 7d 68 00          	cmp    DWORD PTR [rbp+0x68],0x0
   140006a16:	0f 8e f5 02 00 00    	jle    140006d11 <__gdtoa+0x9d7>
   140006a1c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   140006a1f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006a22:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140006a26:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a2b:	f2 0f 10 05 65 49 00 	movsd  xmm0,QWORD PTR [rip+0x4965]        # 14000b398 <.rdata+0x48>
   140006a32:	00 
   140006a33:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006a37:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a3c:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006a40:	66 0f ef c9          	pxor   xmm1,xmm1
   140006a44:	f2 0f 2a 4d 70       	cvtsi2sd xmm1,DWORD PTR [rbp+0x70]
   140006a49:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a4e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006a52:	f2 0f 10 05 46 49 00 	movsd  xmm0,QWORD PTR [rip+0x4946]        # 14000b3a0 <.rdata+0x50>
   140006a59:	00 
   140006a5a:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006a5e:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006a63:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   140006a66:	2d 00 00 40 03       	sub    eax,0x3400000
   140006a6b:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   140006a6e:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006a72:	75 5f                	jne    140006ad3 <__gdtoa+0x799>
   140006a74:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006a7b:	00 
   140006a7c:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006a80:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006a84:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a89:	f2 0f 10 0d 17 49 00 	movsd  xmm1,QWORD PTR [rip+0x4917]        # 14000b3a8 <.rdata+0x58>
   140006a90:	00 
   140006a91:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006a95:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a9a:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a9f:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006aa4:	66 0f 2f c1          	comisd xmm0,xmm1
   140006aa8:	0f 87 ac 07 00 00    	ja     14000725a <__gdtoa+0xf20>
   140006aae:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006ab3:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006ab8:	f3 0f 7e 15 f0 48 00 	movq   xmm2,QWORD PTR [rip+0x48f0]        # 14000b3b0 <.rdata+0x60>
   140006abf:	00 
   140006ac0:	66 0f 57 c2          	xorpd  xmm0,xmm2
   140006ac4:	66 0f 2f c1          	comisd xmm0,xmm1
   140006ac8:	0f 87 6e 07 00 00    	ja     14000723c <__gdtoa+0xf02>
   140006ace:	e9 42 02 00 00       	jmp    140006d15 <__gdtoa+0x9db>
   140006ad3:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006ad7:	0f 84 22 01 00 00    	je     140006bff <__gdtoa+0x8c5>
   140006add:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006ae2:	f2 0f 10 05 d6 48 00 	movsd  xmm0,QWORD PTR [rip+0x48d6]        # 14000b3c0 <.rdata+0x70>
   140006ae9:	00 
   140006aea:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006aee:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006af1:	8d 50 ff             	lea    edx,[rax-0x1]
   140006af4:	48 8b 05 85 4b 00 00 	mov    rax,QWORD PTR [rip+0x4b85]        # 14000b680 <.refptr.__tens_D2A>
   140006afb:	48 63 d2             	movsxd rdx,edx
   140006afe:	f2 0f 10 0c d0       	movsd  xmm1,QWORD PTR [rax+rdx*8]
   140006b03:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006b07:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006b0c:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006b10:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006b15:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006b1c:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b21:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006b26:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006b2a:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006b2d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b32:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b36:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006b3b:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006b40:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006b44:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006b49:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006b4c:	8d 48 30             	lea    ecx,[rax+0x30]
   140006b4f:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006b53:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006b57:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006b5b:	89 ca                	mov    edx,ecx
   140006b5d:	88 10                	mov    BYTE PTR [rax],dl
   140006b5f:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006b64:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006b69:	66 0f 2f c1          	comisd xmm0,xmm1
   140006b6d:	76 29                	jbe    140006b98 <__gdtoa+0x85e>
   140006b6f:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b74:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b78:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006b7c:	7a 0e                	jp     140006b8c <__gdtoa+0x852>
   140006b7e:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b82:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006b86:	0f 84 93 0c 00 00    	je     14000781f <__gdtoa+0x14e5>
   140006b8c:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006b93:	e9 87 0c 00 00       	jmp    14000781f <__gdtoa+0x14e5>
   140006b98:	f2 0f 10 55 a8       	movsd  xmm2,QWORD PTR [rbp-0x58]
   140006b9d:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006ba2:	66 0f 28 c8          	movapd xmm1,xmm0
   140006ba6:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006baa:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006baf:	66 0f 2f c1          	comisd xmm0,xmm1
   140006bb3:	0f 87 c3 02 00 00    	ja     140006e7c <__gdtoa+0xb42>
   140006bb9:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006bbc:	83 c0 01             	add    eax,0x1
   140006bbf:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006bc2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006bc5:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006bc8:	0f 8e 46 01 00 00    	jle    140006d14 <__gdtoa+0x9da>
   140006bce:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006bd3:	f2 0f 10 05 bd 47 00 	movsd  xmm0,QWORD PTR [rip+0x47bd]        # 14000b398 <.rdata+0x48>
   140006bda:	00 
   140006bdb:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006bdf:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006be4:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006be9:	f2 0f 10 05 a7 47 00 	movsd  xmm0,QWORD PTR [rip+0x47a7]        # 14000b398 <.rdata+0x48>
   140006bf0:	00 
   140006bf1:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006bf5:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006bfa:	e9 1d ff ff ff       	jmp    140006b1c <__gdtoa+0x7e2>
   140006bff:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006c04:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006c07:	8d 50 ff             	lea    edx,[rax-0x1]
   140006c0a:	48 8b 05 6f 4a 00 00 	mov    rax,QWORD PTR [rip+0x4a6f]        # 14000b680 <.refptr.__tens_D2A>
   140006c11:	48 63 d2             	movsxd rdx,edx
   140006c14:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006c19:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c1d:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006c22:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006c29:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c2e:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006c33:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006c37:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006c3a:	83 7d d4 00          	cmp    DWORD PTR [rbp-0x2c],0x0
   140006c3e:	74 1c                	je     140006c5c <__gdtoa+0x922>
   140006c40:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c45:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c49:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006c4e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006c53:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006c57:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c5c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006c5f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006c62:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006c66:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006c6a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006c6e:	89 ca                	mov    edx,ecx
   140006c70:	88 10                	mov    BYTE PTR [rax],dl
   140006c72:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006c75:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006c78:	75 73                	jne    140006ced <__gdtoa+0x9b3>
   140006c7a:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006c7f:	f2 0f 10 05 39 47 00 	movsd  xmm0,QWORD PTR [rip+0x4739]        # 14000b3c0 <.rdata+0x70>
   140006c86:	00 
   140006c87:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c8b:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006c90:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c95:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006c9a:	f2 0f 58 4d 08       	addsd  xmm1,QWORD PTR [rbp+0x8]
   140006c9f:	66 0f 2f c1          	comisd xmm0,xmm1
   140006ca3:	0f 87 d6 01 00 00    	ja     140006e7f <__gdtoa+0xb45>
   140006ca9:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006cae:	f2 0f 10 55 a0       	movsd  xmm2,QWORD PTR [rbp-0x60]
   140006cb3:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006cb8:	f2 0f 5c c2          	subsd  xmm0,xmm2
   140006cbc:	66 0f 2f c1          	comisd xmm0,xmm1
   140006cc0:	77 02                	ja     140006cc4 <__gdtoa+0x98a>
   140006cc2:	eb 51                	jmp    140006d15 <__gdtoa+0x9db>
   140006cc4:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006cc9:	66 0f ef c9          	pxor   xmm1,xmm1
   140006ccd:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006cd1:	7a 0e                	jp     140006ce1 <__gdtoa+0x9a7>
   140006cd3:	66 0f ef c9          	pxor   xmm1,xmm1
   140006cd7:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006cdb:	0f 84 41 0b 00 00    	je     140007822 <__gdtoa+0x14e8>
   140006ce1:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006ce8:	e9 35 0b 00 00       	jmp    140007822 <__gdtoa+0x14e8>
   140006ced:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006cf0:	83 c0 01             	add    eax,0x1
   140006cf3:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006cf6:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006cfb:	f2 0f 10 05 95 46 00 	movsd  xmm0,QWORD PTR [rip+0x4695]        # 14000b398 <.rdata+0x48>
   140006d02:	00 
   140006d03:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006d07:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d0c:	e9 18 ff ff ff       	jmp    140006c29 <__gdtoa+0x8ef>
   140006d11:	90                   	nop
   140006d12:	eb 01                	jmp    140006d15 <__gdtoa+0x9db>
   140006d14:	90                   	nop
   140006d15:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006d19:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006d1d:	f2 0f 10 45 e0       	movsd  xmm0,QWORD PTR [rbp-0x20]
   140006d22:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d27:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140006d2a:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006d2d:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140006d30:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006d33:	83 bd 98 00 00 00 00 	cmp    DWORD PTR [rbp+0x98],0x0
   140006d3a:	0f 88 bf 01 00 00    	js     140006eff <__gdtoa+0xbc5>
   140006d40:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006d47:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006d4a:	39 45 58             	cmp    DWORD PTR [rbp+0x58],eax
   140006d4d:	0f 8f ac 01 00 00    	jg     140006eff <__gdtoa+0xbc5>
   140006d53:	48 8b 05 26 49 00 00 	mov    rax,QWORD PTR [rip+0x4926]        # 14000b680 <.refptr.__tens_D2A>
   140006d5a:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   140006d5d:	48 63 d2             	movsxd rdx,edx
   140006d60:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006d65:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006d6a:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006d71:	79 45                	jns    140006db8 <__gdtoa+0xa7e>
   140006d73:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006d77:	7f 3f                	jg     140006db8 <__gdtoa+0xa7e>
   140006d79:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006d80:	00 
   140006d81:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006d85:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006d89:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006d8d:	0f 88 ac 04 00 00    	js     14000723f <__gdtoa+0xf05>
   140006d93:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006d98:	f2 0f 10 55 08       	movsd  xmm2,QWORD PTR [rbp+0x8]
   140006d9d:	f2 0f 10 05 03 46 00 	movsd  xmm0,QWORD PTR [rip+0x4603]        # 14000b3a8 <.rdata+0x58>
   140006da4:	00 
   140006da5:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006da9:	66 0f 2f c1          	comisd xmm0,xmm1
   140006dad:	0f 83 8c 04 00 00    	jae    14000723f <__gdtoa+0xf05>
   140006db3:	e9 a6 04 00 00       	jmp    14000725e <__gdtoa+0xf24>
   140006db8:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006dbf:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006dc4:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006dc9:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006dcd:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006dd0:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006dd5:	66 0f ef c9          	pxor   xmm1,xmm1
   140006dd9:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006dde:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006de3:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006de7:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006dec:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006def:	8d 48 30             	lea    ecx,[rax+0x30]
   140006df2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006df6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006dfa:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006dfe:	89 ca                	mov    edx,ecx
   140006e00:	88 10                	mov    BYTE PTR [rax],dl
   140006e02:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e07:	66 0f ef c9          	pxor   xmm1,xmm1
   140006e0b:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006e0f:	7a 0e                	jp     140006e1f <__gdtoa+0xae5>
   140006e11:	66 0f ef c9          	pxor   xmm1,xmm1
   140006e15:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006e19:	0f 84 da 00 00 00    	je     140006ef9 <__gdtoa+0xbbf>
   140006e1f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006e22:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006e25:	0f 85 aa 00 00 00    	jne    140006ed5 <__gdtoa+0xb9b>
   140006e2b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006e2f:	74 12                	je     140006e43 <__gdtoa+0xb09>
   140006e31:	83 7d 44 01          	cmp    DWORD PTR [rbp+0x44],0x1
   140006e35:	74 4b                	je     140006e82 <__gdtoa+0xb48>
   140006e37:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006e3e:	e9 e3 09 00 00       	jmp    140007826 <__gdtoa+0x14ec>
   140006e43:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e48:	f2 0f 58 c0          	addsd  xmm0,xmm0
   140006e4c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006e51:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e56:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006e5b:	77 28                	ja     140006e85 <__gdtoa+0xb4b>
   140006e5d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e62:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006e67:	7a 63                	jp     140006ecc <__gdtoa+0xb92>
   140006e69:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006e6e:	75 5c                	jne    140006ecc <__gdtoa+0xb92>
   140006e70:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006e73:	83 e0 01             	and    eax,0x1
   140006e76:	85 c0                	test   eax,eax
   140006e78:	74 52                	je     140006ecc <__gdtoa+0xb92>
   140006e7a:	eb 0a                	jmp    140006e86 <__gdtoa+0xb4c>
   140006e7c:	90                   	nop
   140006e7d:	eb 07                	jmp    140006e86 <__gdtoa+0xb4c>
   140006e7f:	90                   	nop
   140006e80:	eb 04                	jmp    140006e86 <__gdtoa+0xb4c>
   140006e82:	90                   	nop
   140006e83:	eb 01                	jmp    140006e86 <__gdtoa+0xb4c>
   140006e85:	90                   	nop
   140006e86:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140006e8d:	eb 17                	jmp    140006ea6 <__gdtoa+0xb6c>
   140006e8f:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e93:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140006e97:	75 0d                	jne    140006ea6 <__gdtoa+0xb6c>
   140006e99:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140006e9d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006ea1:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140006ea4:	eb 10                	jmp    140006eb6 <__gdtoa+0xb7c>
   140006ea6:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140006eab:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006eaf:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140006eb2:	3c 39                	cmp    al,0x39
   140006eb4:	74 d9                	je     140006e8f <__gdtoa+0xb55>
   140006eb6:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006eba:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006ebe:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006ec2:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140006ec5:	83 c2 01             	add    edx,0x1
   140006ec8:	88 10                	mov    BYTE PTR [rax],dl
   140006eca:	eb 2e                	jmp    140006efa <__gdtoa+0xbc0>
   140006ecc:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006ed3:	eb 25                	jmp    140006efa <__gdtoa+0xbc0>
   140006ed5:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006ed8:	83 c0 01             	add    eax,0x1
   140006edb:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006ede:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006ee3:	f2 0f 10 05 ad 44 00 	movsd  xmm0,QWORD PTR [rip+0x44ad]        # 14000b398 <.rdata+0x48>
   140006eea:	00 
   140006eeb:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006eef:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006ef4:	e9 c6 fe ff ff       	jmp    140006dbf <__gdtoa+0xa85>
   140006ef9:	90                   	nop
   140006efa:	e9 27 09 00 00       	jmp    140007826 <__gdtoa+0x14ec>
   140006eff:	8b 45 7c             	mov    eax,DWORD PTR [rbp+0x7c]
   140006f02:	89 45 4c             	mov    DWORD PTR [rbp+0x4c],eax
   140006f05:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006f08:	89 45 48             	mov    DWORD PTR [rbp+0x48],eax
   140006f0b:	48 c7 45 20 00 00 00 	mov    QWORD PTR [rbp+0x20],0x0
   140006f12:	00 
   140006f13:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006f17:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006f1b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006f1f:	0f 84 e0 00 00 00    	je     140007005 <__gdtoa+0xccb>
   140006f25:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   140006f28:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006f2b:	29 c2                	sub    edx,eax
   140006f2d:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006f30:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f33:	8d 50 01             	lea    edx,[rax+0x1]
   140006f36:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006f39:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006f3f:	29 c2                	sub    edx,eax
   140006f41:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006f48:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006f4b:	39 c2                	cmp    edx,eax
   140006f4d:	7d 43                	jge    140006f92 <__gdtoa+0xc58>
   140006f4f:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006f56:	74 3a                	je     140006f92 <__gdtoa+0xc58>
   140006f58:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006f5f:	74 31                	je     140006f92 <__gdtoa+0xc58>
   140006f61:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006f68:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006f6b:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006f71:	29 c2                	sub    edx,eax
   140006f73:	8d 42 01             	lea    eax,[rdx+0x1]
   140006f76:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f79:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006f80:	7e 68                	jle    140006fea <__gdtoa+0xcb0>
   140006f82:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006f86:	7e 62                	jle    140006fea <__gdtoa+0xcb0>
   140006f88:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f8b:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006f8e:	7d 5a                	jge    140006fea <__gdtoa+0xcb0>
   140006f90:	eb 0a                	jmp    140006f9c <__gdtoa+0xc62>
   140006f92:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006f99:	7e 50                	jle    140006feb <__gdtoa+0xcb1>
   140006f9b:	90                   	nop
   140006f9c:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006f9f:	83 e8 01             	sub    eax,0x1
   140006fa2:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006fa5:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006fa8:	3b 45 60             	cmp    eax,DWORD PTR [rbp+0x60]
   140006fab:	7c 08                	jl     140006fb5 <__gdtoa+0xc7b>
   140006fad:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006fb0:	29 45 48             	sub    DWORD PTR [rbp+0x48],eax
   140006fb3:	eb 19                	jmp    140006fce <__gdtoa+0xc94>
   140006fb5:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006fb8:	29 45 60             	sub    DWORD PTR [rbp+0x60],eax
   140006fbb:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006fbe:	01 45 3c             	add    DWORD PTR [rbp+0x3c],eax
   140006fc1:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006fc4:	01 45 78             	add    DWORD PTR [rbp+0x78],eax
   140006fc7:	c7 45 48 00 00 00 00 	mov    DWORD PTR [rbp+0x48],0x0
   140006fce:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006fd1:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006fd4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fd7:	85 c0                	test   eax,eax
   140006fd9:	79 10                	jns    140006feb <__gdtoa+0xcb1>
   140006fdb:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fde:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140006fe1:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006fe8:	eb 01                	jmp    140006feb <__gdtoa+0xcb1>
   140006fea:	90                   	nop
   140006feb:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fee:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   140006ff1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006ff4:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140006ff7:	b9 01 00 00 00       	mov    ecx,0x1
   140006ffc:	e8 f6 0f 00 00       	call   140007ff7 <__i2b_D2A>
   140007001:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007005:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   140007009:	7e 26                	jle    140007031 <__gdtoa+0xcf7>
   14000700b:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   14000700f:	7e 20                	jle    140007031 <__gdtoa+0xcf7>
   140007011:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140007014:	8b 45 4c             	mov    eax,DWORD PTR [rbp+0x4c]
   140007017:	39 c2                	cmp    edx,eax
   140007019:	0f 4e c2             	cmovle eax,edx
   14000701c:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000701f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007022:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140007025:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007028:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   14000702b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000702e:	29 45 40             	sub    DWORD PTR [rbp+0x40],eax
   140007031:	83 7d 78 00          	cmp    DWORD PTR [rbp+0x78],0x0
   140007035:	7e 7e                	jle    1400070b5 <__gdtoa+0xd7b>
   140007037:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   14000703b:	74 65                	je     1400070a2 <__gdtoa+0xd68>
   14000703d:	83 7d 48 00          	cmp    DWORD PTR [rbp+0x48],0x0
   140007041:	7e 3b                	jle    14000707e <__gdtoa+0xd44>
   140007043:	8b 55 48             	mov    edx,DWORD PTR [rbp+0x48]
   140007046:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000704a:	48 89 c1             	mov    rcx,rax
   14000704d:	e8 11 12 00 00       	call   140008263 <__pow5mult_D2A>
   140007052:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007056:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000705a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000705e:	48 89 c1             	mov    rcx,rax
   140007061:	e8 d7 0f 00 00       	call   14000803d <__mult_D2A>
   140007066:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000706a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000706e:	48 89 c1             	mov    rcx,rax
   140007071:	e8 c8 0d 00 00       	call   140007e3e <__Bfree_D2A>
   140007076:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000707a:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000707e:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140007081:	2b 45 48             	sub    eax,DWORD PTR [rbp+0x48]
   140007084:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140007087:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000708b:	74 28                	je     1400070b5 <__gdtoa+0xd7b>
   14000708d:	8b 55 60             	mov    edx,DWORD PTR [rbp+0x60]
   140007090:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007094:	48 89 c1             	mov    rcx,rax
   140007097:	e8 c7 11 00 00       	call   140008263 <__pow5mult_D2A>
   14000709c:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400070a0:	eb 13                	jmp    1400070b5 <__gdtoa+0xd7b>
   1400070a2:	8b 55 78             	mov    edx,DWORD PTR [rbp+0x78]
   1400070a5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070a9:	48 89 c1             	mov    rcx,rax
   1400070ac:	e8 b2 11 00 00       	call   140008263 <__pow5mult_D2A>
   1400070b1:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400070b5:	b9 01 00 00 00       	mov    ecx,0x1
   1400070ba:	e8 38 0f 00 00       	call   140007ff7 <__i2b_D2A>
   1400070bf:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400070c3:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   1400070c7:	7e 13                	jle    1400070dc <__gdtoa+0xda2>
   1400070c9:	8b 55 3c             	mov    edx,DWORD PTR [rbp+0x3c]
   1400070cc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400070d0:	48 89 c1             	mov    rcx,rax
   1400070d3:	e8 8b 11 00 00       	call   140008263 <__pow5mult_D2A>
   1400070d8:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400070dc:	c7 45 38 00 00 00 00 	mov    DWORD PTR [rbp+0x38],0x0
   1400070e3:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   1400070ea:	7f 29                	jg     140007115 <__gdtoa+0xddb>
   1400070ec:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   1400070ef:	83 f8 01             	cmp    eax,0x1
   1400070f2:	75 21                	jne    140007115 <__gdtoa+0xddb>
   1400070f4:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   1400070fb:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400070fe:	83 c0 01             	add    eax,0x1
   140007101:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140007104:	7e 0f                	jle    140007115 <__gdtoa+0xddb>
   140007106:	83 45 7c 01          	add    DWORD PTR [rbp+0x7c],0x1
   14000710a:	83 45 40 01          	add    DWORD PTR [rbp+0x40],0x1
   14000710e:	c7 45 38 01 00 00 00 	mov    DWORD PTR [rbp+0x38],0x1
   140007115:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007119:	74 22                	je     14000713d <__gdtoa+0xe03>
   14000711b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000711f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007122:	8d 50 ff             	lea    edx,[rax-0x1]
   140007125:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007129:	48 63 d2             	movsxd rdx,edx
   14000712c:	48 83 c2 04          	add    rdx,0x4
   140007130:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   140007134:	89 c1                	mov    ecx,eax
   140007136:	e8 c5 f0 ff ff       	call   140006200 <__hi0bits_D2A>
   14000713b:	eb 05                	jmp    140007142 <__gdtoa+0xe08>
   14000713d:	b8 1f 00 00 00       	mov    eax,0x1f
   140007142:	2b 45 40             	sub    eax,DWORD PTR [rbp+0x40]
   140007145:	83 e8 04             	sub    eax,0x4
   140007148:	83 e0 1f             	and    eax,0x1f
   14000714b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000714e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007151:	01 45 4c             	add    DWORD PTR [rbp+0x4c],eax
   140007154:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007157:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   14000715a:	83 7d 7c 00          	cmp    DWORD PTR [rbp+0x7c],0x0
   14000715e:	7e 13                	jle    140007173 <__gdtoa+0xe39>
   140007160:	8b 55 7c             	mov    edx,DWORD PTR [rbp+0x7c]
   140007163:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007167:	48 89 c1             	mov    rcx,rax
   14000716a:	e8 b1 12 00 00       	call   140008420 <__lshift_D2A>
   14000716f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007173:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007176:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140007179:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   14000717d:	7e 13                	jle    140007192 <__gdtoa+0xe58>
   14000717f:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140007182:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007186:	48 89 c1             	mov    rcx,rax
   140007189:	e8 92 12 00 00       	call   140008420 <__lshift_D2A>
   14000718e:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007192:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   140007196:	74 5a                	je     1400071f2 <__gdtoa+0xeb8>
   140007198:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000719c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400071a0:	48 89 c1             	mov    rcx,rax
   1400071a3:	e8 05 14 00 00       	call   1400085ad <__cmp_D2A>
   1400071a8:	85 c0                	test   eax,eax
   1400071aa:	79 46                	jns    1400071f2 <__gdtoa+0xeb8>
   1400071ac:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   1400071b0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400071b4:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400071ba:	ba 0a 00 00 00       	mov    edx,0xa
   1400071bf:	48 89 c1             	mov    rcx,rax
   1400071c2:	e8 02 0d 00 00       	call   140007ec9 <__multadd_D2A>
   1400071c7:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400071cb:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   1400071cf:	74 1b                	je     1400071ec <__gdtoa+0xeb2>
   1400071d1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400071d5:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400071db:	ba 0a 00 00 00       	mov    edx,0xa
   1400071e0:	48 89 c1             	mov    rcx,rax
   1400071e3:	e8 e1 0c 00 00       	call   140007ec9 <__multadd_D2A>
   1400071e8:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400071ec:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   1400071ef:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   1400071f2:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400071f6:	0f 8f 81 00 00 00    	jg     14000727d <__gdtoa+0xf43>
   1400071fc:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   140007203:	7e 78                	jle    14000727d <__gdtoa+0xf43>
   140007205:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007209:	78 37                	js     140007242 <__gdtoa+0xf08>
   14000720b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000720f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007215:	ba 05 00 00 00       	mov    edx,0x5
   14000721a:	48 89 c1             	mov    rcx,rax
   14000721d:	e8 a7 0c 00 00       	call   140007ec9 <__multadd_D2A>
   140007222:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007226:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000722a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000722e:	48 89 c1             	mov    rcx,rax
   140007231:	e8 77 13 00 00       	call   1400085ad <__cmp_D2A>
   140007236:	85 c0                	test   eax,eax
   140007238:	7f 23                	jg     14000725d <__gdtoa+0xf23>
   14000723a:	eb 07                	jmp    140007243 <__gdtoa+0xf09>
   14000723c:	90                   	nop
   14000723d:	eb 04                	jmp    140007243 <__gdtoa+0xf09>
   14000723f:	90                   	nop
   140007240:	eb 01                	jmp    140007243 <__gdtoa+0xf09>
   140007242:	90                   	nop
   140007243:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   140007249:	f7 d0                	not    eax
   14000724b:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   14000724e:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140007255:	e9 87 05 00 00       	jmp    1400077e1 <__gdtoa+0x14a7>
   14000725a:	90                   	nop
   14000725b:	eb 01                	jmp    14000725e <__gdtoa+0xf24>
   14000725d:	90                   	nop
   14000725e:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007265:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007269:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000726d:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007271:	c6 00 31             	mov    BYTE PTR [rax],0x31
   140007274:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140007278:	e9 64 05 00 00       	jmp    1400077e1 <__gdtoa+0x14a7>
   14000727d:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140007281:	0f 84 14 04 00 00    	je     14000769b <__gdtoa+0x1361>
   140007287:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   14000728b:	7e 13                	jle    1400072a0 <__gdtoa+0xf66>
   14000728d:	8b 55 4c             	mov    edx,DWORD PTR [rbp+0x4c]
   140007290:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007294:	48 89 c1             	mov    rcx,rax
   140007297:	e8 84 11 00 00       	call   140008420 <__lshift_D2A>
   14000729c:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400072a0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072a4:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400072a8:	83 7d 38 00          	cmp    DWORD PTR [rbp+0x38],0x0
   1400072ac:	74 57                	je     140007305 <__gdtoa+0xfcb>
   1400072ae:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072b2:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400072b5:	89 c1                	mov    ecx,eax
   1400072b7:	e8 41 0a 00 00       	call   140007cfd <__Balloc_D2A>
   1400072bc:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400072c0:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400072c4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400072c7:	48 98                	cdqe
   1400072c9:	48 83 c0 02          	add    rax,0x2
   1400072cd:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   1400072d4:	00 
   1400072d5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400072d9:	48 8d 50 10          	lea    rdx,[rax+0x10]
   1400072dd:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072e1:	48 83 c0 10          	add    rax,0x10
   1400072e5:	49 89 c8             	mov    r8,rcx
   1400072e8:	48 89 c1             	mov    rcx,rax
   1400072eb:	e8 e8 23 00 00       	call   1400096d8 <memcpy>
   1400072f0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072f4:	ba 01 00 00 00       	mov    edx,0x1
   1400072f9:	48 89 c1             	mov    rcx,rax
   1400072fc:	e8 1f 11 00 00       	call   140008420 <__lshift_D2A>
   140007301:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007305:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   14000730c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007310:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007314:	48 89 c1             	mov    rcx,rax
   140007317:	e8 62 ec ff ff       	call   140005f7e <__quorem_D2A>
   14000731c:	83 c0 30             	add    eax,0x30
   14000731f:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007322:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140007326:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000732a:	48 89 c1             	mov    rcx,rax
   14000732d:	e8 7b 12 00 00       	call   1400085ad <__cmp_D2A>
   140007332:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140007335:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007339:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000733d:	48 89 c1             	mov    rcx,rax
   140007340:	e8 38 13 00 00       	call   14000867d <__diff_D2A>
   140007345:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140007349:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   14000734d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140007350:	85 c0                	test   eax,eax
   140007352:	75 15                	jne    140007369 <__gdtoa+0x102f>
   140007354:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140007358:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000735c:	48 89 c1             	mov    rcx,rax
   14000735f:	e8 49 12 00 00       	call   1400085ad <__cmp_D2A>
   140007364:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007367:	eb 07                	jmp    140007370 <__gdtoa+0x1036>
   140007369:	c7 45 5c 01 00 00 00 	mov    DWORD PTR [rbp+0x5c],0x1
   140007370:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140007374:	48 89 c1             	mov    rcx,rax
   140007377:	e8 c2 0a 00 00       	call   140007e3e <__Bfree_D2A>
   14000737c:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140007380:	75 70                	jne    1400073f2 <__gdtoa+0x10b8>
   140007382:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   140007389:	75 67                	jne    1400073f2 <__gdtoa+0x10b8>
   14000738b:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   140007392:	8b 00                	mov    eax,DWORD PTR [rax]
   140007394:	83 e0 01             	and    eax,0x1
   140007397:	85 c0                	test   eax,eax
   140007399:	75 57                	jne    1400073f2 <__gdtoa+0x10b8>
   14000739b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000739f:	75 51                	jne    1400073f2 <__gdtoa+0x10b8>
   1400073a1:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   1400073a5:	0f 84 01 02 00 00    	je     1400075ac <__gdtoa+0x1272>
   1400073ab:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400073af:	7f 20                	jg     1400073d1 <__gdtoa+0x1097>
   1400073b1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073b5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400073b8:	83 f8 01             	cmp    eax,0x1
   1400073bb:	7f 0b                	jg     1400073c8 <__gdtoa+0x108e>
   1400073bd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073c1:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400073c4:	85 c0                	test   eax,eax
   1400073c6:	74 14                	je     1400073dc <__gdtoa+0x10a2>
   1400073c8:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400073cf:	eb 0b                	jmp    1400073dc <__gdtoa+0x10a2>
   1400073d1:	83 45 74 01          	add    DWORD PTR [rbp+0x74],0x1
   1400073d5:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400073dc:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400073e0:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400073e4:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400073e8:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400073eb:	88 10                	mov    BYTE PTR [rax],dl
   1400073ed:	e9 ef 03 00 00       	jmp    1400077e1 <__gdtoa+0x14a7>
   1400073f2:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400073f6:	78 2b                	js     140007423 <__gdtoa+0x10e9>
   1400073f8:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400073fc:	0f 85 96 01 00 00    	jne    140007598 <__gdtoa+0x125e>
   140007402:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   140007409:	0f 85 89 01 00 00    	jne    140007598 <__gdtoa+0x125e>
   14000740f:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   140007416:	8b 00                	mov    eax,DWORD PTR [rax]
   140007418:	83 e0 01             	and    eax,0x1
   14000741b:	85 c0                	test   eax,eax
   14000741d:	0f 85 75 01 00 00    	jne    140007598 <__gdtoa+0x125e>
   140007423:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140007427:	0f 84 db 00 00 00    	je     140007508 <__gdtoa+0x11ce>
   14000742d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007431:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007434:	83 f8 01             	cmp    eax,0x1
   140007437:	7f 0f                	jg     140007448 <__gdtoa+0x110e>
   140007439:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000743d:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007440:	85 c0                	test   eax,eax
   140007442:	0f 84 c0 00 00 00    	je     140007508 <__gdtoa+0x11ce>
   140007448:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   14000744c:	0f 85 83 00 00 00    	jne    1400074d5 <__gdtoa+0x119b>
   140007452:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140007459:	e9 24 01 00 00       	jmp    140007582 <__gdtoa+0x1248>
   14000745e:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007462:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007466:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000746a:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000746d:	88 10                	mov    BYTE PTR [rax],dl
   14000746f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007473:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007479:	ba 0a 00 00 00       	mov    edx,0xa
   14000747e:	48 89 c1             	mov    rcx,rax
   140007481:	e8 43 0a 00 00       	call   140007ec9 <__multadd_D2A>
   140007486:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000748a:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000748e:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007492:	75 08                	jne    14000749c <__gdtoa+0x1162>
   140007494:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140007498:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   14000749c:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400074a0:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400074a4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074a8:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400074ae:	ba 0a 00 00 00       	mov    edx,0xa
   1400074b3:	48 89 c1             	mov    rcx,rax
   1400074b6:	e8 0e 0a 00 00       	call   140007ec9 <__multadd_D2A>
   1400074bb:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400074bf:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400074c3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074c7:	48 89 c1             	mov    rcx,rax
   1400074ca:	e8 af ea ff ff       	call   140005f7e <__quorem_D2A>
   1400074cf:	83 c0 30             	add    eax,0x30
   1400074d2:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   1400074d5:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400074d9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400074dd:	48 89 c1             	mov    rcx,rax
   1400074e0:	e8 c8 10 00 00       	call   1400085ad <__cmp_D2A>
   1400074e5:	85 c0                	test   eax,eax
   1400074e7:	0f 8f 71 ff ff ff    	jg     14000745e <__gdtoa+0x1124>
   1400074ed:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400074f0:	8d 50 01             	lea    edx,[rax+0x1]
   1400074f3:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   1400074f6:	83 f8 39             	cmp    eax,0x39
   1400074f9:	0f 84 b0 00 00 00    	je     1400075af <__gdtoa+0x1275>
   1400074ff:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007506:	eb 7a                	jmp    140007582 <__gdtoa+0x1248>
   140007508:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000750c:	7e 53                	jle    140007561 <__gdtoa+0x1227>
   14000750e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007512:	ba 01 00 00 00       	mov    edx,0x1
   140007517:	48 89 c1             	mov    rcx,rax
   14000751a:	e8 01 0f 00 00       	call   140008420 <__lshift_D2A>
   14000751f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007523:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007527:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000752b:	48 89 c1             	mov    rcx,rax
   14000752e:	e8 7a 10 00 00       	call   1400085ad <__cmp_D2A>
   140007533:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007536:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000753a:	7f 10                	jg     14000754c <__gdtoa+0x1212>
   14000753c:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140007540:	75 18                	jne    14000755a <__gdtoa+0x1220>
   140007542:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007545:	83 e0 01             	and    eax,0x1
   140007548:	85 c0                	test   eax,eax
   14000754a:	74 0e                	je     14000755a <__gdtoa+0x1220>
   14000754c:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000754f:	8d 50 01             	lea    edx,[rax+0x1]
   140007552:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007555:	83 f8 39             	cmp    eax,0x39
   140007558:	74 58                	je     1400075b2 <__gdtoa+0x1278>
   14000755a:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007561:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007565:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007568:	83 f8 01             	cmp    eax,0x1
   14000756b:	7f 0b                	jg     140007578 <__gdtoa+0x123e>
   14000756d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007571:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007574:	85 c0                	test   eax,eax
   140007576:	74 09                	je     140007581 <__gdtoa+0x1247>
   140007578:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000757f:	eb 01                	jmp    140007582 <__gdtoa+0x1248>
   140007581:	90                   	nop
   140007582:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007586:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000758a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000758e:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   140007591:	88 10                	mov    BYTE PTR [rax],dl
   140007593:	e9 49 02 00 00       	jmp    1400077e1 <__gdtoa+0x14a7>
   140007598:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000759c:	7e 52                	jle    1400075f0 <__gdtoa+0x12b6>
   14000759e:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   1400075a2:	74 4c                	je     1400075f0 <__gdtoa+0x12b6>
   1400075a4:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   1400075a8:	75 24                	jne    1400075ce <__gdtoa+0x1294>
   1400075aa:	eb 07                	jmp    1400075b3 <__gdtoa+0x1279>
   1400075ac:	90                   	nop
   1400075ad:	eb 04                	jmp    1400075b3 <__gdtoa+0x1279>
   1400075af:	90                   	nop
   1400075b0:	eb 01                	jmp    1400075b3 <__gdtoa+0x1279>
   1400075b2:	90                   	nop
   1400075b3:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075b7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075bb:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075bf:	c6 00 39             	mov    BYTE PTR [rax],0x39
   1400075c2:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400075c9:	e9 9d 01 00 00       	jmp    14000776b <__gdtoa+0x1431>
   1400075ce:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400075d5:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400075d8:	8d 48 01             	lea    ecx,[rax+0x1]
   1400075db:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075df:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075e3:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075e7:	89 ca                	mov    edx,ecx
   1400075e9:	88 10                	mov    BYTE PTR [rax],dl
   1400075eb:	e9 f1 01 00 00       	jmp    1400077e1 <__gdtoa+0x14a7>
   1400075f0:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075f4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075f8:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075fc:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400075ff:	88 10                	mov    BYTE PTR [rax],dl
   140007601:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007604:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140007607:	0f 84 ea 00 00 00    	je     1400076f7 <__gdtoa+0x13bd>
   14000760d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007611:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007617:	ba 0a 00 00 00       	mov    edx,0xa
   14000761c:	48 89 c1             	mov    rcx,rax
   14000761f:	e8 a5 08 00 00       	call   140007ec9 <__multadd_D2A>
   140007624:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007628:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000762c:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007630:	75 25                	jne    140007657 <__gdtoa+0x131d>
   140007632:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007636:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000763c:	ba 0a 00 00 00       	mov    edx,0xa
   140007641:	48 89 c1             	mov    rcx,rax
   140007644:	e8 80 08 00 00       	call   140007ec9 <__multadd_D2A>
   140007649:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000764d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007651:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007655:	eb 36                	jmp    14000768d <__gdtoa+0x1353>
   140007657:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000765b:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007661:	ba 0a 00 00 00       	mov    edx,0xa
   140007666:	48 89 c1             	mov    rcx,rax
   140007669:	e8 5b 08 00 00       	call   140007ec9 <__multadd_D2A>
   14000766e:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007672:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007676:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000767c:	ba 0a 00 00 00       	mov    edx,0xa
   140007681:	48 89 c1             	mov    rcx,rax
   140007684:	e8 40 08 00 00       	call   140007ec9 <__multadd_D2A>
   140007689:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000768d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007690:	83 c0 01             	add    eax,0x1
   140007693:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007696:	e9 71 fc ff ff       	jmp    14000730c <__gdtoa+0xfd2>
   14000769b:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   1400076a2:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400076a6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076aa:	48 89 c1             	mov    rcx,rax
   1400076ad:	e8 cc e8 ff ff       	call   140005f7e <__quorem_D2A>
   1400076b2:	83 c0 30             	add    eax,0x30
   1400076b5:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   1400076b8:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076bc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400076c0:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400076c4:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400076c7:	88 10                	mov    BYTE PTR [rax],dl
   1400076c9:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400076cc:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   1400076cf:	7e 29                	jle    1400076fa <__gdtoa+0x13c0>
   1400076d1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076d5:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400076db:	ba 0a 00 00 00       	mov    edx,0xa
   1400076e0:	48 89 c1             	mov    rcx,rax
   1400076e3:	e8 e1 07 00 00       	call   140007ec9 <__multadd_D2A>
   1400076e8:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400076ec:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400076ef:	83 c0 01             	add    eax,0x1
   1400076f2:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400076f5:	eb ab                	jmp    1400076a2 <__gdtoa+0x1368>
   1400076f7:	90                   	nop
   1400076f8:	eb 01                	jmp    1400076fb <__gdtoa+0x13c1>
   1400076fa:	90                   	nop
   1400076fb:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400076ff:	74 26                	je     140007727 <__gdtoa+0x13ed>
   140007701:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   140007705:	0f 84 ae 00 00 00    	je     1400077b9 <__gdtoa+0x147f>
   14000770b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000770f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007712:	83 f8 01             	cmp    eax,0x1
   140007715:	7f 50                	jg     140007767 <__gdtoa+0x142d>
   140007717:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000771b:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   14000771e:	85 c0                	test   eax,eax
   140007720:	75 45                	jne    140007767 <__gdtoa+0x142d>
   140007722:	e9 92 00 00 00       	jmp    1400077b9 <__gdtoa+0x147f>
   140007727:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000772b:	ba 01 00 00 00       	mov    edx,0x1
   140007730:	48 89 c1             	mov    rcx,rax
   140007733:	e8 e8 0c 00 00       	call   140008420 <__lshift_D2A>
   140007738:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000773c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007740:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007744:	48 89 c1             	mov    rcx,rax
   140007747:	e8 61 0e 00 00       	call   1400085ad <__cmp_D2A>
   14000774c:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   14000774f:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007753:	7f 15                	jg     14000776a <__gdtoa+0x1430>
   140007755:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007759:	75 61                	jne    1400077bc <__gdtoa+0x1482>
   14000775b:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000775e:	83 e0 01             	and    eax,0x1
   140007761:	85 c0                	test   eax,eax
   140007763:	74 5a                	je     1400077bf <__gdtoa+0x1485>
   140007765:	eb 04                	jmp    14000776b <__gdtoa+0x1431>
   140007767:	90                   	nop
   140007768:	eb 01                	jmp    14000776b <__gdtoa+0x1431>
   14000776a:	90                   	nop
   14000776b:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007772:	eb 1f                	jmp    140007793 <__gdtoa+0x1459>
   140007774:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007778:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000777c:	75 15                	jne    140007793 <__gdtoa+0x1459>
   14000777e:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140007782:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007786:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000778a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000778e:	c6 00 31             	mov    BYTE PTR [rax],0x31
   140007791:	eb 4e                	jmp    1400077e1 <__gdtoa+0x14a7>
   140007793:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140007798:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000779c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000779f:	3c 39                	cmp    al,0x39
   1400077a1:	74 d1                	je     140007774 <__gdtoa+0x143a>
   1400077a3:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077a7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400077ab:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400077af:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   1400077b2:	83 c2 01             	add    edx,0x1
   1400077b5:	88 10                	mov    BYTE PTR [rax],dl
   1400077b7:	eb 28                	jmp    1400077e1 <__gdtoa+0x14a7>
   1400077b9:	90                   	nop
   1400077ba:	eb 04                	jmp    1400077c0 <__gdtoa+0x1486>
   1400077bc:	90                   	nop
   1400077bd:	eb 01                	jmp    1400077c0 <__gdtoa+0x1486>
   1400077bf:	90                   	nop
   1400077c0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400077c4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400077c7:	83 f8 01             	cmp    eax,0x1
   1400077ca:	7f 0b                	jg     1400077d7 <__gdtoa+0x149d>
   1400077cc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400077d0:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400077d3:	85 c0                	test   eax,eax
   1400077d5:	74 09                	je     1400077e0 <__gdtoa+0x14a6>
   1400077d7:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400077de:	eb 01                	jmp    1400077e1 <__gdtoa+0x14a7>
   1400077e0:	90                   	nop
   1400077e1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400077e5:	48 89 c1             	mov    rcx,rax
   1400077e8:	e8 51 06 00 00       	call   140007e3e <__Bfree_D2A>
   1400077ed:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   1400077f2:	74 31                	je     140007825 <__gdtoa+0x14eb>
   1400077f4:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400077f9:	74 16                	je     140007811 <__gdtoa+0x14d7>
   1400077fb:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400077ff:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007803:	74 0c                	je     140007811 <__gdtoa+0x14d7>
   140007805:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007809:	48 89 c1             	mov    rcx,rax
   14000780c:	e8 2d 06 00 00       	call   140007e3e <__Bfree_D2A>
   140007811:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007815:	48 89 c1             	mov    rcx,rax
   140007818:	e8 21 06 00 00       	call   140007e3e <__Bfree_D2A>
   14000781d:	eb 0e                	jmp    14000782d <__gdtoa+0x14f3>
   14000781f:	90                   	nop
   140007820:	eb 0b                	jmp    14000782d <__gdtoa+0x14f3>
   140007822:	90                   	nop
   140007823:	eb 08                	jmp    14000782d <__gdtoa+0x14f3>
   140007825:	90                   	nop
   140007826:	eb 05                	jmp    14000782d <__gdtoa+0x14f3>
   140007828:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   14000782d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007831:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   140007835:	73 0f                	jae    140007846 <__gdtoa+0x150c>
   140007837:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000783b:	48 83 e8 01          	sub    rax,0x1
   14000783f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140007842:	3c 30                	cmp    al,0x30
   140007844:	74 e2                	je     140007828 <__gdtoa+0x14ee>
   140007846:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000784a:	48 89 c1             	mov    rcx,rax
   14000784d:	e8 ec 05 00 00       	call   140007e3e <__Bfree_D2A>
   140007852:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007856:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140007859:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000785c:	8d 50 01             	lea    edx,[rax+0x1]
   14000785f:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140007866:	89 10                	mov    DWORD PTR [rax],edx
   140007868:	48 83 bd c8 00 00 00 	cmp    QWORD PTR [rbp+0xc8],0x0
   14000786f:	00 
   140007870:	74 0e                	je     140007880 <__gdtoa+0x1546>
   140007872:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140007879:	48 8b 55 00          	mov    rdx,QWORD PTR [rbp+0x0]
   14000787d:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007880:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140007887:	8b 00                	mov    eax,DWORD PTR [rax]
   140007889:	0b 45 64             	or     eax,DWORD PTR [rbp+0x64]
   14000788c:	89 c2                	mov    edx,eax
   14000788e:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   140007895:	89 10                	mov    DWORD PTR [rax],edx
   140007897:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000789b:	48 81 c4 00 01 00 00 	add    rsp,0x100
   1400078a2:	5d                   	pop    rbp
   1400078a3:	c3                   	ret
   1400078a4:	90                   	nop
   1400078a5:	90                   	nop
   1400078a6:	90                   	nop
   1400078a7:	90                   	nop
   1400078a8:	90                   	nop
   1400078a9:	90                   	nop
   1400078aa:	90                   	nop
   1400078ab:	90                   	nop
   1400078ac:	90                   	nop
   1400078ad:	90                   	nop
   1400078ae:	90                   	nop
   1400078af:	90                   	nop

00000001400078b0 <__lo0bits_D2A>:
   1400078b0:	55                   	push   rbp
   1400078b1:	48 89 e5             	mov    rbp,rsp
   1400078b4:	48 83 ec 10          	sub    rsp,0x10
   1400078b8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400078bc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078c0:	8b 00                	mov    eax,DWORD PTR [rax]
   1400078c2:	f3 0f bc c0          	tzcnt  eax,eax
   1400078c6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400078c9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078cd:	8b 10                	mov    edx,DWORD PTR [rax]
   1400078cf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400078d2:	89 c1                	mov    ecx,eax
   1400078d4:	d3 ea                	shr    edx,cl
   1400078d6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078da:	89 10                	mov    DWORD PTR [rax],edx
   1400078dc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400078df:	48 83 c4 10          	add    rsp,0x10
   1400078e3:	5d                   	pop    rbp
   1400078e4:	c3                   	ret

00000001400078e5 <__rshift_D2A>:
   1400078e5:	55                   	push   rbp
   1400078e6:	48 89 e5             	mov    rbp,rsp
   1400078e9:	48 83 ec 20          	sub    rsp,0x20
   1400078ed:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400078f1:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400078f4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400078f8:	48 83 c0 18          	add    rax,0x18
   1400078fc:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007900:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007904:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007908:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000790b:	c1 f8 05             	sar    eax,0x5
   14000790e:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007911:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007915:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007918:	39 45 e8             	cmp    DWORD PTR [rbp-0x18],eax
   14000791b:	0f 8d e4 00 00 00    	jge    140007a05 <__rshift_D2A+0x120>
   140007921:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007925:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007928:	48 98                	cdqe
   14000792a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007931:	00 
   140007932:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007936:	48 01 d0             	add    rax,rdx
   140007939:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000793d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140007940:	48 98                	cdqe
   140007942:	48 c1 e0 02          	shl    rax,0x2
   140007946:	48 01 45 f8          	add    QWORD PTR [rbp-0x8],rax
   14000794a:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000794e:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140007952:	0f 84 a3 00 00 00    	je     1400079fb <__rshift_D2A+0x116>
   140007958:	b8 20 00 00 00       	mov    eax,0x20
   14000795d:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   140007960:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007963:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007967:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000796b:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   14000796f:	8b 10                	mov    edx,DWORD PTR [rax]
   140007971:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007974:	89 c1                	mov    ecx,eax
   140007976:	d3 ea                	shr    edx,cl
   140007978:	89 d0                	mov    eax,edx
   14000797a:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000797d:	eb 3c                	jmp    1400079bb <__rshift_D2A+0xd6>
   14000797f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007983:	8b 10                	mov    edx,DWORD PTR [rax]
   140007985:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140007988:	89 c1                	mov    ecx,eax
   14000798a:	d3 e2                	shl    edx,cl
   14000798c:	89 d1                	mov    ecx,edx
   14000798e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007992:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007996:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000799a:	0b 4d ec             	or     ecx,DWORD PTR [rbp-0x14]
   14000799d:	89 ca                	mov    edx,ecx
   14000799f:	89 10                	mov    DWORD PTR [rax],edx
   1400079a1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079a5:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400079a9:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400079ad:	8b 10                	mov    edx,DWORD PTR [rax]
   1400079af:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400079b2:	89 c1                	mov    ecx,eax
   1400079b4:	d3 ea                	shr    edx,cl
   1400079b6:	89 d0                	mov    eax,edx
   1400079b8:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400079bb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079bf:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   1400079c3:	72 ba                	jb     14000797f <__rshift_D2A+0x9a>
   1400079c5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079c9:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400079cc:	89 10                	mov    DWORD PTR [rax],edx
   1400079ce:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079d2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400079d4:	85 c0                	test   eax,eax
   1400079d6:	74 2d                	je     140007a05 <__rshift_D2A+0x120>
   1400079d8:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   1400079dd:	eb 26                	jmp    140007a05 <__rshift_D2A+0x120>
   1400079df:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400079e3:	48 8d 42 04          	lea    rax,[rdx+0x4]
   1400079e7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400079eb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079ef:	48 8d 48 04          	lea    rcx,[rax+0x4]
   1400079f3:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
   1400079f7:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400079f9:	89 10                	mov    DWORD PTR [rax],edx
   1400079fb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079ff:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140007a03:	72 da                	jb     1400079df <__rshift_D2A+0xfa>
   140007a05:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a09:	48 83 c0 18          	add    rax,0x18
   140007a0d:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140007a11:	48 29 c2             	sub    rdx,rax
   140007a14:	48 89 d0             	mov    rax,rdx
   140007a17:	48 c1 f8 02          	sar    rax,0x2
   140007a1b:	89 c2                	mov    edx,eax
   140007a1d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a21:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007a24:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a28:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007a2b:	85 c0                	test   eax,eax
   140007a2d:	75 0b                	jne    140007a3a <__rshift_D2A+0x155>
   140007a2f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a33:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   140007a3a:	90                   	nop
   140007a3b:	48 83 c4 20          	add    rsp,0x20
   140007a3f:	5d                   	pop    rbp
   140007a40:	c3                   	ret

0000000140007a41 <__trailz_D2A>:
   140007a41:	55                   	push   rbp
   140007a42:	48 89 e5             	mov    rbp,rsp
   140007a45:	48 83 ec 40          	sub    rsp,0x40
   140007a49:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007a4d:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007a54:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a58:	48 83 c0 18          	add    rax,0x18
   140007a5c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007a60:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a64:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007a67:	48 98                	cdqe
   140007a69:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007a70:	00 
   140007a71:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a75:	48 01 d0             	add    rax,rdx
   140007a78:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007a7c:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007a83:	eb 09                	jmp    140007a8e <__trailz_D2A+0x4d>
   140007a85:	83 45 f4 20          	add    DWORD PTR [rbp-0xc],0x20
   140007a89:	48 83 45 f8 04       	add    QWORD PTR [rbp-0x8],0x4
   140007a8e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a92:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007a96:	73 0a                	jae    140007aa2 <__trailz_D2A+0x61>
   140007a98:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a9c:	8b 00                	mov    eax,DWORD PTR [rax]
   140007a9e:	85 c0                	test   eax,eax
   140007aa0:	74 e3                	je     140007a85 <__trailz_D2A+0x44>
   140007aa2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007aa6:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007aaa:	73 18                	jae    140007ac4 <__trailz_D2A+0x83>
   140007aac:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007ab0:	8b 00                	mov    eax,DWORD PTR [rax]
   140007ab2:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007ab5:	48 8d 45 e4          	lea    rax,[rbp-0x1c]
   140007ab9:	48 89 c1             	mov    rcx,rax
   140007abc:	e8 ef fd ff ff       	call   1400078b0 <__lo0bits_D2A>
   140007ac1:	01 45 f4             	add    DWORD PTR [rbp-0xc],eax
   140007ac4:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007ac7:	48 83 c4 40          	add    rsp,0x40
   140007acb:	5d                   	pop    rbp
   140007acc:	c3                   	ret
   140007acd:	90                   	nop
   140007ace:	90                   	nop
   140007acf:	90                   	nop

0000000140007ad0 <dtoa_lock_cleanup>:
   140007ad0:	55                   	push   rbp
   140007ad1:	48 89 e5             	mov    rbp,rsp
   140007ad4:	48 83 ec 40          	sub    rsp,0x40
   140007ad8:	48 8d 05 11 77 00 00 	lea    rax,[rip+0x7711]        # 14000f1f0 <dtoa_CS_init>
   140007adf:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007ae3:	c7 45 ec 03 00 00 00 	mov    DWORD PTR [rbp-0x14],0x3
   140007aea:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007aed:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007af1:	87 10                	xchg   DWORD PTR [rax],edx
   140007af3:	89 d0                	mov    eax,edx
   140007af5:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007af8:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007afc:	75 3d                	jne    140007b3b <dtoa_lock_cleanup+0x6b>
   140007afe:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007b05:	eb 2e                	jmp    140007b35 <dtoa_lock_cleanup+0x65>
   140007b07:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007b0a:	48 63 d0             	movsxd rdx,eax
   140007b0d:	48 89 d0             	mov    rax,rdx
   140007b10:	48 c1 e0 02          	shl    rax,0x2
   140007b14:	48 01 d0             	add    rax,rdx
   140007b17:	48 c1 e0 03          	shl    rax,0x3
   140007b1b:	48 8d 15 7e 76 00 00 	lea    rdx,[rip+0x767e]        # 14000f1a0 <dtoa_CritSec>
   140007b22:	48 01 d0             	add    rax,rdx
   140007b25:	48 89 c1             	mov    rcx,rax
   140007b28:	48 8b 05 c1 86 00 00 	mov    rax,QWORD PTR [rip+0x86c1]        # 1400101f0 <__IAT_start__>
   140007b2f:	ff d0                	call   rax
   140007b31:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007b35:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007b39:	7e cc                	jle    140007b07 <dtoa_lock_cleanup+0x37>
   140007b3b:	90                   	nop
   140007b3c:	48 83 c4 40          	add    rsp,0x40
   140007b40:	5d                   	pop    rbp
   140007b41:	c3                   	ret

0000000140007b42 <dtoa_lock>:
   140007b42:	55                   	push   rbp
   140007b43:	48 89 e5             	mov    rbp,rsp
   140007b46:	48 83 ec 40          	sub    rsp,0x40
   140007b4a:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007b4d:	8b 05 9d 76 00 00    	mov    eax,DWORD PTR [rip+0x769d]        # 14000f1f0 <dtoa_CS_init>
   140007b53:	83 f8 02             	cmp    eax,0x2
   140007b56:	75 2c                	jne    140007b84 <dtoa_lock+0x42>
   140007b58:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007b5b:	48 89 d0             	mov    rax,rdx
   140007b5e:	48 c1 e0 02          	shl    rax,0x2
   140007b62:	48 01 d0             	add    rax,rdx
   140007b65:	48 c1 e0 03          	shl    rax,0x3
   140007b69:	48 8d 15 30 76 00 00 	lea    rdx,[rip+0x7630]        # 14000f1a0 <dtoa_CritSec>
   140007b70:	48 01 d0             	add    rax,rdx
   140007b73:	48 89 c1             	mov    rcx,rax
   140007b76:	48 8b 05 7b 86 00 00 	mov    rax,QWORD PTR [rip+0x867b]        # 1400101f8 <__imp_EnterCriticalSection>
   140007b7d:	ff d0                	call   rax
   140007b7f:	e9 ea 00 00 00       	jmp    140007c6e <dtoa_lock+0x12c>
   140007b84:	8b 05 66 76 00 00    	mov    eax,DWORD PTR [rip+0x7666]        # 14000f1f0 <dtoa_CS_init>
   140007b8a:	85 c0                	test   eax,eax
   140007b8c:	0f 85 9e 00 00 00    	jne    140007c30 <dtoa_lock+0xee>
   140007b92:	48 8d 05 57 76 00 00 	lea    rax,[rip+0x7657]        # 14000f1f0 <dtoa_CS_init>
   140007b99:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007b9d:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140007ba4:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007ba7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007bab:	87 10                	xchg   DWORD PTR [rax],edx
   140007bad:	89 d0                	mov    eax,edx
   140007baf:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007bb2:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140007bb6:	75 58                	jne    140007c10 <dtoa_lock+0xce>
   140007bb8:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007bbf:	eb 2e                	jmp    140007bef <dtoa_lock+0xad>
   140007bc1:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007bc4:	48 63 d0             	movsxd rdx,eax
   140007bc7:	48 89 d0             	mov    rax,rdx
   140007bca:	48 c1 e0 02          	shl    rax,0x2
   140007bce:	48 01 d0             	add    rax,rdx
   140007bd1:	48 c1 e0 03          	shl    rax,0x3
   140007bd5:	48 8d 15 c4 75 00 00 	lea    rdx,[rip+0x75c4]        # 14000f1a0 <dtoa_CritSec>
   140007bdc:	48 01 d0             	add    rax,rdx
   140007bdf:	48 89 c1             	mov    rcx,rax
   140007be2:	48 8b 05 3f 86 00 00 	mov    rax,QWORD PTR [rip+0x863f]        # 140010228 <__imp_InitializeCriticalSection>
   140007be9:	ff d0                	call   rax
   140007beb:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007bef:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007bf3:	7e cc                	jle    140007bc1 <dtoa_lock+0x7f>
   140007bf5:	48 8d 05 d4 fe ff ff 	lea    rax,[rip+0xfffffffffffffed4]        # 140007ad0 <dtoa_lock_cleanup>
   140007bfc:	48 89 c1             	mov    rcx,rax
   140007bff:	e8 2b 9a ff ff       	call   14000162f <atexit>
   140007c04:	c7 05 e2 75 00 00 02 	mov    DWORD PTR [rip+0x75e2],0x2        # 14000f1f0 <dtoa_CS_init>
   140007c0b:	00 00 00 
   140007c0e:	eb 20                	jmp    140007c30 <dtoa_lock+0xee>
   140007c10:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007c14:	75 1a                	jne    140007c30 <dtoa_lock+0xee>
   140007c16:	c7 05 d0 75 00 00 02 	mov    DWORD PTR [rip+0x75d0],0x2        # 14000f1f0 <dtoa_CS_init>
   140007c1d:	00 00 00 
   140007c20:	eb 0e                	jmp    140007c30 <dtoa_lock+0xee>
   140007c22:	b9 01 00 00 00       	mov    ecx,0x1
   140007c27:	48 8b 05 22 86 00 00 	mov    rax,QWORD PTR [rip+0x8622]        # 140010250 <__imp_Sleep>
   140007c2e:	ff d0                	call   rax
   140007c30:	8b 05 ba 75 00 00    	mov    eax,DWORD PTR [rip+0x75ba]        # 14000f1f0 <dtoa_CS_init>
   140007c36:	83 f8 01             	cmp    eax,0x1
   140007c39:	74 e7                	je     140007c22 <dtoa_lock+0xe0>
   140007c3b:	8b 05 af 75 00 00    	mov    eax,DWORD PTR [rip+0x75af]        # 14000f1f0 <dtoa_CS_init>
   140007c41:	83 f8 02             	cmp    eax,0x2
   140007c44:	75 28                	jne    140007c6e <dtoa_lock+0x12c>
   140007c46:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007c49:	48 89 d0             	mov    rax,rdx
   140007c4c:	48 c1 e0 02          	shl    rax,0x2
   140007c50:	48 01 d0             	add    rax,rdx
   140007c53:	48 c1 e0 03          	shl    rax,0x3
   140007c57:	48 8d 15 42 75 00 00 	lea    rdx,[rip+0x7542]        # 14000f1a0 <dtoa_CritSec>
   140007c5e:	48 01 d0             	add    rax,rdx
   140007c61:	48 89 c1             	mov    rcx,rax
   140007c64:	48 8b 05 8d 85 00 00 	mov    rax,QWORD PTR [rip+0x858d]        # 1400101f8 <__imp_EnterCriticalSection>
   140007c6b:	ff d0                	call   rax
   140007c6d:	90                   	nop
   140007c6e:	48 83 c4 40          	add    rsp,0x40
   140007c72:	5d                   	pop    rbp
   140007c73:	c3                   	ret

0000000140007c74 <dtoa_unlock>:
   140007c74:	55                   	push   rbp
   140007c75:	48 89 e5             	mov    rbp,rsp
   140007c78:	48 83 ec 20          	sub    rsp,0x20
   140007c7c:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007c7f:	8b 05 6b 75 00 00    	mov    eax,DWORD PTR [rip+0x756b]        # 14000f1f0 <dtoa_CS_init>
   140007c85:	83 f8 02             	cmp    eax,0x2
   140007c88:	75 27                	jne    140007cb1 <dtoa_unlock+0x3d>
   140007c8a:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007c8d:	48 89 d0             	mov    rax,rdx
   140007c90:	48 c1 e0 02          	shl    rax,0x2
   140007c94:	48 01 d0             	add    rax,rdx
   140007c97:	48 c1 e0 03          	shl    rax,0x3
   140007c9b:	48 8d 15 fe 74 00 00 	lea    rdx,[rip+0x74fe]        # 14000f1a0 <dtoa_CritSec>
   140007ca2:	48 01 d0             	add    rax,rdx
   140007ca5:	48 89 c1             	mov    rcx,rax
   140007ca8:	48 8b 05 81 85 00 00 	mov    rax,QWORD PTR [rip+0x8581]        # 140010230 <__imp_LeaveCriticalSection>
   140007caf:	ff d0                	call   rax
   140007cb1:	90                   	nop
   140007cb2:	48 83 c4 20          	add    rsp,0x20
   140007cb6:	5d                   	pop    rbp
   140007cb7:	c3                   	ret

0000000140007cb8 <__lo0bits_D2A>:
   140007cb8:	55                   	push   rbp
   140007cb9:	48 89 e5             	mov    rbp,rsp
   140007cbc:	48 83 ec 10          	sub    rsp,0x10
   140007cc0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007cc4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007cc8:	8b 00                	mov    eax,DWORD PTR [rax]
   140007cca:	f3 0f bc c0          	tzcnt  eax,eax
   140007cce:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007cd1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007cd5:	8b 10                	mov    edx,DWORD PTR [rax]
   140007cd7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007cda:	89 c1                	mov    ecx,eax
   140007cdc:	d3 ea                	shr    edx,cl
   140007cde:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ce2:	89 10                	mov    DWORD PTR [rax],edx
   140007ce4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007ce7:	48 83 c4 10          	add    rsp,0x10
   140007ceb:	5d                   	pop    rbp
   140007cec:	c3                   	ret

0000000140007ced <__hi0bits_D2A>:
   140007ced:	55                   	push   rbp
   140007cee:	48 89 e5             	mov    rbp,rsp
   140007cf1:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007cf4:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   140007cf8:	83 f0 1f             	xor    eax,0x1f
   140007cfb:	5d                   	pop    rbp
   140007cfc:	c3                   	ret

0000000140007cfd <__Balloc_D2A>:
   140007cfd:	55                   	push   rbp
   140007cfe:	48 89 e5             	mov    rbp,rsp
   140007d01:	48 83 ec 30          	sub    rsp,0x30
   140007d05:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007d08:	b9 00 00 00 00       	mov    ecx,0x0
   140007d0d:	e8 30 fe ff ff       	call   140007b42 <dtoa_lock>
   140007d12:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007d16:	7f 48                	jg     140007d60 <__Balloc_D2A+0x63>
   140007d18:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007d1b:	48 98                	cdqe
   140007d1d:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007d24:	00 
   140007d25:	48 8d 05 d4 74 00 00 	lea    rax,[rip+0x74d4]        # 14000f200 <freelist>
   140007d2c:	48 8b 04 02          	mov    rax,QWORD PTR [rdx+rax*1]
   140007d30:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d34:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007d39:	74 25                	je     140007d60 <__Balloc_D2A+0x63>
   140007d3b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d3f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140007d42:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007d45:	48 63 d2             	movsxd rdx,edx
   140007d48:	48 8d 0c d5 00 00 00 	lea    rcx,[rdx*8+0x0]
   140007d4f:	00 
   140007d50:	48 8d 15 a9 74 00 00 	lea    rdx,[rip+0x74a9]        # 14000f200 <freelist>
   140007d57:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007d5b:	e9 b1 00 00 00       	jmp    140007e11 <__Balloc_D2A+0x114>
   140007d60:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007d63:	ba 01 00 00 00       	mov    edx,0x1
   140007d68:	89 c1                	mov    ecx,eax
   140007d6a:	d3 e2                	shl    edx,cl
   140007d6c:	89 d0                	mov    eax,edx
   140007d6e:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140007d71:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007d74:	83 e8 01             	sub    eax,0x1
   140007d77:	48 98                	cdqe
   140007d79:	48 c1 e0 02          	shl    rax,0x2
   140007d7d:	48 83 c0 27          	add    rax,0x27
   140007d81:	48 c1 e8 03          	shr    rax,0x3
   140007d85:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140007d88:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007d8c:	7f 4e                	jg     140007ddc <__Balloc_D2A+0xdf>
   140007d8e:	48 8b 15 fb 22 00 00 	mov    rdx,QWORD PTR [rip+0x22fb]        # 14000a090 <pmem_next>
   140007d95:	48 8d 05 c4 74 00 00 	lea    rax,[rip+0x74c4]        # 14000f260 <private_mem>
   140007d9c:	48 29 c2             	sub    rdx,rax
   140007d9f:	48 89 d0             	mov    rax,rdx
   140007da2:	48 c1 f8 03          	sar    rax,0x3
   140007da6:	48 89 c2             	mov    rdx,rax
   140007da9:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007dac:	48 01 d0             	add    rax,rdx
   140007daf:	48 3d 20 01 00 00    	cmp    rax,0x120
   140007db5:	77 25                	ja     140007ddc <__Balloc_D2A+0xdf>
   140007db7:	48 8b 05 d2 22 00 00 	mov    rax,QWORD PTR [rip+0x22d2]        # 14000a090 <pmem_next>
   140007dbe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007dc2:	48 8b 05 c7 22 00 00 	mov    rax,QWORD PTR [rip+0x22c7]        # 14000a090 <pmem_next>
   140007dc9:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140007dcc:	48 c1 e2 03          	shl    rdx,0x3
   140007dd0:	48 01 d0             	add    rax,rdx
   140007dd3:	48 89 05 b6 22 00 00 	mov    QWORD PTR [rip+0x22b6],rax        # 14000a090 <pmem_next>
   140007dda:	eb 21                	jmp    140007dfd <__Balloc_D2A+0x100>
   140007ddc:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007ddf:	48 c1 e0 03          	shl    rax,0x3
   140007de3:	48 89 c1             	mov    rcx,rax
   140007de6:	e8 e5 18 00 00       	call   1400096d0 <malloc>
   140007deb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007def:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007df4:	75 07                	jne    140007dfd <__Balloc_D2A+0x100>
   140007df6:	b8 00 00 00 00       	mov    eax,0x0
   140007dfb:	eb 3b                	jmp    140007e38 <__Balloc_D2A+0x13b>
   140007dfd:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e01:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007e04:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140007e07:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e0b:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140007e0e:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140007e11:	b9 00 00 00 00       	mov    ecx,0x0
   140007e16:	e8 59 fe ff ff       	call   140007c74 <dtoa_unlock>
   140007e1b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e1f:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   140007e26:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e2a:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007e2d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e31:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140007e34:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e38:	48 83 c4 30          	add    rsp,0x30
   140007e3c:	5d                   	pop    rbp
   140007e3d:	c3                   	ret

0000000140007e3e <__Bfree_D2A>:
   140007e3e:	55                   	push   rbp
   140007e3f:	48 89 e5             	mov    rbp,rsp
   140007e42:	48 83 ec 20          	sub    rsp,0x20
   140007e46:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007e4a:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140007e4f:	74 71                	je     140007ec2 <__Bfree_D2A+0x84>
   140007e51:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e55:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e58:	83 f8 09             	cmp    eax,0x9
   140007e5b:	7e 0e                	jle    140007e6b <__Bfree_D2A+0x2d>
   140007e5d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e61:	48 89 c1             	mov    rcx,rax
   140007e64:	e8 57 18 00 00       	call   1400096c0 <free>
   140007e69:	eb 57                	jmp    140007ec2 <__Bfree_D2A+0x84>
   140007e6b:	b9 00 00 00 00       	mov    ecx,0x0
   140007e70:	e8 cd fc ff ff       	call   140007b42 <dtoa_lock>
   140007e75:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e79:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e7c:	48 98                	cdqe
   140007e7e:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007e85:	00 
   140007e86:	48 8d 05 73 73 00 00 	lea    rax,[rip+0x7373]        # 14000f200 <freelist>
   140007e8d:	48 8b 14 02          	mov    rdx,QWORD PTR [rdx+rax*1]
   140007e91:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e95:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007e98:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e9c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007e9f:	48 98                	cdqe
   140007ea1:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
   140007ea8:	00 
   140007ea9:	48 8d 15 50 73 00 00 	lea    rdx,[rip+0x7350]        # 14000f200 <freelist>
   140007eb0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007eb4:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007eb8:	b9 00 00 00 00       	mov    ecx,0x0
   140007ebd:	e8 b2 fd ff ff       	call   140007c74 <dtoa_unlock>
   140007ec2:	90                   	nop
   140007ec3:	48 83 c4 20          	add    rsp,0x20
   140007ec7:	5d                   	pop    rbp
   140007ec8:	c3                   	ret

0000000140007ec9 <__multadd_D2A>:
   140007ec9:	55                   	push   rbp
   140007eca:	48 89 e5             	mov    rbp,rsp
   140007ecd:	48 83 ec 50          	sub    rsp,0x50
   140007ed1:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007ed5:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007ed8:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140007edc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ee0:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007ee3:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007ee6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007eea:	48 83 c0 18          	add    rax,0x18
   140007eee:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007ef2:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007ef9:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140007efc:	48 98                	cdqe
   140007efe:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007f02:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007f06:	8b 00                	mov    eax,DWORD PTR [rax]
   140007f08:	89 c2                	mov    edx,eax
   140007f0a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007f0d:	48 98                	cdqe
   140007f0f:	48 0f af d0          	imul   rdx,rax
   140007f13:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140007f17:	48 01 d0             	add    rax,rdx
   140007f1a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140007f1e:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140007f22:	48 c1 e8 20          	shr    rax,0x20
   140007f26:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007f2a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007f2e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007f32:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140007f36:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140007f3a:	89 10                	mov    DWORD PTR [rax],edx
   140007f3c:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007f40:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007f43:	3b 45 e4             	cmp    eax,DWORD PTR [rbp-0x1c]
   140007f46:	7c ba                	jl     140007f02 <__multadd_D2A+0x39>
   140007f48:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140007f4d:	0f 84 9a 00 00 00    	je     140007fed <__multadd_D2A+0x124>
   140007f53:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f57:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140007f5a:	39 45 e4             	cmp    DWORD PTR [rbp-0x1c],eax
   140007f5d:	7c 67                	jl     140007fc6 <__multadd_D2A+0xfd>
   140007f5f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f63:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007f66:	83 c0 01             	add    eax,0x1
   140007f69:	89 c1                	mov    ecx,eax
   140007f6b:	e8 8d fd ff ff       	call   140007cfd <__Balloc_D2A>
   140007f70:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140007f74:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140007f79:	75 07                	jne    140007f82 <__multadd_D2A+0xb9>
   140007f7b:	b8 00 00 00 00       	mov    eax,0x0
   140007f80:	eb 6f                	jmp    140007ff1 <__multadd_D2A+0x128>
   140007f82:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f86:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007f89:	48 98                	cdqe
   140007f8b:	48 83 c0 02          	add    rax,0x2
   140007f8f:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007f96:	00 
   140007f97:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f9b:	48 8d 50 10          	lea    rdx,[rax+0x10]
   140007f9f:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007fa3:	48 83 c0 10          	add    rax,0x10
   140007fa7:	49 89 c8             	mov    r8,rcx
   140007faa:	48 89 c1             	mov    rcx,rax
   140007fad:	e8 26 17 00 00       	call   1400096d8 <memcpy>
   140007fb2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fb6:	48 89 c1             	mov    rcx,rax
   140007fb9:	e8 80 fe ff ff       	call   140007e3e <__Bfree_D2A>
   140007fbe:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007fc2:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007fc6:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140007fc9:	8d 50 01             	lea    edx,[rax+0x1]
   140007fcc:	89 55 e4             	mov    DWORD PTR [rbp-0x1c],edx
   140007fcf:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140007fd3:	89 d1                	mov    ecx,edx
   140007fd5:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007fd9:	48 98                	cdqe
   140007fdb:	48 83 c0 04          	add    rax,0x4
   140007fdf:	89 4c 82 08          	mov    DWORD PTR [rdx+rax*4+0x8],ecx
   140007fe3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fe7:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140007fea:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007fed:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ff1:	48 83 c4 50          	add    rsp,0x50
   140007ff5:	5d                   	pop    rbp
   140007ff6:	c3                   	ret

0000000140007ff7 <__i2b_D2A>:
   140007ff7:	55                   	push   rbp
   140007ff8:	48 89 e5             	mov    rbp,rsp
   140007ffb:	48 83 ec 30          	sub    rsp,0x30
   140007fff:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140008002:	b9 01 00 00 00       	mov    ecx,0x1
   140008007:	e8 f1 fc ff ff       	call   140007cfd <__Balloc_D2A>
   14000800c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008010:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008015:	75 07                	jne    14000801e <__i2b_D2A+0x27>
   140008017:	b8 00 00 00 00       	mov    eax,0x0
   14000801c:	eb 19                	jmp    140008037 <__i2b_D2A+0x40>
   14000801e:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140008021:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008025:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008028:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000802c:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008033:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008037:	48 83 c4 30          	add    rsp,0x30
   14000803b:	5d                   	pop    rbp
   14000803c:	c3                   	ret

000000014000803d <__mult_D2A>:
   14000803d:	55                   	push   rbp
   14000803e:	48 89 e5             	mov    rbp,rsp
   140008041:	48 81 ec 90 00 00 00 	sub    rsp,0x90
   140008048:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000804c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008050:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008054:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140008057:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000805b:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000805e:	39 c2                	cmp    edx,eax
   140008060:	7d 18                	jge    14000807a <__mult_D2A+0x3d>
   140008062:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008066:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000806a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000806e:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008072:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008076:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000807a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000807e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140008081:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008084:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008088:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000808b:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   14000808e:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008092:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008095:	89 45 c0             	mov    DWORD PTR [rbp-0x40],eax
   140008098:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   14000809b:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   14000809e:	01 d0                	add    eax,edx
   1400080a0:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400080a3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080a7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400080aa:	39 45 f8             	cmp    DWORD PTR [rbp-0x8],eax
   1400080ad:	7e 04                	jle    1400080b3 <__mult_D2A+0x76>
   1400080af:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400080b3:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400080b6:	89 c1                	mov    ecx,eax
   1400080b8:	e8 40 fc ff ff       	call   140007cfd <__Balloc_D2A>
   1400080bd:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400080c1:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
   1400080c6:	75 0a                	jne    1400080d2 <__mult_D2A+0x95>
   1400080c8:	b8 00 00 00 00       	mov    eax,0x0
   1400080cd:	e9 88 01 00 00       	jmp    14000825a <__mult_D2A+0x21d>
   1400080d2:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400080d6:	48 83 c0 18          	add    rax,0x18
   1400080da:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400080de:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400080e1:	48 98                	cdqe
   1400080e3:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400080ea:	00 
   1400080eb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400080ef:	48 01 d0             	add    rax,rdx
   1400080f2:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400080f6:	eb 0f                	jmp    140008107 <__mult_D2A+0xca>
   1400080f8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400080fc:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008102:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   140008107:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000810b:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   14000810f:	72 e7                	jb     1400080f8 <__mult_D2A+0xbb>
   140008111:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008115:	48 83 c0 18          	add    rax,0x18
   140008119:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000811d:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140008120:	48 98                	cdqe
   140008122:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008129:	00 
   14000812a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000812e:	48 01 d0             	add    rax,rdx
   140008131:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008135:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008139:	48 83 c0 18          	add    rax,0x18
   14000813d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008141:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   140008144:	48 98                	cdqe
   140008146:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000814d:	00 
   14000814e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008152:	48 01 d0             	add    rax,rdx
   140008155:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   140008159:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000815d:	48 83 c0 18          	add    rax,0x18
   140008161:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008165:	e9 95 00 00 00       	jmp    1400081ff <__mult_D2A+0x1c2>
   14000816a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000816e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008172:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   140008176:	8b 00                	mov    eax,DWORD PTR [rax]
   140008178:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   14000817b:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
   14000817f:	74 79                	je     1400081fa <__mult_D2A+0x1bd>
   140008181:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140008185:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008189:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000818d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008191:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140008198:	00 
   140008199:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000819d:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400081a1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400081a5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400081a7:	89 c2                	mov    edx,eax
   1400081a9:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   1400081ac:	48 0f af d0          	imul   rdx,rax
   1400081b0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400081b4:	8b 00                	mov    eax,DWORD PTR [rax]
   1400081b6:	89 c0                	mov    eax,eax
   1400081b8:	48 01 c2             	add    rdx,rax
   1400081bb:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400081bf:	48 01 d0             	add    rax,rdx
   1400081c2:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   1400081c6:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
   1400081ca:	48 c1 e8 20          	shr    rax,0x20
   1400081ce:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400081d2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400081d6:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400081da:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400081de:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400081e2:	89 10                	mov    DWORD PTR [rax],edx
   1400081e4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400081e8:	48 3b 45 b0          	cmp    rax,QWORD PTR [rbp-0x50]
   1400081ec:	72 ab                	jb     140008199 <__mult_D2A+0x15c>
   1400081ee:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400081f2:	89 c2                	mov    edx,eax
   1400081f4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400081f8:	89 10                	mov    DWORD PTR [rax],edx
   1400081fa:	48 83 45 d8 04       	add    QWORD PTR [rbp-0x28],0x4
   1400081ff:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008203:	48 3b 45 a8          	cmp    rax,QWORD PTR [rbp-0x58]
   140008207:	0f 82 5d ff ff ff    	jb     14000816a <__mult_D2A+0x12d>
   14000820d:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008211:	48 83 c0 18          	add    rax,0x18
   140008215:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008219:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000821c:	48 98                	cdqe
   14000821e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008225:	00 
   140008226:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000822a:	48 01 d0             	add    rax,rdx
   14000822d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008231:	eb 04                	jmp    140008237 <__mult_D2A+0x1fa>
   140008233:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008237:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000823b:	7e 0f                	jle    14000824c <__mult_D2A+0x20f>
   14000823d:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008242:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008246:	8b 00                	mov    eax,DWORD PTR [rax]
   140008248:	85 c0                	test   eax,eax
   14000824a:	74 e7                	je     140008233 <__mult_D2A+0x1f6>
   14000824c:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008250:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140008253:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008256:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000825a:	48 81 c4 90 00 00 00 	add    rsp,0x90
   140008261:	5d                   	pop    rbp
   140008262:	c3                   	ret

0000000140008263 <__pow5mult_D2A>:
   140008263:	55                   	push   rbp
   140008264:	48 89 e5             	mov    rbp,rsp
   140008267:	48 83 ec 40          	sub    rsp,0x40
   14000826b:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000826f:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140008272:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008275:	83 e0 03             	and    eax,0x3
   140008278:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000827b:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   14000827f:	74 41                	je     1400082c2 <__pow5mult_D2A+0x5f>
   140008281:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008284:	83 e8 01             	sub    eax,0x1
   140008287:	48 98                	cdqe
   140008289:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008290:	00 
   140008291:	48 8d 05 00 1e 00 00 	lea    rax,[rip+0x1e00]        # 14000a098 <p05.0>
   140008298:	8b 14 02             	mov    edx,DWORD PTR [rdx+rax*1]
   14000829b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000829f:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400082a5:	48 89 c1             	mov    rcx,rax
   1400082a8:	e8 1c fc ff ff       	call   140007ec9 <__multadd_D2A>
   1400082ad:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400082b1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400082b6:	75 0a                	jne    1400082c2 <__pow5mult_D2A+0x5f>
   1400082b8:	b8 00 00 00 00       	mov    eax,0x0
   1400082bd:	e9 58 01 00 00       	jmp    14000841a <__pow5mult_D2A+0x1b7>
   1400082c2:	c1 7d 18 02          	sar    DWORD PTR [rbp+0x18],0x2
   1400082c6:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400082ca:	75 09                	jne    1400082d5 <__pow5mult_D2A+0x72>
   1400082cc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400082d0:	e9 45 01 00 00       	jmp    14000841a <__pow5mult_D2A+0x1b7>
   1400082d5:	48 8b 05 84 78 00 00 	mov    rax,QWORD PTR [rip+0x7884]        # 14000fb60 <p5s>
   1400082dc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400082e0:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400082e5:	75 5e                	jne    140008345 <__pow5mult_D2A+0xe2>
   1400082e7:	b9 01 00 00 00       	mov    ecx,0x1
   1400082ec:	e8 51 f8 ff ff       	call   140007b42 <dtoa_lock>
   1400082f1:	48 8b 05 68 78 00 00 	mov    rax,QWORD PTR [rip+0x7868]        # 14000fb60 <p5s>
   1400082f8:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400082fc:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008301:	75 38                	jne    14000833b <__pow5mult_D2A+0xd8>
   140008303:	b9 71 02 00 00       	mov    ecx,0x271
   140008308:	e8 ea fc ff ff       	call   140007ff7 <__i2b_D2A>
   14000830d:	48 89 05 4c 78 00 00 	mov    QWORD PTR [rip+0x784c],rax        # 14000fb60 <p5s>
   140008314:	48 8b 05 45 78 00 00 	mov    rax,QWORD PTR [rip+0x7845]        # 14000fb60 <p5s>
   14000831b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000831f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008324:	75 0a                	jne    140008330 <__pow5mult_D2A+0xcd>
   140008326:	b8 00 00 00 00       	mov    eax,0x0
   14000832b:	e9 ea 00 00 00       	jmp    14000841a <__pow5mult_D2A+0x1b7>
   140008330:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008334:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000833b:	b9 01 00 00 00       	mov    ecx,0x1
   140008340:	e8 2f f9 ff ff       	call   140007c74 <dtoa_unlock>
   140008345:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008348:	83 e0 01             	and    eax,0x1
   14000834b:	85 c0                	test   eax,eax
   14000834d:	74 39                	je     140008388 <__pow5mult_D2A+0x125>
   14000834f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008353:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008357:	48 89 c1             	mov    rcx,rax
   14000835a:	e8 de fc ff ff       	call   14000803d <__mult_D2A>
   14000835f:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008363:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
   140008368:	75 0a                	jne    140008374 <__pow5mult_D2A+0x111>
   14000836a:	b8 00 00 00 00       	mov    eax,0x0
   14000836f:	e9 a6 00 00 00       	jmp    14000841a <__pow5mult_D2A+0x1b7>
   140008374:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008378:	48 89 c1             	mov    rcx,rax
   14000837b:	e8 be fa ff ff       	call   140007e3e <__Bfree_D2A>
   140008380:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008384:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008388:	d1 7d 18             	sar    DWORD PTR [rbp+0x18],1
   14000838b:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   14000838f:	0f 84 80 00 00 00    	je     140008415 <__pow5mult_D2A+0x1b2>
   140008395:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008399:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000839c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400083a0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400083a5:	75 61                	jne    140008408 <__pow5mult_D2A+0x1a5>
   1400083a7:	b9 01 00 00 00       	mov    ecx,0x1
   1400083ac:	e8 91 f7 ff ff       	call   140007b42 <dtoa_lock>
   1400083b1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083b5:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400083b8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400083bc:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400083c1:	75 3b                	jne    1400083fe <__pow5mult_D2A+0x19b>
   1400083c3:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400083c7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083cb:	48 89 c1             	mov    rcx,rax
   1400083ce:	e8 6a fc ff ff       	call   14000803d <__mult_D2A>
   1400083d3:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400083d7:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400083da:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083de:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400083e1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400083e5:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400083ea:	75 07                	jne    1400083f3 <__pow5mult_D2A+0x190>
   1400083ec:	b8 00 00 00 00       	mov    eax,0x0
   1400083f1:	eb 27                	jmp    14000841a <__pow5mult_D2A+0x1b7>
   1400083f3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400083f7:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   1400083fe:	b9 01 00 00 00       	mov    ecx,0x1
   140008403:	e8 6c f8 ff ff       	call   140007c74 <dtoa_unlock>
   140008408:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000840c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008410:	e9 30 ff ff ff       	jmp    140008345 <__pow5mult_D2A+0xe2>
   140008415:	90                   	nop
   140008416:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000841a:	48 83 c4 40          	add    rsp,0x40
   14000841e:	5d                   	pop    rbp
   14000841f:	c3                   	ret

0000000140008420 <__lshift_D2A>:
   140008420:	55                   	push   rbp
   140008421:	48 89 e5             	mov    rbp,rsp
   140008424:	48 83 ec 60          	sub    rsp,0x60
   140008428:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000842c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000842f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008432:	c1 f8 05             	sar    eax,0x5
   140008435:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   140008438:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000843c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000843f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008442:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008446:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140008449:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   14000844c:	01 d0                	add    eax,edx
   14000844e:	83 c0 01             	add    eax,0x1
   140008451:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008454:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008458:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000845b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000845e:	eb 07                	jmp    140008467 <__lshift_D2A+0x47>
   140008460:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140008464:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140008467:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000846a:	3b 45 fc             	cmp    eax,DWORD PTR [rbp-0x4]
   14000846d:	7f f1                	jg     140008460 <__lshift_D2A+0x40>
   14000846f:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008472:	89 c1                	mov    ecx,eax
   140008474:	e8 84 f8 ff ff       	call   140007cfd <__Balloc_D2A>
   140008479:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000847d:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008482:	75 0a                	jne    14000848e <__lshift_D2A+0x6e>
   140008484:	b8 00 00 00 00       	mov    eax,0x0
   140008489:	e9 19 01 00 00       	jmp    1400085a7 <__lshift_D2A+0x187>
   14000848e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008492:	48 83 c0 18          	add    rax,0x18
   140008496:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000849a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400084a1:	eb 16                	jmp    1400084b9 <__lshift_D2A+0x99>
   1400084a3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400084a7:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400084ab:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400084af:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400084b5:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400084b9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400084bc:	3b 45 d8             	cmp    eax,DWORD PTR [rbp-0x28]
   1400084bf:	7c e2                	jl     1400084a3 <__lshift_D2A+0x83>
   1400084c1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400084c5:	48 83 c0 18          	add    rax,0x18
   1400084c9:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400084cd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400084d1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400084d4:	48 98                	cdqe
   1400084d6:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400084dd:	00 
   1400084de:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400084e2:	48 01 d0             	add    rax,rdx
   1400084e5:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400084e9:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   1400084ed:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400084f1:	74 71                	je     140008564 <__lshift_D2A+0x144>
   1400084f3:	b8 20 00 00 00       	mov    eax,0x20
   1400084f8:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400084fb:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400084fe:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
   140008505:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008509:	8b 10                	mov    edx,DWORD PTR [rax]
   14000850b:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000850e:	89 c1                	mov    ecx,eax
   140008510:	d3 e2                	shl    edx,cl
   140008512:	89 d1                	mov    ecx,edx
   140008514:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008518:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000851c:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008520:	0b 4d dc             	or     ecx,DWORD PTR [rbp-0x24]
   140008523:	89 ca                	mov    edx,ecx
   140008525:	89 10                	mov    DWORD PTR [rax],edx
   140008527:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000852b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000852f:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   140008533:	8b 10                	mov    edx,DWORD PTR [rax]
   140008535:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008538:	89 c1                	mov    ecx,eax
   14000853a:	d3 ea                	shr    edx,cl
   14000853c:	89 d0                	mov    eax,edx
   14000853e:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008541:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008545:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   140008549:	72 ba                	jb     140008505 <__lshift_D2A+0xe5>
   14000854b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000854f:	8b 55 dc             	mov    edx,DWORD PTR [rbp-0x24]
   140008552:	89 10                	mov    DWORD PTR [rax],edx
   140008554:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008558:	8b 00                	mov    eax,DWORD PTR [rax]
   14000855a:	85 c0                	test   eax,eax
   14000855c:	74 2c                	je     14000858a <__lshift_D2A+0x16a>
   14000855e:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140008562:	eb 26                	jmp    14000858a <__lshift_D2A+0x16a>
   140008564:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140008568:	48 8d 42 04          	lea    rax,[rdx+0x4]
   14000856c:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008570:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008574:	48 8d 48 04          	lea    rcx,[rax+0x4]
   140008578:	48 89 4d e0          	mov    QWORD PTR [rbp-0x20],rcx
   14000857c:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000857e:	89 10                	mov    DWORD PTR [rax],edx
   140008580:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008584:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   140008588:	72 da                	jb     140008564 <__lshift_D2A+0x144>
   14000858a:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000858d:	8d 50 ff             	lea    edx,[rax-0x1]
   140008590:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008594:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008597:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000859b:	48 89 c1             	mov    rcx,rax
   14000859e:	e8 9b f8 ff ff       	call   140007e3e <__Bfree_D2A>
   1400085a3:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400085a7:	48 83 c4 60          	add    rsp,0x60
   1400085ab:	5d                   	pop    rbp
   1400085ac:	c3                   	ret

00000001400085ad <__cmp_D2A>:
   1400085ad:	55                   	push   rbp
   1400085ae:	48 89 e5             	mov    rbp,rsp
   1400085b1:	48 83 ec 30          	sub    rsp,0x30
   1400085b5:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400085b9:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400085bd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400085c1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400085c4:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400085c7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400085cb:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400085ce:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400085d1:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400085d4:	29 45 ec             	sub    DWORD PTR [rbp-0x14],eax
   1400085d7:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   1400085db:	74 08                	je     1400085e5 <__cmp_D2A+0x38>
   1400085dd:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400085e0:	e9 92 00 00 00       	jmp    140008677 <__cmp_D2A+0xca>
   1400085e5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400085e9:	48 83 c0 18          	add    rax,0x18
   1400085ed:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400085f1:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400085f4:	48 98                	cdqe
   1400085f6:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400085fd:	00 
   1400085fe:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008602:	48 01 d0             	add    rax,rdx
   140008605:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008609:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000860d:	48 83 c0 18          	add    rax,0x18
   140008611:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008615:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008618:	48 98                	cdqe
   14000861a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008621:	00 
   140008622:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140008626:	48 01 d0             	add    rax,rdx
   140008629:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000862d:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008632:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008636:	8b 10                	mov    edx,DWORD PTR [rax]
   140008638:	48 83 6d f0 04       	sub    QWORD PTR [rbp-0x10],0x4
   14000863d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008641:	8b 00                	mov    eax,DWORD PTR [rax]
   140008643:	39 c2                	cmp    edx,eax
   140008645:	74 1e                	je     140008665 <__cmp_D2A+0xb8>
   140008647:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000864b:	8b 10                	mov    edx,DWORD PTR [rax]
   14000864d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008651:	8b 00                	mov    eax,DWORD PTR [rax]
   140008653:	39 c2                	cmp    edx,eax
   140008655:	73 07                	jae    14000865e <__cmp_D2A+0xb1>
   140008657:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000865c:	eb 19                	jmp    140008677 <__cmp_D2A+0xca>
   14000865e:	b8 01 00 00 00       	mov    eax,0x1
   140008663:	eb 12                	jmp    140008677 <__cmp_D2A+0xca>
   140008665:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008669:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000866d:	73 02                	jae    140008671 <__cmp_D2A+0xc4>
   14000866f:	eb bc                	jmp    14000862d <__cmp_D2A+0x80>
   140008671:	90                   	nop
   140008672:	b8 00 00 00 00       	mov    eax,0x0
   140008677:	48 83 c4 30          	add    rsp,0x30
   14000867b:	5d                   	pop    rbp
   14000867c:	c3                   	ret

000000014000867d <__diff_D2A>:
   14000867d:	55                   	push   rbp
   14000867e:	48 89 e5             	mov    rbp,rsp
   140008681:	48 83 ec 70          	sub    rsp,0x70
   140008685:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008689:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000868d:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140008691:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008695:	48 89 c1             	mov    rcx,rax
   140008698:	e8 10 ff ff ff       	call   1400085ad <__cmp_D2A>
   14000869d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400086a0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400086a4:	75 3e                	jne    1400086e4 <__diff_D2A+0x67>
   1400086a6:	b9 00 00 00 00       	mov    ecx,0x0
   1400086ab:	e8 4d f6 ff ff       	call   140007cfd <__Balloc_D2A>
   1400086b0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400086b4:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   1400086b9:	75 0a                	jne    1400086c5 <__diff_D2A+0x48>
   1400086bb:	b8 00 00 00 00       	mov    eax,0x0
   1400086c0:	e9 ab 01 00 00       	jmp    140008870 <__diff_D2A+0x1f3>
   1400086c5:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086c9:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   1400086d0:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086d4:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   1400086db:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086df:	e9 8c 01 00 00       	jmp    140008870 <__diff_D2A+0x1f3>
   1400086e4:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400086e8:	79 21                	jns    14000870b <__diff_D2A+0x8e>
   1400086ea:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400086ee:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400086f2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400086f6:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400086fa:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086fe:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140008702:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140008709:	eb 07                	jmp    140008712 <__diff_D2A+0x95>
   14000870b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140008712:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008716:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140008719:	89 c1                	mov    ecx,eax
   14000871b:	e8 dd f5 ff ff       	call   140007cfd <__Balloc_D2A>
   140008720:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008724:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008729:	75 0a                	jne    140008735 <__diff_D2A+0xb8>
   14000872b:	b8 00 00 00 00       	mov    eax,0x0
   140008730:	e9 3b 01 00 00       	jmp    140008870 <__diff_D2A+0x1f3>
   140008735:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008739:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000873c:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000873f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008743:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008746:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008749:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000874d:	48 83 c0 18          	add    rax,0x18
   140008751:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008755:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008758:	48 98                	cdqe
   14000875a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008761:	00 
   140008762:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008766:	48 01 d0             	add    rax,rdx
   140008769:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000876d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008771:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008774:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   140008777:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000877b:	48 83 c0 18          	add    rax,0x18
   14000877f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008783:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140008786:	48 98                	cdqe
   140008788:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000878f:	00 
   140008790:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008794:	48 01 d0             	add    rax,rdx
   140008797:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000879b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000879f:	48 83 c0 18          	add    rax,0x18
   1400087a3:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400087a7:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   1400087ae:	00 
   1400087af:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400087b3:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087b7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400087bb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087bd:	89 c1                	mov    ecx,eax
   1400087bf:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400087c3:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087c7:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   1400087cb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087cd:	89 c2                	mov    edx,eax
   1400087cf:	48 89 c8             	mov    rax,rcx
   1400087d2:	48 29 d0             	sub    rax,rdx
   1400087d5:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   1400087d9:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400087dd:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   1400087e1:	48 c1 e8 20          	shr    rax,0x20
   1400087e5:	83 e0 01             	and    eax,0x1
   1400087e8:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400087ec:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400087f0:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400087f4:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400087f8:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400087fc:	89 10                	mov    DWORD PTR [rax],edx
   1400087fe:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008802:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   140008806:	72 a7                	jb     1400087af <__diff_D2A+0x132>
   140008808:	eb 39                	jmp    140008843 <__diff_D2A+0x1c6>
   14000880a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000880e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008812:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140008816:	8b 00                	mov    eax,DWORD PTR [rax]
   140008818:	89 c0                	mov    eax,eax
   14000881a:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   14000881e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008822:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008826:	48 c1 e8 20          	shr    rax,0x20
   14000882a:	83 e0 01             	and    eax,0x1
   14000882d:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008831:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008835:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008839:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000883d:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140008841:	89 10                	mov    DWORD PTR [rax],edx
   140008843:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008847:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   14000884b:	72 bd                	jb     14000880a <__diff_D2A+0x18d>
   14000884d:	eb 04                	jmp    140008853 <__diff_D2A+0x1d6>
   14000884f:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008853:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008858:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000885c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000885e:	85 c0                	test   eax,eax
   140008860:	74 ed                	je     14000884f <__diff_D2A+0x1d2>
   140008862:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008866:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140008869:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000886c:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008870:	48 83 c4 70          	add    rsp,0x70
   140008874:	5d                   	pop    rbp
   140008875:	c3                   	ret

0000000140008876 <__b2d_D2A>:
   140008876:	55                   	push   rbp
   140008877:	48 89 e5             	mov    rbp,rsp
   14000887a:	48 83 ec 50          	sub    rsp,0x50
   14000887e:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008882:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008886:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000888a:	48 83 c0 18          	add    rax,0x18
   14000888e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008892:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008896:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008899:	48 98                	cdqe
   14000889b:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400088a2:	00 
   1400088a3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400088a7:	48 01 d0             	add    rax,rdx
   1400088aa:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400088ae:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400088b3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088b7:	8b 00                	mov    eax,DWORD PTR [rax]
   1400088b9:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400088bc:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400088bf:	89 c1                	mov    ecx,eax
   1400088c1:	e8 27 f4 ff ff       	call   140007ced <__hi0bits_D2A>
   1400088c6:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400088c9:	b8 20 00 00 00       	mov    eax,0x20
   1400088ce:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400088d1:	89 c2                	mov    edx,eax
   1400088d3:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400088d7:	89 10                	mov    DWORD PTR [rax],edx
   1400088d9:	83 7d dc 0a          	cmp    DWORD PTR [rbp-0x24],0xa
   1400088dd:	7f 66                	jg     140008945 <__b2d_D2A+0xcf>
   1400088df:	b8 0b 00 00 00       	mov    eax,0xb
   1400088e4:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400088e7:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400088ea:	89 c1                	mov    ecx,eax
   1400088ec:	d3 ea                	shr    edx,cl
   1400088ee:	89 d0                	mov    eax,edx
   1400088f0:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400088f5:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400088f8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088fc:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140008900:	73 10                	jae    140008912 <__b2d_D2A+0x9c>
   140008902:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008907:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000890b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000890d:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008910:	eb 07                	jmp    140008919 <__b2d_D2A+0xa3>
   140008912:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140008919:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000891c:	83 c0 15             	add    eax,0x15
   14000891f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008922:	89 c1                	mov    ecx,eax
   140008924:	d3 e2                	shl    edx,cl
   140008926:	41 89 d0             	mov    r8d,edx
   140008929:	b8 0b 00 00 00       	mov    eax,0xb
   14000892e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008931:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140008934:	89 c1                	mov    ecx,eax
   140008936:	d3 ea                	shr    edx,cl
   140008938:	89 d0                	mov    eax,edx
   14000893a:	44 09 c0             	or     eax,r8d
   14000893d:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008940:	e9 ac 00 00 00       	jmp    1400089f1 <__b2d_D2A+0x17b>
   140008945:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008949:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000894d:	73 10                	jae    14000895f <__b2d_D2A+0xe9>
   14000894f:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008954:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008958:	8b 00                	mov    eax,DWORD PTR [rax]
   14000895a:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000895d:	eb 07                	jmp    140008966 <__b2d_D2A+0xf0>
   14000895f:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
   140008966:	83 6d dc 0b          	sub    DWORD PTR [rbp-0x24],0xb
   14000896a:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   14000896e:	74 70                	je     1400089e0 <__b2d_D2A+0x16a>
   140008970:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008973:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008976:	89 c1                	mov    ecx,eax
   140008978:	d3 e2                	shl    edx,cl
   14000897a:	41 89 d0             	mov    r8d,edx
   14000897d:	b8 20 00 00 00       	mov    eax,0x20
   140008982:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008985:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140008988:	89 c1                	mov    ecx,eax
   14000898a:	d3 ea                	shr    edx,cl
   14000898c:	89 d0                	mov    eax,edx
   14000898e:	44 09 c0             	or     eax,r8d
   140008991:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008996:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008999:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000899d:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400089a1:	73 10                	jae    1400089b3 <__b2d_D2A+0x13d>
   1400089a3:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400089a8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400089ac:	8b 00                	mov    eax,DWORD PTR [rax]
   1400089ae:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400089b1:	eb 07                	jmp    1400089ba <__b2d_D2A+0x144>
   1400089b3:	c7 45 f0 00 00 00 00 	mov    DWORD PTR [rbp-0x10],0x0
   1400089ba:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400089bd:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400089c0:	89 c1                	mov    ecx,eax
   1400089c2:	d3 e2                	shl    edx,cl
   1400089c4:	41 89 d0             	mov    r8d,edx
   1400089c7:	b8 20 00 00 00       	mov    eax,0x20
   1400089cc:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400089cf:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400089d2:	89 c1                	mov    ecx,eax
   1400089d4:	d3 ea                	shr    edx,cl
   1400089d6:	89 d0                	mov    eax,edx
   1400089d8:	44 09 c0             	or     eax,r8d
   1400089db:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089de:	eb 11                	jmp    1400089f1 <__b2d_D2A+0x17b>
   1400089e0:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400089e3:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400089e8:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400089eb:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400089ee:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089f1:	f2 0f 10 45 d0       	movsd  xmm0,QWORD PTR [rbp-0x30]
   1400089f6:	48 83 c4 50          	add    rsp,0x50
   1400089fa:	5d                   	pop    rbp
   1400089fb:	c3                   	ret

00000001400089fc <__d2b_D2A>:
   1400089fc:	55                   	push   rbp
   1400089fd:	53                   	push   rbx
   1400089fe:	48 83 ec 58          	sub    rsp,0x58
   140008a02:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140008a07:	f2 0f 11 45 20       	movsd  QWORD PTR [rbp+0x20],xmm0
   140008a0c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140008a10:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140008a14:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140008a19:	f2 0f 11 45 d8       	movsd  QWORD PTR [rbp-0x28],xmm0
   140008a1e:	b9 01 00 00 00       	mov    ecx,0x1
   140008a23:	e8 d5 f2 ff ff       	call   140007cfd <__Balloc_D2A>
   140008a28:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008a2c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008a31:	75 0a                	jne    140008a3d <__d2b_D2A+0x41>
   140008a33:	b8 00 00 00 00       	mov    eax,0x0
   140008a38:	e9 68 01 00 00       	jmp    140008ba5 <__d2b_D2A+0x1a9>
   140008a3d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a41:	48 83 c0 18          	add    rax,0x18
   140008a45:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008a49:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a4c:	25 ff ff 0f 00       	and    eax,0xfffff
   140008a51:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a54:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a57:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008a5c:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008a5f:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a62:	c1 e8 14             	shr    eax,0x14
   140008a65:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140008a68:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008a6c:	74 0b                	je     140008a79 <__d2b_D2A+0x7d>
   140008a6e:	8b 45 d0             	mov    eax,DWORD PTR [rbp-0x30]
   140008a71:	0d 00 00 10 00       	or     eax,0x100000
   140008a76:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a79:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140008a7c:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008a7f:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008a82:	85 c0                	test   eax,eax
   140008a84:	74 7b                	je     140008b01 <__d2b_D2A+0x105>
   140008a86:	48 8d 45 d4          	lea    rax,[rbp-0x2c]
   140008a8a:	48 89 c1             	mov    rcx,rax
   140008a8d:	e8 26 f2 ff ff       	call   140007cb8 <__lo0bits_D2A>
   140008a92:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008a95:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008a99:	74 2b                	je     140008ac6 <__d2b_D2A+0xca>
   140008a9b:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a9e:	b8 20 00 00 00       	mov    eax,0x20
   140008aa3:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008aa6:	89 c1                	mov    ecx,eax
   140008aa8:	d3 e2                	shl    edx,cl
   140008aaa:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008aad:	09 c2                	or     edx,eax
   140008aaf:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008ab3:	89 10                	mov    DWORD PTR [rax],edx
   140008ab5:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008ab8:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008abb:	89 c1                	mov    ecx,eax
   140008abd:	d3 ea                	shr    edx,cl
   140008abf:	89 d0                	mov    eax,edx
   140008ac1:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008ac4:	eb 09                	jmp    140008acf <__d2b_D2A+0xd3>
   140008ac6:	8b 55 d4             	mov    edx,DWORD PTR [rbp-0x2c]
   140008ac9:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008acd:	89 10                	mov    DWORD PTR [rax],edx
   140008acf:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008ad3:	48 83 c0 04          	add    rax,0x4
   140008ad7:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008ada:	89 10                	mov    DWORD PTR [rax],edx
   140008adc:	8b 00                	mov    eax,DWORD PTR [rax]
   140008ade:	85 c0                	test   eax,eax
   140008ae0:	74 07                	je     140008ae9 <__d2b_D2A+0xed>
   140008ae2:	ba 02 00 00 00       	mov    edx,0x2
   140008ae7:	eb 05                	jmp    140008aee <__d2b_D2A+0xf2>
   140008ae9:	ba 01 00 00 00       	mov    edx,0x1
   140008aee:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008af2:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008af5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008af9:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008afc:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008aff:	eb 31                	jmp    140008b32 <__d2b_D2A+0x136>
   140008b01:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140008b05:	48 89 c1             	mov    rcx,rax
   140008b08:	e8 ab f1 ff ff       	call   140007cb8 <__lo0bits_D2A>
   140008b0d:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008b10:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008b13:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b17:	89 10                	mov    DWORD PTR [rax],edx
   140008b19:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b1d:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008b24:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b28:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008b2b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008b2e:	83 45 f8 20          	add    DWORD PTR [rbp-0x8],0x20
   140008b32:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008b36:	74 26                	je     140008b5e <__d2b_D2A+0x162>
   140008b38:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008b3b:	8d 90 cd fb ff ff    	lea    edx,[rax-0x433]
   140008b41:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008b44:	01 c2                	add    edx,eax
   140008b46:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008b4a:	89 10                	mov    DWORD PTR [rax],edx
   140008b4c:	b8 35 00 00 00       	mov    eax,0x35
   140008b51:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008b54:	89 c2                	mov    edx,eax
   140008b56:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008b5a:	89 10                	mov    DWORD PTR [rax],edx
   140008b5c:	eb 43                	jmp    140008ba1 <__d2b_D2A+0x1a5>
   140008b5e:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008b61:	8d 90 ce fb ff ff    	lea    edx,[rax-0x432]
   140008b67:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008b6a:	01 c2                	add    edx,eax
   140008b6c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008b70:	89 10                	mov    DWORD PTR [rax],edx
   140008b72:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008b75:	c1 e0 05             	shl    eax,0x5
   140008b78:	89 c3                	mov    ebx,eax
   140008b7a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008b7d:	48 98                	cdqe
   140008b7f:	48 c1 e0 02          	shl    rax,0x2
   140008b83:	48 8d 50 fc          	lea    rdx,[rax-0x4]
   140008b87:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b8b:	48 01 d0             	add    rax,rdx
   140008b8e:	8b 00                	mov    eax,DWORD PTR [rax]
   140008b90:	89 c1                	mov    ecx,eax
   140008b92:	e8 56 f1 ff ff       	call   140007ced <__hi0bits_D2A>
   140008b97:	29 c3                	sub    ebx,eax
   140008b99:	89 da                	mov    edx,ebx
   140008b9b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008b9f:	89 10                	mov    DWORD PTR [rax],edx
   140008ba1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008ba5:	48 83 c4 58          	add    rsp,0x58
   140008ba9:	5b                   	pop    rbx
   140008baa:	5d                   	pop    rbp
   140008bab:	c3                   	ret

0000000140008bac <__strcp_D2A>:
   140008bac:	55                   	push   rbp
   140008bad:	48 89 e5             	mov    rbp,rsp
   140008bb0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008bb4:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008bb8:	eb 05                	jmp    140008bbf <__strcp_D2A+0x13>
   140008bba:	48 83 45 10 01       	add    QWORD PTR [rbp+0x10],0x1
   140008bbf:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008bc3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140008bc7:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008bcb:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140008bce:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008bd2:	88 10                	mov    BYTE PTR [rax],dl
   140008bd4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008bd8:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008bdb:	84 c0                	test   al,al
   140008bdd:	75 db                	jne    140008bba <__strcp_D2A+0xe>
   140008bdf:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008be3:	5d                   	pop    rbp
   140008be4:	c3                   	ret
   140008be5:	90                   	nop
   140008be6:	90                   	nop
   140008be7:	90                   	nop
   140008be8:	90                   	nop
   140008be9:	90                   	nop
   140008bea:	90                   	nop
   140008beb:	90                   	nop
   140008bec:	90                   	nop
   140008bed:	90                   	nop
   140008bee:	90                   	nop
   140008bef:	90                   	nop

0000000140008bf0 <__fpclassify>:
   140008bf0:	55                   	push   rbp
   140008bf1:	48 89 e5             	mov    rbp,rsp
   140008bf4:	48 83 ec 10          	sub    rsp,0x10
   140008bf8:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008bfd:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008c02:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008c07:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008c0a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008c0d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008c10:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140008c13:	81 e2 ff ff 0f 00    	and    edx,0xfffff
   140008c19:	09 d0                	or     eax,edx
   140008c1b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c1e:	81 65 fc 00 00 f0 7f 	and    DWORD PTR [rbp-0x4],0x7ff00000
   140008c25:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008c28:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008c2b:	85 c0                	test   eax,eax
   140008c2d:	75 07                	jne    140008c36 <__fpclassify+0x46>
   140008c2f:	b8 00 40 00 00       	mov    eax,0x4000
   140008c34:	eb 2f                	jmp    140008c65 <__fpclassify+0x75>
   140008c36:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008c3a:	75 07                	jne    140008c43 <__fpclassify+0x53>
   140008c3c:	b8 00 44 00 00       	mov    eax,0x4400
   140008c41:	eb 22                	jmp    140008c65 <__fpclassify+0x75>
   140008c43:	81 7d fc 00 00 f0 7f 	cmp    DWORD PTR [rbp-0x4],0x7ff00000
   140008c4a:	75 14                	jne    140008c60 <__fpclassify+0x70>
   140008c4c:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008c50:	74 07                	je     140008c59 <__fpclassify+0x69>
   140008c52:	b8 00 01 00 00       	mov    eax,0x100
   140008c57:	eb 0c                	jmp    140008c65 <__fpclassify+0x75>
   140008c59:	b8 00 05 00 00       	mov    eax,0x500
   140008c5e:	eb 05                	jmp    140008c65 <__fpclassify+0x75>
   140008c60:	b8 00 04 00 00       	mov    eax,0x400
   140008c65:	48 83 c4 10          	add    rsp,0x10
   140008c69:	5d                   	pop    rbp
   140008c6a:	c3                   	ret
   140008c6b:	90                   	nop
   140008c6c:	90                   	nop
   140008c6d:	90                   	nop
   140008c6e:	90                   	nop
   140008c6f:	90                   	nop

0000000140008c70 <__fpclassifyl>:
   140008c70:	55                   	push   rbp
   140008c71:	53                   	push   rbx
   140008c72:	48 83 ec 38          	sub    rsp,0x38
   140008c76:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008c7b:	48 89 cb             	mov    rbx,rcx
   140008c7e:	db 2b                	fld    TBYTE PTR [rbx]
   140008c80:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008c83:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008c86:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008c89:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008c8d:	98                   	cwde
   140008c8e:	25 ff 7f 00 00       	and    eax,0x7fff
   140008c93:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008c96:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008c9a:	75 25                	jne    140008cc1 <__fpclassifyl+0x51>
   140008c9c:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008c9f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008ca2:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008ca5:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008ca8:	85 c0                	test   eax,eax
   140008caa:	75 07                	jne    140008cb3 <__fpclassifyl+0x43>
   140008cac:	b8 00 40 00 00       	mov    eax,0x4000
   140008cb1:	eb 3d                	jmp    140008cf0 <__fpclassifyl+0x80>
   140008cb3:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008cb6:	85 c0                	test   eax,eax
   140008cb8:	78 31                	js     140008ceb <__fpclassifyl+0x7b>
   140008cba:	b8 00 44 00 00       	mov    eax,0x4400
   140008cbf:	eb 2f                	jmp    140008cf0 <__fpclassifyl+0x80>
   140008cc1:	81 7d fc ff 7f 00 00 	cmp    DWORD PTR [rbp-0x4],0x7fff
   140008cc8:	75 21                	jne    140008ceb <__fpclassifyl+0x7b>
   140008cca:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008ccd:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008cd2:	89 c2                	mov    edx,eax
   140008cd4:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008cd7:	09 d0                	or     eax,edx
   140008cd9:	85 c0                	test   eax,eax
   140008cdb:	75 07                	jne    140008ce4 <__fpclassifyl+0x74>
   140008cdd:	b8 00 05 00 00       	mov    eax,0x500
   140008ce2:	eb 0c                	jmp    140008cf0 <__fpclassifyl+0x80>
   140008ce4:	b8 00 01 00 00       	mov    eax,0x100
   140008ce9:	eb 05                	jmp    140008cf0 <__fpclassifyl+0x80>
   140008ceb:	b8 00 04 00 00       	mov    eax,0x400
   140008cf0:	48 83 c4 38          	add    rsp,0x38
   140008cf4:	5b                   	pop    rbx
   140008cf5:	5d                   	pop    rbp
   140008cf6:	c3                   	ret
   140008cf7:	90                   	nop
   140008cf8:	90                   	nop
   140008cf9:	90                   	nop
   140008cfa:	90                   	nop
   140008cfb:	90                   	nop
   140008cfc:	90                   	nop
   140008cfd:	90                   	nop
   140008cfe:	90                   	nop
   140008cff:	90                   	nop

0000000140008d00 <__isnan>:
   140008d00:	55                   	push   rbp
   140008d01:	48 89 e5             	mov    rbp,rsp
   140008d04:	48 83 ec 10          	sub    rsp,0x10
   140008d08:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008d0d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008d12:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008d17:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008d1a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d1d:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008d20:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008d25:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d28:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d2b:	f7 d8                	neg    eax
   140008d2d:	0b 45 fc             	or     eax,DWORD PTR [rbp-0x4]
   140008d30:	c1 e8 1f             	shr    eax,0x1f
   140008d33:	89 c2                	mov    edx,eax
   140008d35:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d38:	09 d0                	or     eax,edx
   140008d3a:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d3d:	b8 00 00 f0 7f       	mov    eax,0x7ff00000
   140008d42:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008d45:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d48:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d4b:	c1 f8 1f             	sar    eax,0x1f
   140008d4e:	48 83 c4 10          	add    rsp,0x10
   140008d52:	5d                   	pop    rbp
   140008d53:	c3                   	ret
   140008d54:	90                   	nop
   140008d55:	90                   	nop
   140008d56:	90                   	nop
   140008d57:	90                   	nop
   140008d58:	90                   	nop
   140008d59:	90                   	nop
   140008d5a:	90                   	nop
   140008d5b:	90                   	nop
   140008d5c:	90                   	nop
   140008d5d:	90                   	nop
   140008d5e:	90                   	nop
   140008d5f:	90                   	nop

0000000140008d60 <__isnanl>:
   140008d60:	55                   	push   rbp
   140008d61:	53                   	push   rbx
   140008d62:	48 83 ec 38          	sub    rsp,0x38
   140008d66:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008d6b:	48 89 cb             	mov    rbx,rcx
   140008d6e:	db 2b                	fld    TBYTE PTR [rbx]
   140008d70:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008d73:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008d76:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008d79:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008d7d:	98                   	cwde
   140008d7e:	01 c0                	add    eax,eax
   140008d80:	25 ff ff 00 00       	and    eax,0xffff
   140008d85:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d88:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008d8b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140008d8e:	81 e2 ff ff ff 7f    	and    edx,0x7fffffff
   140008d94:	09 d0                	or     eax,edx
   140008d96:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d99:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d9c:	f7 d8                	neg    eax
   140008d9e:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008da1:	c1 e8 1f             	shr    eax,0x1f
   140008da4:	89 c2                	mov    edx,eax
   140008da6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008da9:	09 d0                	or     eax,edx
   140008dab:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008dae:	b8 fe ff 00 00       	mov    eax,0xfffe
   140008db3:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140008db6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008db9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008dbc:	c1 f8 10             	sar    eax,0x10
   140008dbf:	48 83 c4 38          	add    rsp,0x38
   140008dc3:	5b                   	pop    rbx
   140008dc4:	5d                   	pop    rbp
   140008dc5:	c3                   	ret
   140008dc6:	90                   	nop
   140008dc7:	90                   	nop
   140008dc8:	90                   	nop
   140008dc9:	90                   	nop
   140008dca:	90                   	nop
   140008dcb:	90                   	nop
   140008dcc:	90                   	nop
   140008dcd:	90                   	nop
   140008dce:	90                   	nop
   140008dcf:	90                   	nop

0000000140008dd0 <wcsnlen>:
   140008dd0:	55                   	push   rbp
   140008dd1:	48 89 e5             	mov    rbp,rsp
   140008dd4:	48 83 ec 10          	sub    rsp,0x10
   140008dd8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008ddc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008de0:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140008de7:	00 
   140008de8:	eb 0a                	jmp    140008df4 <wcsnlen+0x24>
   140008dea:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008def:	48 83 45 10 02       	add    QWORD PTR [rbp+0x10],0x2
   140008df4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008df8:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008dfc:	73 0c                	jae    140008e0a <wcsnlen+0x3a>
   140008dfe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e02:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140008e05:	66 85 c0             	test   ax,ax
   140008e08:	75 e0                	jne    140008dea <wcsnlen+0x1a>
   140008e0a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e0e:	48 83 c4 10          	add    rsp,0x10
   140008e12:	5d                   	pop    rbp
   140008e13:	c3                   	ret
   140008e14:	90                   	nop
   140008e15:	90                   	nop
   140008e16:	90                   	nop
   140008e17:	90                   	nop
   140008e18:	90                   	nop
   140008e19:	90                   	nop
   140008e1a:	90                   	nop
   140008e1b:	90                   	nop
   140008e1c:	90                   	nop
   140008e1d:	90                   	nop
   140008e1e:	90                   	nop
   140008e1f:	90                   	nop

0000000140008e20 <strnlen>:
   140008e20:	55                   	push   rbp
   140008e21:	48 89 e5             	mov    rbp,rsp
   140008e24:	48 83 ec 10          	sub    rsp,0x10
   140008e28:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e2c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008e30:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e34:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008e38:	eb 05                	jmp    140008e3f <strnlen+0x1f>
   140008e3a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008e3f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e43:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008e47:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008e4b:	73 0b                	jae    140008e58 <strnlen+0x38>
   140008e4d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e51:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008e54:	84 c0                	test   al,al
   140008e56:	75 e2                	jne    140008e3a <strnlen+0x1a>
   140008e58:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e5c:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008e60:	48 83 c4 10          	add    rsp,0x10
   140008e64:	5d                   	pop    rbp
   140008e65:	c3                   	ret
   140008e66:	90                   	nop
   140008e67:	90                   	nop
   140008e68:	90                   	nop
   140008e69:	90                   	nop
   140008e6a:	90                   	nop
   140008e6b:	90                   	nop
   140008e6c:	90                   	nop
   140008e6d:	90                   	nop
   140008e6e:	90                   	nop
   140008e6f:	90                   	nop

0000000140008e70 <_initterm_e>:
   140008e70:	55                   	push   rbp
   140008e71:	48 89 e5             	mov    rbp,rsp
   140008e74:	48 83 ec 30          	sub    rsp,0x30
   140008e78:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e7c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008e80:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e84:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008e88:	eb 29                	jmp    140008eb3 <_initterm_e+0x43>
   140008e8a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e8e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e91:	48 85 c0             	test   rax,rax
   140008e94:	74 17                	je     140008ead <_initterm_e+0x3d>
   140008e96:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e9a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e9d:	ff d0                	call   rax
   140008e9f:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008ea2:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140008ea6:	74 06                	je     140008eae <_initterm_e+0x3e>
   140008ea8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008eab:	eb 15                	jmp    140008ec2 <_initterm_e+0x52>
   140008ead:	90                   	nop
   140008eae:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140008eb3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008eb7:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008ebb:	72 cd                	jb     140008e8a <_initterm_e+0x1a>
   140008ebd:	b8 00 00 00 00       	mov    eax,0x0
   140008ec2:	48 83 c4 30          	add    rsp,0x30
   140008ec6:	5d                   	pop    rbp
   140008ec7:	c3                   	ret
   140008ec8:	90                   	nop
   140008ec9:	90                   	nop
   140008eca:	90                   	nop
   140008ecb:	90                   	nop
   140008ecc:	90                   	nop
   140008ecd:	90                   	nop
   140008ece:	90                   	nop
   140008ecf:	90                   	nop

0000000140008ed0 <__p__fmode>:
   140008ed0:	55                   	push   rbp
   140008ed1:	48 89 e5             	mov    rbp,rsp
   140008ed4:	48 8b 05 25 27 00 00 	mov    rax,QWORD PTR [rip+0x2725]        # 14000b600 <.refptr.__imp__fmode>
   140008edb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008ede:	5d                   	pop    rbp
   140008edf:	c3                   	ret

0000000140008ee0 <__p__commode>:
   140008ee0:	55                   	push   rbp
   140008ee1:	48 89 e5             	mov    rbp,rsp
   140008ee4:	48 8b 05 05 27 00 00 	mov    rax,QWORD PTR [rip+0x2705]        # 14000b5f0 <.refptr.__imp__commode>
   140008eeb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008eee:	5d                   	pop    rbp
   140008eef:	c3                   	ret

0000000140008ef0 <__p___initenv>:
   140008ef0:	55                   	push   rbp
   140008ef1:	48 89 e5             	mov    rbp,rsp
   140008ef4:	48 8b 05 e5 26 00 00 	mov    rax,QWORD PTR [rip+0x26e5]        # 14000b5e0 <.refptr.__imp___initenv>
   140008efb:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008efe:	5d                   	pop    rbp
   140008eff:	c3                   	ret

0000000140008f00 <_lock_file>:
   140008f00:	55                   	push   rbp
   140008f01:	48 89 e5             	mov    rbp,rsp
   140008f04:	48 83 ec 20          	sub    rsp,0x20
   140008f08:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008f0c:	b9 00 00 00 00       	mov    ecx,0x0
   140008f11:	e8 6a 01 00 00       	call   140009080 <__acrt_iob_func>
   140008f16:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008f1a:	72 52                	jb     140008f6e <_lock_file+0x6e>
   140008f1c:	b9 13 00 00 00       	mov    ecx,0x13
   140008f21:	e8 5a 01 00 00       	call   140009080 <__acrt_iob_func>
   140008f26:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008f2a:	72 42                	jb     140008f6e <_lock_file+0x6e>
   140008f2c:	b9 00 00 00 00       	mov    ecx,0x0
   140008f31:	e8 4a 01 00 00       	call   140009080 <__acrt_iob_func>
   140008f36:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008f3a:	48 29 c2             	sub    rdx,rax
   140008f3d:	48 c1 fa 04          	sar    rdx,0x4
   140008f41:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008f48:	aa aa aa 
   140008f4b:	48 0f af c2          	imul   rax,rdx
   140008f4f:	83 c0 10             	add    eax,0x10
   140008f52:	89 c1                	mov    ecx,eax
   140008f54:	e8 1f 07 00 00       	call   140009678 <_lock>
   140008f59:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f5d:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008f60:	80 cc 80             	or     ah,0x80
   140008f63:	89 c2                	mov    edx,eax
   140008f65:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f69:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008f6c:	eb 15                	jmp    140008f83 <_lock_file+0x83>
   140008f6e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f72:	48 83 c0 30          	add    rax,0x30
   140008f76:	48 89 c1             	mov    rcx,rax
   140008f79:	48 8b 05 78 72 00 00 	mov    rax,QWORD PTR [rip+0x7278]        # 1400101f8 <__imp_EnterCriticalSection>
   140008f80:	ff d0                	call   rax
   140008f82:	90                   	nop
   140008f83:	90                   	nop
   140008f84:	48 83 c4 20          	add    rsp,0x20
   140008f88:	5d                   	pop    rbp
   140008f89:	c3                   	ret

0000000140008f8a <_unlock_file>:
   140008f8a:	55                   	push   rbp
   140008f8b:	48 89 e5             	mov    rbp,rsp
   140008f8e:	48 83 ec 20          	sub    rsp,0x20
   140008f92:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008f96:	b9 00 00 00 00       	mov    ecx,0x0
   140008f9b:	e8 e0 00 00 00       	call   140009080 <__acrt_iob_func>
   140008fa0:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008fa4:	72 52                	jb     140008ff8 <_unlock_file+0x6e>
   140008fa6:	b9 13 00 00 00       	mov    ecx,0x13
   140008fab:	e8 d0 00 00 00       	call   140009080 <__acrt_iob_func>
   140008fb0:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008fb4:	72 42                	jb     140008ff8 <_unlock_file+0x6e>
   140008fb6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fba:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008fbd:	80 e4 7f             	and    ah,0x7f
   140008fc0:	89 c2                	mov    edx,eax
   140008fc2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fc6:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008fc9:	b9 00 00 00 00       	mov    ecx,0x0
   140008fce:	e8 ad 00 00 00       	call   140009080 <__acrt_iob_func>
   140008fd3:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008fd7:	48 29 c2             	sub    rdx,rax
   140008fda:	48 c1 fa 04          	sar    rdx,0x4
   140008fde:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008fe5:	aa aa aa 
   140008fe8:	48 0f af c2          	imul   rax,rdx
   140008fec:	83 c0 10             	add    eax,0x10
   140008fef:	89 c1                	mov    ecx,eax
   140008ff1:	e8 8a 06 00 00       	call   140009680 <_unlock>
   140008ff6:	eb 15                	jmp    14000900d <_unlock_file+0x83>
   140008ff8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008ffc:	48 83 c0 30          	add    rax,0x30
   140009000:	48 89 c1             	mov    rcx,rax
   140009003:	48 8b 05 26 72 00 00 	mov    rax,QWORD PTR [rip+0x7226]        # 140010230 <__imp_LeaveCriticalSection>
   14000900a:	ff d0                	call   rax
   14000900c:	90                   	nop
   14000900d:	90                   	nop
   14000900e:	48 83 c4 20          	add    rsp,0x20
   140009012:	5d                   	pop    rbp
   140009013:	c3                   	ret
   140009014:	90                   	nop
   140009015:	90                   	nop
   140009016:	90                   	nop
   140009017:	90                   	nop
   140009018:	90                   	nop
   140009019:	90                   	nop
   14000901a:	90                   	nop
   14000901b:	90                   	nop
   14000901c:	90                   	nop
   14000901d:	90                   	nop
   14000901e:	90                   	nop
   14000901f:	90                   	nop

0000000140009020 <_set_invalid_parameter_handler>:
   140009020:	55                   	push   rbp
   140009021:	48 89 e5             	mov    rbp,rsp
   140009024:	48 83 ec 10          	sub    rsp,0x10
   140009028:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000902c:	48 8d 05 4d 6b 00 00 	lea    rax,[rip+0x6b4d]        # 14000fb80 <handler>
   140009033:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140009037:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000903b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000903f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140009043:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140009047:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000904a:	48 89 d0             	mov    rax,rdx
   14000904d:	48 83 c4 10          	add    rsp,0x10
   140009051:	5d                   	pop    rbp
   140009052:	c3                   	ret

0000000140009053 <_get_invalid_parameter_handler>:
   140009053:	55                   	push   rbp
   140009054:	48 89 e5             	mov    rbp,rsp
   140009057:	48 8b 05 22 6b 00 00 	mov    rax,QWORD PTR [rip+0x6b22]        # 14000fb80 <handler>
   14000905e:	5d                   	pop    rbp
   14000905f:	c3                   	ret

0000000140009060 <_configthreadlocale>:
   140009060:	55                   	push   rbp
   140009061:	48 89 e5             	mov    rbp,rsp
   140009064:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140009067:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   14000906b:	75 07                	jne    140009074 <_configthreadlocale+0x14>
   14000906d:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140009072:	eb 05                	jmp    140009079 <_configthreadlocale+0x19>
   140009074:	b8 02 00 00 00       	mov    eax,0x2
   140009079:	5d                   	pop    rbp
   14000907a:	c3                   	ret
   14000907b:	90                   	nop
   14000907c:	90                   	nop
   14000907d:	90                   	nop
   14000907e:	90                   	nop
   14000907f:	90                   	nop

0000000140009080 <__acrt_iob_func>:
   140009080:	55                   	push   rbp
   140009081:	48 89 e5             	mov    rbp,rsp
   140009084:	48 83 ec 20          	sub    rsp,0x20
   140009088:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000908b:	e8 b0 05 00 00       	call   140009640 <__iob_func>
   140009090:	48 89 c1             	mov    rcx,rax
   140009093:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140009096:	48 89 d0             	mov    rax,rdx
   140009099:	48 01 c0             	add    rax,rax
   14000909c:	48 01 d0             	add    rax,rdx
   14000909f:	48 c1 e0 04          	shl    rax,0x4
   1400090a3:	48 01 c8             	add    rax,rcx
   1400090a6:	48 83 c4 20          	add    rsp,0x20
   1400090aa:	5d                   	pop    rbp
   1400090ab:	c3                   	ret
   1400090ac:	90                   	nop
   1400090ad:	90                   	nop
   1400090ae:	90                   	nop
   1400090af:	90                   	nop

00000001400090b0 <wcrtomb>:
   1400090b0:	55                   	push   rbp
   1400090b1:	48 89 e5             	mov    rbp,rsp
   1400090b4:	48 83 ec 40          	sub    rsp,0x40
   1400090b8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400090bc:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   1400090c0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400090c4:	e8 5f 05 00 00       	call   140009628 <___lc_codepage_func>
   1400090c9:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400090cc:	e8 5f 05 00 00       	call   140009630 <___mb_cur_max_func>
   1400090d1:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400090d4:	44 8b 4d fc          	mov    r9d,DWORD PTR [rbp-0x4]
   1400090d8:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   1400090dc:	0f b7 55 18          	movzx  edx,WORD PTR [rbp+0x18]
   1400090e0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400090e4:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   1400090e7:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   1400090eb:	48 89 c1             	mov    rcx,rax
   1400090ee:	e8 7d 00 00 00       	call   140009170 <__mingw_wcrtomb_cp>
   1400090f3:	48 83 c4 40          	add    rsp,0x40
   1400090f7:	5d                   	pop    rbp
   1400090f8:	c3                   	ret
   1400090f9:	90                   	nop
   1400090fa:	90                   	nop
   1400090fb:	90                   	nop
   1400090fc:	90                   	nop
   1400090fd:	90                   	nop
   1400090fe:	90                   	nop
   1400090ff:	90                   	nop

0000000140009100 <mbrtowc>:
   140009100:	55                   	push   rbp
   140009101:	48 89 e5             	mov    rbp,rsp
   140009104:	48 83 ec 40          	sub    rsp,0x40
   140009108:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000910c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009110:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009114:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009118:	48 83 7d 28 00       	cmp    QWORD PTR [rbp+0x28],0x0
   14000911d:	75 0b                	jne    14000912a <mbrtowc+0x2a>
   14000911f:	48 8d 05 6a 6a 00 00 	lea    rax,[rip+0x6a6a]        # 14000fb90 <state_mbrtowc.0>
   140009126:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000912a:	e8 f9 04 00 00       	call   140009628 <___lc_codepage_func>
   14000912f:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140009132:	e8 f9 04 00 00       	call   140009630 <___mb_cur_max_func>
   140009137:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000913a:	4c 8b 4d 28          	mov    r9,QWORD PTR [rbp+0x28]
   14000913e:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   140009142:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140009146:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000914a:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   14000914d:	89 4c 24 28          	mov    DWORD PTR [rsp+0x28],ecx
   140009151:	8b 4d fc             	mov    ecx,DWORD PTR [rbp-0x4]
   140009154:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   140009158:	48 89 c1             	mov    rcx,rax
   14000915b:	e8 70 01 00 00       	call   1400092d0 <__mingw_mbrtowc_cp>
   140009160:	48 83 c4 40          	add    rsp,0x40
   140009164:	5d                   	pop    rbp
   140009165:	c3                   	ret
   140009166:	90                   	nop
   140009167:	90                   	nop
   140009168:	90                   	nop
   140009169:	90                   	nop
   14000916a:	90                   	nop
   14000916b:	90                   	nop
   14000916c:	90                   	nop
   14000916d:	90                   	nop
   14000916e:	90                   	nop
   14000916f:	90                   	nop

0000000140009170 <__mingw_wcrtomb_cp>:
   140009170:	55                   	push   rbp
   140009171:	48 89 e5             	mov    rbp,rsp
   140009174:	48 83 ec 50          	sub    rsp,0x50
   140009178:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000917c:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   140009180:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009184:	44 89 4d 28          	mov    DWORD PTR [rbp+0x28],r9d
   140009188:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000918d:	75 1b                	jne    1400091aa <__mingw_wcrtomb_cp+0x3a>
   14000918f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009194:	74 0a                	je     1400091a0 <__mingw_wcrtomb_cp+0x30>
   140009196:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000919a:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400091a0:	b8 01 00 00 00       	mov    eax,0x1
   1400091a5:	e9 17 01 00 00       	jmp    1400092c1 <__mingw_wcrtomb_cp+0x151>
   1400091aa:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400091af:	74 21                	je     1400091d2 <__mingw_wcrtomb_cp+0x62>
   1400091b1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400091b5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400091b7:	85 c0                	test   eax,eax
   1400091b9:	74 17                	je     1400091d2 <__mingw_wcrtomb_cp+0x62>
   1400091bb:	e8 a8 04 00 00       	call   140009668 <_errno>
   1400091c0:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   1400091c6:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400091cd:	e9 ef 00 00 00       	jmp    1400092c1 <__mingw_wcrtomb_cp+0x151>
   1400091d2:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   1400091d6:	66 85 c0             	test   ax,ax
   1400091d9:	75 18                	jne    1400091f3 <__mingw_wcrtomb_cp+0x83>
   1400091db:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400091e0:	74 07                	je     1400091e9 <__mingw_wcrtomb_cp+0x79>
   1400091e2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400091e6:	c6 00 00             	mov    BYTE PTR [rax],0x0
   1400091e9:	b8 01 00 00 00       	mov    eax,0x1
   1400091ee:	e9 ce 00 00 00       	jmp    1400092c1 <__mingw_wcrtomb_cp+0x151>
   1400091f3:	83 7d 28 00          	cmp    DWORD PTR [rbp+0x28],0x0
   1400091f7:	75 2b                	jne    140009224 <__mingw_wcrtomb_cp+0xb4>
   1400091f9:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   1400091fd:	66 3d ff 00          	cmp    ax,0xff
   140009201:	0f 87 a4 00 00 00    	ja     1400092ab <__mingw_wcrtomb_cp+0x13b>
   140009207:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000920c:	74 0c                	je     14000921a <__mingw_wcrtomb_cp+0xaa>
   14000920e:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009212:	89 c2                	mov    edx,eax
   140009214:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009218:	88 10                	mov    BYTE PTR [rax],dl
   14000921a:	b8 01 00 00 00       	mov    eax,0x1
   14000921f:	e9 9d 00 00 00       	jmp    1400092c1 <__mingw_wcrtomb_cp+0x151>
   140009224:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   14000922b:	66 c7 45 f6 00 00    	mov    WORD PTR [rbp-0xa],0x0
   140009231:	48 8d 4d 18          	lea    rcx,[rbp+0x18]
   140009235:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140009238:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   14000923c:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140009241:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
   140009248:	00 00 
   14000924a:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   14000924d:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140009251:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   140009255:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   14000925a:	41 b9 01 00 00 00    	mov    r9d,0x1
   140009260:	49 89 c8             	mov    r8,rcx
   140009263:	ba 00 00 00 00       	mov    edx,0x0
   140009268:	89 c1                	mov    ecx,eax
   14000926a:	48 8b 05 ff 6f 00 00 	mov    rax,QWORD PTR [rip+0x6fff]        # 140010270 <__imp_WideCharToMultiByte>
   140009271:	ff d0                	call   rax
   140009273:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140009276:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000927a:	74 32                	je     1400092ae <__mingw_wcrtomb_cp+0x13e>
   14000927c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000927f:	3b 45 30             	cmp    eax,DWORD PTR [rbp+0x30]
   140009282:	7f 2a                	jg     1400092ae <__mingw_wcrtomb_cp+0x13e>
   140009284:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140009287:	85 c0                	test   eax,eax
   140009289:	75 23                	jne    1400092ae <__mingw_wcrtomb_cp+0x13e>
   14000928b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000928e:	48 63 c8             	movsxd rcx,eax
   140009291:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   140009295:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009299:	49 89 c8             	mov    r8,rcx
   14000929c:	48 89 c1             	mov    rcx,rax
   14000929f:	e8 34 04 00 00       	call   1400096d8 <memcpy>
   1400092a4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400092a7:	48 98                	cdqe
   1400092a9:	eb 16                	jmp    1400092c1 <__mingw_wcrtomb_cp+0x151>
   1400092ab:	90                   	nop
   1400092ac:	eb 01                	jmp    1400092af <__mingw_wcrtomb_cp+0x13f>
   1400092ae:	90                   	nop
   1400092af:	e8 b4 03 00 00       	call   140009668 <_errno>
   1400092b4:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   1400092ba:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400092c1:	48 83 c4 50          	add    rsp,0x50
   1400092c5:	5d                   	pop    rbp
   1400092c6:	c3                   	ret
   1400092c7:	90                   	nop
   1400092c8:	90                   	nop
   1400092c9:	90                   	nop
   1400092ca:	90                   	nop
   1400092cb:	90                   	nop
   1400092cc:	90                   	nop
   1400092cd:	90                   	nop
   1400092ce:	90                   	nop
   1400092cf:	90                   	nop

00000001400092d0 <__mingw_mbrtowc_cp>:
   1400092d0:	55                   	push   rbp
   1400092d1:	48 89 e5             	mov    rbp,rsp
   1400092d4:	48 83 ec 50          	sub    rsp,0x50
   1400092d8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400092dc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400092e0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400092e4:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400092e8:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   1400092ed:	75 1b                	jne    14000930a <__mingw_mbrtowc_cp+0x3a>
   1400092ef:	48 c7 45 10 00 00 00 	mov    QWORD PTR [rbp+0x10],0x0
   1400092f6:	00 
   1400092f7:	48 8d 05 22 22 00 00 	lea    rax,[rip+0x2222]        # 14000b520 <.rdata>
   1400092fe:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140009302:	48 c7 45 20 01 00 00 	mov    QWORD PTR [rbp+0x20],0x1
   140009309:	00 
   14000930a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000930e:	8b 00                	mov    eax,DWORD PTR [rax]
   140009310:	3d ff 00 00 00       	cmp    eax,0xff
   140009315:	0f 87 b9 01 00 00    	ja     1400094d4 <__mingw_mbrtowc_cp+0x204>
   14000931b:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009320:	75 0c                	jne    14000932e <__mingw_mbrtowc_cp+0x5e>
   140009322:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   140009329:	e9 bc 01 00 00       	jmp    1400094ea <__mingw_mbrtowc_cp+0x21a>
   14000932e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009332:	8b 00                	mov    eax,DWORD PTR [rax]
   140009334:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140009337:	83 7d 38 01          	cmp    DWORD PTR [rbp+0x38],0x1
   14000933b:	75 0c                	jne    140009349 <__mingw_mbrtowc_cp+0x79>
   14000933d:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009341:	84 c0                	test   al,al
   140009343:	0f 85 8e 01 00 00    	jne    1400094d7 <__mingw_mbrtowc_cp+0x207>
   140009349:	83 7d 30 00          	cmp    DWORD PTR [rbp+0x30],0x0
   14000934d:	75 2c                	jne    14000937b <__mingw_mbrtowc_cp+0xab>
   14000934f:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140009354:	74 11                	je     140009367 <__mingw_mbrtowc_cp+0x97>
   140009356:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000935a:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000935d:	0f b6 d0             	movzx  edx,al
   140009360:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009364:	66 89 10             	mov    WORD PTR [rax],dx
   140009367:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000936b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000936e:	84 c0                	test   al,al
   140009370:	0f 95 c0             	setne  al
   140009373:	0f b6 c0             	movzx  eax,al
   140009376:	e9 6f 01 00 00       	jmp    1400094ea <__mingw_mbrtowc_cp+0x21a>
   14000937b:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140009382:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140009389:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   14000938d:	84 c0                	test   al,al
   14000938f:	74 1a                	je     1400093ab <__mingw_mbrtowc_cp+0xdb>
   140009391:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009395:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009398:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   14000939b:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400093a2:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   1400093a9:	eb 73                	jmp    14000941e <__mingw_mbrtowc_cp+0x14e>
   1400093ab:	83 7d 38 02          	cmp    DWORD PTR [rbp+0x38],0x2
   1400093af:	75 5c                	jne    14000940d <__mingw_mbrtowc_cp+0x13d>
   1400093b1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093b5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093b8:	0f b6 c0             	movzx  eax,al
   1400093bb:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   1400093be:	89 c1                	mov    ecx,eax
   1400093c0:	e8 ab 01 00 00       	call   140009570 <__mingw_isleadbyte_cp>
   1400093c5:	85 c0                	test   eax,eax
   1400093c7:	74 44                	je     14000940d <__mingw_mbrtowc_cp+0x13d>
   1400093c9:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093cd:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093d0:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   1400093d3:	48 83 7d 20 01       	cmp    QWORD PTR [rbp+0x20],0x1
   1400093d8:	77 15                	ja     1400093ef <__mingw_mbrtowc_cp+0x11f>
   1400093da:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400093dd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400093e1:	89 10                	mov    DWORD PTR [rax],edx
   1400093e3:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   1400093ea:	e9 fb 00 00 00       	jmp    1400094ea <__mingw_mbrtowc_cp+0x21a>
   1400093ef:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093f3:	48 83 c0 01          	add    rax,0x1
   1400093f7:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093fa:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   1400093fd:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140009404:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   14000940b:	eb 11                	jmp    14000941e <__mingw_mbrtowc_cp+0x14e>
   14000940d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009411:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009414:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009417:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   14000941e:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009422:	84 c0                	test   al,al
   140009424:	75 24                	jne    14000944a <__mingw_mbrtowc_cp+0x17a>
   140009426:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000942b:	74 09                	je     140009436 <__mingw_mbrtowc_cp+0x166>
   14000942d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009431:	66 c7 00 00 00       	mov    WORD PTR [rax],0x0
   140009436:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000943a:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009440:	b8 00 00 00 00       	mov    eax,0x0
   140009445:	e9 a0 00 00 00       	jmp    1400094ea <__mingw_mbrtowc_cp+0x21a>
   14000944a:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   14000944e:	75 08                	jne    140009458 <__mingw_mbrtowc_cp+0x188>
   140009450:	0f b6 45 f1          	movzx  eax,BYTE PTR [rbp-0xf]
   140009454:	84 c0                	test   al,al
   140009456:	74 64                	je     1400094bc <__mingw_mbrtowc_cp+0x1ec>
   140009458:	66 c7 45 ee ff ff    	mov    WORD PTR [rbp-0x12],0xffff
   14000945e:	44 8b 45 fc          	mov    r8d,DWORD PTR [rbp-0x4]
   140009462:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   140009466:	8b 45 30             	mov    eax,DWORD PTR [rbp+0x30]
   140009469:	c7 44 24 28 01 00 00 	mov    DWORD PTR [rsp+0x28],0x1
   140009470:	00 
   140009471:	48 8d 55 ee          	lea    rdx,[rbp-0x12]
   140009475:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   14000947a:	45 89 c1             	mov    r9d,r8d
   14000947d:	49 89 c8             	mov    r8,rcx
   140009480:	ba 08 00 00 00       	mov    edx,0x8
   140009485:	89 c1                	mov    ecx,eax
   140009487:	48 8b 05 b2 6d 00 00 	mov    rax,QWORD PTR [rip+0x6db2]        # 140010240 <__imp_MultiByteToWideChar>
   14000948e:	ff d0                	call   rax
   140009490:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140009493:	83 7d f4 01          	cmp    DWORD PTR [rbp-0xc],0x1
   140009497:	75 26                	jne    1400094bf <__mingw_mbrtowc_cp+0x1ef>
   140009499:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000949e:	74 0b                	je     1400094ab <__mingw_mbrtowc_cp+0x1db>
   1400094a0:	0f b7 55 ee          	movzx  edx,WORD PTR [rbp-0x12]
   1400094a4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400094a8:	66 89 10             	mov    WORD PTR [rax],dx
   1400094ab:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400094af:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400094b5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400094b8:	48 98                	cdqe
   1400094ba:	eb 2e                	jmp    1400094ea <__mingw_mbrtowc_cp+0x21a>
   1400094bc:	90                   	nop
   1400094bd:	eb 01                	jmp    1400094c0 <__mingw_mbrtowc_cp+0x1f0>
   1400094bf:	90                   	nop
   1400094c0:	e8 a3 01 00 00       	call   140009668 <_errno>
   1400094c5:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   1400094cb:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400094d2:	eb 16                	jmp    1400094ea <__mingw_mbrtowc_cp+0x21a>
   1400094d4:	90                   	nop
   1400094d5:	eb 01                	jmp    1400094d8 <__mingw_mbrtowc_cp+0x208>
   1400094d7:	90                   	nop
   1400094d8:	e8 8b 01 00 00       	call   140009668 <_errno>
   1400094dd:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   1400094e3:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   1400094ea:	48 83 c4 50          	add    rsp,0x50
   1400094ee:	5d                   	pop    rbp
   1400094ef:	c3                   	ret

00000001400094f0 <fallback_IsDBCSLeadByteEx>:
   1400094f0:	55                   	push   rbp
   1400094f1:	48 89 e5             	mov    rbp,rsp
   1400094f4:	48 83 ec 40          	sub    rsp,0x40
   1400094f8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400094fb:	88 55 18             	mov    BYTE PTR [rbp+0x18],dl
   1400094fe:	48 8d 55 e0          	lea    rdx,[rbp-0x20]
   140009502:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009505:	89 c1                	mov    ecx,eax
   140009507:	48 8b 05 fa 6c 00 00 	mov    rax,QWORD PTR [rip+0x6cfa]        # 140010208 <__imp_GetCPInfo>
   14000950e:	ff d0                	call   rax
   140009510:	85 c0                	test   eax,eax
   140009512:	74 51                	je     140009565 <fallback_IsDBCSLeadByteEx+0x75>
   140009514:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140009517:	83 f8 02             	cmp    eax,0x2
   14000951a:	75 49                	jne    140009565 <fallback_IsDBCSLeadByteEx+0x75>
   14000951c:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140009523:	eb 2c                	jmp    140009551 <fallback_IsDBCSLeadByteEx+0x61>
   140009525:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009528:	48 98                	cdqe
   14000952a:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   14000952f:	38 45 18             	cmp    BYTE PTR [rbp+0x18],al
   140009532:	72 19                	jb     14000954d <fallback_IsDBCSLeadByteEx+0x5d>
   140009534:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009537:	83 c0 01             	add    eax,0x1
   14000953a:	48 98                	cdqe
   14000953c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009541:	3a 45 18             	cmp    al,BYTE PTR [rbp+0x18]
   140009544:	72 07                	jb     14000954d <fallback_IsDBCSLeadByteEx+0x5d>
   140009546:	b8 01 00 00 00       	mov    eax,0x1
   14000954b:	eb 1d                	jmp    14000956a <fallback_IsDBCSLeadByteEx+0x7a>
   14000954d:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   140009551:	83 7d fc 0b          	cmp    DWORD PTR [rbp-0x4],0xb
   140009555:	7f 0e                	jg     140009565 <fallback_IsDBCSLeadByteEx+0x75>
   140009557:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000955a:	48 98                	cdqe
   14000955c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009561:	84 c0                	test   al,al
   140009563:	75 c0                	jne    140009525 <fallback_IsDBCSLeadByteEx+0x35>
   140009565:	b8 00 00 00 00       	mov    eax,0x0
   14000956a:	48 83 c4 40          	add    rsp,0x40
   14000956e:	5d                   	pop    rbp
   14000956f:	c3                   	ret

0000000140009570 <__mingw_isleadbyte_cp>:
   140009570:	55                   	push   rbp
   140009571:	48 89 e5             	mov    rbp,rsp
   140009574:	48 83 ec 40          	sub    rsp,0x40
   140009578:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000957b:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000957e:	48 8b 05 1b 66 00 00 	mov    rax,QWORD PTR [rip+0x661b]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009585:	48 85 c0             	test   rax,rax
   140009588:	75 71                	jne    1400095fb <__mingw_isleadbyte_cp+0x8b>
   14000958a:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140009591:	00 
   140009592:	48 8d 05 97 1f 00 00 	lea    rax,[rip+0x1f97]        # 14000b530 <.rdata>
   140009599:	48 89 c1             	mov    rcx,rax
   14000959c:	48 8b 05 75 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c75]        # 140010218 <__imp_GetModuleHandleA>
   1400095a3:	ff d0                	call   rax
   1400095a5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400095a9:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400095ae:	74 1b                	je     1400095cb <__mingw_isleadbyte_cp+0x5b>
   1400095b0:	48 8d 15 86 1f 00 00 	lea    rdx,[rip+0x1f86]        # 14000b53d <.rdata+0xd>
   1400095b7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400095bb:	48 89 c1             	mov    rcx,rax
   1400095be:	48 8b 05 5b 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c5b]        # 140010220 <__imp_GetProcAddress>
   1400095c5:	ff d0                	call   rax
   1400095c7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400095cb:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   1400095d0:	75 0b                	jne    1400095dd <__mingw_isleadbyte_cp+0x6d>
   1400095d2:	48 8d 05 17 ff ff ff 	lea    rax,[rip+0xffffffffffffff17]        # 1400094f0 <fallback_IsDBCSLeadByteEx>
   1400095d9:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400095dd:	48 8d 05 bc 65 00 00 	lea    rax,[rip+0x65bc]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   1400095e4:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400095e8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400095ec:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400095f0:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   1400095f4:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400095f8:	48 87 10             	xchg   QWORD PTR [rax],rdx
   1400095fb:	4c 8b 05 9e 65 00 00 	mov    r8,QWORD PTR [rip+0x659e]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009602:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009605:	0f b6 d0             	movzx  edx,al
   140009608:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000960b:	89 c1                	mov    ecx,eax
   14000960d:	41 ff d0             	call   r8
   140009610:	48 83 c4 40          	add    rsp,0x40
   140009614:	5d                   	pop    rbp
   140009615:	c3                   	ret
   140009616:	90                   	nop
   140009617:	90                   	nop
   140009618:	90                   	nop
   140009619:	90                   	nop
   14000961a:	90                   	nop
   14000961b:	90                   	nop
   14000961c:	90                   	nop
   14000961d:	90                   	nop
   14000961e:	90                   	nop
   14000961f:	90                   	nop

0000000140009620 <__C_specific_handler>:
   140009620:	ff 25 5a 6c 00 00    	jmp    QWORD PTR [rip+0x6c5a]        # 140010280 <__imp___C_specific_handler>
   140009626:	90                   	nop
   140009627:	90                   	nop

0000000140009628 <___lc_codepage_func>:
   140009628:	ff 25 5a 6c 00 00    	jmp    QWORD PTR [rip+0x6c5a]        # 140010288 <__imp____lc_codepage_func>
   14000962e:	90                   	nop
   14000962f:	90                   	nop

0000000140009630 <___mb_cur_max_func>:
   140009630:	ff 25 5a 6c 00 00    	jmp    QWORD PTR [rip+0x6c5a]        # 140010290 <__imp____mb_cur_max_func>
   140009636:	90                   	nop
   140009637:	90                   	nop

0000000140009638 <__getmainargs>:
   140009638:	ff 25 5a 6c 00 00    	jmp    QWORD PTR [rip+0x6c5a]        # 140010298 <__imp___getmainargs>
   14000963e:	90                   	nop
   14000963f:	90                   	nop

0000000140009640 <__iob_func>:
   140009640:	ff 25 62 6c 00 00    	jmp    QWORD PTR [rip+0x6c62]        # 1400102a8 <__imp___iob_func>
   140009646:	90                   	nop
   140009647:	90                   	nop

0000000140009648 <__set_app_type>:
   140009648:	ff 25 62 6c 00 00    	jmp    QWORD PTR [rip+0x6c62]        # 1400102b0 <__imp___set_app_type>
   14000964e:	90                   	nop
   14000964f:	90                   	nop

0000000140009650 <__setusermatherr>:
   140009650:	ff 25 62 6c 00 00    	jmp    QWORD PTR [rip+0x6c62]        # 1400102b8 <__imp___setusermatherr>
   140009656:	90                   	nop
   140009657:	90                   	nop

0000000140009658 <_amsg_exit>:
   140009658:	ff 25 62 6c 00 00    	jmp    QWORD PTR [rip+0x6c62]        # 1400102c0 <__imp__amsg_exit>
   14000965e:	90                   	nop
   14000965f:	90                   	nop

0000000140009660 <_cexit>:
   140009660:	ff 25 62 6c 00 00    	jmp    QWORD PTR [rip+0x6c62]        # 1400102c8 <__imp__cexit>
   140009666:	90                   	nop
   140009667:	90                   	nop

0000000140009668 <_errno>:
   140009668:	ff 25 6a 6c 00 00    	jmp    QWORD PTR [rip+0x6c6a]        # 1400102d8 <__imp__errno>
   14000966e:	90                   	nop
   14000966f:	90                   	nop

0000000140009670 <_initterm>:
   140009670:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 1400102e8 <__imp__initterm>
   140009676:	90                   	nop
   140009677:	90                   	nop

0000000140009678 <_lock>:
   140009678:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 1400102f0 <__imp__lock>
   14000967e:	90                   	nop
   14000967f:	90                   	nop

0000000140009680 <_unlock>:
   140009680:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 1400102f8 <__imp__unlock>
   140009686:	90                   	nop
   140009687:	90                   	nop

0000000140009688 <_crt_atexit>:
   140009688:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010300 <__imp__crt_atexit>
   14000968e:	90                   	nop
   14000968f:	90                   	nop

0000000140009690 <abort>:
   140009690:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010308 <__imp_abort>
   140009696:	90                   	nop
   140009697:	90                   	nop

0000000140009698 <calloc>:
   140009698:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010310 <__imp_calloc>
   14000969e:	90                   	nop
   14000969f:	90                   	nop

00000001400096a0 <exit>:
   1400096a0:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010318 <__imp_exit>
   1400096a6:	90                   	nop
   1400096a7:	90                   	nop

00000001400096a8 <fflush>:
   1400096a8:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010320 <__imp_fflush>
   1400096ae:	90                   	nop
   1400096af:	90                   	nop

00000001400096b0 <fprintf>:
   1400096b0:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010328 <__imp_fprintf>
   1400096b6:	90                   	nop
   1400096b7:	90                   	nop

00000001400096b8 <fputc>:
   1400096b8:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010330 <__imp_fputc>
   1400096be:	90                   	nop
   1400096bf:	90                   	nop

00000001400096c0 <free>:
   1400096c0:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010338 <__imp_free>
   1400096c6:	90                   	nop
   1400096c7:	90                   	nop

00000001400096c8 <localeconv>:
   1400096c8:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010340 <__imp_localeconv>
   1400096ce:	90                   	nop
   1400096cf:	90                   	nop

00000001400096d0 <malloc>:
   1400096d0:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010348 <__imp_malloc>
   1400096d6:	90                   	nop
   1400096d7:	90                   	nop

00000001400096d8 <memcpy>:
   1400096d8:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010350 <__imp_memcpy>
   1400096de:	90                   	nop
   1400096df:	90                   	nop

00000001400096e0 <memset>:
   1400096e0:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010358 <__imp_memset>
   1400096e6:	90                   	nop
   1400096e7:	90                   	nop

00000001400096e8 <setvbuf>:
   1400096e8:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010360 <__imp_setvbuf>
   1400096ee:	90                   	nop
   1400096ef:	90                   	nop

00000001400096f0 <signal>:
   1400096f0:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010368 <__imp_signal>
   1400096f6:	90                   	nop
   1400096f7:	90                   	nop

00000001400096f8 <strerror>:
   1400096f8:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010370 <__imp_strerror>
   1400096fe:	90                   	nop
   1400096ff:	90                   	nop

0000000140009700 <strlen>:
   140009700:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010378 <__imp_strlen>
   140009706:	90                   	nop
   140009707:	90                   	nop

0000000140009708 <strncmp>:
   140009708:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010380 <__imp_strncmp>
   14000970e:	90                   	nop
   14000970f:	90                   	nop

0000000140009710 <vfprintf>:
   140009710:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010388 <__imp_vfprintf>
   140009716:	90                   	nop
   140009717:	90                   	nop

0000000140009718 <wcslen>:
   140009718:	ff 25 72 6c 00 00    	jmp    QWORD PTR [rip+0x6c72]        # 140010390 <__imp_wcslen>
   14000971e:	90                   	nop
   14000971f:	90                   	nop

0000000140009720 <WideCharToMultiByte>:
   140009720:	ff 25 4a 6b 00 00    	jmp    QWORD PTR [rip+0x6b4a]        # 140010270 <__imp_WideCharToMultiByte>
   140009726:	90                   	nop
   140009727:	90                   	nop

0000000140009728 <VirtualQuery>:
   140009728:	ff 25 3a 6b 00 00    	jmp    QWORD PTR [rip+0x6b3a]        # 140010268 <__imp_VirtualQuery>
   14000972e:	90                   	nop
   14000972f:	90                   	nop

0000000140009730 <VirtualProtect>:
   140009730:	ff 25 2a 6b 00 00    	jmp    QWORD PTR [rip+0x6b2a]        # 140010260 <__imp_VirtualProtect>
   140009736:	90                   	nop
   140009737:	90                   	nop

0000000140009738 <TlsGetValue>:
   140009738:	ff 25 1a 6b 00 00    	jmp    QWORD PTR [rip+0x6b1a]        # 140010258 <__imp_TlsGetValue>
   14000973e:	90                   	nop
   14000973f:	90                   	nop

0000000140009740 <Sleep>:
   140009740:	ff 25 0a 6b 00 00    	jmp    QWORD PTR [rip+0x6b0a]        # 140010250 <__imp_Sleep>
   140009746:	90                   	nop
   140009747:	90                   	nop

0000000140009748 <SetUnhandledExceptionFilter>:
   140009748:	ff 25 fa 6a 00 00    	jmp    QWORD PTR [rip+0x6afa]        # 140010248 <__imp_SetUnhandledExceptionFilter>
   14000974e:	90                   	nop
   14000974f:	90                   	nop

0000000140009750 <MultiByteToWideChar>:
   140009750:	ff 25 ea 6a 00 00    	jmp    QWORD PTR [rip+0x6aea]        # 140010240 <__imp_MultiByteToWideChar>
   140009756:	90                   	nop
   140009757:	90                   	nop

0000000140009758 <LoadLibraryA>:
   140009758:	ff 25 da 6a 00 00    	jmp    QWORD PTR [rip+0x6ada]        # 140010238 <__imp_LoadLibraryA>
   14000975e:	90                   	nop
   14000975f:	90                   	nop

0000000140009760 <LeaveCriticalSection>:
   140009760:	ff 25 ca 6a 00 00    	jmp    QWORD PTR [rip+0x6aca]        # 140010230 <__imp_LeaveCriticalSection>
   140009766:	90                   	nop
   140009767:	90                   	nop

0000000140009768 <InitializeCriticalSection>:
   140009768:	ff 25 ba 6a 00 00    	jmp    QWORD PTR [rip+0x6aba]        # 140010228 <__imp_InitializeCriticalSection>
   14000976e:	90                   	nop
   14000976f:	90                   	nop

0000000140009770 <GetProcAddress>:
   140009770:	ff 25 aa 6a 00 00    	jmp    QWORD PTR [rip+0x6aaa]        # 140010220 <__imp_GetProcAddress>
   140009776:	90                   	nop
   140009777:	90                   	nop

0000000140009778 <GetModuleHandleA>:
   140009778:	ff 25 9a 6a 00 00    	jmp    QWORD PTR [rip+0x6a9a]        # 140010218 <__imp_GetModuleHandleA>
   14000977e:	90                   	nop
   14000977f:	90                   	nop

0000000140009780 <GetLastError>:
   140009780:	ff 25 8a 6a 00 00    	jmp    QWORD PTR [rip+0x6a8a]        # 140010210 <__imp_GetLastError>
   140009786:	90                   	nop
   140009787:	90                   	nop

0000000140009788 <GetCPInfo>:
   140009788:	ff 25 7a 6a 00 00    	jmp    QWORD PTR [rip+0x6a7a]        # 140010208 <__imp_GetCPInfo>
   14000978e:	90                   	nop
   14000978f:	90                   	nop

0000000140009790 <FreeLibrary>:
   140009790:	ff 25 6a 6a 00 00    	jmp    QWORD PTR [rip+0x6a6a]        # 140010200 <__imp_FreeLibrary>
   140009796:	90                   	nop
   140009797:	90                   	nop

0000000140009798 <EnterCriticalSection>:
   140009798:	ff 25 5a 6a 00 00    	jmp    QWORD PTR [rip+0x6a5a]        # 1400101f8 <__imp_EnterCriticalSection>
   14000979e:	90                   	nop
   14000979f:	90                   	nop

00000001400097a0 <DeleteCriticalSection>:
   1400097a0:	ff 25 4a 6a 00 00    	jmp    QWORD PTR [rip+0x6a4a]        # 1400101f0 <__IAT_start__>
   1400097a6:	90                   	nop
   1400097a7:	90                   	nop
   1400097a8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   1400097af:	00 

00000001400097b0 <register_frame_ctor>:
   1400097b0:	e9 bb 7e ff ff       	jmp    140001670 <__gcc_register_frame>
   1400097b5:	90                   	nop
   1400097b6:	90                   	nop
   1400097b7:	90                   	nop
   1400097b8:	90                   	nop
   1400097b9:	90                   	nop
   1400097ba:	90                   	nop
   1400097bb:	90                   	nop
   1400097bc:	90                   	nop
   1400097bd:	90                   	nop
   1400097be:	90                   	nop
   1400097bf:	90                   	nop
